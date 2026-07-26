"""Network-isolated tests for bounded AWS SigV4 application actions."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import boto3  # type: ignore[import-untyped]
import pytest
import yaml
from pydantic import AnyHttpUrl, ValidationError

import cai_verify.aws.action as action_module
from cai_verify.adapters._limits import MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES
from cai_verify.aws import (
    AwsActionFailureCode,
    AwsScopedIdentity,
    AwsSigV4ActionAdapter,
)
from cai_verify.config import (
    ActionInput,
    AwsSigV4Action,
    Target,
    VerificationSuite,
)
from cai_verify.plugins import (
    ActionExecutor,
    ActionOutcome,
    ActionRequest,
    ExecutionContext,
)
from tests.plugins.contract_suite import assert_action_executor_contract

if TYPE_CHECKING:
    from cai_verify.aws import AwsSession

_FIXTURE = Path(__file__).parents[1] / "fixtures/suites/valid/full.yaml"
_FIXED_TIME = datetime(2026, 7, 26, 12, tzinfo=UTC)
_ACCESS_KEY = "AKIDEXAMPLE"
_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"  # noqa: S105
_SESSION_TOKEN = "synthetic-temporary-session-token"  # noqa: S105
_REQUEST_SECRET = "synthetic-request-body-secret"  # noqa: S105
_RESPONSE_SECRET = "synthetic-response-body-secret"  # noqa: S105
_SDK_SECRET = "synthetic-sdk-exception-secret"  # noqa: S105
_DECLARED_TIMEOUT_SECONDS = 15
_DEFAULT_HTTPS_PORT = 443


@dataclass(slots=True)
class _CaptureTransport:
    status: int = 200
    body: bytes = b"{}"
    echo_correlation: bool = True
    correlation_id: str | None = None
    aws_request_ids: tuple[str, ...] = ("synthetic-aws-request-id",)
    error: Exception | None = None
    requests: list[action_module._AwsHttpRequest] = field(
        default_factory=list,
    )

    def send(
        self,
        request: action_module._AwsHttpRequest,
        /,
    ) -> action_module._AwsHttpResponse:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        correlation_id = self.correlation_id
        if self.echo_correlation:
            correlation_id = request.header_map()["X-Cai-Correlation-Id"]
        return action_module._AwsHttpResponse(  # noqa: SLF001
            status=self.status,
            correlation_id=correlation_id,
            too_large=len(self.body) > MAX_RESPONSE_BYTES,
            aws_request_ids=self.aws_request_ids,
        )


def test_validated_suite_action_to_signed_request_and_normalized_result() -> None:
    """The contract path remains typed from suite input through safe output."""
    suite = _suite()
    action = _action(suite)
    transport = _CaptureTransport()
    adapter = _adapter(transport)
    request = _request(suite, action=action)

    assert isinstance(adapter, ActionExecutor)
    result = assert_action_executor_contract(adapter, request)

    assert result.outcome is ActionOutcome.SUCCEEDED
    assert result.correlation_ids == ("aws-9503a2a4136a58c50e5c0ab3",)
    assert result.aws_request_ids == ("synthetic-aws-request-id",)
    assert result.observed.to_json_value() == {
        "correlation_state": "MATCHED",
        "http_status": 200,
        "response_too_large": False,
        "service": "execute-api",
        "signing_region": "eu-west-2",
    }
    assert adapter.metadata.capabilities == (
        "action.aws-sigv4.bedrock-runtime",
        "action.aws-sigv4.execute-api",
    )
    captured = transport.requests[0]
    headers = captured.header_map()
    assert captured.method == "POST"
    assert captured.url == (
        "https://assistant.sandbox.example.test/v1/documents/synthetic/summarize"
    )
    assert captured.target == "/v1/documents/synthetic/summarize"
    assert captured.service == "execute-api"
    assert captured.region == "eu-west-2"
    assert captured.timeout_seconds == _DECLARED_TIMEOUT_SECONDS
    assert captured.body == b'{"documentId":"synthetic-document-001"}'
    assert headers["X-Amz-Date"] == "20260726T120000Z"
    assert "/eu-west-2/execute-api/aws4_request" in headers["Authorization"]


def test_bedrock_runtime_signing_uses_declared_service_and_target_region() -> None:
    """Bedrock uses its exact signing name and inherits the target region."""
    suite = _suite()
    action = _action(suite).model_copy(
        update={
            "path": "/model/synthetic-model/invoke",
            "region": None,
            "service": "bedrock-runtime",
        },
    )
    target = _target(
        suite,
        endpoint="https://bedrock-runtime.eu-west-2.amazonaws.com",
        allowed_hosts=("bedrock-runtime.eu-west-2.amazonaws.com",),
    )
    transport = _CaptureTransport()

    result = _adapter(transport).execute_action(
        _request(suite, action=action, target=target),
    )

    assert result.outcome is ActionOutcome.SUCCEEDED
    captured = transport.requests[0]
    authorization = captured.header_map()["Authorization"]
    assert captured.service == "bedrock-runtime"
    assert captured.region == target.aws_region
    assert "/eu-west-2/bedrock-runtime/aws4_request" in authorization


def test_temporary_session_token_is_signed_but_never_normalized() -> None:
    """Botocore places the token in transport headers, not the public result."""
    suite = _suite()
    transport = _CaptureTransport()

    result = _adapter(transport).execute_action(
        _request(suite, identity=_identity(session_token=_SESSION_TOKEN)),
    )

    headers = transport.requests[0].header_map()
    assert headers["X-Amz-Security-Token"] == _SESSION_TOKEN
    assert "x-amz-security-token" in headers["Authorization"]
    rendered = repr(result) + json.dumps(result.observed.to_json_value())
    assert _SESSION_TOKEN not in rendered
    assert _ACCESS_KEY not in rendered


def test_signature_is_exact_and_deterministic_for_fixed_time() -> None:
    """A fixed timestamp and request produce an exact Botocore signature."""
    suite = _suite()
    first = _CaptureTransport()
    second = _CaptureTransport()

    _adapter(first).execute_action(_request(suite))
    _adapter(second).execute_action(_request(suite))

    first_authorization = first.requests[0].header_map()["Authorization"]
    second_authorization = second.requests[0].header_map()["Authorization"]
    assert first_authorization == second_authorization
    assert first_authorization == (
        "AWS4-HMAC-SHA256 "
        "Credential=AKIDEXAMPLE/20260726/eu-west-2/execute-api/aws4_request, "
        "SignedHeaders=content-type;host;x-amz-date;x-cai-correlation-id, "
        "Signature="
        "4876ba1a6dd8d0dbe98d45b80665dcc20704f56a597b33e786aa63e3b2a2df13"
    )


def test_literal_and_environment_inputs_keep_exact_locations() -> None:
    """Resolved inputs are signed in their declared header, query, and JSON slots."""
    suite = _suite()
    action = _action_with_inputs(
        suite,
        _environment_input("header", "X-Synthetic-Trace", "TRACE_VALUE"),
        _literal_input("query", "a", 7),
        _environment_input("query", "z", "QUERY_VALUE"),
        _environment_input("json", "privateNote", "BODY_VALUE"),
    )
    transport = _CaptureTransport()
    adapter = AwsSigV4ActionAdapter(
        environment={
            "BODY_VALUE": _REQUEST_SECRET,
            "QUERY_VALUE": "synthetic query",
            "TRACE_VALUE": "trace-public",
        },
        transport=transport,
        clock=lambda: _FIXED_TIME,
    )

    result = adapter.execute_action(_request(suite, action=action))

    assert result.outcome is ActionOutcome.SUCCEEDED
    captured = transport.requests[0]
    assert captured.header_map()["X-Synthetic-Trace"] == "trace-public"
    assert captured.target.endswith("?a=7&z=synthetic%20query")
    assert json.loads(captured.body) == {
        "documentId": "synthetic-document-001",
        "privateNote": _REQUEST_SECRET,
    }
    assert "synthetic query" not in repr(captured)
    assert _REQUEST_SECRET not in repr(captured)
    assert _REQUEST_SECRET not in repr(result)
    assert _REQUEST_SECRET not in json.dumps(result.observed.to_json_value())


def test_missing_environment_reference_is_a_stable_error() -> None:
    """Missing values fail before signing without consulting neighboring values."""
    suite = _suite()
    action = _action_with_inputs(
        suite,
        _environment_input("json", "privateNote", "MISSING_VALUE"),
    )
    transport = _CaptureTransport()
    adapter = AwsSigV4ActionAdapter(
        environment={"NEIGHBOR": _REQUEST_SECRET},
        transport=transport,
        clock=lambda: _FIXED_TIME,
    )

    result = adapter.execute_action(_request(suite, action=action))

    assert result.outcome is ActionOutcome.ERROR
    assert _error(result) is AwsActionFailureCode.ENVIRONMENT_VALUE_INVALID
    assert transport.requests == []
    assert _REQUEST_SECRET not in repr(adapter)
    assert _REQUEST_SECRET not in repr(result)


@pytest.mark.parametrize(
    "header_name",
    [
        "Authorization",
        "Host",
        "Content-Length",
        "Transfer-Encoding",
        "Connection",
        "X-Amz-Date",
        "X-Amz-Security-Token",
        "X-Amz-Content-Sha256",
        "X-Amzn-RequestId",
    ],
)
def test_caller_controlled_signing_and_transport_headers_are_rejected(
    header_name: str,
) -> None:
    """Case-insensitive adapter-owned headers never reach Botocore or transport."""
    suite = _suite()
    action = _action_with_inputs(
        suite,
        _environment_input("header", header_name, "RESERVED_VALUE"),
    )
    transport = _CaptureTransport()
    adapter = AwsSigV4ActionAdapter(
        environment={"RESERVED_VALUE": _REQUEST_SECRET},
        transport=transport,
        clock=lambda: _FIXED_TIME,
    )

    result = adapter.execute_action(_request(suite, action=action))

    assert result.outcome is ActionOutcome.ERROR
    assert _error(result) is AwsActionFailureCode.RESERVED_HEADER
    assert transport.requests == []
    assert header_name not in json.dumps(result.observed.to_json_value())
    assert _REQUEST_SECRET not in repr(result)


@pytest.mark.parametrize(
    ("target", "expected_error"),
    [
        ("not-allowlisted", AwsActionFailureCode.INVALID_CONFIGURATION),
        ("cleartext", AwsActionFailureCode.INVALID_CONFIGURATION),
        ("loopback", AwsActionFailureCode.INVALID_CONFIGURATION),
    ],
)
def test_https_exact_host_allowlist_and_non_local_guards(
    target: str,
    expected_error: AwsActionFailureCode,
) -> None:
    """Defense-in-depth checks reject bypassed malformed target models."""
    suite = _suite()
    if target == "not-allowlisted":
        runtime_target = _target(
            suite,
            allowed_hosts=("other.example.test",),
        )
    elif target == "cleartext":
        runtime_target = _target(
            suite,
            endpoint="http://assistant.sandbox.example.test/v1",
        )
    else:
        runtime_target = _target(
            suite,
            endpoint="https://127.0.0.1/v1",
            allowed_hosts=("127.0.0.1",),
        )
    transport = _CaptureTransport()

    result = _adapter(transport).execute_action(
        _request(suite, target=runtime_target),
    )

    assert result.outcome is ActionOutcome.ERROR
    assert _error(result) is expected_error
    assert transport.requests == []


@pytest.mark.parametrize("status", [401, 403])
def test_denial_responses_are_normalized_separately(status: int) -> None:
    """Authentication and authorization denials are not transport errors."""
    suite = _suite()
    transport = _CaptureTransport(status=status)

    result = _adapter(transport).execute_action(_request(suite))

    assert result.outcome is ActionOutcome.DENIED
    observed = cast("dict[str, object]", result.observed.to_json_value())
    assert observed["http_status"] == status
    assert "error" not in observed


def test_timeout_and_transport_exception_are_redacted() -> None:
    """The declared timeout reaches transport while exception text does not."""
    suite = _suite()
    transport = _CaptureTransport(error=TimeoutError(_SDK_SECRET))

    result = _adapter(transport).execute_action(_request(suite))

    assert transport.requests[0].timeout_seconds == _DECLARED_TIMEOUT_SECONDS
    assert result.outcome is ActionOutcome.ERROR
    assert _error(result) is AwsActionFailureCode.TRANSPORT_ERROR
    assert _SDK_SECRET not in repr(result)
    assert _SDK_SECRET not in json.dumps(result.observed.to_json_value())


def test_oversized_request_and_response_are_bounded() -> None:
    """Both body directions fail with stable categories and no retained content."""
    suite = _suite()
    action = _action_with_inputs(
        suite,
        _environment_input("json", "privateNote", "BODY_VALUE"),
    )
    request_transport = _CaptureTransport()
    request_result = AwsSigV4ActionAdapter(
        environment={"BODY_VALUE": "r" * (MAX_REQUEST_BYTES + 1)},
        transport=request_transport,
        clock=lambda: _FIXED_TIME,
    ).execute_action(_request(suite, action=action))
    response_transport = _CaptureTransport(
        body=b"s" * (MAX_RESPONSE_BYTES + 1),
    )
    response_result = _adapter(response_transport).execute_action(_request(suite))

    assert _error(request_result) is AwsActionFailureCode.REQUEST_TOO_LARGE
    assert request_transport.requests == []
    assert _error(response_result) is AwsActionFailureCode.RESPONSE_TOO_LARGE
    assert response_result.outcome is ActionOutcome.ERROR
    assert b"s" * 32 not in repr(response_result).encode()


def test_conflicting_and_malformed_configuration_fails_closed() -> None:
    """Semantic validation and adapter defenses reject unsafe action settings."""
    data = _suite_mapping()
    data["scenarios"][0]["actions"][1]["region"] = "us-east-1"

    with pytest.raises(
        ValidationError,
        match="awsSigV4 action regions must match target awsRegion",
    ):
        VerificationSuite.model_validate(data)

    suite = _suite()
    conflicting = _action(suite).model_copy(update={"region": "us-east-1"})
    unsupported = _action(suite).model_copy(update={"service": "s3"})

    assert (
        _error(
            _adapter(_CaptureTransport()).execute_action(
                _request(suite, action=conflicting),
            ),
        )
        is AwsActionFailureCode.INVALID_CONFIGURATION
    )
    assert (
        _error(
            _adapter(_CaptureTransport()).execute_action(
                _request(suite, action=unsupported),
            ),
        )
        is AwsActionFailureCode.INVALID_CONFIGURATION
    )


def test_mismatched_correlation_redirect_and_other_statuses_are_errors() -> None:
    """The adapter never follows redirects or accepts contradictory correlation."""
    suite = _suite()
    mismatch = _CaptureTransport(correlation_id="wrong", echo_correlation=False)
    redirect = _CaptureTransport(status=302, echo_correlation=False)

    mismatch_result = _adapter(mismatch).execute_action(_request(suite))
    redirect_result = _adapter(redirect).execute_action(_request(suite))

    assert _error(mismatch_result) is AwsActionFailureCode.INVALID_CORRELATION
    assert mismatch_result.correlation_ids == ()
    assert _error(redirect_result) is AwsActionFailureCode.UNEXPECTED_HTTP_STATUS
    assert len(redirect.requests) == 1


def test_results_redact_credentials_headers_bodies_and_sdk_errors() -> None:
    """Every sensitive signing and transport value stops at its internal boundary."""
    suite = _suite()
    action = _action_with_inputs(
        suite,
        _environment_input("json", "privateNote", "BODY_VALUE"),
    )
    transport = _CaptureTransport(body=_RESPONSE_SECRET.encode())
    adapter = AwsSigV4ActionAdapter(
        environment={"BODY_VALUE": _REQUEST_SECRET},
        transport=transport,
        clock=lambda: _FIXED_TIME,
    )
    result = adapter.execute_action(
        _request(
            suite,
            action=action,
            identity=_identity(session_token=_SESSION_TOKEN),
        ),
    )
    authorization = transport.requests[0].header_map()["Authorization"]

    failing_result = _adapter(_CaptureTransport()).execute_action(
        _request(suite, identity=_failing_identity()),
    )

    rendered = (
        repr(adapter)
        + repr(transport.requests[0])
        + repr(result)
        + repr(failing_result)
        + json.dumps(result.observed.to_json_value())
        + json.dumps(failing_result.observed.to_json_value())
    )
    for sensitive in (
        _ACCESS_KEY,
        _SECRET_KEY,
        _SESSION_TOKEN,
        _REQUEST_SECRET,
        _RESPONSE_SECRET,
        _SDK_SECRET,
        authorization,
    ):
        assert sensitive not in rendered
    assert _error(failing_result) is AwsActionFailureCode.SIGNING_ERROR


def test_default_transport_ignores_proxy_and_endpoint_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Direct HTTPS selects only the validated target and does not retry redirects."""
    suite = _suite()
    connections: list[_FakeHttpsConnection] = []

    def connection_factory(
        host: str,
        port: int,
        **kwargs: object,
    ) -> _FakeHttpsConnection:
        connection = _FakeHttpsConnection(host, port, **kwargs)
        connections.append(connection)
        return connection

    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("AWS_ENDPOINT_URL", "https://override.example.test")
    monkeypatch.setattr(
        "cai_verify.aws.action.http.client.HTTPSConnection",
        connection_factory,
    )

    result = AwsSigV4ActionAdapter(
        environment={},
        clock=lambda: _FIXED_TIME,
    ).execute_action(_request(suite))

    assert result.outcome is ActionOutcome.ERROR
    assert _error(result) is AwsActionFailureCode.UNEXPECTED_HTTP_STATUS
    assert len(connections) == 1
    assert connections[0].host == "assistant.sandbox.example.test"
    assert connections[0].port == _DEFAULT_HTTPS_PORT
    assert connections[0].requested_target == "/v1/documents/synthetic/summarize"
    assert result.aws_request_ids == ("transport-aws-request-id",)


class _FakeHttpResponse:
    status = 302

    def read(self, amount: int) -> bytes:
        assert amount == MAX_RESPONSE_BYTES + 1
        return b"redirect-body-must-not-be-retained"

    def getheader(self, name: str) -> str | None:
        del name
        return None

    def getheaders(self) -> list[tuple[str, str]]:
        return [
            ("Server", "synthetic"),
            ("X-Amzn-RequestId", "transport-aws-request-id"),
        ]


class _FakeHttpsConnection:
    def __init__(self, host: str, port: int, **kwargs: object) -> None:
        assert kwargs["timeout"] == _DECLARED_TIMEOUT_SECONDS
        self.host = host
        self.port = port
        self.requested_target: str | None = None

    def request(
        self,
        method: str,
        target: str,
        body: bytes,
        headers: dict[str, str],
        *,
        encode_chunked: bool,
    ) -> None:
        assert method == "POST"
        assert body
        assert "Authorization" in headers
        assert encode_chunked is False
        self.requested_target = target

    def getresponse(self) -> _FakeHttpResponse:
        return _FakeHttpResponse()

    def close(self) -> None:
        pass


class _FailingSigningSession:
    def client(self, service_name: str, **kwargs: object) -> object:
        del service_name, kwargs
        return object()

    def get_credentials(self) -> object:
        raise RuntimeError(_SDK_SECRET)


def _suite_mapping() -> dict[str, Any]:
    return cast("dict[str, Any]", yaml.safe_load(_FIXTURE.read_text(encoding="utf-8")))


def _suite() -> VerificationSuite:
    return VerificationSuite.model_validate(_suite_mapping())


def _action(suite: VerificationSuite) -> AwsSigV4Action:
    action = suite.scenarios[0].actions[1]
    assert isinstance(action, AwsSigV4Action)
    return action


def _adapter(transport: _CaptureTransport) -> AwsSigV4ActionAdapter:
    return AwsSigV4ActionAdapter(
        environment={},
        transport=transport,
        clock=lambda: _FIXED_TIME,
    )


def _identity(
    *,
    session_token: str | None = None,
    expires_at: datetime | None = None,
) -> AwsScopedIdentity:
    session = boto3.Session(
        aws_access_key_id=_ACCESS_KEY,
        aws_secret_access_key=_SECRET_KEY,
        aws_session_token=session_token,
        region_name="eu-west-2",
    )
    return AwsScopedIdentity(
        _identity_id="unauthorized-caller",
        _account_id="111122223333",
        _partition="aws",
        _expires_at=expires_at,
        _session=cast("AwsSession", session),
    )


def _failing_identity() -> AwsScopedIdentity:
    return AwsScopedIdentity(
        _identity_id="unauthorized-caller",
        _account_id="111122223333",
        _partition="aws",
        _expires_at=_FIXED_TIME + timedelta(hours=1),
        _session=cast("AwsSession", _FailingSigningSession()),
    )


def _request(
    suite: VerificationSuite,
    *,
    action: AwsSigV4Action | None = None,
    target: Target | None = None,
    identity: AwsScopedIdentity | None = None,
) -> ActionRequest:
    return ActionRequest(
        context=ExecutionContext(
            run_id="aws-action-contract",
            scenario_id=suite.scenarios[0].id,
            target=target or suite.target,
        ),
        action=action or _action(suite),
        identity=identity or _identity(),
    )


def _target(
    suite: VerificationSuite,
    *,
    endpoint: str | None = None,
    allowed_hosts: tuple[str, ...] | None = None,
) -> Target:
    updates: dict[str, object] = {}
    if endpoint is not None:
        updates["endpoint"] = AnyHttpUrl(endpoint)
    if allowed_hosts is not None:
        updates["allowed_hosts"] = allowed_hosts
    return suite.target.model_copy(update=updates)


def _action_with_inputs(
    suite: VerificationSuite,
    *inputs: ActionInput,
) -> AwsSigV4Action:
    action = _action(suite)
    return action.model_copy(update={"inputs": (*action.inputs, *inputs)})


def _environment_input(
    location: str,
    name: str,
    environment_name: str,
) -> ActionInput:
    return ActionInput.model_validate(
        {
            "location": location,
            "name": name,
            "value": {
                "name": environment_name,
                "source": "environment",
            },
        },
    )


def _literal_input(location: str, name: str, value: object) -> ActionInput:
    return ActionInput.model_validate(
        {
            "location": location,
            "name": name,
            "value": {
                "sensitive": False,
                "source": "literal",
                "value": value,
            },
        },
    )


def _error(result: object) -> AwsActionFailureCode:
    assert hasattr(result, "observed")
    observed = result.observed.to_json_value()
    assert isinstance(observed, dict)
    return AwsActionFailureCode(cast("str", observed["error"]))
