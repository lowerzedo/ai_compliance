"""Network-isolated tests for normalized Amazon Bedrock invocation evidence."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import boto3  # type: ignore[import-untyped]
import pytest
import yaml
from botocore.exceptions import ClientError  # type: ignore[import-untyped]
from botocore.stub import Stubber  # type: ignore[import-untyped]

import cai_verify.aws.action as action_module
import cai_verify.aws.cloudwatch_logs as cloudwatch_module
from cai_verify.aws import (
    CLOUDWATCH_LOGS_ADAPTER_NAME,
    CLOUDWATCH_LOGS_ADAPTER_VERSION,
    AwsScopedIdentity,
    AwsSigV4ActionAdapter,
    CloudWatchLogsProbeAdapter,
)
from cai_verify.config import (
    AwsSigV4Action,
    BedrockInvocationDeclaration,
    CloudWatchLogsProbe,
    SafeModelAlias,
    Target,
    VerificationSuite,
)
from cai_verify.config.models import ObservationKind
from cai_verify.core import RedactedValue
from cai_verify.plugins import (
    ActionExecutionResult,
    ActionOutcome,
    ActionRequest,
    EvidenceProbe,
    ExecutionContext,
    ProbeRequest,
)
from tests.plugins.contract_suite import assert_evidence_probe_contract

if TYPE_CHECKING:
    from collections.abc import Mapping

    from cai_verify.aws import AwsSession
    from cai_verify.plugins import ProbeResult

_FIXTURE = Path(__file__).parents[1] / "fixtures/suites/valid/full.yaml"
_COLLECTED_AT = datetime(2026, 7, 26, 12, tzinfo=UTC)
_ACTION_TIME = _COLLECTED_AT - timedelta(seconds=30)
_MODEL_ID = "synthetic.foundation-model-v1"
_MODEL_ALIAS = "synthetic-primary-model"
_CANARY = "synthetic-cloudwatch-canary"
_ACCOUNT_ID = "111122223333"
_RAW_SECRET = "raw-model-response-secret-must-not-leak"  # noqa: S105
_SDK_SECRET = "sdk-bedrock-secret-must-not-leak"  # noqa: S105


@dataclass(slots=True)
class _LogsClient:
    responses: list[object]
    calls: list[dict[str, object]] = field(default_factory=list)

    def filter_log_events(self, **kwargs: object) -> Mapping[str, object]:
        """Return queued synthetic pages without performing network I/O."""
        self.calls.append(dict(kwargs))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return cast("Mapping[str, object]", response)


@dataclass(slots=True)
class _LogsSession:
    client_value: object
    regions: list[str] = field(default_factory=list)
    configs: list[object] = field(default_factory=list)

    def client(self, service_name: str, **kwargs: object) -> object:
        """Expose only the synthetic Logs client expected by the identity."""
        assert service_name == "logs"
        assert set(kwargs) == {"config", "region_name"}
        self.regions.append(cast("str", kwargs["region_name"]))
        self.configs.append(kwargs["config"])
        return self.client_value


@dataclass(frozen=True, slots=True)
class _EchoActionTransport:
    def send(
        self,
        request: action_module._AwsHttpRequest,
        /,
    ) -> action_module._AwsHttpResponse:
        """Return the action correlation without retaining request content."""
        return action_module._AwsHttpResponse(  # noqa: SLF001
            status=200,
            correlation_id=request.header_map()["X-Cai-Correlation-Id"],
            too_large=False,
        )


def test_correlated_bedrock_invocation_uses_exact_query_and_contract() -> None:
    """One exact post-invocation record becomes safe normalized facts."""
    suite = _suite()
    client = _LogsClient([_page(_bedrock_event("bedrock-1"))])
    identity, session = _identity(client)
    adapter = _adapter()
    request = _request(suite, identity=identity)

    assert isinstance(adapter, EvidenceProbe)
    result = assert_evidence_probe_contract(adapter, request)

    assert result.source.name == CLOUDWATCH_LOGS_ADAPTER_NAME
    assert result.source.version == CLOUDWATCH_LOGS_ADAPTER_VERSION == "1.1.0"
    assert result.freshness.collected_at == _COLLECTED_AT
    assert result.freshness.source_time == _ACTION_TIME
    assert _bedrock(result) == {
        "accepted_correlated_invocations": 1,
        "ambiguous": False,
        "complete_correlated_bedrock_invocation_found": True,
        "declared_model_matched": True,
        "error_category": None,
        "evidence_complete": True,
        "future_dated": False,
        "malformed": False,
        "model_alias": _MODEL_ALIAS,
        "oversized": False,
        "partial": False,
        "provider_matched": True,
        "stale": False,
        "target_region_matched": True,
    }
    assert session.regions == ["eu-west-2"]
    assert client.calls == [
        {
            "endTime": _milliseconds(_COLLECTED_AT) + 1,
            "filterPattern": ('{ $.correlationId = "aws-synthetic-correlation" }'),
            "interleaved": True,
            "limit": cloudwatch_module.MAX_CLOUDWATCH_EVENTS + 1,
            "logGroupName": "/aws/cai-verify/synthetic-assistant",
            "startFromHead": True,
            "startTime": _milliseconds(
                _ACTION_TIME - timedelta(seconds=30),
            ),
            "unmask": False,
        },
    ]


@pytest.mark.parametrize(
    ("provider", "model_id", "region", "expected_error"),
    [
        ("Amazon SageMaker", _MODEL_ID, "eu-west-2", "provider_mismatch"),
        ("Amazon Bedrock", "synthetic.other-model-v2", "eu-west-2", "model_mismatch"),
        ("Amazon Bedrock", _MODEL_ID, "us-east-1", "region_mismatch"),
    ],
)
def test_provider_model_and_region_must_match_exactly(
    provider: str,
    model_id: str,
    region: str,
    expected_error: str,
) -> None:
    """Configuration, service names, and proximity cannot replace exact fields."""
    suite = _suite()
    record = _bedrock_event(
        "wrong-fixed-value",
        provider=provider,
        model_id=model_id,
        region=region,
    )

    result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(_LogsClient([_page(record)]))[0],
        ),
    )

    observed = _bedrock(result)
    assert observed["error_category"] == expected_error
    _assert_no_positive_bedrock_facts(observed)
    assert observed["ambiguous"] is True
    assert _MODEL_ID not in json.dumps(observed)


@pytest.mark.parametrize(
    ("case", "expected_error"),
    [
        ("missing", "missing_invocation"),
        ("multiple", "invocation_limit_exceeded"),
        ("conflicting", "ambiguous_correlation"),
        ("wrong-correlation", "ambiguous_correlation"),
    ],
)
def test_missing_multiple_conflicting_and_wrong_correlations_fail_closed(
    case: str,
    expected_error: str,
) -> None:
    """Only one unambiguous record for the action correlation can be accepted."""
    if case == "missing":
        records: tuple[dict[str, object], ...] = ()
    elif case == "multiple":
        records = (
            _bedrock_event("first-invocation"),
            _bedrock_event("second-invocation"),
        )
    elif case == "conflicting":
        records = (
            _bedrock_event("conflicting-id"),
            _bedrock_event(
                "conflicting-id",
                model_id="synthetic.other-model-v2",
            ),
        )
    elif case == "wrong-correlation":
        records = (
            _bedrock_event(
                "wrong-correlation",
                correlation_id="aws-other-correlation",
            ),
        )
    else:
        raise AssertionError
    result = _adapter().collect_evidence(
        _request(
            _suite(),
            identity=_identity(_LogsClient([_page(*records)]))[0],
        ),
    )

    observed = _bedrock(result)
    assert observed["error_category"] == expected_error
    _assert_no_positive_bedrock_facts(observed)


def test_time_only_proximity_without_action_correlation_is_not_evidence() -> None:
    """A nearby timestamp does not authorize a FilterLogEvents query."""
    client = _LogsClient([_page(_bedrock_event("nearby"))])

    result = _adapter().collect_evidence(
        _request(
            _suite(),
            identity=_identity(client)[0],
            action_result=_action_result(correlations=()),
        ),
    )

    assert client.calls == []
    assert _bedrock(result)["error_category"] == "missing_correlation"
    _assert_no_positive_bedrock_facts(_bedrock(result))


@pytest.mark.parametrize(
    ("occurred_at", "cloudwatch_time", "expected_error", "flag"),
    [
        (
            _COLLECTED_AT - timedelta(minutes=4),
            None,
            "stale_event",
            "stale",
        ),
        (
            _COLLECTED_AT + timedelta(seconds=31),
            None,
            "future_event",
            "future_dated",
        ),
        (
            _ACTION_TIME,
            _ACTION_TIME + timedelta(seconds=31),
            "timestamp_conflict",
            "malformed",
        ),
    ],
)
def test_stale_future_and_conflicting_timestamps_suppress_facts(
    occurred_at: datetime,
    cloudwatch_time: datetime | None,
    expected_error: str,
    flag: str,
) -> None:
    """Both structured and CloudWatch times must be fresh and consistent."""
    record = _bedrock_event(
        "bad-time",
        occurred_at=occurred_at,
        cloudwatch_time=cloudwatch_time,
    )

    result = _adapter().collect_evidence(
        _request(
            _suite(),
            identity=_identity(_LogsClient([_page(record)]))[0],
        ),
    )

    observed = _bedrock(result)
    assert observed["error_category"] == expected_error
    assert observed[flag] is True
    assert result.freshness.source_time is None
    _assert_no_positive_bedrock_facts(observed)


@pytest.mark.parametrize(
    "message",
    [
        "{not-json",
        (
            '{"awsRegion":"eu-west-2","correlationId":"aws-synthetic-correlation",'
            '"eventKind":"bedrockInvocation","eventTime":"2026-07-26T11:59:30.000Z",'
            '"invocationStatus":"SUCCEEDED","modelId":"first",'
            '"modelId":"second","provider":"Amazon Bedrock","schemaVersion":"1"}'
        ),
        (
            '{"awsRegion":"eu-west-2","correlationId":"aws-synthetic-correlation",'
            '"eventKind":"bedrockInvocation","eventTime":"2026-07-26T11:59:30.000Z",'
            '"invocationStatus":"SUCCEEDED","modelId":"\\ud800",'
            '"provider":"Amazon Bedrock","schemaVersion":"1"}'
        ),
    ],
)
def test_malformed_json_and_duplicate_fields_are_rejected(message: str) -> None:
    """Bedrock records must be duplicate-free JSON before field validation."""
    record = _raw_message("invalid-json", message)

    result = _adapter().collect_evidence(
        _request(
            _suite(),
            identity=_identity(_LogsClient([_page(record)]))[0],
        ),
    )

    assert _bedrock(result)["error_category"] == "invalid_event"
    assert _bedrock(result)["malformed"] is True
    _assert_no_positive_bedrock_facts(_bedrock(result))


@pytest.mark.parametrize(
    "case",
    [
        "missing-field",
        "unexpected-field",
        "wrong-version",
        "bad-status",
        "bad-model-type",
        "bad-region-shape",
    ],
)
def test_malformed_fixed_bedrock_records_are_rejected(case: str) -> None:
    """No extension or partial variant can enter the fixed record contract."""
    message = _bedrock_message()
    if case == "missing-field":
        message.pop("modelId")
    elif case == "unexpected-field":
        message["response"] = _RAW_SECRET
    elif case == "wrong-version":
        message["schemaVersion"] = "2"
    elif case == "bad-status":
        message["invocationStatus"] = "FAILED"
    elif case == "bad-model-type":
        message["modelId"] = 123
    elif case == "bad-region-shape":
        message["awsRegion"] = "not-a-region"
    else:
        raise AssertionError

    result = _adapter().collect_evidence(
        _request(
            _suite(),
            identity=_identity(
                _LogsClient([_page(_raw_event(case, message))]),
            )[0],
        ),
    )

    observed = _bedrock(result)
    assert observed["error_category"] == "invalid_event"
    assert observed["malformed"] is True
    _assert_no_positive_bedrock_facts(observed)
    assert _RAW_SECRET not in json.dumps(observed)


def test_duplicates_ordering_and_pagination_are_deterministic() -> None:
    """Identical IDs deduplicate across pages without depending on page order."""
    event = _bedrock_event("deduplicated")
    first_client = _LogsClient(
        [
            _page(
                _provider_event("unrelated-provider"),
                event,
                pagination_token="synthetic-next-page",  # noqa: S106
            ),
            _page(deepcopy(event)),
        ],
    )
    second_client = _LogsClient(
        [
            _page(
                deepcopy(event),
                _provider_event("unrelated-provider"),
                pagination_token="synthetic-next-page",  # noqa: S106
            ),
            _page(event),
        ],
    )

    first = _adapter().collect_evidence(
        _request(_suite(), identity=_identity(first_client)[0]),
    )
    second = _adapter().collect_evidence(
        _request(_suite(), identity=_identity(second_client)[0]),
    )

    assert _bedrock(first) == _bedrock(second)
    assert _bedrock(first)["accepted_correlated_invocations"] == 1
    assert first_client.calls[1]["nextToken"] == "synthetic-next-page"


@pytest.mark.parametrize("case", ["repeated", "excessive", "oversized-token"])
def test_repeated_and_excessive_pagination_suppresses_bedrock_facts(
    case: str,
) -> None:
    """Incomplete pagination chains can never leave a positive invocation."""
    if case == "repeated":
        pages: list[object] = [
            _page(
                _bedrock_event("page-one"),
                pagination_token="repeated-token",  # noqa: S106
            ),
            _page(pagination_token="repeated-token"),  # noqa: S106
        ]
    elif case == "excessive":
        pages = [
            _page(
                _bedrock_event("only-invocation") if index == 0 else None,
                pagination_token=f"page-{index + 1}",
            )
            for index in range(cloudwatch_module.MAX_CLOUDWATCH_PAGES)
        ]
    elif case == "oversized-token":
        pages = [
            _page(
                _bedrock_event("oversized-token"),
                pagination_token=(
                    "t" * (cloudwatch_module.MAX_CLOUDWATCH_PAGINATION_TOKEN_LENGTH + 1)
                ),
            ),
        ]
    else:
        raise AssertionError
    client = _LogsClient(pages)

    result = _adapter().collect_evidence(
        _request(_suite(), identity=_identity(client)[0]),
    )

    observed = _bedrock(result)
    assert observed["error_category"] == "pagination_limit_exceeded"
    assert observed["partial"] is True
    _assert_no_positive_bedrock_facts(observed)


def test_event_record_total_byte_invocation_and_alias_limits_are_bounded() -> None:
    """Every Bedrock-specific and shared CloudWatch resource limit fails closed."""
    too_many_events = tuple(
        _bedrock_event(f"event-{index}")
        for index in range(cloudwatch_module.MAX_CLOUDWATCH_EVENTS + 1)
    )
    event_result = _adapter().collect_evidence(
        _request(
            _suite(),
            identity=_identity(_LogsClient([_page(*too_many_events)]))[0],
        ),
    )
    assert _bedrock(event_result)["error_category"] == "event_limit_exceeded"
    _assert_no_positive_bedrock_facts(_bedrock(event_result))

    oversized = {
        "eventId": "oversized",
        "message": "x" * (cloudwatch_module.MAX_CLOUDWATCH_EVENT_BYTES + 1),
        "timestamp": _milliseconds(_ACTION_TIME),
    }
    oversized_result = _adapter().collect_evidence(
        _request(
            _suite(),
            identity=_identity(_LogsClient([_page(oversized)]))[0],
        ),
    )
    assert _bedrock(oversized_result)["oversized"] is True
    _assert_no_positive_bedrock_facts(_bedrock(oversized_result))

    large_canaries = tuple(
        _canary_event(f"large-{index}", value="x" * 3500) for index in range(40)
    )
    total_result = _adapter().collect_evidence(
        _request(
            _suite(),
            identity=_identity(_LogsClient([_page(*large_canaries)]))[0],
        ),
    )
    assert _bedrock(total_result)["error_category"] == "total_bytes_exceeded"
    assert _bedrock(total_result)["oversized"] is True
    _assert_no_positive_bedrock_facts(_bedrock(total_result))

    suite = _suite()
    probe = _probe(suite)
    declaration = cast("BedrockInvocationDeclaration", probe.bedrock)
    unsafe_alias = SafeModelAlias.model_construct(
        source="literal",
        value="a" * (cloudwatch_module.MAX_CLOUDWATCH_MODEL_ALIAS_BYTES + 1),
        sensitive=False,
    )
    bypassed = declaration.model_copy(update={"model_alias": unsafe_alias})
    bypassed_probe = probe.model_copy(update={"bedrock": bypassed})
    alias_client = _LogsClient([_page(_bedrock_event("never-queried"))])
    alias_result = _adapter().collect_evidence(
        _request(
            suite,
            probe=bypassed_probe,
            identity=_identity(alias_client)[0],
        ),
    )
    assert alias_client.calls == []
    assert _bedrock(alias_result)["error_category"] == "invalid_configuration"
    _assert_no_positive_bedrock_facts(_bedrock(alias_result))
    assert cloudwatch_module.MAX_CLOUDWATCH_MODEL_ALIASES == 1

    model_client = _LogsClient([_page(_bedrock_event("never-queried-model"))])
    model_result = _adapter(
        environment={
            "SYNTHETIC_BEDROCK_MODEL_ID": (
                "m" * (cloudwatch_module.MAX_BEDROCK_MODEL_ID_BYTES + 1)
            ),
            "SYNTHETIC_TELEMETRY_CANARY": _CANARY,
        },
    ).collect_evidence(
        _request(
            suite,
            identity=_identity(model_client)[0],
        ),
    )
    assert model_client.calls == []
    assert _bedrock(model_result)["error_category"] == "environment_value_invalid"
    _assert_no_positive_bedrock_facts(_bedrock(model_result))

    same_mapping = _suite_mapping()
    same_mapping["scenarios"][0]["probes"][0]["bedrock"]["modelAlias"]["value"] = (
        "same-model"
    )
    same_suite = VerificationSuite.model_validate(same_mapping)
    same_client = _LogsClient([_page(_bedrock_event("never-queried-same-model"))])
    same_result = _adapter(
        environment={
            "SYNTHETIC_BEDROCK_MODEL_ID": "same-model",
            "SYNTHETIC_TELEMETRY_CANARY": _CANARY,
        },
    ).collect_evidence(
        _request(
            same_suite,
            identity=_identity(same_client)[0],
        ),
    )
    assert same_client.calls == []
    assert _bedrock(same_result)["error_category"] == "invalid_configuration"
    _assert_no_positive_bedrock_facts(_bedrock(same_result))


def test_total_collection_duration_includes_post_page_normalization() -> None:
    """The 15-second bound covers parsing after the last SDK response."""
    times = iter(
        [
            0.0,
            0.0,
            cloudwatch_module.MAX_CLOUDWATCH_QUERY_SECONDS + 0.1,
        ],
    )
    adapter = CloudWatchLogsProbeAdapter(
        environment={
            "SYNTHETIC_BEDROCK_MODEL_ID": _MODEL_ID,
            "SYNTHETIC_TELEMETRY_CANARY": _CANARY,
        },
        suite_max_age=timedelta(minutes=5),
        clock_skew_tolerance=timedelta(seconds=30),
        clock=lambda: _COLLECTED_AT,
        monotonic=lambda: next(times),
    )

    result = adapter.collect_evidence(
        _request(
            _suite(),
            identity=_identity(
                _LogsClient([_page(_bedrock_event("normalization-timeout"))]),
            )[0],
        ),
    )

    assert _bedrock(result)["error_category"] == "query_timeout"
    assert _bedrock(result)["partial"] is True
    _assert_no_positive_bedrock_facts(_bedrock(result))


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (TimeoutError(_SDK_SECRET), "sdk_timeout"),
        (
            ClientError(
                {
                    "Error": {
                        "Code": "AccessDeniedException",
                        "Message": _SDK_SECRET,
                    },
                },
                "FilterLogEvents",
            ),
            "access_denied",
        ),
        (RuntimeError(_SDK_SECRET), "sdk_error"),
    ],
)
def test_sdk_timeout_denial_and_generic_failure_are_redacted(
    error: Exception,
    expected: str,
) -> None:
    """SDK diagnostics collapse to stable categories with no positive facts."""
    result = _adapter().collect_evidence(
        _request(
            _suite(),
            identity=_identity(_LogsClient([error]))[0],
        ),
    )

    observed = _bedrock(result)
    assert observed["error_category"] == expected
    assert observed["partial"] is True
    assert _SDK_SECRET not in repr(result)
    assert _SDK_SECRET not in json.dumps(observed)
    _assert_no_positive_bedrock_facts(observed)


@pytest.mark.parametrize(
    "case",
    [
        "missing-events",
        "unexpected-field",
        "incomplete-stream",
    ],
)
def test_partial_sdk_responses_suppress_complete_invocations(
    case: str,
) -> None:
    """Missing or incomplete fixed SDK fields make the Bedrock result partial."""
    if case == "missing-events":
        response: dict[str, object] = {"searchedLogStreams": []}
    elif case == "unexpected-field":
        response = {"events": [], "unexpectedSdkField": _RAW_SECRET}
    elif case == "incomplete-stream":
        response = {
            "events": [_bedrock_event("partial-stream")],
            "searchedLogStreams": [
                {
                    "logStreamName": "synthetic-stream",
                    "searchedCompletely": False,
                },
            ],
        }
    else:
        raise AssertionError
    result = _adapter().collect_evidence(
        _request(
            _suite(),
            identity=_identity(_LogsClient([response]))[0],
        ),
    )

    observed = _bedrock(result)
    assert observed["error_category"] == "partial_response"
    assert observed["partial"] is True
    _assert_no_positive_bedrock_facts(observed)
    assert _RAW_SECRET not in json.dumps(observed)


@pytest.mark.parametrize(
    ("account", "partition", "expires_at", "closed"),
    [
        ("999900001111", "aws", None, False),
        (_ACCOUNT_ID, "aws-cn", None, False),
        (_ACCOUNT_ID, "aws", _COLLECTED_AT, False),
        (_ACCOUNT_ID, "aws", None, True),
    ],
)
def test_identity_account_partition_expiry_and_closed_boundaries(
    account: str,
    partition: str,
    expires_at: datetime | None,
    closed: bool,  # noqa: FBT001 - parametrized lease state.
) -> None:
    """Invalid scoped identities are rejected before any SDK request."""
    client = _LogsClient([_page(_bedrock_event("never-queried"))])
    identity, session = _identity(
        client,
        account=account,
        partition=partition,
        expires_at=expires_at,
    )
    if closed:
        identity.close()

    result = _adapter().collect_evidence(
        _request(_suite(), identity=identity),
    )

    assert session.regions == []
    assert client.calls == []
    assert _bedrock(result)["error_category"] == "identity_boundary_invalid"
    _assert_no_positive_bedrock_facts(_bedrock(result))


def test_model_arns_accounts_bodies_environment_and_errors_are_redacted() -> None:
    """Sensitive model and tenant identifiers never cross normalization."""
    model_arn = (
        "arn:aws:bedrock:eu-west-2:111122223333:provisioned-model/syntheticmodel"
    )
    suite = _suite()
    adapter = _adapter(
        environment={
            "SYNTHETIC_BEDROCK_MODEL_ID": model_arn,
            "SYNTHETIC_TELEMETRY_CANARY": _CANARY,
            "NEIGHBOR_SECRET": _RAW_SECRET,
        },
    )
    record = _bedrock_event("sensitive-model", model_id=model_arn)
    success = adapter.collect_evidence(
        _request(
            suite,
            identity=_identity(_LogsClient([_page(record)]))[0],
        ),
    )
    failure = adapter.collect_evidence(
        _request(
            suite,
            identity=_identity(_LogsClient([RuntimeError(_SDK_SECRET)]))[0],
        ),
    )
    rendered = (
        repr(adapter)
        + repr(success)
        + repr(failure)
        + json.dumps(_result_values(success))
        + json.dumps(_result_values(failure))
    )

    assert _bedrock(success)["model_alias"] == _MODEL_ALIAS
    for sensitive in (
        model_arn,
        _ACCOUNT_ID,
        _RAW_SECRET,
        _SDK_SECRET,
        "provisioned-model/syntheticmodel",
    ):
        assert sensitive not in rendered


def test_validated_suite_action_identity_and_botocore_stub_integration() -> None:
    """Validated inputs reach a normalized ProbeResult through FilterLogEvents."""
    mapping = _suite_mapping()
    probe_mapping = mapping["scenarios"][0]["probes"][0]
    probe_mapping["actionRef"] = "signed-request"
    mapping["scenarios"][0]["assertions"][2]["actionRef"] = "signed-request"
    suite = VerificationSuite.model_validate(mapping)
    action = suite.scenarios[0].actions[1]
    assert isinstance(action, AwsSigV4Action)
    context = ExecutionContext(
        run_id="bedrock-contract",
        scenario_id=suite.scenarios[0].id,
        target=suite.target,
    )
    action_result = AwsSigV4ActionAdapter(
        environment={},
        transport=_EchoActionTransport(),
        clock=lambda: _ACTION_TIME,
    ).execute_action(
        ActionRequest(
            context=context,
            action=action,
            identity=_signing_identity(),
        ),
    )
    assert action_result.outcome is ActionOutcome.SUCCEEDED
    correlation_id = action_result.correlation_ids[0]
    client = boto3.client(
        "logs",
        region_name="eu-west-2",
        aws_access_key_id="synthetic-source-key",
        aws_secret_access_key="synthetic-source-secret",  # noqa: S106
        aws_session_token="synthetic-source-token",  # noqa: S106
    )
    expected = {
        "endTime": _milliseconds(_COLLECTED_AT) + 1,
        "filterPattern": (f'{{ $.correlationId = "{correlation_id}" }}'),
        "interleaved": True,
        "limit": cloudwatch_module.MAX_CLOUDWATCH_EVENTS + 1,
        "logGroupName": "/aws/cai-verify/synthetic-assistant",
        "startFromHead": True,
        "startTime": _milliseconds(_ACTION_TIME - timedelta(seconds=30)),
        "unmask": False,
    }
    stubber = Stubber(client)
    stubber.add_response(
        "filter_log_events",
        {
            "events": [
                _bedrock_event(
                    "botocore-stubbed-invocation",
                    correlation_id=correlation_id,
                ),
            ],
            "searchedLogStreams": [
                {
                    "logStreamName": "synthetic-stream",
                    "searchedCompletely": True,
                },
            ],
        },
        expected,
    )
    stubber.activate()
    session = _LogsSession(client)
    identity = AwsScopedIdentity(
        _identity_id="evidence-reader",
        _account_id=_ACCOUNT_ID,
        _partition="aws",
        _expires_at=_COLLECTED_AT + timedelta(hours=1),
        _session=cast("AwsSession", session),
    )
    request = _request(
        suite,
        probe=cast("CloudWatchLogsProbe", suite.scenarios[0].probes[0]),
        identity=identity,
        action_result=action_result,
    )

    result = assert_evidence_probe_contract(_adapter(), request)

    stubber.assert_no_pending_responses()
    stubber.deactivate()
    assert _bedrock(result)["complete_correlated_bedrock_invocation_found"] is True
    assert _bedrock(result)["declared_model_matched"] is True
    assert result.probe_id == "application-telemetry"


def _suite_mapping() -> dict[str, Any]:
    loaded = yaml.safe_load(_FIXTURE.read_text(encoding="utf-8"))
    mapping = cast("dict[str, Any]", loaded)
    probe = mapping["scenarios"][0]["probes"][0]
    probe["observations"].append("bedrockInvocation")
    probe["bedrock"] = {
        "modelAlias": {
            "sensitive": False,
            "source": "literal",
            "value": _MODEL_ALIAS,
        },
        "modelId": {
            "name": "SYNTHETIC_BEDROCK_MODEL_ID",
            "source": "environment",
        },
    }
    return mapping


def _suite() -> VerificationSuite:
    return VerificationSuite.model_validate(_suite_mapping())


def _probe(suite: VerificationSuite) -> CloudWatchLogsProbe:
    probe = suite.scenarios[0].probes[0]
    assert isinstance(probe, CloudWatchLogsProbe)
    return probe


def _adapter(
    *,
    environment: dict[str, str] | None = None,
) -> CloudWatchLogsProbeAdapter:
    return CloudWatchLogsProbeAdapter(
        environment=environment
        or {
            "SYNTHETIC_BEDROCK_MODEL_ID": _MODEL_ID,
            "SYNTHETIC_TELEMETRY_CANARY": _CANARY,
        },
        suite_max_age=timedelta(minutes=5),
        clock_skew_tolerance=timedelta(seconds=30),
        clock=lambda: _COLLECTED_AT,
    )


def _identity(
    client: object,
    *,
    account: str = _ACCOUNT_ID,
    partition: str = "aws",
    expires_at: datetime | None = None,
) -> tuple[AwsScopedIdentity, _LogsSession]:
    session = _LogsSession(client)
    identity = AwsScopedIdentity(
        _identity_id="evidence-reader",
        _account_id=account,
        _partition=partition,
        _expires_at=expires_at,
        _session=cast("AwsSession", session),
    )
    return identity, session


def _signing_identity() -> AwsScopedIdentity:
    session = boto3.Session(
        aws_access_key_id="AKIDEXAMPLE",
        aws_secret_access_key=(  # noqa: S106 - explicit synthetic test value.
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
        ),
        region_name="eu-west-2",
    )
    return AwsScopedIdentity(
        _identity_id="unauthorized-caller",
        _account_id=_ACCOUNT_ID,
        _partition="aws",
        _expires_at=_COLLECTED_AT + timedelta(hours=1),
        _session=cast("AwsSession", session),
    )


def _request(
    suite: VerificationSuite,
    *,
    identity: AwsScopedIdentity,
    probe: CloudWatchLogsProbe | None = None,
    action_result: ActionExecutionResult | None = None,
    target: Target | None = None,
) -> ProbeRequest:
    selected_probe = probe or _probe(suite)
    return ProbeRequest(
        context=ExecutionContext(
            run_id="bedrock-contract",
            scenario_id=suite.scenarios[0].id,
            target=target or suite.target,
        ),
        probe=selected_probe,
        action_result=action_result
        or _action_result(action_id=selected_probe.action_ref),
        identity=identity,
    )


def _action_result(
    *,
    action_id: str = "unsigned-request",
    correlations: tuple[str, ...] = ("aws-synthetic-correlation",),
    completed_at: datetime = _ACTION_TIME,
) -> ActionExecutionResult:
    return ActionExecutionResult(
        action_id=action_id,
        outcome=ActionOutcome.SUCCEEDED,
        started_at=completed_at - timedelta(seconds=1),
        completed_at=completed_at,
        observed=RedactedValue(
            {
                "correlation_state": "MATCHED",
                "service": "execute-api",
                "signing_region": "eu-west-2",
            },
        ),
        correlation_ids=correlations,
        limitations=("Synthetic normalized AWS action result.",),
    )


def _bedrock_event(  # noqa: PLR0913 - fixed synthetic fields are explicit.
    event_id: str,
    *,
    provider: str = "Amazon Bedrock",
    model_id: str = _MODEL_ID,
    region: str = "eu-west-2",
    correlation_id: str = "aws-synthetic-correlation",
    occurred_at: datetime = _ACTION_TIME,
    cloudwatch_time: datetime | None = None,
) -> dict[str, object]:
    return _raw_event(
        event_id,
        _bedrock_message(
            provider=provider,
            model_id=model_id,
            region=region,
            correlation_id=correlation_id,
            occurred_at=occurred_at,
        ),
        cloudwatch_time=cloudwatch_time or occurred_at,
    )


def _bedrock_message(
    *,
    provider: str = "Amazon Bedrock",
    model_id: str = _MODEL_ID,
    region: str = "eu-west-2",
    correlation_id: str = "aws-synthetic-correlation",
    occurred_at: datetime = _ACTION_TIME,
) -> dict[str, object]:
    return {
        "awsRegion": region,
        "correlationId": correlation_id,
        "eventKind": "bedrockInvocation",
        "eventTime": _event_time(occurred_at),
        "invocationStatus": "SUCCEEDED",
        "modelId": model_id,
        "provider": provider,
        "schemaVersion": "1",
    }


def _provider_event(event_id: str) -> dict[str, object]:
    return _raw_event(
        event_id,
        {
            "correlationId": "aws-synthetic-correlation",
            "eventKind": "providerInvocation",
            "eventTime": _event_time(_ACTION_TIME),
            "providerId": "amazon-bedrock",
            "schemaVersion": "1",
        },
    )


def _canary_event(event_id: str, *, value: str) -> dict[str, object]:
    return _raw_event(
        event_id,
        {
            "canary": value,
            "correlationId": "aws-synthetic-correlation",
            "eventKind": "telemetryCanary",
            "eventTime": _event_time(_ACTION_TIME),
            "schemaVersion": "1",
        },
    )


def _raw_event(
    event_id: str,
    message: dict[str, object],
    *,
    cloudwatch_time: datetime = _ACTION_TIME,
) -> dict[str, object]:
    return _raw_message(
        event_id,
        json.dumps(
            message,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ),
        cloudwatch_time=cloudwatch_time,
    )


def _raw_message(
    event_id: str,
    message: str,
    *,
    cloudwatch_time: datetime = _ACTION_TIME,
) -> dict[str, object]:
    return {
        "eventId": event_id,
        "logStreamName": "synthetic-stream",
        "message": message,
        "timestamp": _milliseconds(cloudwatch_time),
    }


def _page(
    *events: dict[str, object] | None,
    pagination_token: str | None = None,
) -> dict[str, object]:
    page: dict[str, object] = {
        "events": [event for event in events if event is not None],
        "searchedLogStreams": [
            {
                "logStreamName": "synthetic-stream",
                "searchedCompletely": True,
            },
        ],
    }
    if pagination_token is not None:
        page["nextToken"] = pagination_token
    return page


def _event_time(value: datetime) -> str:
    return (
        value.astimezone(UTC)
        .isoformat(timespec="milliseconds")
        .replace(
            "+00:00",
            "Z",
        )
    )


def _milliseconds(value: datetime) -> int:
    return int(value.timestamp() * 1000)


def _bedrock(result: ProbeResult) -> dict[str, object]:
    matching = tuple(
        item
        for item in result.observations
        if item.kind == ObservationKind.BEDROCK_INVOCATION.value
    )
    assert len(matching) == 1
    return cast("dict[str, object]", matching[0].observed.to_json_value())


def _result_values(result: ProbeResult) -> list[object]:
    return [item.observed.to_json_value() for item in result.observations]


def _assert_no_positive_bedrock_facts(observed: dict[str, object]) -> None:
    assert observed["accepted_correlated_invocations"] == 0
    assert observed["complete_correlated_bedrock_invocation_found"] is False
    assert observed["declared_model_matched"] is False
    assert observed["evidence_complete"] is False
    assert observed["model_alias"] is None
    assert observed["provider_matched"] is False
    assert observed["target_region_matched"] is False
