"""Network-isolated tests for the fixed synthetic Lambda handler."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

import pytest
from examples.aws.reference_target import handler

from tests.reference_target.helpers import (
    ACCOUNT_ID,
    REQUESTER_A_ROLE_ARN,
    REQUESTER_A_SESSION,
    REQUESTER_B_ROLE_ARN,
    REQUESTER_B_SESSION,
    TABLE_NAME,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

_CANARY_A = "synthetic_canary_requester_a_001"
_CANARY_B = "synthetic_canary_requester_b_002"
_CORRELATION = "aws-synthetic-correlation-001"
_MILLISECONDS = 1_786_532_400_123
_HTTP_BAD_REQUEST = 400
_HTTP_FORBIDDEN = 403
_HTTP_OK = 200
_HTTP_UNAVAILABLE = 503
_SDK_TIMEOUT_SECONDS = 2
_VULNERABLE_ITEM_COUNT = 2


@dataclass(slots=True)
class _DynamoDb:
    calls: list[dict[str, object]] = field(default_factory=list)

    def get_item(self, **kwargs: object) -> Mapping[str, object]:
        """Return one fixed synthetic item for the requested key."""
        self.calls.append(kwargs)
        key = cast("dict[str, dict[str, str]]", kwargs["Key"])
        document_id = key["documentId"]["S"]
        suffix = "a" if document_id == "requester-a" else "b"
        return {
            "Item": {
                "content": {"S": _CANARY_A if suffix == "a" else _CANARY_B},
                "documentId": {"S": document_id},
                "syntheticQuery": {
                    "S": f"requester-{suffix}-synthetic-topic",
                },
            },
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }


@dataclass(slots=True)
class _Logs:
    successful: bool = True
    calls: list[dict[str, object]] = field(default_factory=list)

    def put_log_events(self, **kwargs: object) -> Mapping[str, object]:
        """Retain the exact event and return one bounded SDK-shaped result."""
        self.calls.append(kwargs)
        if not self.successful:
            message = "synthetic SDK detail that must not escape"
            raise TimeoutError(message)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}


@dataclass(slots=True)
class _IncompleteDynamoDb(_DynamoDb):
    def get_item(self, **kwargs: object) -> Mapping[str, object]:
        """Remove the mandatory SDK completion metadata."""
        response = dict(super().get_item(**kwargs))
        response.pop("ResponseMetadata")
        return response


@dataclass(slots=True)
class _EqualCanaryDynamoDb(_DynamoDb):
    def get_item(self, **kwargs: object) -> Mapping[str, object]:
        """Return two otherwise-valid documents with one conflicting marker."""
        response = dict(super().get_item(**kwargs))
        item = cast("dict[str, dict[str, str]]", response["Item"])
        item["content"] = {"S": _CANARY_A}
        return response


@dataclass(slots=True)
class _RejectedLogs(_Logs):
    def put_log_events(self, **kwargs: object) -> Mapping[str, object]:
        """Return HTTP success with an explicitly rejected event range."""
        self.calls.append(kwargs)
        return {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "rejectedLogEventsInfo": {"tooNewLogEventStartIndex": 0},
        }


@pytest.fixture(autouse=True)
def _runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOCUMENTS_TABLE_NAME", TABLE_NAME)
    monkeypatch.setenv("EXPECTED_ACCOUNT_ID", ACCOUNT_ID)
    monkeypatch.setenv("LOG_GROUP_NAME", "/aws/cai-verify/reference/synthetic")
    monkeypatch.setenv("LOG_STREAM_NAME", "retrieval-events")
    monkeypatch.setenv("REFERENCE_MODE", "isolated")
    monkeypatch.setenv("REQUESTER_A_ROLE_ARN", REQUESTER_A_ROLE_ARN)
    monkeypatch.setenv("REQUESTER_A_SESSION_NAME", REQUESTER_A_SESSION)
    monkeypatch.setenv("REQUESTER_B_ROLE_ARN", REQUESTER_B_ROLE_ARN)
    monkeypatch.setenv("REQUESTER_B_SESSION_NAME", REQUESTER_B_SESSION)
    monkeypatch.setattr(handler, "_clock_milliseconds", lambda: _MILLISECONDS)
    monkeypatch.setattr(handler, "_DYNAMODB", _DynamoDb())
    monkeypatch.setattr(handler, "_LOGS", _Logs())


@pytest.mark.parametrize(
    ("requester", "role_arn", "session_name", "expected_canary"),
    [
        ("requester-a", REQUESTER_A_ROLE_ARN, REQUESTER_A_SESSION, _CANARY_A),
        ("requester-b", REQUESTER_B_ROLE_ARN, REQUESTER_B_SESSION, _CANARY_B),
    ],
)
def test_isolated_mode_emits_one_exact_correlated_record(
    requester: str,
    role_arn: str,
    session_name: str,
    expected_canary: str,
) -> None:
    """Each exact IAM requester gets only its own synthetic document."""
    result = handler.lambda_handler(
        _event(requester, role_arn=role_arn, session_name=session_name),
        object(),
    )

    logs = cast("_Logs", handler._LOGS)  # noqa: SLF001
    assert result == {
        "body": '{"retrieval":"completed"}',
        "headers": {
            "Content-Type": "application/json",
            "X-Cai-Correlation-Id": _CORRELATION,
        },
        "isBase64Encoded": False,
        "statusCode": 200,
    }
    assert len(logs.calls) == 1
    event = cast("list[dict[str, object]]", logs.calls[0]["logEvents"])[0]
    assert event["timestamp"] == _MILLISECONDS
    assert json.loads(cast("str", event["message"])) == {
        "canaries": [expected_canary],
        "correlationId": _CORRELATION,
        "eventKind": "retrievalCanary",
        "eventTime": "2026-08-12T11:00:00.123Z",
        "phase": "PRE_GENERATION",
        "retrievalStatus": "SUCCEEDED",
        "retrievedItemCount": 1,
        "scanStatus": "COMPLETE",
        "schemaVersion": "1",
    }
    assert logs.calls[0]["logGroupName"] == ("/aws/cai-verify/reference/synthetic")
    assert logs.calls[0]["logStreamName"] == "retrieval-events"


def test_vulnerable_mode_exposes_both_markers_deterministically(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The deliberate vulnerable mode causes both reciprocal directions to fail."""
    monkeypatch.setenv("REFERENCE_MODE", "vulnerable")

    result = handler.lambda_handler(
        _event(
            "requester-a",
            role_arn=REQUESTER_A_ROLE_ARN,
            session_name=REQUESTER_A_SESSION,
        ),
        object(),
    )

    logs = cast("_Logs", handler._LOGS)  # noqa: SLF001
    event = cast("list[dict[str, object]]", logs.calls[0]["logEvents"])[0]
    record = json.loads(cast("str", event["message"]))
    assert result["statusCode"] == _HTTP_OK
    assert record["canaries"] == [_CANARY_A, _CANARY_B]
    assert record["retrievedItemCount"] == _VULNERABLE_ITEM_COUNT


def test_sdk_policy_has_bounded_timeouts_and_no_automatic_retry() -> None:
    """A lost response cannot cause a second correlated telemetry write."""
    config = handler._SDK_CONFIG  # noqa: SLF001

    assert config.connect_timeout == _SDK_TIMEOUT_SECONDS
    assert config.read_timeout == _SDK_TIMEOUT_SECONDS
    assert config.retries == {"mode": "standard", "total_max_attempts": 1}


@pytest.mark.parametrize(
    "mutate",
    [
        lambda event: event.update({"httpMethod": "GET"}),
        lambda event: event.update({"path": "/other"}),
        lambda event: event.update({"body": "{}"}),
        lambda event: event.update(
            {"body": '{"syntheticQuery":"x","syntheticQuery":"x"}'}
        ),
        lambda event: cast("dict[str, str]", event["headers"]).pop(
            "X-Cai-Correlation-Id"
        ),
        lambda event: event.update(
            {
                "multiValueHeaders": {
                    "X-Cai-Correlation-Id": [_CORRELATION, _CORRELATION]
                }
            }
        ),
    ],
    ids=(
        "wrong-method",
        "wrong-path",
        "wrong-query",
        "duplicate-json-field",
        "missing-correlation",
        "duplicate-correlation",
    ),
)
def test_malformed_requests_fail_without_telemetry(
    mutate: Callable[[dict[str, object]], object],
) -> None:
    """Malformed bodies, headers, and routes cannot create evidence."""
    event = _event(
        "requester-a",
        role_arn=REQUESTER_A_ROLE_ARN,
        session_name=REQUESTER_A_SESSION,
    )
    mutate(event)

    result = handler.lambda_handler(event, object())

    assert result["statusCode"] == _HTTP_BAD_REQUEST
    assert "correlation" not in json.dumps(result).lower()
    assert cast("_Logs", handler._LOGS).calls == []  # noqa: SLF001


def test_caller_supplied_identity_is_ignored_and_wrong_iam_user_is_forbidden() -> None:
    """Only API Gateway's authenticated principal can choose the requester."""
    event = _event(
        "requester-a",
        role_arn=REQUESTER_A_ROLE_ARN,
        session_name=REQUESTER_A_SESSION,
    )
    cast("dict[str, str]", event["headers"])["X-Cai-Requester"] = "requester-b"
    context = cast("dict[str, object]", event["requestContext"])
    identity = cast("dict[str, str]", context["identity"])
    identity["userArn"] = f"arn:aws:iam::{ACCOUNT_ID}:user/untrusted"

    result = handler.lambda_handler(event, object())

    assert result["statusCode"] == _HTTP_FORBIDDEN
    assert cast("_Logs", handler._LOGS).calls == []  # noqa: SLF001


def test_logs_failure_returns_fixed_error_without_success_echo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unrecorded fact cannot be presented as an acknowledged action."""
    monkeypatch.setattr(handler, "_LOGS", _Logs(successful=False))

    result = handler.lambda_handler(
        _event(
            "requester-a",
            role_arn=REQUESTER_A_ROLE_ARN,
            session_name=REQUESTER_A_SESSION,
        ),
        object(),
    )

    serialized = json.dumps(result)
    assert result["statusCode"] == _HTTP_UNAVAILABLE
    assert _CORRELATION not in serialized
    assert "synthetic SDK detail" not in serialized
    assert _CANARY_A not in serialized


def test_incomplete_document_response_cannot_create_telemetry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A partial SDK-shaped document read fails before the evidence write."""
    monkeypatch.setattr(handler, "_DYNAMODB", _IncompleteDynamoDb())

    result = handler.lambda_handler(
        _event(
            "requester-a",
            role_arn=REQUESTER_A_ROLE_ARN,
            session_name=REQUESTER_A_SESSION,
        ),
        object(),
    )

    assert result["statusCode"] == _HTTP_UNAVAILABLE
    assert cast("_Logs", handler._LOGS).calls == []  # noqa: SLF001


def test_equal_document_canaries_fail_before_telemetry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The two synthetic boundary markers must remain distinct."""
    monkeypatch.setattr(handler, "_DYNAMODB", _EqualCanaryDynamoDb())

    result = handler.lambda_handler(
        _event(
            "requester-a",
            role_arn=REQUESTER_A_ROLE_ARN,
            session_name=REQUESTER_A_SESSION,
        ),
        object(),
    )

    assert result["statusCode"] == _HTTP_UNAVAILABLE
    assert cast("_Logs", handler._LOGS).calls == []  # noqa: SLF001


def test_rejected_log_event_is_not_acknowledged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An SDK page reporting rejection cannot produce a success echo."""
    monkeypatch.setattr(handler, "_LOGS", _RejectedLogs())

    result = handler.lambda_handler(
        _event(
            "requester-a",
            role_arn=REQUESTER_A_ROLE_ARN,
            session_name=REQUESTER_A_SESSION,
        ),
        object(),
    )

    assert result["statusCode"] == _HTTP_UNAVAILABLE
    assert _CORRELATION not in json.dumps(result)
    assert len(cast("_Logs", handler._LOGS).calls) == 1  # noqa: SLF001


def _event(
    requester: str,
    *,
    role_arn: str,
    session_name: str,
) -> dict[str, object]:
    partition, _, account_and_role = role_arn.partition(":iam::")
    account_id, _, role_name = account_and_role.partition(":role/")
    assumed_arn = (
        f"{partition}:sts::{account_id}:assumed-role/{role_name}/{session_name}"
    )
    suffix = "a" if requester == "requester-a" else "b"
    return {
        "body": json.dumps(
            {"syntheticQuery": f"requester-{suffix}-synthetic-topic"},
            separators=(",", ":"),
        ),
        "headers": {
            "Content-Type": "application/json",
            "X-Cai-Correlation-Id": _CORRELATION,
        },
        "httpMethod": "POST",
        "isBase64Encoded": False,
        "path": "/retrieve",
        "requestContext": {"identity": {"userArn": assumed_arn}},
        "resource": "/retrieve",
    }
