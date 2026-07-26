"""Network-isolated tests for pre-generation retrieval-canary evidence."""

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
from cai_verify.aws.identity import _AwsSdkUnavailableError
from cai_verify.config import AwsSigV4Action, CloudWatchLogsProbe, VerificationSuite
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
_ACTION_STARTED = _COLLECTED_AT - timedelta(seconds=40)
_ACTION_COMPLETED = _COLLECTED_AT - timedelta(seconds=30)
_BASELINE = "synthetic-baseline-marker"
_BOUNDARY = "synthetic-boundary-marker"
_TELEMETRY_CANARY = "synthetic-telemetry-canary"
_MODEL_ID = "synthetic.foundation-model-v1"
_ACCOUNT_ID = "111122223333"
_ACTION_CORRELATION = "aws-synthetic-correlation"
_SDK_SECRET = "sdk-retrieval-secret-must-not-leak"  # noqa: S105
_RAW_SECRET = "raw-retrieved-document-secret-must-not-leak"  # noqa: S105
_CREDENTIAL = "ASIASYNTHETIC000010"
_PRINCIPAL_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:role/synthetic-retrieval-reader"


@dataclass(slots=True)
class _LogsClient:
    responses: list[object]
    calls: list[dict[str, object]] = field(default_factory=list)

    def filter_log_events(self, **kwargs: object) -> Mapping[str, object]:
        """Return queued synthetic pages and retain only request metadata."""
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
        """Expose only the injected Logs client."""
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
        """Echo only the fixed application correlation header."""
        return action_module._AwsHttpResponse(  # noqa: SLF001
            status=200,
            correlation_id=request.header_map()["X-Cai-Correlation-Id"],
            too_large=False,
        )


@pytest.mark.parametrize(
    ("markers", "baseline", "boundary"),
    [
        ([_BASELINE], True, False),
        ([_BASELINE, _BOUNDARY], True, True),
        ([_BOUNDARY], False, True),
        ([], False, False),
    ],
    ids=[
        "baseline-only",
        "both",
        "boundary-only",
        "neither",
    ],
)
def test_paired_canary_presence_is_normalized_independently(
    markers: list[str],
    baseline: bool,  # noqa: FBT001 - parametrized expected fact.
    boundary: bool,  # noqa: FBT001 - parametrized expected fact.
) -> None:
    """Complete records report exact facts without assigning compliance status."""
    client = _LogsClient([_page(_retrieval_event("retrieval", canaries=markers))])
    identity, session = _identity(client)
    request = _request(_suite(), identity=identity)
    adapter = _adapter()

    assert isinstance(adapter, EvidenceProbe)
    result = assert_evidence_probe_contract(adapter, request)

    observed = _retrieval(result)
    assert result.source.name == CLOUDWATCH_LOGS_ADAPTER_NAME
    assert result.source.version == CLOUDWATCH_LOGS_ADAPTER_VERSION == "1.2.0"
    assert result.freshness.collected_at == _COLLECTED_AT
    assert result.freshness.source_time == _ACTION_COMPLETED
    assert observed == {
        "accepted_correlated_records": 1,
        "ambiguous": False,
        "baseline_canary_observed": baseline,
        "boundary_canary_observed": boundary,
        "complete_context_scan_succeeded": True,
        "complete_correlated_retrieval_record_found": True,
        "error_category": None,
        "evidence_complete": True,
        "future_dated": False,
        "malformed": False,
        "oversized": False,
        "partial": False,
        "pre_generation_phase_matched": True,
        "retrieval_succeeded": True,
        "retrieved_item_count": 2,
        "stale": False,
        "undeclared_synthetic_marker_observed": False,
    }
    assert "status" not in observed
    assert "PASS" not in json.dumps(observed)
    assert all(marker not in json.dumps(observed) for marker in markers)
    assert session.regions == ["eu-west-2"]
    assert client.calls == [_expected_filter_request()]


def test_zero_retrieved_items_and_undeclared_markers_are_unambiguous() -> None:
    """Zero items is valid only with no markers; other markers stay a safe fact."""
    zero = _adapter().collect_evidence(
        _request(
            _suite(),
            identity=_identity(
                _LogsClient(
                    [_page(_retrieval_event("zero", item_count=0, canaries=[]))],
                ),
            )[0],
        ),
    )
    undeclared = _adapter().collect_evidence(
        _request(
            _suite(),
            identity=_identity(
                _LogsClient(
                    [
                        _page(
                            _retrieval_event(
                                "undeclared",
                                canaries=[_BASELINE, "synthetic-third-marker"],
                            ),
                        ),
                    ],
                ),
            )[0],
        ),
    )

    assert _retrieval(zero)["retrieved_item_count"] == 0
    assert _retrieval(zero)["baseline_canary_observed"] is False
    assert _retrieval(zero)["boundary_canary_observed"] is False
    assert _retrieval(undeclared)["baseline_canary_observed"] is True
    assert _retrieval(undeclared)["boundary_canary_observed"] is False
    assert _retrieval(undeclared)["undeclared_synthetic_marker_observed"] is True


def test_action_interval_window_uses_probe_and_suite_freshness() -> None:
    """The complete action interval cannot be silently clipped by freshness."""
    suite = _suite()
    action = _action_result(
        started_at=_COLLECTED_AT - timedelta(minutes=2, seconds=40),
        completed_at=_COLLECTED_AT - timedelta(minutes=2, seconds=30),
    )
    probe_client = _LogsClient([_page()])

    probe_result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(probe_client)[0],
            action_result=action,
        ),
    )

    assert probe_result.freshness.max_age == timedelta(minutes=3)
    assert _retrieval(probe_result)["error_category"] == "stale_action"
    assert _retrieval(probe_result)["stale"] is True
    assert probe_client.calls == []
    _assert_unknown_retrieval_facts(_retrieval(probe_result))

    suite_probe = _probe(suite).model_copy(update={"max_age": None})
    suite_client = _LogsClient(
        [
            _page(
                _retrieval_event(
                    "suite-fresh",
                    occurred_at=action.completed_at,
                ),
            ),
        ],
    )
    suite_result = _adapter().collect_evidence(
        _request(
            suite,
            probe=suite_probe,
            identity=_identity(suite_client)[0],
            action_result=action,
        ),
    )

    assert suite_result.freshness.max_age == timedelta(minutes=5)
    assert _retrieval(suite_result)["evidence_complete"] is True
    assert suite_client.calls[0]["startTime"] == _milliseconds(
        action.started_at - timedelta(seconds=30),
    )
    assert suite_client.calls[0]["endTime"] == (
        _milliseconds(action.completed_at + timedelta(seconds=30)) + 1
    )


@pytest.mark.parametrize(
    ("case", "correlations"),
    [
        ("missing", ()),
        ("multiple", ("aws-first-correlation", "aws-second-correlation")),
        ("conflicting", (_ACTION_CORRELATION, "aws-conflicting-correlation")),
    ],
)
def test_unusable_action_correlations_fail_before_client_creation(
    case: str,
    correlations: tuple[str, ...],
) -> None:
    """Only one usable normalized application correlation can authorize a query."""
    del case
    client = _LogsClient([_page(_retrieval_event("never-queried"))])
    identity, session = _identity(client)

    result = _adapter().collect_evidence(
        _request(
            _suite(),
            identity=identity,
            action_result=_action_result(correlations=correlations),
        ),
    )

    expected = "missing_correlation" if not correlations else "ambiguous_correlation"
    assert _retrieval(result)["error_category"] == expected
    assert client.calls == []
    assert session.regions == []
    _assert_unknown_retrieval_facts(_retrieval(result))


def test_malformed_and_wrong_correlations_fail_closed() -> None:
    """A bypassed malformed ID and a time-near wrong record are not evidence."""
    malformed_action = _action_result()
    object.__setattr__(malformed_action, "correlation_ids", ("bad correlation",))
    malformed_client = _LogsClient([_page(_retrieval_event("never-queried"))])
    malformed = _adapter().collect_evidence(
        _request(
            _suite(),
            identity=_identity(malformed_client)[0],
            action_result=malformed_action,
        ),
    )
    wrong = _adapter().collect_evidence(
        _request(
            _suite(),
            identity=_identity(
                _LogsClient(
                    [
                        _page(
                            _retrieval_event(
                                "wrong-correlation",
                                correlation_id="aws-other-correlation",
                            ),
                        ),
                    ],
                ),
            )[0],
        ),
    )

    assert malformed_client.calls == []
    assert _retrieval(malformed)["error_category"] == "ambiguous_correlation"
    assert _retrieval(wrong)["error_category"] == "ambiguous_correlation"
    _assert_unknown_retrieval_facts(_retrieval(malformed))
    _assert_unknown_retrieval_facts(_retrieval(wrong))


def test_missing_multiple_and_duplicate_records_are_deterministic() -> None:
    """Exactly one unique application record is required."""
    missing = _adapter().collect_evidence(
        _request(
            _suite(),
            identity=_identity(_LogsClient([_page()]))[0],
        ),
    )
    first = _retrieval_event("first")
    second = _retrieval_event("second")
    multiple = _adapter().collect_evidence(
        _request(
            _suite(),
            identity=_identity(_LogsClient([_page(first, second)]))[0],
        ),
    )
    identical = _adapter().collect_evidence(
        _request(
            _suite(),
            identity=_identity(
                _LogsClient([_page(first, deepcopy(first))]),
            )[0],
        ),
    )
    conflict = deepcopy(first)
    conflict["message"] = _message(
        _retrieval_message(canaries=[_BASELINE, _BOUNDARY]),
    )
    conflicting = _adapter().collect_evidence(
        _request(
            _suite(),
            identity=_identity(_LogsClient([_page(first, conflict)]))[0],
        ),
    )

    assert _retrieval(missing)["error_category"] == "retrieval_record_missing"
    assert _retrieval(multiple)["error_category"] == "retrieval_limit_exceeded"
    assert _retrieval(multiple)["ambiguous"] is True
    assert _retrieval(identical)["evidence_complete"] is True
    assert _retrieval(identical)["accepted_correlated_records"] == 1
    assert _retrieval(conflicting)["error_category"] == "ambiguous_correlation"
    assert _retrieval(conflicting)["ambiguous"] is True
    for result in (missing, multiple, conflicting):
        assert result.freshness.source_time is None
        _assert_unknown_retrieval_facts(_retrieval(result))


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("phase", "POST_GENERATION"),
        ("retrievalStatus", "FAILED"),
        ("scanStatus", "PARTIAL"),
    ],
)
def test_fixed_completion_states_must_match_exactly(
    field_name: str,
    value: str,
) -> None:
    """Incomplete, failed, or post-generation application states are invalid."""
    message = _retrieval_message()
    message[field_name] = value

    result = _collect_message(message)

    assert _retrieval(result)["error_category"] == "invalid_event"
    assert _retrieval(result)["malformed"] is True
    _assert_unknown_retrieval_facts(_retrieval(result))


@pytest.mark.parametrize(
    "message",
    [
        "{not-json",
        (
            '{"canaries":[],"correlationId":"aws-synthetic-correlation",'
            '"eventKind":"retrievalCanary",'
            '"eventTime":"2026-07-26T11:59:30.000Z",'
            '"phase":"PRE_GENERATION","retrievalStatus":"SUCCEEDED",'
            '"retrievedItemCount":2,"retrievedItemCount":3,'
            '"scanStatus":"COMPLETE","schemaVersion":"1"}'
        ),
    ],
)
def test_malformed_and_duplicate_key_json_is_rejected(message: str) -> None:
    """The fixed record must be duplicate-free JSON."""
    result = _collect_raw_message(message)

    assert _retrieval(result)["error_category"] == "invalid_event"
    assert _retrieval(result)["malformed"] is True
    _assert_unknown_retrieval_facts(_retrieval(result))


@pytest.mark.parametrize(
    "case",
    [
        "missing",
        "extra",
        "wrong-version-type",
        "wrong-correlation-type",
        "wrong-canaries-type",
        "contradictory-zero",
    ],
)
def test_missing_extra_incorrect_and_contradictory_fields_are_invalid(
    case: str,
) -> None:
    """Unknown, missing, mistyped, or contradictory fixed fields fail closed."""
    message = _retrieval_message()
    if case == "missing":
        message.pop("scanStatus")
    elif case == "extra":
        message["document"] = _RAW_SECRET
    elif case == "wrong-version-type":
        message["schemaVersion"] = 1
    elif case == "wrong-correlation-type":
        message["correlationId"] = 123
    elif case == "wrong-canaries-type":
        message["canaries"] = _BASELINE
    elif case == "contradictory-zero":
        message["retrievedItemCount"] = 0
        message["canaries"] = [_BASELINE]
    else:
        raise AssertionError

    result = _collect_message(message)

    assert _retrieval(result)["error_category"] == "invalid_event"
    assert _RAW_SECRET not in json.dumps(_retrieval(result))
    _assert_unknown_retrieval_facts(_retrieval(result))


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (True, "invalid_event"),
        (-1, "invalid_event"),
        ("2", "invalid_event"),
        (
            cloudwatch_module.MAX_CLOUDWATCH_RETRIEVED_ITEMS + 1,
            "retrieved_item_limit_exceeded",
        ),
    ],
)
def test_retrieved_item_count_is_a_strict_bounded_integer(
    value: object,
    expected: str,
) -> None:
    """Booleans, negative values, strings, and over-limit counts are rejected."""
    message = _retrieval_message()
    message["retrievedItemCount"] = value

    result = _collect_message(message)

    assert _retrieval(result)["error_category"] == expected
    _assert_unknown_retrieval_facts(_retrieval(result))


@pytest.mark.parametrize(
    ("markers", "expected"),
    [
        ([123], "invalid_event"),
        ([""], "invalid_event"),
        ([_BASELINE, _BASELINE], "invalid_event"),
        (
            [
                f"synthetic-marker-{index}"
                for index in range(
                    cloudwatch_module.MAX_CLOUDWATCH_RETRIEVAL_MARKERS + 1
                )
            ],
            "marker_limit_exceeded",
        ),
        (
            ["x" * (cloudwatch_module.MAX_CLOUDWATCH_RETRIEVAL_MARKER_BYTES + 1)],
            "marker_size_exceeded",
        ),
        (
            ["a" * 800, "b" * 800, "c" * 800, "d" * 800],
            "marker_total_bytes_exceeded",
        ),
    ],
)
def test_marker_values_and_bounds_fail_closed(
    markers: list[object],
    expected: str,
) -> None:
    """Marker values are non-empty, UTF-8, unique, and independently bounded."""
    message = _retrieval_message()
    message["canaries"] = markers

    result = _collect_message(message)

    assert _retrieval(result)["error_category"] == expected
    _assert_unknown_retrieval_facts(_retrieval(result))


def test_malformed_marker_utf8_is_rejected() -> None:
    """A decoded lone surrogate cannot enter constant-time comparisons."""
    message = (
        '{"canaries":["\\ud800"],'
        '"correlationId":"aws-synthetic-correlation",'
        '"eventKind":"retrievalCanary",'
        '"eventTime":"2026-07-26T11:59:30.000Z",'
        '"phase":"PRE_GENERATION","retrievalStatus":"SUCCEEDED",'
        '"retrievedItemCount":2,"scanStatus":"COMPLETE","schemaVersion":"1"}'
    )

    result = _collect_raw_message(message)

    assert _retrieval(result)["error_category"] == "invalid_event"
    _assert_unknown_retrieval_facts(_retrieval(result))


@pytest.mark.parametrize(
    ("case", "expected", "flag"),
    [
        ("malformed-inner", "invalid_event", "malformed"),
        ("malformed-outer", "invalid_event", "malformed"),
        ("conflict", "timestamp_conflict", "malformed"),
        ("stale", "stale_event", "stale"),
        ("future", "future_event", "future_dated"),
        ("outside-action", "event_outside_window", "ambiguous"),
    ],
)
def test_inner_outer_stale_future_and_conflicting_timestamps(
    case: str,
    expected: str,
    flag: str,
) -> None:
    """Both timestamps must be valid, consistent, fresh, and in the action window."""
    if case == "malformed-inner":
        message = _retrieval_message()
        message["eventTime"] = "not-a-time"
        record = _raw_event("bad-inner", message)
    elif case == "malformed-outer":
        record = _retrieval_event("bad-outer")
        record["timestamp"] = True
    elif case == "conflict":
        record = _retrieval_event(
            "conflict",
            cloudwatch_time=_ACTION_COMPLETED + timedelta(seconds=31),
        )
    elif case == "stale":
        record = _retrieval_event(
            "stale",
            occurred_at=_COLLECTED_AT - timedelta(minutes=4),
        )
    elif case == "future":
        record = _retrieval_event(
            "future",
            occurred_at=_COLLECTED_AT + timedelta(seconds=31),
        )
    elif case == "outside-action":
        record = _retrieval_event(
            "outside",
            occurred_at=_ACTION_STARTED - timedelta(seconds=31),
        )
    else:
        raise AssertionError

    result = _adapter().collect_evidence(
        _request(
            _suite(),
            identity=_identity(_LogsClient([_page(record)]))[0],
        ),
    )

    assert _retrieval(result)["error_category"] == expected
    assert _retrieval(result)[flag] is True
    assert result.freshness.source_time is None
    _assert_unknown_retrieval_facts(_retrieval(result))


def test_observation_order_is_deterministic_with_existing_cloudwatch_kinds() -> None:
    """Combined observations retain stable kind and identifier ordering."""
    suite = _combined_suite()
    records = (
        _telemetry_event("telemetry"),
        _retrieval_event("retrieval"),
        _provider_event("provider"),
        _bedrock_event("bedrock"),
    )
    first = _adapter(combined=True).collect_evidence(
        _request(
            suite,
            identity=_identity(_LogsClient([_page(*records)]))[0],
        ),
    )
    second = _adapter(combined=True).collect_evidence(
        _request(
            suite,
            identity=_identity(
                _LogsClient([_page(*reversed(records))]),
            )[0],
        ),
    )

    expected = [
        "bedrockInvocation",
        "providerInvocation",
        "retrievalCanary",
        "telemetryCanary",
    ]
    assert [item.kind for item in first.observations] == expected
    assert [item.kind for item in second.observations] == expected
    assert _result_values(first) == _result_values(second)


def test_pagination_within_limits_is_complete() -> None:
    """The fixed token chain is followed exactly once within page bounds."""
    client = _LogsClient(
        [
            _page(
                pagination_token="synthetic-page-two",  # noqa: S106 - cursor.
            ),
            _page(_retrieval_event("page-two")),
        ],
    )

    result = _adapter().collect_evidence(
        _request(_suite(), identity=_identity(client)[0]),
    )

    assert _retrieval(result)["evidence_complete"] is True
    assert "nextToken" not in client.calls[0]
    assert client.calls[1]["nextToken"] == "synthetic-page-two"


@pytest.mark.parametrize("case", ["repeated", "excessive", "oversized"])
def test_repeated_excessive_and_oversized_pagination_is_partial(case: str) -> None:
    """No incomplete or over-limit pagination chain leaves retrieval facts."""
    if case == "repeated":
        pages: list[object] = [
            _page(
                _retrieval_event("first"),
                pagination_token="repeated-token",  # noqa: S106 - cursor.
            ),
            _page(
                pagination_token="repeated-token",  # noqa: S106 - cursor.
            ),
        ]
    elif case == "excessive":
        pages = [
            _page(
                _retrieval_event("first") if index == 0 else None,
                pagination_token=f"page-{index + 1}",
            )
            for index in range(cloudwatch_module.MAX_CLOUDWATCH_PAGES)
        ]
    elif case == "oversized":
        pages = [
            _page(
                _retrieval_event("first"),
                pagination_token=(
                    "é"
                    * (
                        cloudwatch_module.MAX_CLOUDWATCH_PAGINATION_TOKEN_LENGTH // 2
                        + 1
                    )
                ),
            ),
        ]
    else:
        raise AssertionError

    result = _adapter().collect_evidence(
        _request(
            _suite(),
            identity=_identity(_LogsClient(pages))[0],
        ),
    )

    assert _retrieval(result)["error_category"] == "pagination_limit_exceeded"
    assert _retrieval(result)["partial"] is True
    _assert_unknown_retrieval_facts(_retrieval(result))


def test_shared_event_message_byte_and_action_duration_limits() -> None:
    """Shared CloudWatch and retrieval duration bounds all suppress facts."""
    events = [_retrieval_event("retrieval")]
    events.extend(
        _provider_event(f"provider-{index}")
        for index in range(cloudwatch_module.MAX_CLOUDWATCH_EVENTS)
    )
    event_limit = _adapter().collect_evidence(
        _request(
            _suite(),
            identity=_identity(_LogsClient([_page(*events)]))[0],
        ),
    )
    oversized = {
        "eventId": "oversized",
        "message": "x" * (cloudwatch_module.MAX_CLOUDWATCH_EVENT_BYTES + 1),
        "timestamp": _milliseconds(_ACTION_COMPLETED),
    }
    message_limit = _adapter().collect_evidence(
        _request(
            _suite(),
            identity=_identity(_LogsClient([_page(oversized)]))[0],
        ),
    )
    large_messages = tuple(
        _telemetry_event(f"large-{index}", canary="x" * 3500) for index in range(40)
    )
    byte_limit = _adapter().collect_evidence(
        _request(
            _suite(),
            identity=_identity(_LogsClient([_page(*large_messages)]))[0],
        ),
    )
    long_action_client = _LogsClient([_page()])
    long_suite = _suite()
    long_probe = _probe(long_suite).model_copy(update={"max_age": None})
    duration_adapter = CloudWatchLogsProbeAdapter(
        environment=_environment(),
        suite_max_age=timedelta(hours=24),
        clock_skew_tolerance=timedelta(seconds=30),
        clock=lambda: _COLLECTED_AT,
    )
    duration_limit = duration_adapter.collect_evidence(
        _request(
            long_suite,
            probe=long_probe,
            identity=_identity(long_action_client)[0],
            action_result=_action_result(
                started_at=_ACTION_COMPLETED - timedelta(minutes=9, seconds=1),
            ),
        ),
    )

    assert _retrieval(event_limit)["error_category"] == "event_limit_exceeded"
    assert _retrieval(message_limit)["error_category"] == "oversized_message"
    assert _retrieval(message_limit)["oversized"] is True
    assert _retrieval(byte_limit)["error_category"] == "total_bytes_exceeded"
    assert _retrieval(byte_limit)["oversized"] is True
    assert _retrieval(duration_limit)["error_category"] == "query_window_exceeded"
    assert _retrieval(duration_limit)["partial"] is True
    assert long_action_client.calls == []
    for result in (event_limit, message_limit, byte_limit, duration_limit):
        _assert_unknown_retrieval_facts(_retrieval(result))


def test_total_collection_duration_includes_normalization() -> None:
    """The 15-second deadline includes parsing after the SDK response."""
    times = iter(
        [
            0.0,
            0.0,
            cloudwatch_module.MAX_CLOUDWATCH_QUERY_SECONDS + 0.1,
        ],
    )
    adapter = CloudWatchLogsProbeAdapter(
        environment=_environment(),
        suite_max_age=timedelta(minutes=5),
        clock_skew_tolerance=timedelta(seconds=30),
        clock=lambda: _COLLECTED_AT,
        monotonic=lambda: next(times),
    )

    result = adapter.collect_evidence(
        _request(
            _suite(),
            identity=_identity(
                _LogsClient([_page(_retrieval_event("timeout"))]),
            )[0],
        ),
    )

    assert _retrieval(result)["error_category"] == "query_timeout"
    assert _retrieval(result)["partial"] is True
    _assert_unknown_retrieval_facts(_retrieval(result))


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
        (
            ClientError(
                {
                    "Error": {
                        "Code": "ThrottlingException",
                        "Message": _SDK_SECRET,
                    },
                },
                "FilterLogEvents",
            ),
            "throttled",
        ),
        (RuntimeError(_SDK_SECRET), "sdk_error"),
    ],
)
def test_sdk_failures_are_stable_partial_and_redacted(
    error: Exception,
    expected: str,
) -> None:
    """SDK text is discarded for timeout, denial, throttling, and other errors."""
    result = _adapter().collect_evidence(
        _request(
            _suite(),
            identity=_identity(_LogsClient([error]))[0],
        ),
    )

    assert _retrieval(result)["error_category"] == expected
    assert _retrieval(result)["partial"] is True
    assert _SDK_SECRET not in repr(result)
    assert _SDK_SECRET not in json.dumps(_retrieval(result))
    _assert_unknown_retrieval_facts(_retrieval(result))


def test_unavailable_sdk_is_stable_and_does_not_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unavailable optional SDK becomes one non-secret incomplete category."""
    client = _LogsClient([_page(_retrieval_event("never-queried"))])
    identity, session = _identity(client)

    def unavailable(
        self: AwsScopedIdentity,
        *,
        region: str,
        evaluated_at: datetime,
    ) -> object:
        del self, region, evaluated_at
        raise _AwsSdkUnavailableError

    monkeypatch.setattr(AwsScopedIdentity, "_cloudwatch_logs_client", unavailable)
    result = _adapter().collect_evidence(
        _request(_suite(), identity=identity),
    )

    assert _retrieval(result)["error_category"] == "aws_sdk_unavailable"
    assert _retrieval(result)["partial"] is True
    assert client.calls == []
    assert session.regions == []
    _assert_unknown_retrieval_facts(_retrieval(result))


@pytest.mark.parametrize(
    "case",
    ["missing-events", "unexpected-field", "incomplete-stream", "partial-status"],
)
def test_partial_sdk_responses_suppress_retrieval_facts(
    case: str,
) -> None:
    """Malformed pages and incomplete stream searches never normalize positives."""
    if case == "missing-events":
        response: dict[str, object] = {"searchedLogStreams": []}
    elif case == "unexpected-field":
        response = {"events": [], "unexpectedSdkField": _RAW_SECRET}
    elif case == "incomplete-stream":
        response = {
            "events": [_retrieval_event("incomplete")],
            "searchedLogStreams": [
                {
                    "logStreamName": "synthetic-stream",
                    "searchedCompletely": False,
                },
            ],
        }
    elif case == "partial-status":
        response = {
            "ResponseMetadata": {"HTTPStatusCode": 206},
            "events": [_retrieval_event("partial-status")],
        }
    else:
        raise AssertionError
    result = _adapter().collect_evidence(
        _request(
            _suite(),
            identity=_identity(_LogsClient([response]))[0],
        ),
    )

    assert _retrieval(result)["error_category"] == "partial_response"
    assert _retrieval(result)["partial"] is True
    assert _RAW_SECRET not in json.dumps(_retrieval(result))
    _assert_unknown_retrieval_facts(_retrieval(result))


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
    """Every scoped identity boundary is enforced before client creation."""
    client = _LogsClient([_page(_retrieval_event("never-queried"))])
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

    assert _retrieval(result)["error_category"] == "identity_boundary_invalid"
    assert client.calls == []
    assert session.regions == []
    _assert_unknown_retrieval_facts(_retrieval(result))


def test_probe_identity_reference_must_match_scoped_identity() -> None:
    """A declared probe identity cannot be substituted at collection time."""
    client = _LogsClient([_page(_retrieval_event("never-queried"))])
    identity, session = _identity(client, identity_id="different-reader")

    result = _adapter().collect_evidence(
        _request(_suite(), identity=identity),
    )

    assert _retrieval(result)["error_category"] == "invalid_configuration"
    assert client.calls == []
    assert session.regions == []
    _assert_unknown_retrieval_facts(_retrieval(result))


@pytest.mark.parametrize(
    ("environment", "expected"),
    [
        (
            {"SYNTHETIC_BASELINE_CANARY": _BASELINE},
            "environment_value_invalid",
        ),
        (
            {
                "SYNTHETIC_BASELINE_CANARY": "",
                "SYNTHETIC_BOUNDARY_CANARY": _BOUNDARY,
            },
            "environment_value_invalid",
        ),
        (
            {
                "SYNTHETIC_BASELINE_CANARY": "\ud800",
                "SYNTHETIC_BOUNDARY_CANARY": _BOUNDARY,
            },
            "environment_value_invalid",
        ),
        (
            {
                "SYNTHETIC_BASELINE_CANARY": _BASELINE,
                "SYNTHETIC_BOUNDARY_CANARY": _BASELINE,
            },
            "environment_value_invalid",
        ),
        (
            {
                "SYNTHETIC_BASELINE_CANARY": (
                    "x" * (cloudwatch_module.MAX_CLOUDWATCH_RETRIEVAL_CANARY_BYTES + 1)
                ),
                "SYNTHETIC_BOUNDARY_CANARY": _BOUNDARY,
            },
            "canary_value_limit_exceeded",
        ),
    ],
)
def test_environment_resolution_fails_before_any_sdk_call(
    environment: dict[str, str],
    expected: str,
) -> None:
    """Missing, empty, equal, and oversized canary values never reach AWS."""
    client = _LogsClient([_page(_retrieval_event("never-queried"))])
    identity, session = _identity(client)

    result = _adapter(environment=environment).collect_evidence(
        _request(_suite(), identity=identity),
    )

    assert _retrieval(result)["error_category"] == expected
    assert client.calls == []
    assert session.regions == []
    if expected == "canary_value_limit_exceeded":
        assert _retrieval(result)["oversized"] is True
    _assert_unknown_retrieval_facts(_retrieval(result))


def test_sensitive_source_material_and_diagnostics_are_never_normalized() -> None:
    """Raw messages and every sensitive identifier class stay outside results."""
    sensitive_correlation = "aws-sensitive-correlation"
    malformed = _retrieval_message(correlation_id=sensitive_correlation)
    malformed.update(
        {
            "account": _ACCOUNT_ID,
            "arn": _PRINCIPAL_ARN,
            "credential": _CREDENTIAL,
            "document": _RAW_SECRET,
            "principal": "synthetic-sensitive-principal",
            "query": "synthetic-sensitive-query",
            "tenant": "synthetic-sensitive-tenant",
            "user": "synthetic-sensitive-user",
        },
    )
    adapter = _adapter(
        environment={
            "SYNTHETIC_BASELINE_CANARY": _BASELINE,
            "SYNTHETIC_BOUNDARY_CANARY": _BOUNDARY,
            "NEIGHBOR_ENVIRONMENT": "synthetic-sensitive-environment-value",
        },
    )
    malformed_result = adapter.collect_evidence(
        _request(
            _suite(),
            identity=_identity(
                _LogsClient(
                    [
                        _page(
                            _raw_event("sensitive", malformed),
                        ),
                    ],
                ),
            )[0],
            action_result=_action_result(correlations=(sensitive_correlation,)),
        ),
    )
    sdk_result = adapter.collect_evidence(
        _request(
            _suite(),
            identity=_identity(_LogsClient([RuntimeError(_SDK_SECRET)]))[0],
        ),
    )
    rendered = (
        repr(adapter)
        + repr(malformed_result)
        + repr(sdk_result)
        + json.dumps(_result_values(malformed_result))
        + json.dumps(_result_values(sdk_result))
    )

    for sensitive in (
        _BASELINE,
        _BOUNDARY,
        _RAW_SECRET,
        _ACCOUNT_ID,
        _PRINCIPAL_ARN,
        _CREDENTIAL,
        "synthetic-sensitive-principal",
        "synthetic-sensitive-query",
        "synthetic-sensitive-tenant",
        "synthetic-sensitive-user",
        "synthetic-sensitive-environment-value",
        sensitive_correlation,
        _SDK_SECRET,
    ):
        assert sensitive not in rendered


def test_validated_action_identity_and_botocore_stubber_integration() -> None:
    """The complete contract flows through SigV4, identity, and FilterLogEvents."""
    mapping = _suite_mapping()
    probe_mapping = mapping["scenarios"][0]["probes"][0]
    probe_mapping["actionRef"] = "signed-request"
    suite = VerificationSuite.model_validate(mapping)
    action = suite.scenarios[0].actions[1]
    assert isinstance(action, AwsSigV4Action)
    context = ExecutionContext(
        run_id="retrieval-contract",
        scenario_id=suite.scenarios[0].id,
        target=suite.target,
    )
    action_result = AwsSigV4ActionAdapter(
        environment={},
        transport=_EchoActionTransport(),
        clock=lambda: _ACTION_COMPLETED,
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
    expected = _expected_filter_request(
        correlation_id=correlation_id,
        started_at=action_result.started_at,
        completed_at=action_result.completed_at,
    )
    stubber = Stubber(client)
    stubber.add_response(
        "filter_log_events",
        {
            "events": [
                _retrieval_event(
                    "stubbed-retrieval",
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
    assert _retrieval(result)["complete_correlated_retrieval_record_found"] is True
    assert _retrieval(result)["baseline_canary_observed"] is True
    assert _retrieval(result)["boundary_canary_observed"] is False
    assert result.probe_id == "application-telemetry"


def _suite_mapping() -> dict[str, Any]:
    loaded = yaml.safe_load(_FIXTURE.read_text(encoding="utf-8"))
    mapping = cast("dict[str, Any]", loaded)
    scenario = mapping["scenarios"][0]
    probe = scenario["probes"][0]
    probe["observations"] = ["retrievalCanary"]
    probe.pop("canary")
    probe["retrieval"] = {
        "baselineCanary": {
            "name": "SYNTHETIC_BASELINE_CANARY",
            "source": "environment",
        },
        "boundaryCanary": {
            "name": "SYNTHETIC_BOUNDARY_CANARY",
            "source": "environment",
        },
    }
    scenario["assertions"] = [
        assertion
        for assertion in scenario["assertions"]
        if assertion["type"] not in {"providerBoundary", "telemetryCanary"}
    ]
    return mapping


def _suite() -> VerificationSuite:
    return VerificationSuite.model_validate(_suite_mapping())


def _combined_suite() -> VerificationSuite:
    mapping = _suite_mapping()
    probe = mapping["scenarios"][0]["probes"][0]
    probe["observations"] = [
        "telemetryCanary",
        "retrievalCanary",
        "providerInvocation",
        "bedrockInvocation",
    ]
    probe["canary"] = {
        "name": "SYNTHETIC_TELEMETRY_CANARY",
        "source": "environment",
    }
    probe["bedrock"] = {
        "modelId": {
            "name": "SYNTHETIC_BEDROCK_MODEL_ID",
            "source": "environment",
        },
    }
    return VerificationSuite.model_validate(mapping)


def _probe(suite: VerificationSuite) -> CloudWatchLogsProbe:
    probe = suite.scenarios[0].probes[0]
    assert isinstance(probe, CloudWatchLogsProbe)
    return probe


def _environment() -> dict[str, str]:
    return {
        "SYNTHETIC_BASELINE_CANARY": _BASELINE,
        "SYNTHETIC_BOUNDARY_CANARY": _BOUNDARY,
    }


def _adapter(
    *,
    environment: dict[str, str] | None = None,
    combined: bool = False,
) -> CloudWatchLogsProbeAdapter:
    selected = environment if environment is not None else _environment()
    if combined:
        selected = {
            **selected,
            "SYNTHETIC_BEDROCK_MODEL_ID": _MODEL_ID,
            "SYNTHETIC_TELEMETRY_CANARY": _TELEMETRY_CANARY,
        }
    return CloudWatchLogsProbeAdapter(
        environment=selected,
        suite_max_age=timedelta(minutes=5),
        clock_skew_tolerance=timedelta(seconds=30),
        clock=lambda: _COLLECTED_AT,
    )


def _identity(
    client: object,
    *,
    identity_id: str = "evidence-reader",
    account: str = _ACCOUNT_ID,
    partition: str = "aws",
    expires_at: datetime | None = None,
) -> tuple[AwsScopedIdentity, _LogsSession]:
    session = _LogsSession(client)
    identity = AwsScopedIdentity(
        _identity_id=identity_id,
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
) -> ProbeRequest:
    selected_probe = probe or _probe(suite)
    return ProbeRequest(
        context=ExecutionContext(
            run_id="retrieval-contract",
            scenario_id=suite.scenarios[0].id,
            target=suite.target,
        ),
        probe=selected_probe,
        action_result=action_result
        or _action_result(action_id=selected_probe.action_ref),
        identity=identity,
    )


def _action_result(
    *,
    action_id: str = "unsigned-request",
    correlations: tuple[str, ...] = (_ACTION_CORRELATION,),
    started_at: datetime = _ACTION_STARTED,
    completed_at: datetime = _ACTION_COMPLETED,
) -> ActionExecutionResult:
    return ActionExecutionResult(
        action_id=action_id,
        outcome=ActionOutcome.SUCCEEDED,
        started_at=started_at,
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


def _retrieval_event(  # noqa: PLR0913 - fixed synthetic fields are explicit.
    event_id: str,
    *,
    canaries: list[str] | None = None,
    item_count: int = 2,
    correlation_id: str = _ACTION_CORRELATION,
    occurred_at: datetime = _ACTION_COMPLETED,
    cloudwatch_time: datetime | None = None,
) -> dict[str, object]:
    return _raw_event(
        event_id,
        _retrieval_message(
            canaries=canaries,
            item_count=item_count,
            correlation_id=correlation_id,
            occurred_at=occurred_at,
        ),
        cloudwatch_time=cloudwatch_time or occurred_at,
    )


def _retrieval_message(
    *,
    canaries: list[str] | None = None,
    item_count: int = 2,
    correlation_id: str = _ACTION_CORRELATION,
    occurred_at: datetime = _ACTION_COMPLETED,
) -> dict[str, object]:
    return {
        "canaries": [_BASELINE] if canaries is None else canaries,
        "correlationId": correlation_id,
        "eventKind": "retrievalCanary",
        "eventTime": _event_time(occurred_at),
        "phase": "PRE_GENERATION",
        "retrievalStatus": "SUCCEEDED",
        "retrievedItemCount": item_count,
        "scanStatus": "COMPLETE",
        "schemaVersion": "1",
    }


def _provider_event(event_id: str) -> dict[str, object]:
    return _raw_event(
        event_id,
        {
            "correlationId": _ACTION_CORRELATION,
            "eventKind": "providerInvocation",
            "eventTime": _event_time(_ACTION_COMPLETED),
            "providerId": "amazon-bedrock",
            "schemaVersion": "1",
        },
    )


def _telemetry_event(
    event_id: str,
    *,
    canary: str = _TELEMETRY_CANARY,
) -> dict[str, object]:
    return _raw_event(
        event_id,
        {
            "canary": canary,
            "correlationId": _ACTION_CORRELATION,
            "eventKind": "telemetryCanary",
            "eventTime": _event_time(_ACTION_COMPLETED),
            "schemaVersion": "1",
        },
    )


def _bedrock_event(event_id: str) -> dict[str, object]:
    return _raw_event(
        event_id,
        {
            "awsRegion": "eu-west-2",
            "correlationId": _ACTION_CORRELATION,
            "eventKind": "bedrockInvocation",
            "eventTime": _event_time(_ACTION_COMPLETED),
            "invocationStatus": "SUCCEEDED",
            "modelId": _MODEL_ID,
            "provider": "Amazon Bedrock",
            "schemaVersion": "1",
        },
    )


def _raw_event(
    event_id: str,
    message: dict[str, object],
    *,
    cloudwatch_time: datetime = _ACTION_COMPLETED,
) -> dict[str, object]:
    return _raw_message(
        event_id,
        _message(message),
        cloudwatch_time=cloudwatch_time,
    )


def _raw_message(
    event_id: str,
    message: str,
    *,
    cloudwatch_time: datetime = _ACTION_COMPLETED,
) -> dict[str, object]:
    return {
        "eventId": event_id,
        "logStreamName": "synthetic-stream",
        "message": message,
        "timestamp": _milliseconds(cloudwatch_time),
    }


def _message(value: dict[str, object]) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


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


def _collect_message(message: dict[str, object]) -> ProbeResult:
    return _collect_raw_message(_message(message))


def _collect_raw_message(message: str) -> ProbeResult:
    return _adapter().collect_evidence(
        _request(
            _suite(),
            identity=_identity(
                _LogsClient([_page(_raw_message("raw", message))]),
            )[0],
        ),
    )


def _expected_filter_request(
    *,
    correlation_id: str = _ACTION_CORRELATION,
    started_at: datetime = _ACTION_STARTED,
    completed_at: datetime = _ACTION_COMPLETED,
) -> dict[str, object]:
    return {
        "endTime": _milliseconds(completed_at + timedelta(seconds=30)) + 1,
        "filterPattern": (f'{{ $.correlationId = "{correlation_id}" }}'),
        "interleaved": True,
        "limit": cloudwatch_module.MAX_CLOUDWATCH_EVENTS + 1,
        "logGroupName": "/aws/cai-verify/synthetic-assistant",
        "startFromHead": True,
        "startTime": _milliseconds(started_at - timedelta(seconds=30)),
        "unmask": False,
    }


def _event_time(value: datetime) -> str:
    return (
        value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    )


def _milliseconds(value: datetime) -> int:
    return int(value.timestamp() * 1000)


def _retrieval(result: ProbeResult) -> dict[str, object]:
    matching = tuple(
        item
        for item in result.observations
        if item.kind == ObservationKind.RETRIEVAL_CANARY.value
    )
    assert len(matching) == 1
    return cast("dict[str, object]", matching[0].observed.to_json_value())


def _result_values(result: ProbeResult) -> list[object]:
    return [item.observed.to_json_value() for item in result.observations]


def _assert_unknown_retrieval_facts(observed: dict[str, object]) -> None:
    assert observed["accepted_correlated_records"] == 0
    assert observed["baseline_canary_observed"] is None
    assert observed["boundary_canary_observed"] is None
    assert observed["complete_context_scan_succeeded"] is None
    assert observed["complete_correlated_retrieval_record_found"] is False
    assert observed["evidence_complete"] is False
    assert observed["pre_generation_phase_matched"] is None
    assert observed["retrieval_succeeded"] is None
    assert observed["retrieved_item_count"] is None
    assert observed["undeclared_synthetic_marker_observed"] is None
