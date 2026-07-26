"""Network-isolated tests for bounded CloudTrail audit evidence collection."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import boto3  # type: ignore[import-untyped]
import pytest
import yaml
from botocore.exceptions import ClientError  # type: ignore[import-untyped]

import cai_verify.aws.action as action_module
import cai_verify.aws.cloudtrail as cloudtrail_module
from cai_verify.aws import (
    CLOUDTRAIL_ADAPTER_NAME,
    CLOUDTRAIL_ADAPTER_VERSION,
    AwsScopedIdentity,
    AwsSigV4ActionAdapter,
    CloudTrailProbeAdapter,
    CloudTrailProbeError,
    CloudTrailProbeFailureCode,
)
from cai_verify.config import AwsSigV4Action, CloudTrailProbe, Target, VerificationSuite
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
_REQUEST_ID = "4c70d310-9954-4d4f-a615-synthetic-request"
_APP_CORRELATION = "aws-synthetic-application-correlation"
_ACCOUNT_ID = "111122223333"
_EVENT_SOURCE = "execute-api.amazonaws.com"
_EVENT_NAME = "Invoke"
_PRINCIPAL_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:role/synthetic-reader"
_PRINCIPAL_ID = "SYNTHETICPRINCIPALID"
_CREDENTIAL = "ASIASYNTHETIC000042"
_RAW_SECRET = "raw-cloudtrail-secret-must-not-leak"  # noqa: S105
_SDK_SECRET = "sdk-cloudtrail-error-must-not-leak"  # noqa: S105
_CONNECT_TIMEOUT_SECONDS = 3
_READ_TIMEOUT_SECONDS = 5
_MAX_ATTEMPTS = 2
_FULL_EVENT_PAGES = 3


@dataclass(slots=True)
class _CloudTrailClient:
    responses: list[object]
    calls: list[dict[str, object]] = field(default_factory=list)

    def lookup_events(self, **kwargs: object) -> Mapping[str, object]:
        self.calls.append(dict(kwargs))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return cast("Mapping[str, object]", response)


@dataclass(slots=True)
class _CloudTrailSession:
    client_value: _CloudTrailClient
    regions: list[str] = field(default_factory=list)
    configs: list[object] = field(default_factory=list)

    def client(self, service_name: str, **kwargs: object) -> object:
        assert service_name == "cloudtrail"
        assert set(kwargs) == {"config", "region_name"}
        self.regions.append(cast("str", kwargs["region_name"]))
        self.configs.append(kwargs["config"])
        return self.client_value


@dataclass(frozen=True, slots=True)
class _CorrelatedActionTransport:
    def send(
        self,
        request: action_module._AwsHttpRequest,
        /,
    ) -> action_module._AwsHttpResponse:
        return action_module._AwsHttpResponse(  # noqa: SLF001
            status=200,
            correlation_id=request.header_map()["X-Cai-Correlation-Id"],
            too_large=False,
            aws_request_ids=(_REQUEST_ID,),
        )


def test_correlated_audit_event_uses_exact_lookup_and_plugin_contract() -> None:
    """One exact requestID match becomes bounded normalized audit evidence."""
    suite = _suite()
    client = _CloudTrailClient([_page(_event("event-success"))])
    identity, session = _identity(client)
    adapter = _adapter()
    request = _request(suite, identity=identity)

    assert isinstance(adapter, EvidenceProbe)
    result = assert_evidence_probe_contract(adapter, request)

    assert result.source.name == CLOUDTRAIL_ADAPTER_NAME
    assert result.source.version == CLOUDTRAIL_ADAPTER_VERSION
    assert result.freshness.collected_at == _COLLECTED_AT
    assert result.freshness.source_time == _ACTION_TIME
    assert _audit(result) == {
        "accepted_correlated_events": 1,
        "ambiguous": False,
        "complete_correlated_event_set_found": True,
        "correlated_events_found": True,
        "error_category": None,
        "event_names": ["Invoke"],
        "event_source_matched": True,
        "evidence_complete": True,
        "future_dated": False,
        "malformed": False,
        "oversized": False,
        "partial": False,
        "region_matched": True,
        "stale": False,
    }
    assert session.regions == ["eu-west-2"]
    assert client.calls == [
        {
            "EndTime": _COLLECTED_AT,
            "LookupAttributes": [
                {
                    "AttributeKey": "EventSource",
                    "AttributeValue": _EVENT_SOURCE,
                },
            ],
            "MaxResults": cloudtrail_module.MAX_CLOUDTRAIL_CORRELATED_EVENTS + 1,
            "StartTime": _ACTION_TIME - timedelta(seconds=30),
        },
    ]


def test_declared_source_names_region_and_order_are_exact() -> None:
    """The fixed source lookup and local name/region checks do not broaden scope."""
    suite = _suite()
    probe = _probe(suite).model_copy(
        update={"event_names": ("ZetaAction", "AlphaAction")},
    )
    client = _CloudTrailClient(
        [
            _page(
                _event("event-zeta", event_name="ZetaAction"),
                _event("event-alpha", event_name="AlphaAction"),
            ),
        ],
    )
    identity, session = _identity(client)

    result = _adapter().collect_evidence(
        _request(suite, probe=probe, identity=identity),
    )

    assert _audit(result)["event_names"] == ["AlphaAction", "ZetaAction"]
    assert client.calls[0]["LookupAttributes"] == [
        {
            "AttributeKey": "EventSource",
            "AttributeValue": _EVENT_SOURCE,
        },
    ]
    assert session.regions == [cast("str", suite.target.aws_region)]


def test_probe_and_suite_freshness_are_selected_deterministically() -> None:
    """A probe override wins while omission uses the suite freshness policy."""
    suite = _suite()
    old_action = _action_result(
        completed_at=_COLLECTED_AT - timedelta(minutes=2),
    )
    probe = _probe(suite).model_copy(update={"max_age": "PT1M"})
    probe_client = _CloudTrailClient([_page()])

    probe_result = _adapter().collect_evidence(
        _request(
            suite,
            probe=probe,
            identity=_identity(probe_client)[0],
            action_result=old_action,
        ),
    )

    assert probe_result.freshness.max_age == timedelta(minutes=1)
    assert _audit(probe_result)["error_category"] == "stale_action"
    assert probe_client.calls == []

    suite_probe = probe.model_copy(update={"max_age": None})
    suite_client = _CloudTrailClient([_page()])
    suite_result = _adapter().collect_evidence(
        _request(
            suite,
            probe=suite_probe,
            identity=_identity(suite_client)[0],
            action_result=old_action,
        ),
    )

    assert suite_result.freshness.max_age == timedelta(minutes=5)
    assert _audit(suite_result)["stale"] is False
    assert len(suite_client.calls) == 1
    assert suite_client.calls[0]["StartTime"] == (
        old_action.completed_at - timedelta(seconds=30)
    )


@pytest.mark.parametrize(
    ("request_ids", "expected_error"),
    [
        ((), "missing_correlation"),
        (("first-request", "second-request"), "ambiguous_correlation"),
        (("repeated-request", "repeated-request"), "ambiguous_correlation"),
    ],
)
def test_missing_multiple_and_conflicting_action_correlations_fail_closed(
    request_ids: tuple[str, ...],
    expected_error: str,
) -> None:
    """Only one fixed AWS request ID can authorize a CloudTrail lookup."""
    suite = _suite()
    client = _CloudTrailClient([_page()])

    result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(client)[0],
            action_result=_action_result(aws_request_ids=request_ids),
        ),
    )

    assert _audit(result)["error_category"] == expected_error
    assert _audit(result)["evidence_complete"] is False
    assert client.calls == []


def test_time_only_proximity_without_aws_request_id_is_not_correlation() -> None:
    """An application correlation and nearby time do not substitute for requestID."""
    suite = _suite()
    client = _CloudTrailClient([_page(_event("nearby-event"))])

    result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(client)[0],
            action_result=_action_result(aws_request_ids=()),
        ),
    )

    assert _audit(result)["error_category"] == "missing_correlation"
    assert client.calls == []


def test_complete_lookup_with_no_events_has_no_positive_evidence() -> None:
    """A complete empty page remains missing evidence without inventing a failure."""
    suite = _suite()

    result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(_CloudTrailClient([_page()]))[0],
        ),
    )

    audit = _audit(result)
    assert audit["error_category"] is None
    assert audit["evidence_complete"] is False
    assert audit["correlated_events_found"] is False
    assert audit["event_names"] == []
    assert result.freshness.source_time is None


@pytest.mark.parametrize(
    ("case", "expected_error"),
    [
        ("source", "event_source_mismatch"),
        ("name", "event_name_mismatch"),
        ("region", "region_mismatch"),
        ("request", "correlation_unmatched"),
    ],
)
def test_wrong_fixed_event_values_are_rejected(
    case: str,
    expected_error: str,
) -> None:
    """Source, name, region, and requestID must all match exactly."""
    suite = _suite()
    event: dict[str, object] = {
        "source": _event(
            "wrong-source",
            event_source="bedrock.amazonaws.com",
        ),
        "name": _event("wrong-name", event_name="DeleteStage"),
        "region": _event("wrong-region", region="us-east-1"),
        "request": _event(
            "wrong-request",
            request_id="different-request-id",
        ),
    }[case]

    result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(_CloudTrailClient([_page(event)]))[0],
        ),
    )

    audit = _audit(result)
    assert audit["error_category"] == expected_error
    assert audit["evidence_complete"] is False
    assert audit["event_names"] == []
    assert result.freshness.source_time is None


@pytest.mark.parametrize(
    ("occurred_at", "expected_error", "flag"),
    [
        (
            _COLLECTED_AT - timedelta(minutes=6),
            "stale_event",
            "stale",
        ),
        (
            _COLLECTED_AT + timedelta(seconds=31),
            "future_event",
            "future_dated",
        ),
        (
            _COLLECTED_AT + timedelta(seconds=1),
            "event_outside_window",
            "ambiguous",
        ),
    ],
)
def test_stale_future_and_outside_window_events_fail_closed(
    occurred_at: datetime,
    expected_error: str,
    flag: str,
) -> None:
    """Freshness, future skew, and action-window checks are independent."""
    suite = _suite()

    result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(
                _CloudTrailClient(
                    [_page(_event("timing-event", occurred_at=occurred_at))],
                ),
            )[0],
        ),
    )

    audit = _audit(result)
    assert audit["error_category"] == expected_error
    assert audit[flag] is True
    assert audit["event_names"] == []


@pytest.mark.parametrize(
    "outer_time",
    ["2026-07-26T11:59:30Z", _ACTION_TIME.replace(tzinfo=None)],
)
def test_malformed_outer_event_timestamps_are_rejected(outer_time: object) -> None:
    """LookupEvents EventTime must be one timezone-aware SDK datetime."""
    suite = _suite()
    event = _event("bad-outer-time")
    event["EventTime"] = outer_time

    result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(_CloudTrailClient([_page(event)]))[0],
        ),
    )

    assert _audit(result)["error_category"] == "invalid_event"
    assert _audit(result)["malformed"] is True


def test_malformed_and_conflicting_inner_event_timestamps_are_rejected() -> None:
    """CloudTrailEvent eventTime must parse and equal the SDK outer timestamp."""
    suite = _suite()
    malformed = _event(
        "malformed-inner-time",
        inner_updates={"eventTime": "not-a-time"},
    )
    conflicting = _event(
        "conflicting-inner-time",
        inner_updates={
            "eventTime": _event_time(_ACTION_TIME + timedelta(seconds=1)),
        },
    )

    malformed_result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(_CloudTrailClient([_page(malformed)]))[0],
        ),
    )
    conflict_result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(_CloudTrailClient([_page(conflicting)]))[0],
        ),
    )

    assert _audit(malformed_result)["error_category"] == "invalid_event"
    assert _audit(conflict_result)["error_category"] == "timestamp_conflict"
    assert _audit(conflict_result)["ambiguous"] is True


@pytest.mark.parametrize(
    "payload",
    [
        "{not-json",
        (
            '{"awsRegion":"eu-west-2","eventID":"duplicate-json",'
            '"eventName":"Invoke","eventSource":"execute-api.amazonaws.com",'
            '"eventTime":"2026-07-26T11:59:30Z",'
            '"recipientAccountId":"111122223333",'
            f'"requestID":"{_REQUEST_ID}","requestID":"duplicate",'
            '"userIdentity":{"accountId":"111122223333"}}'
        ),
    ],
)
def test_malformed_json_and_duplicate_json_keys_are_rejected(payload: str) -> None:
    """CloudTrailEvent must be duplicate-free JSON before fixed-field access."""
    suite = _suite()
    event = _event("malformed-json")
    event["CloudTrailEvent"] = payload

    result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(_CloudTrailClient([_page(event)]))[0],
        ),
    )

    assert _audit(result)["error_category"] == "invalid_event"
    assert _audit(result)["malformed"] is True


@pytest.mark.parametrize(
    ("case", "expected_error"),
    [
        ("outer", "invalid_event"),
        ("request", "invalid_event"),
        ("principal", "invalid_event"),
        ("event-id", "ambiguous_correlation"),
    ],
)
def test_malformed_fixed_event_records_are_rejected(
    case: str,
    expected_error: str,
) -> None:
    """Missing or contradictory fixed records never become audit facts."""
    suite = _suite()
    events_by_case: dict[str, dict[str, object]] = {
        "outer": {"EventName": _EVENT_NAME},
        "request": _event(
            "missing-request-id",
            remove_inner=("requestID",),
        ),
        "principal": _event(
            "missing-principal-account",
            inner_updates={"userIdentity": {"type": "AssumedRole"}},
        ),
        "event-id": _event(
            "inner-id-conflict",
            inner_updates={"eventID": "different-event-id"},
        ),
    }
    event = events_by_case[case]

    result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(_CloudTrailClient([_page(event)]))[0],
        ),
    )

    assert _audit(result)["error_category"] == expected_error
    assert _audit(result)["evidence_complete"] is False


def test_duplicate_events_deduplicate_deterministically() -> None:
    """Identical EventId records normalize once regardless of response order."""
    suite = _suite()
    event = _event("duplicate-event")

    result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(
                _CloudTrailClient([_page(event, dict(event))]),
            )[0],
        ),
    )

    assert _audit(result)["accepted_correlated_events"] == 1
    assert _audit(result)["evidence_complete"] is True


def test_conflicting_duplicate_event_ids_are_ambiguous() -> None:
    """One EventId with contradictory payloads suppresses all positive facts."""
    suite = _suite()
    first = _event("conflicting-duplicate")
    second = _event(
        "conflicting-duplicate",
        inner_updates={"requestID": "other-request"},
    )

    result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(
                _CloudTrailClient([_page(second, first)]),
            )[0],
        ),
    )

    assert _audit(result)["error_category"] == "ambiguous_correlation"
    assert _audit(result)["ambiguous"] is True
    assert _audit(result)["event_names"] == []


def test_pagination_within_limits_is_deterministic() -> None:
    """Each bounded continuation is passed exactly once and then normalized."""
    suite = _suite()
    client = _CloudTrailClient(
        [
            _page(
                _event("page-zeta", event_name="ZetaAction"),
                next_token="synthetic-page-2",  # noqa: S106 - page cursor.
            ),
            _page(_event("page-alpha", event_name="AlphaAction")),
        ],
    )
    probe = _probe(suite).model_copy(
        update={"event_names": ("ZetaAction", "AlphaAction")},
    )

    result = _adapter().collect_evidence(
        _request(suite, probe=probe, identity=_identity(client)[0]),
    )

    assert _audit(result)["event_names"] == ["AlphaAction", "ZetaAction"]
    assert "NextToken" not in client.calls[0]
    assert client.calls[1]["NextToken"] == "synthetic-page-2"


def test_repeated_pagination_tokens_are_partial() -> None:
    """A repeated continuation cannot create an unbounded lookup cycle."""
    suite = _suite()
    client = _CloudTrailClient(
        [
            _page(
                _event("repeat-1"),
                next_token="repeat-token",  # noqa: S106 - page cursor.
            ),
            _page(
                _event("repeat-2"),
                next_token="repeat-token",  # noqa: S106 - page cursor.
            ),
        ],
    )

    result = _adapter().collect_evidence(
        _request(suite, identity=_identity(client)[0]),
    )

    assert _audit(result)["error_category"] == "pagination_limit_exceeded"
    assert _audit(result)["partial"] is True
    assert _audit(result)["event_names"] == []


def test_pagination_beyond_page_limit_is_partial() -> None:
    """A continuation after the fifth page suppresses otherwise valid events."""
    suite = _suite()
    pages: list[object] = [
        _page(
            _event(f"page-{index}"),
            next_token=f"page-{index + 1}",
        )
        for index in range(cloudtrail_module.MAX_CLOUDTRAIL_PAGES)
    ]
    client = _CloudTrailClient(pages)

    result = _adapter().collect_evidence(
        _request(suite, identity=_identity(client)[0]),
    )

    assert len(client.calls) == cloudtrail_module.MAX_CLOUDTRAIL_PAGES
    assert _audit(result)["error_category"] == "pagination_limit_exceeded"
    assert _audit(result)["evidence_complete"] is False


def test_oversized_individual_cloudtrail_event_is_not_parsed() -> None:
    """One payload over the fixed byte limit sets only safe size facts."""
    suite = _suite()
    event = _event("oversized-event")
    event["CloudTrailEvent"] = "x" * (cloudtrail_module.MAX_CLOUDTRAIL_EVENT_BYTES + 1)

    result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(_CloudTrailClient([_page(event)]))[0],
        ),
    )

    assert _audit(result)["error_category"] == "oversized_event"
    assert _audit(result)["oversized"] is True
    assert _audit(result)["event_names"] == []


def test_excessive_total_cloudtrail_event_bytes_are_bounded() -> None:
    """Individually valid event strings cannot exceed the aggregate byte budget."""
    suite = _suite()
    events = tuple(
        _event(
            f"large-{index}",
            inner_updates={"padding": "x" * 60_000},
        )
        for index in range(5)
    )

    result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(_CloudTrailClient([_page(*events)]))[0],
        ),
    )

    assert _audit(result)["error_category"] == "total_bytes_exceeded"
    assert _audit(result)["oversized"] is True
    assert _audit(result)["partial"] is True


def test_excessive_examined_and_correlated_event_counts_are_bounded() -> None:
    """Examined and accepted events have independent fixed detection limits."""
    suite = _suite()
    pages: list[object] = []
    next_index = 0
    for page_index in range(4):
        count = 33 if page_index < _FULL_EVENT_PAGES else 2
        events = tuple(
            _event(f"examined-{index}")
            for index in range(next_index, next_index + count)
        )
        next_index += count
        pages.append(
            _page(
                *events,
                next_token=(
                    f"examined-page-{page_index + 1}"
                    if page_index < _FULL_EVENT_PAGES
                    else None
                ),
            ),
        )
    examined_result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(_CloudTrailClient(pages))[0],
        ),
    )

    assert _audit(examined_result)["error_category"] == "event_limit_exceeded"
    assert _audit(examined_result)["partial"] is True

    correlated = tuple(
        _event(f"correlated-{index}")
        for index in range(
            cloudtrail_module.MAX_CLOUDTRAIL_CORRELATED_EVENTS + 1,
        )
    )
    correlated_result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(
                _CloudTrailClient([_page(*correlated)]),
            )[0],
        ),
    )

    assert _audit(correlated_result)["error_category"] == (
        "correlated_event_limit_exceeded"
    )
    assert _audit(correlated_result)["accepted_correlated_events"] == 0


def test_excessive_normalized_event_name_count_is_suppressed() -> None:
    """More than the fixed unique-name limit cannot enter normalized output."""
    suite = _suite()
    names = tuple(
        f"Action{index:02d}"
        for index in range(cloudtrail_module.MAX_CLOUDTRAIL_EVENT_NAMES + 1)
    )
    probe = _probe(suite).model_copy(update={"event_names": names})
    events = tuple(
        _event(f"name-{index}", event_name=name) for index, name in enumerate(names)
    )

    result = _adapter().collect_evidence(
        _request(
            suite,
            probe=probe,
            identity=_identity(_CloudTrailClient([_page(*events)]))[0],
        ),
    )

    assert _audit(result)["error_category"] == "event_name_limit_exceeded"
    assert _audit(result)["event_names"] == []


@pytest.mark.parametrize(
    "kind",
    [ObservationKind.ENCRYPTION_STATE, ObservationKind.PROVIDER_INVOCATION],
)
def test_unsupported_observations_fail_before_client_creation(
    kind: ObservationKind,
) -> None:
    """Encryption and every non-audit kind remain outside this adapter slice."""
    suite = _suite()
    probe = _probe(suite).model_copy(update={"observations": (kind,)})
    client = _CloudTrailClient([_page()])

    with pytest.raises(CloudTrailProbeError) as caught:
        _adapter().collect_evidence(
            _request(suite, probe=probe, identity=_identity(client)[0]),
        )

    assert caught.value.code is CloudTrailProbeFailureCode.UNSUPPORTED_OBSERVATION
    assert client.calls == []


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
                "LookupEvents",
            ),
            "access_denied",
        ),
        (RuntimeError(_SDK_SECRET), "sdk_error"),
    ],
)
def test_sdk_failures_are_stable_partial_and_redacted(
    error: Exception,
    expected: str,
) -> None:
    """SDK diagnostics collapse to fixed categories without exception text."""
    suite = _suite()

    result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(_CloudTrailClient([error]))[0],
        ),
    )

    audit = _audit(result)
    assert audit["error_category"] == expected
    assert audit["partial"] is True
    assert audit["event_names"] == []
    assert _SDK_SECRET not in repr(result)
    assert _SDK_SECRET not in json.dumps(audit)


@pytest.mark.parametrize(
    "response",
    [
        {},
        {"Events": [], "Unexpected": _RAW_SECRET},
        {"Events": [], "ResponseMetadata": "invalid"},
        {
            "Events": [],
            "NextToken": "x"
            * (cloudtrail_module.MAX_CLOUDTRAIL_PAGINATION_TOKEN_LENGTH + 1),
        },
    ],
)
def test_partial_sdk_pages_never_produce_complete_evidence(
    response: dict[str, object],
) -> None:
    """Missing, extended, malformed, or unbounded SDK pages are partial."""
    suite = _suite()

    result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(_CloudTrailClient([response]))[0],
        ),
    )

    assert _audit(result)["error_category"] == "partial_response"
    assert _audit(result)["partial"] is True
    assert _audit(result)["evidence_complete"] is False


@pytest.mark.parametrize(
    ("account", "partition", "expires_at", "closed"),
    [
        ("999900001111", "aws", None, False),
        (_ACCOUNT_ID, "aws-cn", None, False),
        (_ACCOUNT_ID, "aws", _COLLECTED_AT, False),
        (_ACCOUNT_ID, "aws", None, True),
    ],
)
def test_account_partition_expired_and_closed_identity_failures(
    account: str,
    partition: str,
    expires_at: datetime | None,
    closed: bool,  # noqa: FBT001 - parametrized lease state.
) -> None:
    """Every scoped identity boundary is checked before client creation."""
    suite = _suite()
    client = _CloudTrailClient([_page()])
    identity, session = _identity(
        client,
        account=account,
        partition=partition,
        expires_at=expires_at,
    )
    if closed:
        identity.close()

    result = _adapter().collect_evidence(_request(suite, identity=identity))

    assert _audit(result)["error_category"] == "identity_boundary_invalid"
    assert session.regions == []
    assert client.calls == []


def test_event_recipient_and_principal_account_mismatch_is_rejected() -> None:
    """Fixed inner account checks occur without normalizing either raw account."""
    suite = _suite()
    event = _event(
        "event-account-mismatch",
        inner_updates={
            "recipientAccountId": "999900001111",
            "userIdentity": {"accountId": "999900001111"},
        },
    )

    result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(_CloudTrailClient([_page(event)]))[0],
        ),
    )

    assert _audit(result)["error_category"] == "account_mismatch"
    assert _ACCOUNT_ID not in json.dumps(_audit(result))
    assert "999900001111" not in json.dumps(_audit(result))


def test_query_duration_limit_marks_page_partial() -> None:
    """Total collection time is bounded independently from SDK timeouts."""
    suite = _suite()
    times = iter([0.0, cloudtrail_module.MAX_CLOUDTRAIL_QUERY_SECONDS + 0.1])
    adapter = CloudTrailProbeAdapter(
        suite_max_age=timedelta(minutes=5),
        clock_skew_tolerance=timedelta(seconds=30),
        clock=lambda: _COLLECTED_AT,
        monotonic=lambda: next(times),
    )

    result = adapter.collect_evidence(
        _request(
            suite,
            identity=_identity(
                _CloudTrailClient([_page(_event("late-page"))]),
            )[0],
        ),
    )

    assert _audit(result)["error_category"] == "query_timeout"
    assert _audit(result)["partial"] is True


def test_cloudtrail_client_ignores_endpoint_overrides_and_bounds_sdk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The identity creates only a bounded regional CloudTrail SDK client."""
    monkeypatch.setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("AWS_ENDPOINT_URL_CLOUDTRAIL", "http://127.0.0.1:9")
    session = boto3.Session(
        aws_access_key_id="synthetic-source-key",
        aws_secret_access_key="synthetic-source-secret",  # noqa: S106
        aws_session_token="synthetic-source-token",  # noqa: S106
        region_name="us-east-1",
    )
    identity = AwsScopedIdentity(
        _identity_id="evidence-reader",
        _account_id=_ACCOUNT_ID,
        _partition="aws",
        _expires_at=_COLLECTED_AT + timedelta(hours=1),
        _session=cast("AwsSession", session),
    )

    client = cast(
        "Any",
        identity._cloudtrail_client(  # noqa: SLF001
            region="eu-west-2",
            evaluated_at=_COLLECTED_AT,
        ),
    )

    assert client.meta.endpoint_url == "https://cloudtrail.eu-west-2.amazonaws.com"
    assert client.meta.region_name == "eu-west-2"
    assert client.meta.config.connect_timeout == _CONNECT_TIMEOUT_SECONDS
    assert client.meta.config.read_timeout == _READ_TIMEOUT_SECONDS
    assert client.meta.config.retries["total_max_attempts"] == _MAX_ATTEMPTS
    identity.close()


def test_closed_or_expired_identity_cannot_create_cloudtrail_client() -> None:
    """The exact internal client capability enforces lease state itself."""
    expired, _ = _identity(
        _CloudTrailClient([_page()]),
        expires_at=_COLLECTED_AT,
    )
    closed, _ = _identity(_CloudTrailClient([_page()]))
    closed.close()

    with pytest.raises(RuntimeError, match="cannot create"):
        expired._cloudtrail_client(  # noqa: SLF001
            region="eu-west-2",
            evaluated_at=_COLLECTED_AT,
        )
    with pytest.raises(RuntimeError, match="cannot create"):
        closed._cloudtrail_client(  # noqa: SLF001
            region="eu-west-2",
            evaluated_at=_COLLECTED_AT,
        )


def test_raw_event_identifiers_credentials_environment_and_errors_are_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No sensitive raw event or correlation material enters ProbeResult."""
    suite = _suite()
    monkeypatch.setenv("SYNTHETIC_NEIGHBOR", "environment-secret-must-not-leak")
    event = _event(
        "sensitive-event",
        inner_updates={
            "credential": _CREDENTIAL,
            "environment": "environment-secret-must-not-leak",
            "requestParameters": {"prompt": _RAW_SECRET},
            "responseElements": {"document": _RAW_SECRET},
            "resources": [_PRINCIPAL_ARN],
            "sourceIPAddress": "192.0.2.42",
            "userAgent": _RAW_SECRET,
            "userIdentity": {
                "accountId": _ACCOUNT_ID,
                "arn": _PRINCIPAL_ARN,
                "principalId": _PRINCIPAL_ID,
            },
        },
    )
    successful = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(_CloudTrailClient([_page(event)]))[0],
            action_result=_action_result(aws_request_ids=(_REQUEST_ID,)),
        ),
    )
    failed = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(
                _CloudTrailClient([RuntimeError(_SDK_SECRET)]),
            )[0],
        ),
    )
    rendered = (
        repr(successful)
        + repr(failed)
        + json.dumps(_audit(successful))
        + json.dumps(_audit(failed))
    )

    for sensitive in (
        _RAW_SECRET,
        _ACCOUNT_ID,
        _PRINCIPAL_ARN,
        _PRINCIPAL_ID,
        _CREDENTIAL,
        _REQUEST_ID,
        _APP_CORRELATION,
        _SDK_SECRET,
        "environment-secret-must-not-leak",
        "192.0.2.42",
    ):
        assert sensitive not in rendered


def test_validated_suite_action_identity_lookup_contract_integration() -> None:
    """Validated action output correlates through the exact probe contract."""
    suite = _suite()
    scenario = suite.scenarios[0]
    action = scenario.actions[1]
    assert isinstance(action, AwsSigV4Action)
    context = ExecutionContext(
        run_id="cloudtrail-contract",
        scenario_id=scenario.id,
        target=suite.target,
    )
    action_result = AwsSigV4ActionAdapter(
        environment={},
        transport=_CorrelatedActionTransport(),
        clock=lambda: _ACTION_TIME,
    ).execute_action(
        ActionRequest(
            context=context,
            action=action,
            identity=_signing_identity(),
        ),
    )
    assert action_result.outcome is ActionOutcome.SUCCEEDED
    assert action_result.aws_request_ids == (_REQUEST_ID,)
    client = _CloudTrailClient([_page(_event("contract-event"))])
    request = ProbeRequest(
        context=context,
        probe=_probe(suite),
        action_result=action_result,
        identity=_identity(client)[0],
    )

    result = assert_evidence_probe_contract(_adapter(), request)

    assert result.probe_id == "cloud-audit"
    assert _audit(result)["evidence_complete"] is True
    assert _audit(result)["event_names"] == ["Invoke"]
    assert client.calls[0]["MaxResults"] == (
        cloudtrail_module.MAX_CLOUDTRAIL_CORRELATED_EVENTS + 1
    )


def _suite_mapping() -> dict[str, Any]:
    loaded = yaml.safe_load(_FIXTURE.read_text(encoding="utf-8"))
    return cast("dict[str, Any]", loaded)


def _suite() -> VerificationSuite:
    return VerificationSuite.model_validate(_suite_mapping())


def _probe(suite: VerificationSuite) -> CloudTrailProbe:
    probe = suite.scenarios[0].probes[1]
    assert isinstance(probe, CloudTrailProbe)
    return probe.model_copy(
        update={"observations": (ObservationKind.AUDIT_EVENT,)},
    )


def _adapter() -> CloudTrailProbeAdapter:
    return CloudTrailProbeAdapter(
        suite_max_age=timedelta(minutes=5),
        clock_skew_tolerance=timedelta(seconds=30),
        clock=lambda: _COLLECTED_AT,
    )


def _identity(
    client: _CloudTrailClient,
    *,
    account: str = _ACCOUNT_ID,
    partition: str = "aws",
    expires_at: datetime | None = None,
) -> tuple[AwsScopedIdentity, _CloudTrailSession]:
    session = _CloudTrailSession(client)
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
        aws_secret_access_key=(  # noqa: S106 - explicit synthetic value.
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
    probe: CloudTrailProbe | None = None,
    action_result: ActionExecutionResult | None = None,
    target: Target | None = None,
) -> ProbeRequest:
    selected_probe = probe or _probe(suite)
    return ProbeRequest(
        context=ExecutionContext(
            run_id="cloudtrail-contract",
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
    action_id: str = "signed-request",
    aws_request_ids: tuple[str, ...] = (_REQUEST_ID,),
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
        correlation_ids=(_APP_CORRELATION,),
        limitations=("Synthetic normalized AWS action result.",),
        aws_request_ids=aws_request_ids,
    )


def _event(  # noqa: PLR0913 - synthetic fixed fields remain explicit.
    event_id: str,
    *,
    event_name: str = _EVENT_NAME,
    event_source: str = _EVENT_SOURCE,
    region: str = "eu-west-2",
    request_id: str = _REQUEST_ID,
    occurred_at: datetime = _ACTION_TIME,
    inner_updates: Mapping[str, object] | None = None,
    remove_inner: tuple[str, ...] = (),
) -> dict[str, object]:
    inner: dict[str, object] = {
        "awsRegion": region,
        "eventID": event_id,
        "eventName": event_name,
        "eventSource": event_source,
        "eventTime": _event_time(occurred_at),
        "recipientAccountId": _ACCOUNT_ID,
        "requestID": request_id,
        "userIdentity": {
            "accountId": _ACCOUNT_ID,
            "arn": _PRINCIPAL_ARN,
            "principalId": _PRINCIPAL_ID,
            "type": "AssumedRole",
        },
    }
    if inner_updates is not None:
        inner.update(inner_updates)
    for field_name in remove_inner:
        inner.pop(field_name, None)
    return {
        "CloudTrailEvent": json.dumps(
            inner,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ),
        "EventId": event_id,
        "EventName": event_name,
        "EventSource": event_source,
        "EventTime": occurred_at,
        "ReadOnly": "true",
    }


def _page(
    *events: dict[str, object],
    next_token: str | None = None,
) -> dict[str, object]:
    page: dict[str, object] = {"Events": list(events)}
    if next_token is not None:
        page["NextToken"] = next_token
    return page


def _event_time(value: datetime) -> str:
    return (
        value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    )


def _audit(result: ProbeResult) -> dict[str, object]:
    matching = tuple(
        item
        for item in result.observations
        if item.kind == ObservationKind.AUDIT_EVENT.value
    )
    assert len(matching) == 1
    return cast("dict[str, object]", matching[0].observed.to_json_value())
