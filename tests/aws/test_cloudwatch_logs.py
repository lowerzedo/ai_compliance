"""Network-isolated tests for bounded CloudWatch Logs evidence collection."""

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

import cai_verify.aws.action as action_module
import cai_verify.aws.cloudwatch_logs as cloudwatch_module
from cai_verify.aws import (
    CLOUDWATCH_LOGS_ADAPTER_NAME,
    CLOUDWATCH_LOGS_ADAPTER_VERSION,
    AwsScopedIdentity,
    AwsSigV4ActionAdapter,
    CloudWatchLogsProbeAdapter,
    CloudWatchLogsProbeError,
    CloudWatchLogsProbeFailureCode,
)
from cai_verify.config import (
    AwsSigV4Action,
    CloudWatchLogsProbe,
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
_CANARY = "synthetic-cloudwatch-canary"
_SDK_SECRET = "sdk-error-secret-must-not-leak"  # noqa: S105
_RAW_SECRET = "raw-prompt-secret-must-not-leak"  # noqa: S105
_CREDENTIAL = "ASIASYNTHETIC000009"
_ACCOUNT_ID = "111122223333"
_PRINCIPAL_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:role/synthetic-reader"
_EXPECTED_PROVIDER_COUNT = 2
_CONNECT_TIMEOUT_SECONDS = 3
_READ_TIMEOUT_SECONDS = 5
_MAX_ATTEMPTS = 2


@dataclass(slots=True)
class _LogsClient:
    responses: list[object]
    calls: list[dict[str, object]] = field(default_factory=list)

    def filter_log_events(self, **kwargs: object) -> Mapping[str, object]:
        self.calls.append(dict(kwargs))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return cast("Mapping[str, object]", response)


@dataclass(slots=True)
class _LogsSession:
    client_value: _LogsClient
    regions: list[str] = field(default_factory=list)
    configs: list[object] = field(default_factory=list)

    def client(self, service_name: str, **kwargs: object) -> object:
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
        return action_module._AwsHttpResponse(  # noqa: SLF001
            status=200,
            correlation_id=request.header_map()["X-Cai-Correlation-Id"],
            too_large=False,
        )


def test_correlated_provider_invocation_uses_exact_query_and_contract() -> None:
    """A fixed correlated record becomes bounded, ordered provider evidence."""
    suite = _suite()
    client = _LogsClient(
        [_page(_event("event-1", provider="amazon-bedrock"))],
    )
    identity, session = _identity(client)
    adapter = _adapter()
    request = _request(suite, identity=identity)

    assert isinstance(adapter, EvidenceProbe)
    result = assert_evidence_probe_contract(adapter, request)

    provider = _observation(result, ObservationKind.PROVIDER_INVOCATION)
    assert result.source.name == CLOUDWATCH_LOGS_ADAPTER_NAME
    assert result.source.version == CLOUDWATCH_LOGS_ADAPTER_VERSION
    assert result.freshness.collected_at == _COLLECTED_AT
    assert result.freshness.source_time == _ACTION_TIME
    assert provider == {
        "accepted_correlated_records": 1,
        "ambiguous": False,
        "correlated_records_found": True,
        "error_category": None,
        "evidence_complete": True,
        "future_dated": False,
        "malformed": False,
        "oversized": False,
        "partial": False,
        "providers": ["amazon-bedrock"],
        "stale": False,
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
    ("recorded_canary", "expected"),
    [
        (_CANARY, True),
        ("different-synthetic-canary", False),
    ],
)
def test_correlated_telemetry_canary_present_and_absent(
    recorded_canary: str,
    expected: bool,  # noqa: FBT001 - parametrized expected fact.
) -> None:
    """Canary comparison reports only a boolean for complete correlated data."""
    suite = _suite()
    client = _LogsClient(
        [_page(_event("canary-1", canary=recorded_canary))],
    )

    result = _adapter().collect_evidence(
        _request(suite, identity=_identity(client)[0]),
    )

    canary = _observation(result, ObservationKind.TELEMETRY_CANARY)
    assert canary["canary_observed"] is expected
    assert canary["accepted_correlated_records"] == 1
    assert canary["evidence_complete"] is True
    assert recorded_canary not in json.dumps(canary)


def test_probe_and_suite_freshness_are_selected_deterministically() -> None:
    """A probe override wins, while omission uses the explicit suite policy."""
    suite = _suite()
    probe = _probe(suite)
    stale_action = _action_result(
        completed_at=_COLLECTED_AT - timedelta(minutes=4),
    )
    probe_client = _LogsClient([_page()])

    probe_result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(probe_client)[0],
            action_result=stale_action,
        ),
    )

    assert probe_result.freshness.max_age == timedelta(minutes=3)
    assert _provider(probe_result)["stale"] is True
    assert _provider(probe_result)["error_category"] == "stale_action"
    assert probe_client.calls == []

    suite_probe = probe.model_copy(update={"max_age": None})
    suite_client = _LogsClient([_page()])
    suite_result = _adapter().collect_evidence(
        _request(
            suite,
            probe=suite_probe,
            identity=_identity(suite_client)[0],
            action_result=stale_action,
        ),
    )

    assert suite_result.freshness.max_age == timedelta(minutes=5)
    assert _provider(suite_result)["stale"] is False
    assert len(suite_client.calls) == 1


@pytest.mark.parametrize(
    ("correlations", "expected_error"),
    [
        ((), "missing_correlation"),
        (
            ("aws-first-correlation", "aws-second-correlation"),
            "ambiguous_correlation",
        ),
    ],
)
def test_missing_or_multiple_action_correlations_fail_without_querying(
    correlations: tuple[str, ...],
    expected_error: str,
) -> None:
    """Only one normalized action correlation may authorize a log query."""
    suite = _suite()
    client = _LogsClient([_page()])

    result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(client)[0],
            action_result=_action_result(correlations=correlations),
        ),
    )

    assert client.calls == []
    for observation in result.observations:
        value = cast("dict[str, object]", observation.observed.to_json_value())
        assert value["error_category"] == expected_error
        assert value["evidence_complete"] is False
        assert value["correlated_records_found"] is False
        assert value.get("providers", []) == []
        assert value.get("canary_observed", False) is False


def test_contradictory_action_reference_is_rejected() -> None:
    """A probe cannot consume a completed result for another action."""
    suite = _suite()
    client = _LogsClient([_page()])

    with pytest.raises(CloudWatchLogsProbeError) as caught:
        _adapter().collect_evidence(
            _request(
                suite,
                identity=_identity(client)[0],
                action_result=_action_result(action_id="signed-request"),
            ),
        )

    assert caught.value.code is CloudWatchLogsProbeFailureCode.INVALID_CONFIGURATION
    assert client.calls == []


def test_missing_canary_environment_value_fails_before_querying() -> None:
    """A canary is resolved only from its probe environment reference."""
    suite = _suite()
    client = _LogsClient([_page()])
    adapter = CloudWatchLogsProbeAdapter(
        environment={"NEIGHBOR": "neighbor-value-must-not-leak"},
        suite_max_age=timedelta(minutes=5),
        clock_skew_tolerance=timedelta(seconds=30),
        clock=lambda: _COLLECTED_AT,
    )

    result = adapter.collect_evidence(
        _request(suite, identity=_identity(client)[0]),
    )

    assert _canary(result)["error_category"] == "environment_value_invalid"
    assert _canary(result)["canary_observed"] is False
    assert client.calls == []
    assert "neighbor-value-must-not-leak" not in repr(result)


def test_complete_query_with_no_matching_events_has_no_positive_evidence() -> None:
    """An empty complete page remains explicit absence, never a provider fact."""
    suite = _suite()

    result = _adapter().collect_evidence(
        _request(suite, identity=_identity(_LogsClient([_page()]))[0]),
    )

    assert result.freshness.source_time is None
    assert _provider(result)["correlated_records_found"] is False
    assert _provider(result)["providers"] == []
    assert _provider(result)["evidence_complete"] is True
    assert _canary(result)["canary_observed"] is False


@pytest.mark.parametrize(
    ("case", "expected_error", "flag"),
    [
        ("stale", "stale_event", "stale"),
        ("future", "future_event", "future_dated"),
        ("conflict", "timestamp_conflict", "malformed"),
    ],
)
def test_stale_future_and_conflicting_event_times_fail_closed(
    case: str,
    expected_error: str,
    flag: str,
) -> None:
    """Untrustworthy source times never yield a normalized provider."""
    suite = _suite()
    event = _timing_event(case)

    result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(_LogsClient([_page(event)]))[0],
        ),
    )

    provider = _provider(result)
    assert provider["error_category"] == expected_error
    assert provider[flag] is True
    assert provider["providers"] == []
    assert result.freshness.source_time is None


@pytest.mark.parametrize(
    "case",
    [
        "malformed-json",
        "missing-envelope-field",
        "malformed-time",
        "unexpected-sensitive-field",
        "unsafe-provider",
        "account-like-provider",
    ],
)
def test_malformed_structured_records_are_rejected(
    case: str,
) -> None:
    """Only the exact fixed message schema can contribute an accepted record."""
    suite = _suite()
    record = _malformed_record(case)

    result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(_LogsClient([_page(record)]))[0],
        ),
    )

    provider = _provider(result)
    assert provider["error_category"] == "invalid_event"
    assert provider["malformed"] is True
    assert provider["providers"] == []
    assert _RAW_SECRET not in json.dumps(provider)
    assert _PRINCIPAL_ARN not in json.dumps(provider)


def test_wrong_response_correlation_is_ambiguous_and_suppressed() -> None:
    """A service response with another correlation cannot become evidence."""
    suite = _suite()
    wrong = _event(
        "wrong-correlation",
        provider="amazon-bedrock",
        correlation_id="aws-other-correlation",
    )

    result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(_LogsClient([_page(wrong)]))[0],
        ),
    )

    assert _provider(result)["ambiguous"] is True
    assert _provider(result)["providers"] == []
    assert _provider(result)["error_category"] == "ambiguous_correlation"


def test_duplicate_events_deduplicate_and_providers_sort_deterministically() -> None:
    """Repeated event IDs collapse and provider ordering ignores page order."""
    suite = _suite()
    zulu = _event("provider-z", provider="zeta-provider")
    alpha_time = _ACTION_TIME - timedelta(seconds=10)
    alpha = _event(
        "provider-a",
        provider="alpha-provider",
        occurred_at=alpha_time,
    )
    duplicate = deepcopy(zulu)
    client = _LogsClient([_page(zulu, alpha, duplicate)])

    first = _adapter().collect_evidence(
        _request(suite, identity=_identity(client)[0]),
    )
    second_client = _LogsClient([_page(duplicate, alpha, zulu)])
    second = _adapter().collect_evidence(
        _request(suite, identity=_identity(second_client)[0]),
    )

    assert _provider(first) == _provider(second)
    assert _provider(first)["accepted_correlated_records"] == _EXPECTED_PROVIDER_COUNT
    assert _provider(first)["providers"] == ["alpha-provider", "zeta-provider"]
    assert first.freshness.source_time == alpha_time


def test_conflicting_duplicate_event_ids_are_ambiguous() -> None:
    """One event ID cannot describe two different source records."""
    suite = _suite()
    first = _event("conflicting-id", provider="amazon-bedrock")
    second = _event("conflicting-id", provider="different-provider")

    result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(_LogsClient([_page(first, second)]))[0],
        ),
    )

    assert _provider(result)["error_category"] == "ambiguous_correlation"
    assert _provider(result)["ambiguous"] is True
    assert _provider(result)["providers"] == []


def test_pagination_within_limit_is_complete_and_deterministic() -> None:
    """All bounded pages are consumed with the prior token and normalized once."""
    suite = _suite()
    first = _page(
        _event("page-1", provider="zeta-provider"),
        pagination_token="synthetic-page-2",  # noqa: S106 - page cursor.
    )
    second = _page(_event("page-2", provider="alpha-provider"))
    client = _LogsClient([first, second])

    result = _adapter().collect_evidence(
        _request(suite, identity=_identity(client)[0]),
    )

    assert _provider(result)["evidence_complete"] is True
    assert _provider(result)["providers"] == ["alpha-provider", "zeta-provider"]
    assert "nextToken" not in client.calls[0]
    assert client.calls[1]["nextToken"] == "synthetic-page-2"


def test_pagination_exceeding_limit_is_partial_and_suppresses_matches() -> None:
    """A continuation after the final allowed page prevents positive evidence."""
    suite = _suite()
    pages: list[object] = [
        _page(
            _event(f"page-{index}", provider="amazon-bedrock"),
            pagination_token=f"page-{index + 1}",
        )
        for index in range(cloudwatch_module.MAX_CLOUDWATCH_PAGES)
    ]
    client = _LogsClient(pages)

    result = _adapter().collect_evidence(
        _request(suite, identity=_identity(client)[0]),
    )

    provider = _provider(result)
    assert len(client.calls) == cloudwatch_module.MAX_CLOUDWATCH_PAGES
    assert provider["partial"] is True
    assert provider["evidence_complete"] is False
    assert provider["error_category"] == "pagination_limit_exceeded"
    assert provider["providers"] == []


def test_oversized_individual_message_is_rejected_without_parsing() -> None:
    """One over-limit raw message sets only safe size and completion facts."""
    suite = _suite()
    record = {
        "eventId": "oversized",
        "message": "x" * (cloudwatch_module.MAX_CLOUDWATCH_EVENT_BYTES + 1),
        "timestamp": _milliseconds(_ACTION_TIME),
    }

    result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(_LogsClient([_page(record)]))[0],
        ),
    )

    assert _provider(result)["error_category"] == "oversized_message"
    assert _provider(result)["oversized"] is True
    assert _provider(result)["providers"] == []


def test_excessive_total_message_bytes_are_rejected() -> None:
    """Many individually valid records cannot exceed the aggregate byte budget."""
    suite = _suite()
    large_value = "x" * 3500
    records = tuple(_event(f"large-{index}", canary=large_value) for index in range(40))

    result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(_LogsClient([_page(*records)]))[0],
        ),
    )

    canary = _canary(result)
    assert canary["error_category"] == "total_bytes_exceeded"
    assert canary["oversized"] is True
    assert canary["canary_observed"] is False


def test_excessive_event_and_provider_counts_are_bounded() -> None:
    """Accepted counts and unique provider output never exceed fixed limits."""
    suite = _suite()
    too_many_events = tuple(
        _event(f"event-{index}", provider="amazon-bedrock")
        for index in range(cloudwatch_module.MAX_CLOUDWATCH_EVENTS + 1)
    )
    event_result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(
                _LogsClient([_page(*too_many_events)]),
            )[0],
        ),
    )

    assert _provider(event_result)["error_category"] == "event_limit_exceeded"
    assert (
        cast("int", _provider(event_result)["accepted_correlated_records"])
        <= cloudwatch_module.MAX_CLOUDWATCH_EVENTS
    )
    assert _provider(event_result)["providers"] == []

    too_many_providers = tuple(
        _event(f"provider-{index}", provider=f"provider-{index:02d}")
        for index in range(cloudwatch_module.MAX_CLOUDWATCH_PROVIDERS + 1)
    )
    provider_result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(
                _LogsClient([_page(*too_many_providers)]),
            )[0],
        ),
    )

    assert _provider(provider_result)["error_category"] == ("provider_limit_exceeded")
    assert _provider(provider_result)["providers"] == []


def test_unsupported_observation_kind_is_rejected_before_client_creation() -> None:
    """A bypassed schema cannot expand the adapter normalization vocabulary."""
    suite = _suite()
    probe = _probe(suite).model_copy(
        update={"observations": (ObservationKind.AUDIT_EVENT,)},
    )
    client = _LogsClient([_page()])

    with pytest.raises(CloudWatchLogsProbeError) as caught:
        _adapter().collect_evidence(
            _request(suite, probe=probe, identity=_identity(client)[0]),
        )

    assert caught.value.code is (CloudWatchLogsProbeFailureCode.UNSUPPORTED_OBSERVATION)
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
                "FilterLogEvents",
            ),
            "access_denied",
        ),
    ],
)
def test_sdk_timeout_and_access_denied_are_stable_redacted_failures(
    error: Exception,
    expected: str,
) -> None:
    """SDK diagnostics collapse to fixed categories and incomplete evidence."""
    suite = _suite()

    result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(_LogsClient([error]))[0],
        ),
    )

    provider = _provider(result)
    assert provider["error_category"] == expected
    assert provider["partial"] is True
    assert provider["providers"] == []
    assert _SDK_SECRET not in repr(result)
    assert _SDK_SECRET not in json.dumps(provider)


@pytest.mark.parametrize(
    "response",
    [
        {"searchedLogStreams": []},
        {
            "events": [],
            "searchedLogStreams": [
                {
                    "logStreamName": "synthetic-stream",
                    "searchedCompletely": False,
                },
            ],
        },
    ],
)
def test_partial_sdk_responses_never_produce_complete_evidence(
    response: dict[str, object],
) -> None:
    """Missing events or an incomplete stream search is explicitly partial."""
    suite = _suite()

    result = _adapter().collect_evidence(
        _request(
            suite,
            identity=_identity(_LogsClient([response]))[0],
        ),
    )

    assert _provider(result)["error_category"] == "partial_response"
    assert _provider(result)["partial"] is True
    assert _provider(result)["evidence_complete"] is False


@pytest.mark.parametrize(
    ("account", "partition", "expires_at", "closed"),
    [
        ("999900001111", "aws", None, False),
        (_ACCOUNT_ID, "aws-cn", None, False),
        (_ACCOUNT_ID, "aws", _COLLECTED_AT, False),
        (_ACCOUNT_ID, "aws", None, True),
    ],
)
def test_account_partition_expiry_and_closed_identity_failures(
    account: str,
    partition: str,
    expires_at: datetime | None,
    closed: bool,  # noqa: FBT001 - parametrized lease state.
) -> None:
    """Every scoped-identity boundary is checked before a Logs client exists."""
    suite = _suite()
    client = _LogsClient([_page()])
    identity, session = _identity(
        client,
        account=account,
        partition=partition,
        expires_at=expires_at,
    )
    if closed:
        identity.close()

    result = _adapter().collect_evidence(
        _request(suite, identity=identity),
    )

    assert _provider(result)["error_category"] == "identity_boundary_invalid"
    assert _provider(result)["providers"] == []
    assert session.regions == []
    assert client.calls == []


def test_query_duration_limit_marks_an_otherwise_valid_page_partial() -> None:
    """Elapsed query time is bounded independently from SDK socket timeouts."""
    suite = _suite()
    times = iter([0.0, cloudwatch_module.MAX_CLOUDWATCH_QUERY_SECONDS + 0.1])
    adapter = CloudWatchLogsProbeAdapter(
        environment={"SYNTHETIC_TELEMETRY_CANARY": _CANARY},
        suite_max_age=timedelta(minutes=5),
        clock_skew_tolerance=timedelta(seconds=30),
        clock=lambda: _COLLECTED_AT,
        monotonic=lambda: next(times),
    )

    result = adapter.collect_evidence(
        _request(
            suite,
            identity=_identity(
                _LogsClient([_page(_event("late", provider="amazon-bedrock"))]),
            )[0],
        ),
    )

    assert _provider(result)["error_category"] == "query_timeout"
    assert _provider(result)["partial"] is True
    assert _provider(result)["providers"] == []


def test_cloudwatch_client_ignores_endpoint_overrides_and_bounds_sdk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The identity creates only a bounded regional Logs SDK client."""
    monkeypatch.setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("AWS_ENDPOINT_URL_LOGS", "http://127.0.0.1:9")
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
        identity._cloudwatch_logs_client(  # noqa: SLF001
            region="eu-west-2",
            evaluated_at=_COLLECTED_AT,
        ),
    )

    assert client.meta.endpoint_url == "https://logs.eu-west-2.amazonaws.com"
    assert client.meta.region_name == "eu-west-2"
    assert client.meta.config.connect_timeout == _CONNECT_TIMEOUT_SECONDS
    assert client.meta.config.read_timeout == _READ_TIMEOUT_SECONDS
    assert client.meta.config.retries["total_max_attempts"] == _MAX_ATTEMPTS
    identity.close()


def test_closed_or_expired_identity_cannot_create_logs_client() -> None:
    """The internal client capability independently enforces lease lifetime."""
    active, _ = _identity(
        _LogsClient([_page()]),
        expires_at=_COLLECTED_AT,
    )
    closed, _ = _identity(_LogsClient([_page()]))
    closed.close()

    with pytest.raises(RuntimeError, match="cannot create"):
        active._cloudwatch_logs_client(  # noqa: SLF001
            region="eu-west-2",
            evaluated_at=_COLLECTED_AT,
        )
    with pytest.raises(RuntimeError, match="cannot create"):
        closed._cloudwatch_logs_client(  # noqa: SLF001
            region="eu-west-2",
            evaluated_at=_COLLECTED_AT,
        )


def test_raw_canary_credentials_environment_and_sdk_values_are_redacted() -> None:
    """Every sensitive source value is absent from normalized serialization."""
    suite = _suite()
    malformed = _raw_event(
        "sensitive-source",
        {
            "canary": _CANARY,
            "correlationId": "aws-synthetic-correlation",
            "credential": _CREDENTIAL,
            "environment": "synthetic-environment-secret",
            "eventKind": "telemetryCanary",
            "eventTime": _event_time(_ACTION_TIME),
            "principal": _PRINCIPAL_ARN,
            "prompt": _RAW_SECRET,
            "schemaVersion": "1",
        },
    )
    adapter = CloudWatchLogsProbeAdapter(
        environment={
            "SYNTHETIC_TELEMETRY_CANARY": _CANARY,
            "NEIGHBOR": "synthetic-environment-secret",
        },
        suite_max_age=timedelta(minutes=5),
        clock_skew_tolerance=timedelta(seconds=30),
        clock=lambda: _COLLECTED_AT,
    )
    malformed_result = adapter.collect_evidence(
        _request(
            suite,
            identity=_identity(_LogsClient([_page(malformed)]))[0],
        ),
    )
    sdk_result = adapter.collect_evidence(
        _request(
            suite,
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
        _RAW_SECRET,
        _CANARY,
        _CREDENTIAL,
        "synthetic-environment-secret",
        _ACCOUNT_ID,
        _PRINCIPAL_ARN,
        _SDK_SECRET,
    ):
        assert sensitive not in rendered


def test_validated_sigv4_action_to_scoped_identity_contract_integration() -> None:
    """Validated AWS inputs flow through the plugin contract to safe evidence."""
    mapping = _suite_mapping()
    scenario = mapping["scenarios"][0]
    scenario["probes"][0]["actionRef"] = "signed-request"
    scenario["assertions"][2]["actionRef"] = "signed-request"
    suite = VerificationSuite.model_validate(mapping)
    action = suite.scenarios[0].actions[1]
    assert isinstance(action, AwsSigV4Action)
    context = ExecutionContext(
        run_id="cloudwatch-contract",
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
    client = _LogsClient(
        [
            _page(
                _event(
                    "provider",
                    provider="amazon-bedrock",
                    correlation_id=correlation_id,
                ),
                _event(
                    "canary",
                    canary=_CANARY,
                    correlation_id=correlation_id,
                ),
            ),
        ],
    )
    request = _request(
        suite,
        identity=_identity(client)[0],
        action_result=action_result,
    )

    result = assert_evidence_probe_contract(_adapter(), request)

    assert _provider(result)["providers"] == ["amazon-bedrock"]
    assert _canary(result)["canary_observed"] is True
    assert result.probe_id == "application-telemetry"
    assert client.calls[0]["logGroupName"] == ("/aws/cai-verify/synthetic-assistant")


def _suite_mapping() -> dict[str, Any]:
    loaded = yaml.safe_load(_FIXTURE.read_text(encoding="utf-8"))
    return cast("dict[str, Any]", loaded)


def _suite() -> VerificationSuite:
    return VerificationSuite.model_validate(_suite_mapping())


def _probe(suite: VerificationSuite) -> CloudWatchLogsProbe:
    probe = suite.scenarios[0].probes[0]
    assert isinstance(probe, CloudWatchLogsProbe)
    return probe


def _adapter() -> CloudWatchLogsProbeAdapter:
    return CloudWatchLogsProbeAdapter(
        environment={"SYNTHETIC_TELEMETRY_CANARY": _CANARY},
        suite_max_age=timedelta(minutes=5),
        clock_skew_tolerance=timedelta(seconds=30),
        clock=lambda: _COLLECTED_AT,
    )


def _identity(
    client: _LogsClient,
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
    probe: CloudWatchLogsProbe | None = None,
    identity: AwsScopedIdentity,
    action_result: ActionExecutionResult | None = None,
    target: Target | None = None,
) -> ProbeRequest:
    selected_probe = probe or _probe(suite)
    return ProbeRequest(
        context=ExecutionContext(
            run_id="cloudwatch-contract",
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


def _timing_event(case: str) -> dict[str, object]:
    if case == "stale":
        return _event(
            "stale",
            provider="amazon-bedrock",
            occurred_at=_COLLECTED_AT - timedelta(minutes=4),
        )
    if case == "future":
        return _event(
            "future",
            provider="amazon-bedrock",
            occurred_at=_COLLECTED_AT + timedelta(seconds=31),
        )
    if case == "conflict":
        return _event(
            "conflict",
            provider="amazon-bedrock",
            occurred_at=_ACTION_TIME,
            cloudwatch_time=_ACTION_TIME + timedelta(seconds=31),
        )
    raise AssertionError


def _malformed_record(case: str) -> dict[str, object]:
    if case == "malformed-json":
        return {
            "eventId": "malformed-json",
            "message": "{not-json",
            "timestamp": _milliseconds(_ACTION_TIME),
        }
    if case == "missing-envelope-field":
        return {
            "message": "{}",
            "timestamp": _milliseconds(_ACTION_TIME),
        }
    if case == "malformed-time":
        return _raw_event(
            case,
            {
                "correlationId": "aws-synthetic-correlation",
                "eventKind": "providerInvocation",
                "eventTime": "not-a-time",
                "providerId": "amazon-bedrock",
                "schemaVersion": "1",
            },
        )
    if case == "unexpected-sensitive-field":
        return _raw_event(
            case,
            {
                "correlationId": "aws-synthetic-correlation",
                "eventKind": "providerInvocation",
                "eventTime": _event_time(_ACTION_TIME),
                "prompt": _RAW_SECRET,
                "providerId": "amazon-bedrock",
                "schemaVersion": "1",
            },
        )
    if case == "unsafe-provider":
        return _event(case, provider=_PRINCIPAL_ARN)
    if case == "account-like-provider":
        return _event(case, provider=f"provider-{_ACCOUNT_ID}")
    raise AssertionError


def _event(  # noqa: PLR0913 - synthetic fixed fields are explicit.
    event_id: str,
    *,
    provider: str | None = None,
    canary: str | None = None,
    correlation_id: str = "aws-synthetic-correlation",
    occurred_at: datetime = _ACTION_TIME,
    cloudwatch_time: datetime | None = None,
) -> dict[str, object]:
    if provider is not None and canary is not None:
        raise ValueError
    if provider is not None:
        message: dict[str, object] = {
            "correlationId": correlation_id,
            "eventKind": "providerInvocation",
            "eventTime": _event_time(occurred_at),
            "providerId": provider,
            "schemaVersion": "1",
        }
    else:
        message = {
            "canary": canary or "different-synthetic-canary",
            "correlationId": correlation_id,
            "eventKind": "telemetryCanary",
            "eventTime": _event_time(occurred_at),
            "schemaVersion": "1",
        }
    return _raw_event(
        event_id,
        message,
        cloudwatch_time=cloudwatch_time or occurred_at,
    )


def _raw_event(
    event_id: str,
    message: dict[str, object],
    *,
    cloudwatch_time: datetime = _ACTION_TIME,
) -> dict[str, object]:
    return {
        "eventId": event_id,
        "logStreamName": "synthetic-stream",
        "message": json.dumps(
            message,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ),
        "timestamp": _milliseconds(cloudwatch_time),
    }


def _page(
    *events: dict[str, object],
    pagination_token: str | None = None,
) -> dict[str, object]:
    page: dict[str, object] = {
        "events": list(events),
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


def _observation(
    result: ProbeResult,
    kind: ObservationKind,
) -> dict[str, object]:
    matching = tuple(item for item in result.observations if item.kind == kind.value)
    assert len(matching) == 1
    return cast("dict[str, object]", matching[0].observed.to_json_value())


def _provider(result: ProbeResult) -> dict[str, object]:
    return _observation(result, ObservationKind.PROVIDER_INVOCATION)


def _canary(result: ProbeResult) -> dict[str, object]:
    return _observation(result, ObservationKind.TELEMETRY_CANARY)


def _result_values(result: ProbeResult) -> list[object]:
    return [item.observed.to_json_value() for item in result.observations]
