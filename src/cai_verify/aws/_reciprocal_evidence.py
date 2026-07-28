"""Fixed serializers for the reciprocal AWS retrieval evidence contract."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, cast

from cai_verify.aws.action import AwsActionFailureCode
from cai_verify.aws.cloudwatch_logs import (
    CLOUDWATCH_LOGS_ADAPTER_NAME,
    CLOUDWATCH_LOGS_ADAPTER_VERSION,
    CloudWatchLogsProbeFailureCode,
)
from cai_verify.config.models import ObservationKind
from cai_verify.core import AssertionStatus
from cai_verify.plugins import (
    ActionExecutionResult,
    ActionOutcome,
    Observation,
    ProbeResult,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cai_verify.core import JsonValue

AWS_RECIPROCAL_EVIDENCE_SCHEMA_VERSION = "1"
AWS_RECIPROCAL_BUNDLE_KIND = "aws-reciprocal-retrieval-boundary"

_ACTION_ARTIFACT_KIND = "aws-retrieval-action"
_PROBE_ARTIFACT_KIND = "aws-retrieval-probe"
_ACTION_FIELDS = frozenset(
    {
        "correlation_state",
        "http_status",
        "response_too_large",
        "service",
        "signing_region",
    }
)
_ACTION_FIELDS_WITH_ERROR = _ACTION_FIELDS | {"error"}
_CORRELATION_STATES = frozenset(
    {"MATCHED", "MISMATCHED", "NOT_CHECKED", "NOT_RETURNED"}
)
_RETRIEVAL_FIELDS = frozenset(
    {
        "accepted_correlated_records",
        "ambiguous",
        "baseline_canary_observed",
        "boundary_canary_observed",
        "complete_context_scan_succeeded",
        "complete_correlated_retrieval_record_found",
        "error_category",
        "evidence_complete",
        "future_dated",
        "malformed",
        "oversized",
        "partial",
        "pre_generation_phase_matched",
        "retrieval_succeeded",
        "retrieved_item_count",
        "stale",
        "undeclared_synthetic_marker_observed",
    }
)
_RETRIEVAL_STATE_FIELDS = (
    "ambiguous",
    "future_dated",
    "malformed",
    "oversized",
    "partial",
    "stale",
)
_RETRIEVAL_NULLABLE_BOOLEAN_FIELDS = (
    "baseline_canary_observed",
    "boundary_canary_observed",
    "complete_context_scan_succeeded",
    "pre_generation_phase_matched",
    "retrieval_succeeded",
    "undeclared_synthetic_marker_observed",
)
_ACTION_ERROR_CATEGORIES = frozenset(item.value for item in AwsActionFailureCode)
_PRE_RESPONSE_ACTION_ERRORS = frozenset(
    {
        AwsActionFailureCode.ENVIRONMENT_VALUE_INVALID.value,
        AwsActionFailureCode.IDENTITY_BOUNDARY_INVALID.value,
        AwsActionFailureCode.INVALID_CONFIGURATION.value,
        AwsActionFailureCode.INVALID_RESPONSE.value,
        AwsActionFailureCode.REQUEST_TOO_LARGE.value,
        AwsActionFailureCode.RESERVED_HEADER.value,
        AwsActionFailureCode.SIGNING_ERROR.value,
        AwsActionFailureCode.TRANSPORT_ERROR.value,
    }
)
_RESPONSE_CORRELATION_STATES = frozenset({"MATCHED", "MISMATCHED", "NOT_RETURNED"})
_NON_MISMATCHED_RESPONSE_STATES = frozenset({"MATCHED", "NOT_RETURNED"})
_PROBE_ERROR_CATEGORIES = frozenset(
    item.value for item in CloudWatchLogsProbeFailureCode
)
_AMBIGUOUS_PROBE_ERRORS = frozenset(
    {
        CloudWatchLogsProbeFailureCode.AMBIGUOUS_CORRELATION.value,
        CloudWatchLogsProbeFailureCode.EVENT_OUTSIDE_WINDOW.value,
        CloudWatchLogsProbeFailureCode.INVOCATION_LIMIT_EXCEEDED.value,
        CloudWatchLogsProbeFailureCode.MODEL_MISMATCH.value,
        CloudWatchLogsProbeFailureCode.PROVIDER_MISMATCH.value,
        CloudWatchLogsProbeFailureCode.REGION_MISMATCH.value,
        CloudWatchLogsProbeFailureCode.RETRIEVAL_LIMIT_EXCEEDED.value,
        CloudWatchLogsProbeFailureCode.TIMESTAMP_CONFLICT.value,
    }
)
_FUTURE_PROBE_ERRORS = frozenset(
    {
        CloudWatchLogsProbeFailureCode.FUTURE_ACTION.value,
        CloudWatchLogsProbeFailureCode.FUTURE_EVENT.value,
    }
)
_MALFORMED_PROBE_ERRORS = frozenset(
    {
        CloudWatchLogsProbeFailureCode.INVALID_EVENT.value,
        CloudWatchLogsProbeFailureCode.TIMESTAMP_CONFLICT.value,
    }
)
_OVERSIZED_PROBE_ERRORS = frozenset(
    {
        CloudWatchLogsProbeFailureCode.OVERSIZED_MESSAGE.value,
        CloudWatchLogsProbeFailureCode.CANARY_VALUE_LIMIT_EXCEEDED.value,
        CloudWatchLogsProbeFailureCode.MARKER_SIZE_EXCEEDED.value,
        CloudWatchLogsProbeFailureCode.MARKER_TOTAL_BYTES_EXCEEDED.value,
        CloudWatchLogsProbeFailureCode.TOTAL_BYTES_EXCEEDED.value,
    }
)
_PARTIAL_PROBE_ERRORS = frozenset(
    {
        CloudWatchLogsProbeFailureCode.ACCESS_DENIED.value,
        CloudWatchLogsProbeFailureCode.EVENT_LIMIT_EXCEEDED.value,
        CloudWatchLogsProbeFailureCode.INVOCATION_LIMIT_EXCEEDED.value,
        CloudWatchLogsProbeFailureCode.MARKER_LIMIT_EXCEEDED.value,
        CloudWatchLogsProbeFailureCode.MARKER_SIZE_EXCEEDED.value,
        CloudWatchLogsProbeFailureCode.MARKER_TOTAL_BYTES_EXCEEDED.value,
        CloudWatchLogsProbeFailureCode.PAGINATION_LIMIT_EXCEEDED.value,
        CloudWatchLogsProbeFailureCode.PARTIAL_RESPONSE.value,
        CloudWatchLogsProbeFailureCode.PROVIDER_LIMIT_EXCEEDED.value,
        CloudWatchLogsProbeFailureCode.QUERY_TIMEOUT.value,
        CloudWatchLogsProbeFailureCode.QUERY_WINDOW_EXCEEDED.value,
        CloudWatchLogsProbeFailureCode.RETRIEVAL_LIMIT_EXCEEDED.value,
        CloudWatchLogsProbeFailureCode.RETRIEVED_ITEM_LIMIT_EXCEEDED.value,
        CloudWatchLogsProbeFailureCode.SDK_ERROR.value,
        CloudWatchLogsProbeFailureCode.SDK_TIMEOUT.value,
        CloudWatchLogsProbeFailureCode.SDK_UNAVAILABLE.value,
        CloudWatchLogsProbeFailureCode.THROTTLED.value,
        CloudWatchLogsProbeFailureCode.TOTAL_BYTES_EXCEEDED.value,
    }
)
_STALE_PROBE_ERRORS = frozenset(
    {
        CloudWatchLogsProbeFailureCode.STALE_ACTION.value,
        CloudWatchLogsProbeFailureCode.STALE_EVENT.value,
    }
)
_MAX_RETRIEVED_ITEMS = 10_000
_MAX_PROBE_AGE = timedelta(hours=24)
_HTTP_STATUS_MIN = 100
_HTTP_STATUS_MAX = 599
_HTTP_SUCCESS_MIN = 200
_HTTP_SUCCESS_MAX = 300
_ACTION_SERIALIZER_LIMITATIONS = (
    "Application correlations and AWS request identifiers are transient and "
    "excluded from stored evidence.",
    "The artifact represents one bounded non-mutating execute-api request and "
    "does not establish broader authorization or compliance.",
)
_PROBE_SERIALIZER_LIMITATIONS = (
    "Only fixed normalized retrieval facts are stored; CloudWatch messages, "
    "event identifiers, pages, canary values, and source containers are excluded.",
    "Retrieval facts are application-reported and unsigned; compromised "
    "instrumentation can report false facts.",
)
_EXPECTED_ACTION_RESULT_LIMITATIONS = tuple(
    sorted(
        (
            "Request and response bodies, credentials, and signing headers are "
            "excluded from normalized evidence.",
            "The result reports one bounded application response; it does not "
            "establish service permission coverage or compliance.",
        )
    )
)
_EXPECTED_RETRIEVAL_OBSERVATION_LIMITATIONS = tuple(
    sorted(
        (
            "Collection is limited to one declared log group and a fixed synthetic "
            "application log schema.",
            "Bedrock facts come from correlated post-invocation application telemetry; "
            "the target application can still emit false telemetry.",
            "Normalized evidence excludes raw messages, model identifiers, canary "
            "values, credentials, account and principal identifiers, and SDK "
            "diagnostics.",
            "The probe reports bounded telemetry facts and does not decide compliance.",
            "Retrieval facts come from application-reported telemetry; a compromised "
            "or incorrectly instrumented target can emit false records.",
            "PRE_GENERATION describes application record timing and is not "
            "cryptographically proven.",
            "Model output, refusal, or absence of output cannot prove retrieval "
            "isolation.",
        )
    )
)


class InvalidAwsReciprocalEvidenceError(ValueError):
    """A normalized input is outside the exact built-in evidence contract."""

    def __init__(self) -> None:
        """Use one fixed message without input values."""
        super().__init__("invalid normalized AWS reciprocal retrieval evidence")


def serialize_aws_retrieval_action(
    result: ActionExecutionResult,
    *,
    expected_action_id: str,
    expected_region: str,
) -> bytes:
    """Validate and serialize one exact built-in SigV4 retrieval result."""
    if (
        type(result) is not ActionExecutionResult
        or result.action_id != (expected_action_id)
        or result.limitations != _EXPECTED_ACTION_RESULT_LIMITATIONS
    ):
        raise InvalidAwsReciprocalEvidenceError
    observed = result.observed.to_json_value()
    if not isinstance(observed, dict) or (
        set(observed) != _ACTION_FIELDS and set(observed) != _ACTION_FIELDS_WITH_ERROR
    ):
        raise InvalidAwsReciprocalEvidenceError
    correlation_state = observed["correlation_state"]
    http_status = observed["http_status"]
    response_too_large = observed["response_too_large"]
    service = observed["service"]
    signing_region = observed["signing_region"]
    error = observed.get("error")
    if (
        type(correlation_state) is not str
        or correlation_state not in _CORRELATION_STATES
        or (
            http_status is not None
            and (
                type(http_status) is not int
                or not _HTTP_STATUS_MIN <= http_status <= _HTTP_STATUS_MAX
            )
        )
        or type(response_too_large) is not bool
        or service != "execute-api"
        or signing_region != expected_region
        or ("error" in observed and error is None)
        or (
            error is not None
            and (type(error) is not str or error not in _ACTION_ERROR_CATEGORIES)
        )
    ):
        raise InvalidAwsReciprocalEvidenceError
    correlation_established = (
        isinstance(result.correlation_ids, tuple) and len(result.correlation_ids) == 1
    )
    if correlation_established != (correlation_state == "MATCHED"):
        raise InvalidAwsReciprocalEvidenceError
    if not _valid_action_shape(
        outcome=result.outcome,
        correlation_state=correlation_state,
        http_status=http_status,
        response_too_large=response_too_large,
        error=error,
    ):
        raise InvalidAwsReciprocalEvidenceError

    return _json_bytes(
        {
            "action_id": result.action_id,
            "application_correlation_established": correlation_established,
            "artifact_kind": _ACTION_ARTIFACT_KIND,
            "completed_at": _timestamp(result.completed_at),
            "correlation_state": correlation_state,
            "error_category": error,
            "evidence_id": f"action.{result.action_id}",
            "http_status": http_status,
            "limitations": list(_ACTION_SERIALIZER_LIMITATIONS),
            "outcome": result.outcome.value,
            "response_too_large": response_too_large,
            "schema_version": AWS_RECIPROCAL_EVIDENCE_SCHEMA_VERSION,
            "service": service,
            "signing_region": signing_region,
            "started_at": _timestamp(result.started_at),
        }
    )


def serialize_aws_retrieval_probe(
    result: ProbeResult,
    *,
    expected_probe_id: str,
    expected_max_age: timedelta,
    clock_skew_tolerance: timedelta,
) -> bytes:
    """Validate and serialize one exact CloudWatch retrieval observation."""
    if (
        type(result) is not ProbeResult
        or result.probe_id != expected_probe_id
        or result.source.name != CLOUDWATCH_LOGS_ADAPTER_NAME
        or result.source.version != CLOUDWATCH_LOGS_ADAPTER_VERSION
        or len(result.observations) != 1
        or type(result.observations[0]) is not Observation
    ):
        raise InvalidAwsReciprocalEvidenceError
    observation = result.observations[0]
    expected_observation_id = f"{expected_probe_id}.retrieval-canary"
    if (
        observation.kind != ObservationKind.RETRIEVAL_CANARY.value
        or observation.observation_id != expected_observation_id
        or observation.limitations != _EXPECTED_RETRIEVAL_OBSERVATION_LIMITATIONS
    ):
        raise InvalidAwsReciprocalEvidenceError
    retrieval = _validated_retrieval_fields(observation.observed.to_json_value())
    maximum_age_seconds = _maximum_age_seconds(result.freshness.max_age)
    if _maximum_age_seconds(expected_max_age) != maximum_age_seconds or not isinstance(
        clock_skew_tolerance, timedelta
    ):
        raise InvalidAwsReciprocalEvidenceError
    skew_seconds = clock_skew_tolerance.total_seconds()
    if (
        not skew_seconds.is_integer()
        or not 0 <= skew_seconds <= timedelta(minutes=5).total_seconds()
    ):
        raise InvalidAwsReciprocalEvidenceError
    collected_at = result.freshness.collected_at
    source_time = result.freshness.source_time
    if bool(retrieval["evidence_complete"]) != (source_time is not None):
        raise InvalidAwsReciprocalEvidenceError
    if source_time is not None and not (
        collected_at - expected_max_age
        <= source_time
        <= collected_at + clock_skew_tolerance
    ):
        raise InvalidAwsReciprocalEvidenceError

    return _json_bytes(
        {
            "adapter_name": CLOUDWATCH_LOGS_ADAPTER_NAME,
            "adapter_version": CLOUDWATCH_LOGS_ADAPTER_VERSION,
            "artifact_kind": _PROBE_ARTIFACT_KIND,
            "collected_at": _timestamp(collected_at),
            "limitations": list(_PROBE_SERIALIZER_LIMITATIONS),
            "maximum_age_seconds": maximum_age_seconds,
            "observation": {
                "kind": ObservationKind.RETRIEVAL_CANARY.value,
                "observation_id": observation.observation_id,
                "retrieval": retrieval,
            },
            "probe_id": result.probe_id,
            "schema_version": AWS_RECIPROCAL_EVIDENCE_SCHEMA_VERSION,
            "source_time": _timestamp(source_time) if source_time is not None else None,
        }
    )


def serialize_aws_reciprocal_run(  # noqa: PLR0913 - fixed schema fields are explicit.
    *,
    run_id: str,
    scenario_id: str,
    action_ids: Sequence[str],
    probe_ids: Sequence[str],
    assertion_ids: Sequence[str],
    aggregate_status: AssertionStatus,
    target_id: str,
    target_environment: str,
    target_region: str,
) -> bytes:
    """Serialize only the allowlisted reciprocal run metadata."""
    if not isinstance(aggregate_status, AssertionStatus):
        raise InvalidAwsReciprocalEvidenceError
    return _json_bytes(
        {
            "action_ids": sorted(action_ids),
            "aggregate_status": aggregate_status.value,
            "assertion_ids": sorted(assertion_ids),
            "bundle_kind": AWS_RECIPROCAL_BUNDLE_KIND,
            "evidence_schema_version": AWS_RECIPROCAL_EVIDENCE_SCHEMA_VERSION,
            "probe_ids": sorted(probe_ids),
            "run_id": run_id,
            "scenario_id": scenario_id,
            "target_environment": target_environment,
            "target_pseudonym_sha256": hashlib.sha256(target_id.encode()).hexdigest(),
            "target_region": target_region,
        }
    )


def _valid_action_shape(  # noqa: PLR0911 - exact adapter states stay explicit.
    *,
    outcome: ActionOutcome,
    correlation_state: str,
    http_status: int | None,
    response_too_large: bool,
    error: object,
) -> bool:
    if error is None:
        if outcome is ActionOutcome.SUCCEEDED:
            return (
                type(http_status) is int
                and _HTTP_SUCCESS_MIN <= http_status < _HTTP_SUCCESS_MAX
                and not response_too_large
                and correlation_state in _NON_MISMATCHED_RESPONSE_STATES
            )
        if outcome is ActionOutcome.DENIED:
            return (
                http_status in {401, 403}
                and not response_too_large
                and correlation_state in _NON_MISMATCHED_RESPONSE_STATES
            )
        return False
    if outcome is not ActionOutcome.ERROR or not isinstance(error, str):
        return False
    if error in _PRE_RESPONSE_ACTION_ERRORS:
        return (
            http_status is None
            and not response_too_large
            and correlation_state == "NOT_CHECKED"
        )
    if error == AwsActionFailureCode.RESPONSE_TOO_LARGE.value:
        return (
            type(http_status) is int
            and response_too_large
            and correlation_state in _RESPONSE_CORRELATION_STATES
        )
    if error == AwsActionFailureCode.INVALID_CORRELATION.value:
        return (
            type(http_status) is int
            and not response_too_large
            and correlation_state == "MISMATCHED"
        )
    if error == AwsActionFailureCode.UNEXPECTED_HTTP_STATUS.value:
        return (
            type(http_status) is int
            and not _HTTP_SUCCESS_MIN <= http_status < _HTTP_SUCCESS_MAX
            and http_status not in {401, 403}
            and not response_too_large
            and correlation_state in _NON_MISMATCHED_RESPONSE_STATES
        )
    return False


def _validated_retrieval_fields(value: JsonValue) -> dict[str, JsonValue]:
    if not isinstance(value, dict) or set(value) != _RETRIEVAL_FIELDS:
        raise InvalidAwsReciprocalEvidenceError
    accepted = value["accepted_correlated_records"]
    complete_record = value["complete_correlated_retrieval_record_found"]
    evidence_complete = value["evidence_complete"]
    error_category = value["error_category"]
    if (
        type(accepted) is not int
        or accepted not in {0, 1}
        or type(complete_record) is not bool
        or type(evidence_complete) is not bool
        or any(
            type(value[field_name]) is not bool
            for field_name in _RETRIEVAL_STATE_FIELDS
        )
        or any(
            value[field_name] is not None and type(value[field_name]) is not bool
            for field_name in _RETRIEVAL_NULLABLE_BOOLEAN_FIELDS
        )
        or (
            error_category is not None
            and (
                type(error_category) is not str
                or error_category not in _PROBE_ERROR_CATEGORIES
            )
        )
    ):
        raise InvalidAwsReciprocalEvidenceError
    item_count = value["retrieved_item_count"]
    if item_count is not None and (
        type(item_count) is not int or not 0 <= item_count <= _MAX_RETRIEVED_ITEMS
    ):
        raise InvalidAwsReciprocalEvidenceError

    state_flags = tuple(
        cast("bool", value[field_name]) for field_name in _RETRIEVAL_STATE_FIELDS
    )
    nullable_values = tuple(
        value[field_name] for field_name in _RETRIEVAL_NULLABLE_BOOLEAN_FIELDS
    )
    if evidence_complete:
        if (
            accepted != 1
            or complete_record is not True
            or any(state_flags)
            or error_category is not None
            or any(item is None for item in nullable_values)
            or item_count is None
            or value["complete_context_scan_succeeded"] is not True
            or value["pre_generation_phase_matched"] is not True
            or value["retrieval_succeeded"] is not True
        ):
            raise InvalidAwsReciprocalEvidenceError
    elif (
        accepted != 0
        or complete_record is not False
        or error_category is None
        or any(item is not None for item in nullable_values)
        or item_count is not None
    ):
        raise InvalidAwsReciprocalEvidenceError
    required_flags = (
        (error_category in _AMBIGUOUS_PROBE_ERRORS, value["ambiguous"]),
        (error_category in _FUTURE_PROBE_ERRORS, value["future_dated"]),
        (error_category in _MALFORMED_PROBE_ERRORS, value["malformed"]),
        (error_category in _OVERSIZED_PROBE_ERRORS, value["oversized"]),
        (error_category in _PARTIAL_PROBE_ERRORS, value["partial"]),
        (error_category in _STALE_PROBE_ERRORS, value["stale"]),
    )
    if any(required and flag is not True for required, flag in required_flags):
        raise InvalidAwsReciprocalEvidenceError
    if (
        evidence_complete
        and item_count == 0
        and any(
            value[field_name] is True
            for field_name in (
                "baseline_canary_observed",
                "boundary_canary_observed",
                "undeclared_synthetic_marker_observed",
            )
        )
    ):
        raise InvalidAwsReciprocalEvidenceError
    return dict(value)


def _maximum_age_seconds(value: timedelta) -> int:
    if not isinstance(value, timedelta):
        raise InvalidAwsReciprocalEvidenceError
    seconds = value.total_seconds()
    if not seconds.is_integer() or not 1 <= seconds <= _MAX_PROBE_AGE.total_seconds():
        raise InvalidAwsReciprocalEvidenceError
    return int(seconds)


def _timestamp(value: datetime) -> str:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise InvalidAwsReciprocalEvidenceError
    return (
        value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    )


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
