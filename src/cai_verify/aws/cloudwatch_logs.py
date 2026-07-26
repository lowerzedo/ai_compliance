"""Bounded, correlated CloudWatch Logs evidence collection."""

from __future__ import annotations

import hmac
import json
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, cast, final

from cai_verify.aws.identity import (
    AwsScopedIdentity,
    _AwsCloudWatchLogsClient,
    _AwsSdkUnavailableError,
    _partition_for_region,
)
from cai_verify.config import CloudWatchLogsProbe, EnvironmentReference
from cai_verify.config.models import ObservationKind
from cai_verify.core import JsonValue, RedactedValue
from cai_verify.plugins import (
    PLUGIN_API_VERSION,
    EvidenceFreshness,
    EvidenceSource,
    Observation,
    PluginMetadata,
    ProbeRequest,
    ProbeResult,
)

if TYPE_CHECKING:
    from collections.abc import Callable

CLOUDWATCH_LOGS_ADAPTER_NAME = "aws-cloudwatch-logs"
CLOUDWATCH_LOGS_ADAPTER_VERSION = "1.0.0"
MAX_CLOUDWATCH_QUERY_SECONDS = 15.0
MAX_CLOUDWATCH_PAGES = 5
MAX_CLOUDWATCH_EVENTS = 100
MAX_CLOUDWATCH_EVENT_BYTES = 4 * 1024
MAX_CLOUDWATCH_TOTAL_BYTES = 128 * 1024
MAX_CLOUDWATCH_PROVIDERS = 32

_MAX_FRESHNESS = timedelta(hours=24)
_MAX_CLOCK_SKEW = timedelta(minutes=5)
_MAX_EVENT_ID_LENGTH = 512
_MAX_PAGINATION_TOKEN_LENGTH = 8192
_SECONDS_PER_MINUTE = 60
_STRUCTURED_LOG_VERSION = "1"
_SUPPORTED_OBSERVATIONS = frozenset(
    {
        ObservationKind.PROVIDER_INVOCATION,
        ObservationKind.TELEMETRY_CANARY,
    },
)
_EVENT_FIELDS = frozenset(
    {
        "eventId",
        "ingestionTime",
        "logStreamName",
        "message",
        "timestamp",
    },
)
_PROVIDER_FIELDS = frozenset(
    {
        "correlationId",
        "eventKind",
        "eventTime",
        "providerId",
        "schemaVersion",
    },
)
_CANARY_FIELDS = frozenset(
    {
        "canary",
        "correlationId",
        "eventKind",
        "eventTime",
        "schemaVersion",
    },
)
_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_LOG_GROUP_PATTERN = re.compile(r"[A-Za-z0-9_./#-]{1,512}\Z")
_AWS_REGION_PATTERN = re.compile(r"[a-z]{2}(?:-gov)?-[a-z]+-\d\Z")
_PROVIDER_PATTERN = re.compile(r"[a-z][a-z0-9.-]{0,63}\Z")
_SENSITIVE_PROVIDER_PATTERN = re.compile(
    r"(?:^|[.-])(?:account|arn|credential|password|secret|token)(?:[.-]|$)"
    r"|\d{12}",
)
_EVENT_TIME_PATTERN = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z",
)
_FRESHNESS_PATTERN = re.compile(
    r"PT(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?"
    r"(?:(?P<seconds>\d+)S)?\Z",
)
_LIMITATIONS = (
    "Collection is limited to one declared log group and a fixed synthetic "
    "application log schema.",
    "Normalized evidence excludes raw messages, canary values, credentials, "
    "account and principal identifiers, and SDK diagnostics.",
    "The probe reports bounded telemetry facts and does not decide compliance.",
)


class CloudWatchLogsProbeFailureCode(StrEnum):
    """Stable, non-secret CloudWatch Logs collection failure categories."""

    ACCESS_DENIED = "access_denied"
    AMBIGUOUS_CORRELATION = "ambiguous_correlation"
    ENVIRONMENT_VALUE_INVALID = "environment_value_invalid"
    EVENT_LIMIT_EXCEEDED = "event_limit_exceeded"
    EVENT_OUTSIDE_WINDOW = "event_outside_window"
    FUTURE_ACTION = "future_action"
    FUTURE_EVENT = "future_event"
    IDENTITY_BOUNDARY_INVALID = "identity_boundary_invalid"
    INVALID_CONFIGURATION = "invalid_configuration"
    INVALID_EVENT = "invalid_event"
    MISSING_CORRELATION = "missing_correlation"
    OVERSIZED_MESSAGE = "oversized_message"
    PAGINATION_LIMIT_EXCEEDED = "pagination_limit_exceeded"
    PARTIAL_RESPONSE = "partial_response"
    PROVIDER_LIMIT_EXCEEDED = "provider_limit_exceeded"
    QUERY_TIMEOUT = "query_timeout"
    SDK_ERROR = "sdk_error"
    SDK_TIMEOUT = "sdk_timeout"
    SDK_UNAVAILABLE = "aws_sdk_unavailable"
    STALE_ACTION = "stale_action"
    STALE_EVENT = "stale_event"
    TIMESTAMP_CONFLICT = "timestamp_conflict"
    TOTAL_BYTES_EXCEEDED = "total_bytes_exceeded"
    UNSUPPORTED_OBSERVATION = "unsupported_observation"


_FAILURE_PRIORITY = {
    code: position for position, code in enumerate(CloudWatchLogsProbeFailureCode)
}


class CloudWatchLogsProbeError(RuntimeError):
    """A declaration failure whose text contains no source or environment data."""

    def __init__(
        self,
        code: CloudWatchLogsProbeFailureCode,
        probe_id: str,
    ) -> None:
        """Create one stable fail-closed declaration error."""
        self.code = code
        super().__init__(
            f"CloudWatch Logs probe {probe_id!r} was rejected ({code.value})",
        )


@dataclass(frozen=True, slots=True)
class _QueryWindow:
    start: datetime
    end: datetime

    @property
    def start_milliseconds(self) -> int:
        return _epoch_milliseconds(self.start)

    @property
    def end_milliseconds(self) -> int:
        # FilterLogEvents treats endTime as exclusive. One millisecond keeps
        # an event exactly on the validated upper boundary in scope.
        return _epoch_milliseconds(self.end) + 1


@dataclass(frozen=True, slots=True)
class _RawEvent:
    event_id: str
    timestamp: datetime
    message: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class _ParsedEvent:
    kind: ObservationKind
    source_time: datetime
    provider: str | None = None
    canary_observed: bool = False


@dataclass(frozen=True, slots=True)
class _Collection:
    events: tuple[_ParsedEvent, ...] = ()
    failures: frozenset[CloudWatchLogsProbeFailureCode] = frozenset()

    @property
    def complete(self) -> bool:
        return not self.failures


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class CloudWatchLogsProbeAdapter:
    """Collect fixed-format CloudWatch telemetry through one scoped identity."""

    environment: Mapping[str, str] = field(repr=False)
    suite_max_age: timedelta
    clock_skew_tolerance: timedelta
    clock: Callable[[], datetime] = field(
        default=lambda: datetime.now(UTC),
        repr=False,
    )
    monotonic: Callable[[], float] = field(
        default=time.monotonic,
        repr=False,
    )

    def __post_init__(self) -> None:
        """Reject adapter policy values outside the validated suite bounds."""
        _validate_policy(
            self.suite_max_age,
            self.clock_skew_tolerance,
        )

    @property
    def metadata(self) -> PluginMetadata:
        """Declare the exact built-in CloudWatch Logs probe capability."""
        return PluginMetadata(
            name="aws-cloudwatch-logs-probe",
            api_version=PLUGIN_API_VERSION,
            capabilities=("probe.aws-cloudwatch-logs",),
        )

    def collect_evidence(  # noqa: C901, PLR0912 - fail-closed states are explicit.
        self,
        request: ProbeRequest,
        /,
    ) -> ProbeResult:
        """Collect one complete bounded query or normalize a fail-closed result."""
        probe = request.probe
        if not isinstance(probe, CloudWatchLogsProbe):
            message = (
                "AWS CloudWatch Logs adapter requires a cloudWatchLogs declaration"
            )
            raise TypeError(message)
        if request.probe.action_ref != request.action_result.action_id:
            raise CloudWatchLogsProbeError(
                CloudWatchLogsProbeFailureCode.INVALID_CONFIGURATION,
                probe.id,
            )
        unsupported = set(probe.observations) - _SUPPORTED_OBSERVATIONS
        if unsupported:
            raise CloudWatchLogsProbeError(
                CloudWatchLogsProbeFailureCode.UNSUPPORTED_OBSERVATION,
                probe.id,
            )
        identity = request.identity
        if type(identity) is not AwsScopedIdentity:
            message = "AWS CloudWatch Logs probes require an AWS scoped identity"
            raise TypeError(message)

        collected_at = _normalized_time(
            self.clock(),
            field_name="CloudWatch Logs probe clock",
        )
        max_age = _probe_max_age(probe, self.suite_max_age)
        target = request.context.target
        correlation_ids = request.action_result.correlation_ids

        failures: set[CloudWatchLogsProbeFailureCode] = set()
        if not correlation_ids:
            failures.add(CloudWatchLogsProbeFailureCode.MISSING_CORRELATION)
        elif len(correlation_ids) != 1:
            failures.add(CloudWatchLogsProbeFailureCode.AMBIGUOUS_CORRELATION)
        if not _valid_target_and_identity(identity, target, collected_at):
            failures.add(
                CloudWatchLogsProbeFailureCode.IDENTITY_BOUNDARY_INVALID,
            )
        if (
            probe.identity_ref is not None
            and probe.identity_ref != identity.identity_id
        ):
            failures.add(CloudWatchLogsProbeFailureCode.INVALID_CONFIGURATION)
        if request.action_result.completed_at > (
            collected_at + self.clock_skew_tolerance
        ):
            failures.add(CloudWatchLogsProbeFailureCode.FUTURE_ACTION)
        if collected_at > request.action_result.completed_at + max_age:
            failures.add(CloudWatchLogsProbeFailureCode.STALE_ACTION)
        canary, canary_failure = self._canary(probe)
        if canary_failure is not None:
            failures.add(canary_failure)

        region = target.aws_region
        if (
            not isinstance(region, str)
            or _AWS_REGION_PATTERN.fullmatch(region) is None
            or not isinstance(probe.log_group, str)
            or _LOG_GROUP_PATTERN.fullmatch(probe.log_group) is None
        ):
            failures.add(CloudWatchLogsProbeFailureCode.INVALID_CONFIGURATION)
        if failures:
            return _probe_result(
                probe,
                collected_at=collected_at,
                max_age=max_age,
                collection=_Collection(failures=frozenset(failures)),
            )

        correlation_id = correlation_ids[0]
        validated_region = cast("str", region)
        window = _query_window(
            completed_at=request.action_result.completed_at,
            collected_at=collected_at,
            max_age=max_age,
            clock_skew_tolerance=self.clock_skew_tolerance,
        )
        try:
            client = identity._cloudwatch_logs_client(  # noqa: SLF001
                region=validated_region,
                evaluated_at=collected_at,
            )
        except ModuleNotFoundError, _AwsSdkUnavailableError:
            collection = _Collection(
                failures=frozenset(
                    {CloudWatchLogsProbeFailureCode.SDK_UNAVAILABLE},
                ),
            )
        except Exception:  # noqa: BLE001 - identity/SDK diagnostics are redacted.
            collection = _Collection(
                failures=frozenset(
                    {CloudWatchLogsProbeFailureCode.SDK_ERROR},
                ),
            )
        else:
            collection = self._query(
                client,
                probe=probe,
                correlation_id=correlation_id,
                canary=canary,
                collected_at=collected_at,
                max_age=max_age,
                window=window,
            )
        return _probe_result(
            probe,
            collected_at=collected_at,
            max_age=max_age,
            collection=collection,
        )

    def _canary(
        self,
        probe: CloudWatchLogsProbe,
    ) -> tuple[str | None, CloudWatchLogsProbeFailureCode | None]:
        if ObservationKind.TELEMETRY_CANARY not in probe.observations:
            if probe.canary is not None:
                return None, CloudWatchLogsProbeFailureCode.INVALID_CONFIGURATION
            return None, None
        reference = probe.canary
        if not isinstance(reference, EnvironmentReference):
            return None, CloudWatchLogsProbeFailureCode.INVALID_CONFIGURATION
        try:
            value: object = self.environment[reference.name]
        except Exception:  # noqa: BLE001 - environment mappings are untrusted.
            return None, CloudWatchLogsProbeFailureCode.ENVIRONMENT_VALUE_INVALID
        if (
            not isinstance(value, str)
            or not value
            or len(value.encode("utf-8")) > MAX_CLOUDWATCH_EVENT_BYTES
        ):
            return None, CloudWatchLogsProbeFailureCode.ENVIRONMENT_VALUE_INVALID
        return value, None

    def _query(  # noqa: C901, PLR0912, PLR0913 - explicit query bounds.
        self,
        client: _AwsCloudWatchLogsClient,
        *,
        probe: CloudWatchLogsProbe,
        correlation_id: str,
        canary: str | None,
        collected_at: datetime,
        max_age: timedelta,
        window: _QueryWindow,
    ) -> _Collection:
        query_started = self.monotonic()
        failures: set[CloudWatchLogsProbeFailureCode] = set()
        raw_events: list[_RawEvent] = []
        total_bytes = 0
        next_token: str | None = None
        seen_tokens: set[str] = set()

        for page_number in range(1, MAX_CLOUDWATCH_PAGES + 1):
            arguments: dict[str, object] = {
                "endTime": window.end_milliseconds,
                "filterPattern": (f'{{ $.correlationId = "{correlation_id}" }}'),
                "interleaved": True,
                "limit": MAX_CLOUDWATCH_EVENTS + 1,
                "logGroupName": probe.log_group,
                "startFromHead": True,
                "startTime": window.start_milliseconds,
                "unmask": False,
            }
            if next_token is not None:
                arguments["nextToken"] = next_token
            try:
                response = client.filter_log_events(**arguments)
            except Exception as error:  # noqa: BLE001 - SDK text is discarded.
                failures.add(_sdk_failure(error))
                failures.add(CloudWatchLogsProbeFailureCode.PARTIAL_RESPONSE)
                break
            if self.monotonic() - query_started > MAX_CLOUDWATCH_QUERY_SECONDS:
                failures.update(
                    {
                        CloudWatchLogsProbeFailureCode.PARTIAL_RESPONSE,
                        CloudWatchLogsProbeFailureCode.QUERY_TIMEOUT,
                    },
                )
                break
            page_events, page_token, page_failures = _validated_page(response)
            failures.update(page_failures)
            for raw_record in page_events:
                event, message_bytes, event_failures = _validated_event_record(
                    raw_record,
                )
                failures.update(event_failures)
                total_bytes += message_bytes
                if total_bytes > MAX_CLOUDWATCH_TOTAL_BYTES:
                    failures.add(
                        CloudWatchLogsProbeFailureCode.TOTAL_BYTES_EXCEEDED,
                    )
                    break
                if event is not None:
                    if len(raw_events) >= MAX_CLOUDWATCH_EVENTS:
                        failures.add(
                            CloudWatchLogsProbeFailureCode.EVENT_LIMIT_EXCEEDED,
                        )
                        break
                    raw_events.append(event)
            if (
                CloudWatchLogsProbeFailureCode.TOTAL_BYTES_EXCEEDED in failures
                or CloudWatchLogsProbeFailureCode.EVENT_LIMIT_EXCEEDED in failures
            ):
                break
            if page_token is None:
                break
            if page_token in seen_tokens:
                failures.update(
                    {
                        CloudWatchLogsProbeFailureCode.PARTIAL_RESPONSE,
                        CloudWatchLogsProbeFailureCode.PAGINATION_LIMIT_EXCEEDED,
                    },
                )
                break
            seen_tokens.add(page_token)
            next_token = page_token
            if page_number == MAX_CLOUDWATCH_PAGES:
                failures.update(
                    {
                        CloudWatchLogsProbeFailureCode.PARTIAL_RESPONSE,
                        CloudWatchLogsProbeFailureCode.PAGINATION_LIMIT_EXCEEDED,
                    },
                )

        parsed, parse_failures = _normalize_events(
            raw_events,
            correlation_id=correlation_id,
            canary=canary,
            requested=frozenset(probe.observations),
            collected_at=collected_at,
            max_age=max_age,
            clock_skew_tolerance=self.clock_skew_tolerance,
            window=window,
        )
        failures.update(parse_failures)
        providers = {event.provider for event in parsed if event.provider is not None}
        if len(providers) > MAX_CLOUDWATCH_PROVIDERS:
            failures.add(
                CloudWatchLogsProbeFailureCode.PROVIDER_LIMIT_EXCEEDED,
            )
        return _Collection(
            events=parsed,
            failures=frozenset(failures),
        )


def _probe_result(
    probe: CloudWatchLogsProbe,
    *,
    collected_at: datetime,
    max_age: timedelta,
    collection: _Collection,
) -> ProbeResult:
    observations: list[Observation] = []
    source_times = [event.source_time for event in collection.events]
    failure = _primary_failure(collection.failures)
    for kind in sorted(probe.observations, key=lambda item: item.value):
        relevant = tuple(event for event in collection.events if event.kind is kind)
        observed: dict[str, JsonValue] = {
            "accepted_correlated_records": len(relevant),
            "ambiguous": _ambiguous(collection.failures),
            "correlated_records_found": bool(relevant),
            "error_category": failure.value if failure is not None else None,
            "evidence_complete": collection.complete,
            "future_dated": _future_dated(collection.failures),
            "malformed": _malformed(collection.failures),
            "oversized": _oversized(collection.failures),
            "partial": _partial(collection.failures),
            "stale": _stale(collection.failures),
        }
        if kind is ObservationKind.PROVIDER_INVOCATION:
            provider_names = sorted(
                event.provider for event in relevant if event.provider is not None
            )
            providers = cast("list[JsonValue]", list(provider_names))
            observed["providers"] = providers if collection.complete else []
            suffix = "provider-invocation"
        else:
            observed["canary_observed"] = (
                any(event.canary_observed for event in relevant)
                if collection.complete
                else False
            )
            suffix = "telemetry-canary"
        observations.append(
            Observation(
                observation_id=f"{probe.id}.{suffix}",
                kind=kind.value,
                observed=RedactedValue(observed),
                limitations=_LIMITATIONS,
            ),
        )
    return ProbeResult(
        probe_id=probe.id,
        source=EvidenceSource(
            name=CLOUDWATCH_LOGS_ADAPTER_NAME,
            version=CLOUDWATCH_LOGS_ADAPTER_VERSION,
        ),
        freshness=EvidenceFreshness(
            collected_at=collected_at,
            source_time=min(source_times) if source_times else None,
            max_age=max_age,
        ),
        observations=tuple(observations),
    )


def _validated_page(
    response: object,
) -> tuple[
    tuple[object, ...],
    str | None,
    set[CloudWatchLogsProbeFailureCode],
]:
    failures: set[CloudWatchLogsProbeFailureCode] = set()
    if not isinstance(response, Mapping):
        return (), None, {CloudWatchLogsProbeFailureCode.PARTIAL_RESPONSE}
    events = response.get("events")
    if not isinstance(events, list):
        failures.add(CloudWatchLogsProbeFailureCode.PARTIAL_RESPONSE)
        raw_events: tuple[object, ...] = ()
    else:
        raw_events = tuple(events)
    searched = response.get("searchedLogStreams")
    if searched is not None:
        if not isinstance(searched, list):
            failures.add(CloudWatchLogsProbeFailureCode.PARTIAL_RESPONSE)
        else:
            for item in searched:
                if (
                    not isinstance(item, Mapping)
                    or type(item.get("searchedCompletely")) is not bool
                    or item["searchedCompletely"] is not True
                ):
                    failures.add(
                        CloudWatchLogsProbeFailureCode.PARTIAL_RESPONSE,
                    )
    token = response.get("nextToken")
    if token is None:
        next_token = None
    elif (
        isinstance(token, str) and token and len(token) <= _MAX_PAGINATION_TOKEN_LENGTH
    ):
        next_token = token
    else:
        failures.add(CloudWatchLogsProbeFailureCode.PARTIAL_RESPONSE)
        next_token = None
    return raw_events, next_token, failures


def _validated_event_record(  # noqa: PLR0911 - malformed states stay explicit.
    value: object,
) -> tuple[
    _RawEvent | None,
    int,
    set[CloudWatchLogsProbeFailureCode],
]:
    if not isinstance(value, Mapping):
        return None, 0, {CloudWatchLogsProbeFailureCode.INVALID_EVENT}
    message_value = value.get("message")
    message_bytes = (
        len(message_value.encode("utf-8")) if isinstance(message_value, str) else 0
    )
    if message_bytes > MAX_CLOUDWATCH_EVENT_BYTES:
        return (
            None,
            message_bytes,
            {CloudWatchLogsProbeFailureCode.OVERSIZED_MESSAGE},
        )
    if (
        not {"eventId", "message", "timestamp"} <= set(value)
        or not set(value) <= _EVENT_FIELDS
    ):
        return (
            None,
            message_bytes,
            {CloudWatchLogsProbeFailureCode.INVALID_EVENT},
        )
    event_id = value["eventId"]
    message = message_value
    if (
        not isinstance(event_id, str)
        or not event_id
        or len(event_id) > _MAX_EVENT_ID_LENGTH
        or not isinstance(message, str)
    ):
        return (
            None,
            message_bytes,
            {CloudWatchLogsProbeFailureCode.INVALID_EVENT},
        )
    if "logStreamName" in value and not isinstance(value["logStreamName"], str):
        return (
            None,
            message_bytes,
            {CloudWatchLogsProbeFailureCode.INVALID_EVENT},
        )
    if "ingestionTime" in value and (
        isinstance(value["ingestionTime"], bool)
        or not isinstance(value["ingestionTime"], int)
        or value["ingestionTime"] < 0
    ):
        return (
            None,
            message_bytes,
            {CloudWatchLogsProbeFailureCode.INVALID_EVENT},
        )
    timestamp = _cloudwatch_timestamp(value["timestamp"])
    if timestamp is None:
        return (
            None,
            message_bytes,
            {CloudWatchLogsProbeFailureCode.INVALID_EVENT},
        )
    return (
        _RawEvent(
            event_id=event_id,
            timestamp=timestamp,
            message=message,
        ),
        message_bytes,
        set(),
    )


def _normalize_events(  # noqa: PLR0913 - each validation boundary is explicit.
    raw_events: list[_RawEvent],
    *,
    correlation_id: str,
    canary: str | None,
    requested: frozenset[ObservationKind],
    collected_at: datetime,
    max_age: timedelta,
    clock_skew_tolerance: timedelta,
    window: _QueryWindow,
) -> tuple[
    tuple[_ParsedEvent, ...],
    set[CloudWatchLogsProbeFailureCode],
]:
    failures: set[CloudWatchLogsProbeFailureCode] = set()
    by_id: dict[str, _RawEvent] = {}
    conflicting_ids: set[str] = set()
    for event in sorted(
        raw_events,
        key=lambda item: (item.event_id, item.timestamp, item.message),
    ):
        previous = by_id.get(event.event_id)
        if previous is None:
            by_id[event.event_id] = event
        elif previous.timestamp != event.timestamp or previous.message != event.message:
            conflicting_ids.add(event.event_id)
            failures.add(
                CloudWatchLogsProbeFailureCode.AMBIGUOUS_CORRELATION,
            )

    parsed: list[_ParsedEvent] = []
    for event in sorted(
        (item for event_id, item in by_id.items() if event_id not in conflicting_ids),
        key=lambda item: (item.timestamp, item.event_id),
    ):
        normalized, event_failures = _parse_structured_event(
            event,
            correlation_id=correlation_id,
            canary=canary,
            requested=requested,
            collected_at=collected_at,
            max_age=max_age,
            clock_skew_tolerance=clock_skew_tolerance,
            window=window,
        )
        failures.update(event_failures)
        if normalized is not None:
            parsed.append(normalized)
    return (
        tuple(
            sorted(
                parsed,
                key=lambda item: (
                    item.kind.value,
                    item.source_time,
                    item.provider or "",
                    item.canary_observed,
                ),
            ),
        ),
        failures,
    )


def _parse_structured_event(  # noqa: C901, PLR0911, PLR0912, PLR0913
    event: _RawEvent,
    *,
    correlation_id: str,
    canary: str | None,
    requested: frozenset[ObservationKind],
    collected_at: datetime,
    max_age: timedelta,
    clock_skew_tolerance: timedelta,
    window: _QueryWindow,
) -> tuple[_ParsedEvent | None, set[CloudWatchLogsProbeFailureCode]]:
    try:
        decoded = json.loads(event.message, object_pairs_hook=_unique_object)
    except UnicodeError, ValueError, RecursionError:
        return None, {CloudWatchLogsProbeFailureCode.INVALID_EVENT}
    if not isinstance(decoded, dict):
        return None, {CloudWatchLogsProbeFailureCode.INVALID_EVENT}
    event_kind = decoded.get("eventKind")
    expected_fields = (
        _PROVIDER_FIELDS
        if event_kind == ObservationKind.PROVIDER_INVOCATION.value
        else _CANARY_FIELDS
        if event_kind == ObservationKind.TELEMETRY_CANARY.value
        else frozenset()
    )
    if (
        not expected_fields
        or set(decoded) != expected_fields
        or decoded.get("schemaVersion") != _STRUCTURED_LOG_VERSION
    ):
        return None, {CloudWatchLogsProbeFailureCode.INVALID_EVENT}
    observed_correlation = decoded.get("correlationId")
    if (
        not isinstance(observed_correlation, str)
        or _IDENTIFIER_PATTERN.fullmatch(observed_correlation) is None
        or observed_correlation != correlation_id
    ):
        return None, {CloudWatchLogsProbeFailureCode.AMBIGUOUS_CORRELATION}
    structured_time = _structured_time(decoded.get("eventTime"))
    if structured_time is None:
        return None, {CloudWatchLogsProbeFailureCode.INVALID_EVENT}
    if abs(structured_time - event.timestamp) > clock_skew_tolerance:
        return None, {CloudWatchLogsProbeFailureCode.TIMESTAMP_CONFLICT}
    source_time = min(structured_time, event.timestamp)
    latest_time = max(structured_time, event.timestamp)
    if source_time < collected_at - max_age:
        return None, {CloudWatchLogsProbeFailureCode.STALE_EVENT}
    if latest_time > collected_at + clock_skew_tolerance:
        return None, {CloudWatchLogsProbeFailureCode.FUTURE_EVENT}
    if source_time < window.start or latest_time > window.end:
        return None, {CloudWatchLogsProbeFailureCode.EVENT_OUTSIDE_WINDOW}

    kind = ObservationKind(cast("str", event_kind))
    if kind not in requested:
        return None, set()
    if kind is ObservationKind.PROVIDER_INVOCATION:
        provider = decoded.get("providerId")
        if (
            not isinstance(provider, str)
            or _PROVIDER_PATTERN.fullmatch(provider) is None
            or _SENSITIVE_PROVIDER_PATTERN.search(provider) is not None
        ):
            return None, {CloudWatchLogsProbeFailureCode.INVALID_EVENT}
        return (
            _ParsedEvent(
                kind=kind,
                source_time=source_time,
                provider=provider,
            ),
            set(),
        )
    observed_canary = decoded.get("canary")
    if not isinstance(observed_canary, str) or not observed_canary or canary is None:
        return None, {CloudWatchLogsProbeFailureCode.INVALID_EVENT}
    return (
        _ParsedEvent(
            kind=kind,
            source_time=source_time,
            canary_observed=hmac.compare_digest(
                observed_canary.encode("utf-8"),
                canary.encode("utf-8"),
            ),
        ),
        set(),
    )


def _query_window(
    *,
    completed_at: datetime,
    collected_at: datetime,
    max_age: timedelta,
    clock_skew_tolerance: timedelta,
) -> _QueryWindow:
    start = max(
        completed_at - clock_skew_tolerance,
        collected_at - max_age,
    )
    end = min(
        completed_at + clock_skew_tolerance,
        collected_at + clock_skew_tolerance,
    )
    return _QueryWindow(start=start, end=max(start, end))


def _probe_max_age(
    probe: CloudWatchLogsProbe,
    suite_max_age: timedelta,
) -> timedelta:
    if probe.max_age is None:
        return suite_max_age
    if not isinstance(probe.max_age, str):
        raise CloudWatchLogsProbeError(
            CloudWatchLogsProbeFailureCode.INVALID_CONFIGURATION,
            probe.id,
        )
    parsed = _duration(probe.max_age)
    if parsed is None or not timedelta(0) < parsed <= _MAX_FRESHNESS:
        raise CloudWatchLogsProbeError(
            CloudWatchLogsProbeFailureCode.INVALID_CONFIGURATION,
            probe.id,
        )
    return parsed


def _valid_target_and_identity(
    identity: AwsScopedIdentity,
    target: object,
    evaluated_at: datetime,
) -> bool:
    region = getattr(target, "aws_region", None)
    account_id = getattr(target, "aws_account_id", None)
    expires_at = identity.expires_at
    return (
        not identity.closed
        and isinstance(region, str)
        and _AWS_REGION_PATTERN.fullmatch(region) is not None
        and isinstance(account_id, str)
        and identity.matches_account(account_id)
        and identity.matches_partition(_partition_for_region(region))
        and (
            expires_at is None
            or (
                isinstance(expires_at, datetime)
                and expires_at.tzinfo is not None
                and expires_at.utcoffset() is not None
                and expires_at.astimezone(UTC) > evaluated_at
            )
        )
    )


def _validate_policy(max_age: object, clock_skew_tolerance: object) -> None:
    if (
        not isinstance(max_age, timedelta)
        or not timedelta(0) < max_age <= _MAX_FRESHNESS
    ):
        message = "suite_max_age must be positive and no longer than 24 hours"
        raise ValueError(message)
    if (
        not isinstance(clock_skew_tolerance, timedelta)
        or not timedelta(0) <= clock_skew_tolerance <= _MAX_CLOCK_SKEW
    ):
        message = "clock_skew_tolerance must be between zero and five minutes"
        raise ValueError(message)


def _duration(value: str) -> timedelta | None:
    match = _FRESHNESS_PATTERN.fullmatch(value)
    if match is None or not any(match.groupdict().values()):
        return None
    minutes = int(match.group("minutes") or 0)
    seconds = int(match.group("seconds") or 0)
    if minutes >= _SECONDS_PER_MINUTE or seconds >= _SECONDS_PER_MINUTE:
        return None
    return timedelta(
        hours=int(match.group("hours") or 0),
        minutes=minutes,
        seconds=seconds,
    )


def _cloudwatch_timestamp(value: object) -> datetime | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    try:
        return datetime.fromtimestamp(value / 1000, tz=UTC)
    except OverflowError, OSError, ValueError:
        return None


def _structured_time(value: object) -> datetime | None:
    if not isinstance(value, str) or _EVENT_TIME_PATTERN.fullmatch(value) is None:
        return None
    try:
        return datetime.fromisoformat(f"{value[:-1]}+00:00").astimezone(UTC)
    except ValueError:
        return None


def _epoch_milliseconds(value: datetime) -> int:
    return int(value.timestamp() * 1000)


def _normalized_time(value: object, *, field_name: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        message = f"{field_name} must return a timezone-aware datetime"
        raise ValueError(message)
    return value.astimezone(UTC)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _sdk_failure(error: Exception) -> CloudWatchLogsProbeFailureCode:
    if isinstance(error, TimeoutError) or type(error).__name__ in {
        "ConnectTimeoutError",
        "ReadTimeoutError",
    }:
        return CloudWatchLogsProbeFailureCode.SDK_TIMEOUT
    response = getattr(error, "response", None)
    if isinstance(response, Mapping):
        details = response.get("Error")
        if isinstance(details, Mapping) and details.get("Code") in {
            "AccessDenied",
            "AccessDeniedException",
            "UnauthorizedOperation",
        }:
            return CloudWatchLogsProbeFailureCode.ACCESS_DENIED
    return CloudWatchLogsProbeFailureCode.SDK_ERROR


def _primary_failure(
    failures: frozenset[CloudWatchLogsProbeFailureCode],
) -> CloudWatchLogsProbeFailureCode | None:
    if not failures:
        return None
    specific = failures - {CloudWatchLogsProbeFailureCode.PARTIAL_RESPONSE}
    candidates = specific or failures
    return min(candidates, key=_FAILURE_PRIORITY.__getitem__)


def _ambiguous(failures: frozenset[CloudWatchLogsProbeFailureCode]) -> bool:
    return bool(
        failures
        & {
            CloudWatchLogsProbeFailureCode.AMBIGUOUS_CORRELATION,
            CloudWatchLogsProbeFailureCode.EVENT_OUTSIDE_WINDOW,
            CloudWatchLogsProbeFailureCode.TIMESTAMP_CONFLICT,
        },
    )


def _future_dated(failures: frozenset[CloudWatchLogsProbeFailureCode]) -> bool:
    return bool(
        failures
        & {
            CloudWatchLogsProbeFailureCode.FUTURE_ACTION,
            CloudWatchLogsProbeFailureCode.FUTURE_EVENT,
        },
    )


def _malformed(failures: frozenset[CloudWatchLogsProbeFailureCode]) -> bool:
    return bool(
        failures
        & {
            CloudWatchLogsProbeFailureCode.INVALID_EVENT,
            CloudWatchLogsProbeFailureCode.TIMESTAMP_CONFLICT,
        },
    )


def _oversized(failures: frozenset[CloudWatchLogsProbeFailureCode]) -> bool:
    return bool(
        failures
        & {
            CloudWatchLogsProbeFailureCode.OVERSIZED_MESSAGE,
            CloudWatchLogsProbeFailureCode.TOTAL_BYTES_EXCEEDED,
        },
    )


def _partial(failures: frozenset[CloudWatchLogsProbeFailureCode]) -> bool:
    return bool(
        failures
        & {
            CloudWatchLogsProbeFailureCode.ACCESS_DENIED,
            CloudWatchLogsProbeFailureCode.PAGINATION_LIMIT_EXCEEDED,
            CloudWatchLogsProbeFailureCode.PARTIAL_RESPONSE,
            CloudWatchLogsProbeFailureCode.QUERY_TIMEOUT,
            CloudWatchLogsProbeFailureCode.SDK_ERROR,
            CloudWatchLogsProbeFailureCode.SDK_TIMEOUT,
        },
    )


def _stale(failures: frozenset[CloudWatchLogsProbeFailureCode]) -> bool:
    return bool(
        failures
        & {
            CloudWatchLogsProbeFailureCode.STALE_ACTION,
            CloudWatchLogsProbeFailureCode.STALE_EVENT,
        },
    )
