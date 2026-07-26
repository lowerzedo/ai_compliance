"""Bounded, exactly correlated CloudTrail audit evidence collection."""

from __future__ import annotations

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
    _AwsCloudTrailClient,
    _AwsSdkUnavailableError,
    _partition_for_region,
)
from cai_verify.config import CloudTrailProbe
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

CLOUDTRAIL_ADAPTER_NAME = "aws-cloudtrail"
CLOUDTRAIL_ADAPTER_VERSION = "1.0.0"
MAX_CLOUDTRAIL_QUERY_SECONDS = 15.0
MAX_CLOUDTRAIL_LOOKUP_WINDOW = timedelta(minutes=10)
MAX_CLOUDTRAIL_PAGES = 5
MAX_CLOUDTRAIL_EVENTS = 100
MAX_CLOUDTRAIL_EVENT_BYTES = 64 * 1024
MAX_CLOUDTRAIL_TOTAL_BYTES = 256 * 1024
MAX_CLOUDTRAIL_CORRELATED_EVENTS = 32
MAX_CLOUDTRAIL_DECLARED_EVENT_NAMES = 32
MAX_CLOUDTRAIL_EVENT_NAMES = 16
MAX_CLOUDTRAIL_PAGINATION_TOKEN_LENGTH = 8192

_MAX_FRESHNESS = timedelta(hours=24)
_MAX_CLOCK_SKEW = timedelta(minutes=5)
_MAX_EVENT_ID_LENGTH = 256
_HTTP_OK = 200
_LOOKUP_PAGE_SIZE = MAX_CLOUDTRAIL_CORRELATED_EVENTS + 1
_SECONDS_PER_MINUTE = 60
_SUPPORTED_OBSERVATIONS = frozenset({ObservationKind.AUDIT_EVENT})
_OUTER_EVENT_FIELDS = frozenset(
    {
        "AccessKeyId",
        "CloudTrailEvent",
        "EventId",
        "EventName",
        "EventSource",
        "EventTime",
        "ReadOnly",
        "Resources",
        "Username",
    },
)
_REQUIRED_OUTER_EVENT_FIELDS = frozenset(
    {
        "CloudTrailEvent",
        "EventId",
        "EventName",
        "EventSource",
        "EventTime",
    },
)
_REQUIRED_INNER_EVENT_FIELDS = frozenset(
    {
        "awsRegion",
        "eventID",
        "eventName",
        "eventSource",
        "eventTime",
        "recipientAccountId",
        "requestID",
        "userIdentity",
    },
)
_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_EVENT_NAME_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9]{0,127}\Z")
_EVENT_SOURCE_PATTERN = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+\Z")
_AWS_REGION_PATTERN = re.compile(r"[a-z]{2}(?:-gov)?-[a-z]+-\d\Z")
_EVENT_TIME_PATTERN = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z",
)
_FRESHNESS_PATTERN = re.compile(
    r"PT(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?"
    r"(?:(?P<seconds>\d+)S)?\Z",
)
_LIMITATIONS = (
    "Collection uses one regional CloudTrail LookupEvents EventSource lookup "
    "and fixed local event-field validation.",
    "LookupEvents exposes recent event history only; CloudTrail Lake, trail "
    "files, data stores, S3, and Athena are not queried.",
    "Normalized evidence excludes raw events, request and response data, "
    "account and principal identifiers, credentials, and SDK diagnostics.",
    "The probe reports bounded audit facts and does not decide compliance.",
)


class CloudTrailProbeFailureCode(StrEnum):
    """Stable, non-secret CloudTrail collection failure categories."""

    ACCESS_DENIED = "access_denied"
    ACCOUNT_MISMATCH = "account_mismatch"
    AMBIGUOUS_CORRELATION = "ambiguous_correlation"
    CORRELATION_UNMATCHED = "correlation_unmatched"
    EVENT_LIMIT_EXCEEDED = "event_limit_exceeded"
    CORRELATED_EVENT_LIMIT_EXCEEDED = "correlated_event_limit_exceeded"
    EVENT_NAME_LIMIT_EXCEEDED = "event_name_limit_exceeded"
    EVENT_NAME_MISMATCH = "event_name_mismatch"
    EVENT_OUTSIDE_WINDOW = "event_outside_window"
    FUTURE_ACTION = "future_action"
    FUTURE_EVENT = "future_event"
    IDENTITY_BOUNDARY_INVALID = "identity_boundary_invalid"
    INVALID_CONFIGURATION = "invalid_configuration"
    INVALID_EVENT = "invalid_event"
    MISSING_CORRELATION = "missing_correlation"
    OVERSIZED_EVENT = "oversized_event"
    PAGINATION_LIMIT_EXCEEDED = "pagination_limit_exceeded"
    PARTIAL_RESPONSE = "partial_response"
    QUERY_TIMEOUT = "query_timeout"
    REGION_MISMATCH = "region_mismatch"
    SDK_ERROR = "sdk_error"
    SDK_TIMEOUT = "sdk_timeout"
    SDK_UNAVAILABLE = "aws_sdk_unavailable"
    SOURCE_MISMATCH = "event_source_mismatch"
    STALE_ACTION = "stale_action"
    STALE_EVENT = "stale_event"
    TIMESTAMP_CONFLICT = "timestamp_conflict"
    TOTAL_BYTES_EXCEEDED = "total_bytes_exceeded"
    UNSUPPORTED_OBSERVATION = "unsupported_observation"


_FAILURE_PRIORITY = {
    code: position for position, code in enumerate(CloudTrailProbeFailureCode)
}


class CloudTrailProbeError(RuntimeError):
    """A declaration failure whose text contains no source event data."""

    def __init__(
        self,
        code: CloudTrailProbeFailureCode,
        probe_id: str,
    ) -> None:
        """Create one stable fail-closed declaration error."""
        self.code = code
        super().__init__(
            f"CloudTrail probe {probe_id!r} was rejected ({code.value})",
        )


@dataclass(frozen=True, slots=True)
class _LookupWindow:
    start: datetime
    end: datetime


@dataclass(frozen=True, slots=True)
class _RawEvent:
    event_id: str
    event_time: datetime
    event_source: str
    event_name: str
    payload: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class _ParsedEvent:
    event_id: str
    event_time: datetime
    event_name: str


@dataclass(frozen=True, slots=True)
class _Collection:
    events: tuple[_ParsedEvent, ...] = ()
    failures: frozenset[CloudTrailProbeFailureCode] = frozenset()

    @property
    def complete(self) -> bool:
        return not self.failures


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class CloudTrailProbeAdapter:
    """Collect fixed CloudTrail audit facts through one scoped identity."""

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
        """Reject adapter policy values outside validated suite bounds."""
        _validate_policy(self.suite_max_age, self.clock_skew_tolerance)

    @property
    def metadata(self) -> PluginMetadata:
        """Declare the exact built-in CloudTrail probe capability."""
        return PluginMetadata(
            name="aws-cloudtrail-probe",
            api_version=PLUGIN_API_VERSION,
            capabilities=("probe.aws-cloudtrail",),
        )

    def collect_evidence(  # noqa: C901, PLR0912 - fail-closed states are explicit.
        self,
        request: ProbeRequest,
        /,
    ) -> ProbeResult:
        """Collect one complete bounded lookup or normalize a closed result."""
        probe = request.probe
        if not isinstance(probe, CloudTrailProbe):
            message = "AWS CloudTrail adapter requires a cloudTrail declaration"
            raise TypeError(message)
        if probe.action_ref != request.action_result.action_id:
            raise CloudTrailProbeError(
                CloudTrailProbeFailureCode.INVALID_CONFIGURATION,
                probe.id,
            )
        if set(probe.observations) - _SUPPORTED_OBSERVATIONS:
            raise CloudTrailProbeError(
                CloudTrailProbeFailureCode.UNSUPPORTED_OBSERVATION,
                probe.id,
            )
        identity = request.identity
        if type(identity) is not AwsScopedIdentity:
            message = "AWS CloudTrail probes require an AWS scoped identity"
            raise TypeError(message)

        collected_at = _normalized_time(
            self.clock(),
            field_name="CloudTrail probe clock",
        )
        max_age = _probe_max_age(probe, self.suite_max_age)
        target = request.context.target
        failures: set[CloudTrailProbeFailureCode] = set()
        request_ids = request.action_result.aws_request_ids

        if not request_ids:
            failures.add(CloudTrailProbeFailureCode.MISSING_CORRELATION)
        elif len(request_ids) != 1:
            failures.add(CloudTrailProbeFailureCode.AMBIGUOUS_CORRELATION)
        if not _valid_target_and_identity(identity, target, collected_at):
            failures.add(CloudTrailProbeFailureCode.IDENTITY_BOUNDARY_INVALID)
        if (
            probe.identity_ref is not None
            and probe.identity_ref != identity.identity_id
        ):
            failures.add(CloudTrailProbeFailureCode.INVALID_CONFIGURATION)
        if request.action_result.completed_at > (
            collected_at + self.clock_skew_tolerance
        ):
            failures.add(CloudTrailProbeFailureCode.FUTURE_ACTION)
        if collected_at > request.action_result.completed_at + max_age:
            failures.add(CloudTrailProbeFailureCode.STALE_ACTION)

        region = target.aws_region
        account_id = target.aws_account_id
        event_names = probe.event_names
        if (
            not isinstance(region, str)
            or _AWS_REGION_PATTERN.fullmatch(region) is None
            or not isinstance(account_id, str)
            or not isinstance(probe.event_source, str)
            or _EVENT_SOURCE_PATTERN.fullmatch(probe.event_source) is None
            or not _valid_event_names(event_names)
        ):
            failures.add(CloudTrailProbeFailureCode.INVALID_CONFIGURATION)
        if failures:
            return _probe_result(
                probe,
                collected_at=collected_at,
                max_age=max_age,
                collection=_Collection(failures=frozenset(failures)),
            )

        validated_region = cast("str", region)
        validated_account = cast("str", account_id)
        window = _lookup_window(
            completed_at=request.action_result.completed_at,
            collected_at=collected_at,
            max_age=max_age,
            clock_skew_tolerance=self.clock_skew_tolerance,
        )
        if window.end - window.start > MAX_CLOUDTRAIL_LOOKUP_WINDOW:
            return _probe_result(
                probe,
                collected_at=collected_at,
                max_age=max_age,
                collection=_Collection(
                    failures=frozenset(
                        {CloudTrailProbeFailureCode.INVALID_CONFIGURATION},
                    ),
                ),
            )
        try:
            client = identity._cloudtrail_client(  # noqa: SLF001
                region=validated_region,
                evaluated_at=collected_at,
            )
        except ModuleNotFoundError, _AwsSdkUnavailableError:
            collection = _Collection(
                failures=frozenset(
                    {CloudTrailProbeFailureCode.SDK_UNAVAILABLE},
                ),
            )
        except Exception:  # noqa: BLE001 - identity/SDK diagnostics are redacted.
            collection = _Collection(
                failures=frozenset({CloudTrailProbeFailureCode.SDK_ERROR}),
            )
        else:
            collection = self._query(
                client,
                event_source=probe.event_source,
                event_names=frozenset(event_names),
                request_id=request_ids[0],
                expected_region=validated_region,
                expected_account=validated_account,
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

    def _query(  # noqa: C901, PLR0912, PLR0913, PLR0915
        self,
        client: _AwsCloudTrailClient,
        *,
        event_source: str,
        event_names: frozenset[str],
        request_id: str,
        expected_region: str,
        expected_account: str,
        collected_at: datetime,
        max_age: timedelta,
        window: _LookupWindow,
    ) -> _Collection:
        query_started = self.monotonic()
        failures: set[CloudTrailProbeFailureCode] = set()
        raw_events: list[_RawEvent] = []
        total_bytes = 0
        events_examined = 0
        next_token: str | None = None
        seen_tokens: set[str] = set()

        for page_number in range(1, MAX_CLOUDTRAIL_PAGES + 1):
            arguments: dict[str, object] = {
                "EndTime": window.end,
                "LookupAttributes": [
                    {
                        "AttributeKey": "EventSource",
                        "AttributeValue": event_source,
                    },
                ],
                "MaxResults": _LOOKUP_PAGE_SIZE,
                "StartTime": window.start,
            }
            if next_token is not None:
                arguments["NextToken"] = next_token
            try:
                response = client.lookup_events(**arguments)
            except Exception as error:  # noqa: BLE001 - SDK text is discarded.
                failures.update(
                    {
                        _sdk_failure(error),
                        CloudTrailProbeFailureCode.PARTIAL_RESPONSE,
                    },
                )
                break
            if self.monotonic() - query_started > MAX_CLOUDTRAIL_QUERY_SECONDS:
                failures.update(
                    {
                        CloudTrailProbeFailureCode.PARTIAL_RESPONSE,
                        CloudTrailProbeFailureCode.QUERY_TIMEOUT,
                    },
                )
                break
            page_events, page_token, page_failures = _validated_page(response)
            failures.update(page_failures)
            for raw_record in page_events:
                events_examined += 1
                if events_examined > MAX_CLOUDTRAIL_EVENTS:
                    failures.add(CloudTrailProbeFailureCode.EVENT_LIMIT_EXCEEDED)
                    break
                event, payload_bytes, event_failures = _validated_outer_event(
                    raw_record,
                )
                failures.update(event_failures)
                total_bytes += payload_bytes
                if total_bytes > MAX_CLOUDTRAIL_TOTAL_BYTES:
                    failures.add(
                        CloudTrailProbeFailureCode.TOTAL_BYTES_EXCEEDED,
                    )
                    break
                if event is not None:
                    raw_events.append(event)
            if (
                CloudTrailProbeFailureCode.EVENT_LIMIT_EXCEEDED in failures
                or CloudTrailProbeFailureCode.TOTAL_BYTES_EXCEEDED in failures
            ):
                break
            if self.monotonic() - query_started > MAX_CLOUDTRAIL_QUERY_SECONDS:
                failures.update(
                    {
                        CloudTrailProbeFailureCode.PARTIAL_RESPONSE,
                        CloudTrailProbeFailureCode.QUERY_TIMEOUT,
                    },
                )
                break
            if page_token is None:
                break
            if page_token in seen_tokens:
                failures.update(
                    {
                        CloudTrailProbeFailureCode.PAGINATION_LIMIT_EXCEEDED,
                        CloudTrailProbeFailureCode.PARTIAL_RESPONSE,
                    },
                )
                break
            seen_tokens.add(page_token)
            next_token = page_token
            if page_number == MAX_CLOUDTRAIL_PAGES:
                failures.update(
                    {
                        CloudTrailProbeFailureCode.PAGINATION_LIMIT_EXCEEDED,
                        CloudTrailProbeFailureCode.PARTIAL_RESPONSE,
                    },
                )

        parsed, parse_failures = _normalize_events(
            raw_events,
            event_source=event_source,
            event_names=event_names,
            request_id=request_id,
            expected_region=expected_region,
            expected_account=expected_account,
            collected_at=collected_at,
            max_age=max_age,
            clock_skew_tolerance=self.clock_skew_tolerance,
            window=window,
        )
        failures.update(parse_failures)
        if (
            CloudTrailProbeFailureCode.QUERY_TIMEOUT not in failures
            and self.monotonic() - query_started > MAX_CLOUDTRAIL_QUERY_SECONDS
        ):
            failures.update(
                {
                    CloudTrailProbeFailureCode.PARTIAL_RESPONSE,
                    CloudTrailProbeFailureCode.QUERY_TIMEOUT,
                },
            )
        normalized_names = {event.event_name for event in parsed}
        if len(normalized_names) > MAX_CLOUDTRAIL_EVENT_NAMES:
            failures.add(
                CloudTrailProbeFailureCode.EVENT_NAME_LIMIT_EXCEEDED,
            )
        return _Collection(events=parsed, failures=frozenset(failures))


def _probe_result(
    probe: CloudTrailProbe,
    *,
    collected_at: datetime,
    max_age: timedelta,
    collection: _Collection,
) -> ProbeResult:
    failure = _primary_failure(collection.failures)
    complete_set = collection.complete and bool(collection.events)
    event_names: list[JsonValue] = (
        cast(
            "list[JsonValue]",
            sorted({event.event_name for event in collection.events}),
        )
        if complete_set
        else []
    )
    observed: dict[str, JsonValue] = {
        "accepted_correlated_events": len(collection.events) if complete_set else 0,
        "ambiguous": _ambiguous(collection.failures),
        "complete_correlated_event_set_found": complete_set,
        "correlated_events_found": complete_set,
        "error_category": failure.value if failure is not None else None,
        "event_names": event_names,
        "event_source_matched": complete_set,
        "evidence_complete": complete_set,
        "future_dated": _future_dated(collection.failures),
        "malformed": _malformed(collection.failures),
        "oversized": _oversized(collection.failures),
        "partial": _partial(collection.failures),
        "region_matched": complete_set,
        "stale": _stale(collection.failures),
    }
    observation = Observation(
        observation_id=f"{probe.id}.audit-event",
        kind=ObservationKind.AUDIT_EVENT.value,
        observed=RedactedValue(observed),
        limitations=_LIMITATIONS,
    )
    source_time = (
        min(event.event_time for event in collection.events) if complete_set else None
    )
    return ProbeResult(
        probe_id=probe.id,
        source=EvidenceSource(
            name=CLOUDTRAIL_ADAPTER_NAME,
            version=CLOUDTRAIL_ADAPTER_VERSION,
        ),
        freshness=EvidenceFreshness(
            collected_at=collected_at,
            source_time=source_time,
            max_age=max_age,
        ),
        observations=(observation,),
    )


def _validated_page(
    response: object,
) -> tuple[
    tuple[object, ...],
    str | None,
    set[CloudTrailProbeFailureCode],
]:
    failures: set[CloudTrailProbeFailureCode] = set()
    if not isinstance(response, Mapping):
        return (), None, {CloudTrailProbeFailureCode.PARTIAL_RESPONSE}
    if not set(response) <= {"Events", "NextToken", "ResponseMetadata"}:
        failures.add(CloudTrailProbeFailureCode.PARTIAL_RESPONSE)
    events = response.get("Events")
    if not isinstance(events, list):
        failures.add(CloudTrailProbeFailureCode.PARTIAL_RESPONSE)
        raw_events: tuple[object, ...] = ()
    else:
        raw_events = tuple(events)
        if len(events) > _LOOKUP_PAGE_SIZE:
            failures.add(CloudTrailProbeFailureCode.PARTIAL_RESPONSE)
    metadata = response.get("ResponseMetadata")
    if metadata is not None and not isinstance(metadata, Mapping):
        failures.add(CloudTrailProbeFailureCode.PARTIAL_RESPONSE)
    elif isinstance(metadata, Mapping):
        status = metadata.get("HTTPStatusCode")
        if status is not None and status != _HTTP_OK:
            failures.add(CloudTrailProbeFailureCode.PARTIAL_RESPONSE)
    token = response.get("NextToken")
    if token is None:
        next_token = None
    elif (
        isinstance(token, str)
        and token
        and len(token) <= MAX_CLOUDTRAIL_PAGINATION_TOKEN_LENGTH
    ):
        next_token = token
    else:
        failures.add(CloudTrailProbeFailureCode.PARTIAL_RESPONSE)
        next_token = None
    return raw_events, next_token, failures


def _validated_outer_event(
    value: object,
) -> tuple[
    _RawEvent | None,
    int,
    set[CloudTrailProbeFailureCode],
]:
    if not isinstance(value, Mapping):
        return None, 0, {CloudTrailProbeFailureCode.INVALID_EVENT}
    payload_value = value.get("CloudTrailEvent")
    payload_bytes = (
        len(payload_value.encode("utf-8")) if isinstance(payload_value, str) else 0
    )
    if payload_bytes > MAX_CLOUDTRAIL_EVENT_BYTES:
        return (
            None,
            payload_bytes,
            {CloudTrailProbeFailureCode.OVERSIZED_EVENT},
        )
    if (
        not set(value) >= _REQUIRED_OUTER_EVENT_FIELDS
        or not set(
            value,
        )
        <= _OUTER_EVENT_FIELDS
    ):
        return None, payload_bytes, {CloudTrailProbeFailureCode.INVALID_EVENT}
    event_id = value["EventId"]
    event_name = value["EventName"]
    event_source = value["EventSource"]
    event_time = _outer_event_time(value["EventTime"])
    if (
        not isinstance(event_id, str)
        or not event_id
        or len(event_id) > _MAX_EVENT_ID_LENGTH
        or _IDENTIFIER_PATTERN.fullmatch(event_id) is None
        or not isinstance(event_name, str)
        or _EVENT_NAME_PATTERN.fullmatch(event_name) is None
        or not isinstance(event_source, str)
        or _EVENT_SOURCE_PATTERN.fullmatch(event_source) is None
        or event_time is None
        or not isinstance(payload_value, str)
    ):
        return None, payload_bytes, {CloudTrailProbeFailureCode.INVALID_EVENT}
    if (
        ("AccessKeyId" in value and not isinstance(value["AccessKeyId"], str))
        or ("ReadOnly" in value and not isinstance(value["ReadOnly"], str))
        or ("Resources" in value and not isinstance(value["Resources"], list))
        or ("Username" in value and not isinstance(value["Username"], str))
    ):
        return None, payload_bytes, {CloudTrailProbeFailureCode.INVALID_EVENT}
    return (
        _RawEvent(
            event_id=event_id,
            event_time=event_time,
            event_source=event_source,
            event_name=event_name,
            payload=payload_value,
        ),
        payload_bytes,
        set(),
    )


def _normalize_events(  # noqa: PLR0913 - validation inputs remain explicit.
    raw_events: list[_RawEvent],
    *,
    event_source: str,
    event_names: frozenset[str],
    request_id: str,
    expected_region: str,
    expected_account: str,
    collected_at: datetime,
    max_age: timedelta,
    clock_skew_tolerance: timedelta,
    window: _LookupWindow,
) -> tuple[
    tuple[_ParsedEvent, ...],
    set[CloudTrailProbeFailureCode],
]:
    failures: set[CloudTrailProbeFailureCode] = set()
    by_id: dict[str, _RawEvent] = {}
    conflicting_ids: set[str] = set()
    for event in sorted(
        raw_events,
        key=lambda item: (
            item.event_id,
            item.event_time,
            item.event_source,
            item.event_name,
            item.payload,
        ),
    ):
        previous = by_id.get(event.event_id)
        if previous is None:
            by_id[event.event_id] = event
        elif previous != event:
            conflicting_ids.add(event.event_id)
            failures.add(CloudTrailProbeFailureCode.AMBIGUOUS_CORRELATION)

    parsed: list[_ParsedEvent] = []
    for event in sorted(
        (item for event_id, item in by_id.items() if event_id not in conflicting_ids),
        key=lambda item: (item.event_time, item.event_id),
    ):
        normalized, event_failures = _parse_event(
            event,
            event_source=event_source,
            event_names=event_names,
            request_id=request_id,
            expected_region=expected_region,
            expected_account=expected_account,
            collected_at=collected_at,
            max_age=max_age,
            clock_skew_tolerance=clock_skew_tolerance,
            window=window,
        )
        failures.update(event_failures)
        if normalized is not None:
            if len(parsed) >= MAX_CLOUDTRAIL_CORRELATED_EVENTS:
                failures.add(
                    CloudTrailProbeFailureCode.CORRELATED_EVENT_LIMIT_EXCEEDED,
                )
                break
            parsed.append(normalized)
    return (
        tuple(
            sorted(
                parsed,
                key=lambda item: (
                    item.event_time,
                    item.event_name,
                    item.event_id,
                ),
            ),
        ),
        failures,
    )


def _parse_event(  # noqa: C901, PLR0911, PLR0912, PLR0913
    event: _RawEvent,
    *,
    event_source: str,
    event_names: frozenset[str],
    request_id: str,
    expected_region: str,
    expected_account: str,
    collected_at: datetime,
    max_age: timedelta,
    clock_skew_tolerance: timedelta,
    window: _LookupWindow,
) -> tuple[_ParsedEvent | None, set[CloudTrailProbeFailureCode]]:
    try:
        decoded = json.loads(event.payload, object_pairs_hook=_unique_object)
    except UnicodeError, ValueError, RecursionError:
        return None, {CloudTrailProbeFailureCode.INVALID_EVENT}
    if (
        not isinstance(decoded, dict)
        or not set(
            decoded,
        )
        >= _REQUIRED_INNER_EVENT_FIELDS
    ):
        return None, {CloudTrailProbeFailureCode.INVALID_EVENT}
    inner_event_id = decoded.get("eventID")
    inner_event_name = decoded.get("eventName")
    inner_event_source = decoded.get("eventSource")
    inner_region = decoded.get("awsRegion")
    inner_request_id = decoded.get("requestID")
    recipient_account = decoded.get("recipientAccountId")
    user_identity = decoded.get("userIdentity")
    if (
        not isinstance(inner_event_id, str)
        or _IDENTIFIER_PATTERN.fullmatch(inner_event_id) is None
        or not isinstance(inner_event_name, str)
        or _EVENT_NAME_PATTERN.fullmatch(inner_event_name) is None
        or not isinstance(inner_event_source, str)
        or _EVENT_SOURCE_PATTERN.fullmatch(inner_event_source) is None
        or not isinstance(inner_region, str)
        or _AWS_REGION_PATTERN.fullmatch(inner_region) is None
        or not isinstance(inner_request_id, str)
        or _IDENTIFIER_PATTERN.fullmatch(inner_request_id) is None
        or not isinstance(recipient_account, str)
        or not isinstance(user_identity, dict)
    ):
        return None, {CloudTrailProbeFailureCode.INVALID_EVENT}
    principal_account = user_identity.get("accountId")
    if not isinstance(principal_account, str):
        return None, {CloudTrailProbeFailureCode.INVALID_EVENT}
    structured_time = _structured_time(decoded.get("eventTime"))
    if structured_time is None:
        return None, {CloudTrailProbeFailureCode.INVALID_EVENT}
    if structured_time != event.event_time:
        return None, {CloudTrailProbeFailureCode.TIMESTAMP_CONFLICT}
    if inner_event_id != event.event_id:
        return None, {CloudTrailProbeFailureCode.AMBIGUOUS_CORRELATION}
    if event.event_source != event_source or inner_event_source != event.event_source:
        return None, {CloudTrailProbeFailureCode.SOURCE_MISMATCH}
    if event.event_name not in event_names or inner_event_name != event.event_name:
        return None, {CloudTrailProbeFailureCode.EVENT_NAME_MISMATCH}
    if inner_region != expected_region:
        return None, {CloudTrailProbeFailureCode.REGION_MISMATCH}
    if recipient_account != expected_account or principal_account != expected_account:
        return None, {CloudTrailProbeFailureCode.ACCOUNT_MISMATCH}
    if inner_request_id != request_id:
        return None, {CloudTrailProbeFailureCode.CORRELATION_UNMATCHED}
    if event.event_time < collected_at - max_age:
        return None, {CloudTrailProbeFailureCode.STALE_EVENT}
    if event.event_time > collected_at + clock_skew_tolerance:
        return None, {CloudTrailProbeFailureCode.FUTURE_EVENT}
    if event.event_time < window.start or event.event_time > window.end:
        return None, {CloudTrailProbeFailureCode.EVENT_OUTSIDE_WINDOW}
    return (
        _ParsedEvent(
            event_id=event.event_id,
            event_time=event.event_time,
            event_name=event.event_name,
        ),
        set(),
    )


def _lookup_window(
    *,
    completed_at: datetime,
    collected_at: datetime,
    max_age: timedelta,
    clock_skew_tolerance: timedelta,
) -> _LookupWindow:
    start = max(completed_at - clock_skew_tolerance, collected_at - max_age)
    end = min(
        completed_at + clock_skew_tolerance,
        collected_at + clock_skew_tolerance,
    )
    return _LookupWindow(start=start, end=max(start, end))


def _probe_max_age(
    probe: CloudTrailProbe,
    suite_max_age: timedelta,
) -> timedelta:
    if probe.max_age is None:
        return suite_max_age
    if not isinstance(probe.max_age, str):
        raise CloudTrailProbeError(
            CloudTrailProbeFailureCode.INVALID_CONFIGURATION,
            probe.id,
        )
    parsed = _duration(probe.max_age)
    if parsed is None or not timedelta(0) < parsed <= _MAX_FRESHNESS:
        raise CloudTrailProbeError(
            CloudTrailProbeFailureCode.INVALID_CONFIGURATION,
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


def _valid_event_names(value: object) -> bool:
    return (
        isinstance(value, tuple)
        and 0 < len(value) <= MAX_CLOUDTRAIL_DECLARED_EVENT_NAMES
        and len(value) == len(set(value))
        and all(
            isinstance(item, str) and _EVENT_NAME_PATTERN.fullmatch(item) is not None
            for item in value
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


def _outer_event_time(value: object) -> datetime | None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        return None
    return value.astimezone(UTC)


def _structured_time(value: object) -> datetime | None:
    if not isinstance(value, str) or _EVENT_TIME_PATTERN.fullmatch(value) is None:
        return None
    try:
        return datetime.fromisoformat(f"{value[:-1]}+00:00").astimezone(UTC)
    except ValueError:
        return None


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


def _sdk_failure(error: Exception) -> CloudTrailProbeFailureCode:
    if isinstance(error, TimeoutError) or type(error).__name__ in {
        "ConnectTimeoutError",
        "ReadTimeoutError",
    }:
        return CloudTrailProbeFailureCode.SDK_TIMEOUT
    response = getattr(error, "response", None)
    if isinstance(response, Mapping):
        details = response.get("Error")
        if isinstance(details, Mapping) and details.get("Code") in {
            "AccessDenied",
            "AccessDeniedException",
            "UnauthorizedOperation",
        }:
            return CloudTrailProbeFailureCode.ACCESS_DENIED
    return CloudTrailProbeFailureCode.SDK_ERROR


def _primary_failure(
    failures: frozenset[CloudTrailProbeFailureCode],
) -> CloudTrailProbeFailureCode | None:
    if not failures:
        return None
    specific = failures - {CloudTrailProbeFailureCode.PARTIAL_RESPONSE}
    candidates = specific or failures
    return min(candidates, key=_FAILURE_PRIORITY.__getitem__)


def _ambiguous(failures: frozenset[CloudTrailProbeFailureCode]) -> bool:
    return bool(
        failures
        & {
            CloudTrailProbeFailureCode.AMBIGUOUS_CORRELATION,
            CloudTrailProbeFailureCode.CORRELATION_UNMATCHED,
            CloudTrailProbeFailureCode.EVENT_NAME_MISMATCH,
            CloudTrailProbeFailureCode.EVENT_OUTSIDE_WINDOW,
            CloudTrailProbeFailureCode.REGION_MISMATCH,
            CloudTrailProbeFailureCode.SOURCE_MISMATCH,
            CloudTrailProbeFailureCode.TIMESTAMP_CONFLICT,
        },
    )


def _future_dated(failures: frozenset[CloudTrailProbeFailureCode]) -> bool:
    return bool(
        failures
        & {
            CloudTrailProbeFailureCode.FUTURE_ACTION,
            CloudTrailProbeFailureCode.FUTURE_EVENT,
        },
    )


def _malformed(failures: frozenset[CloudTrailProbeFailureCode]) -> bool:
    return bool(
        failures
        & {
            CloudTrailProbeFailureCode.ACCOUNT_MISMATCH,
            CloudTrailProbeFailureCode.INVALID_EVENT,
            CloudTrailProbeFailureCode.TIMESTAMP_CONFLICT,
        },
    )


def _oversized(failures: frozenset[CloudTrailProbeFailureCode]) -> bool:
    return bool(
        failures
        & {
            CloudTrailProbeFailureCode.OVERSIZED_EVENT,
            CloudTrailProbeFailureCode.TOTAL_BYTES_EXCEEDED,
        },
    )


def _partial(failures: frozenset[CloudTrailProbeFailureCode]) -> bool:
    return bool(
        failures
        & {
            CloudTrailProbeFailureCode.ACCESS_DENIED,
            CloudTrailProbeFailureCode.CORRELATED_EVENT_LIMIT_EXCEEDED,
            CloudTrailProbeFailureCode.EVENT_LIMIT_EXCEEDED,
            CloudTrailProbeFailureCode.EVENT_NAME_LIMIT_EXCEEDED,
            CloudTrailProbeFailureCode.PAGINATION_LIMIT_EXCEEDED,
            CloudTrailProbeFailureCode.PARTIAL_RESPONSE,
            CloudTrailProbeFailureCode.QUERY_TIMEOUT,
            CloudTrailProbeFailureCode.SDK_ERROR,
            CloudTrailProbeFailureCode.SDK_TIMEOUT,
            CloudTrailProbeFailureCode.TOTAL_BYTES_EXCEEDED,
        },
    )


def _stale(failures: frozenset[CloudTrailProbeFailureCode]) -> bool:
    return bool(
        failures
        & {
            CloudTrailProbeFailureCode.STALE_ACTION,
            CloudTrailProbeFailureCode.STALE_EVENT,
        },
    )
