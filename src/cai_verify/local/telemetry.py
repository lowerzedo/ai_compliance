"""Bounded synthetic telemetry storage and normalized local probing."""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, final

from cai_verify.config import LocalTelemetryProbe
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
    from datetime import timedelta

_MAX_RECORDS = 1_000
_MAX_RECORD_TEXT = 4_096
_PSEUDONYM_DOMAIN = b"cai-verify-local-principal-v1\0"
_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class TelemetryRecord:
    """One bounded application telemetry message."""

    correlation_id: str
    message: str = field(repr=False)
    occurred_at: datetime

    def __post_init__(self) -> None:
        """Reject malformed or unbounded local telemetry records."""
        _validate_identifier(self.correlation_id, field_name="correlation_id")
        if (
            not isinstance(self.message, str)
            or not self.message
            or len(self.message) > _MAX_RECORD_TEXT
        ):
            message = "telemetry message must be bounded non-empty text"
            raise ValueError(message)
        _validate_timestamp(self.occurred_at)


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class AuditRecord:
    """One local audit record kept separately from application telemetry."""

    correlation_id: str
    event_name: str
    principal: str = field(repr=False)
    occurred_at: datetime

    def __post_init__(self) -> None:
        """Reject malformed audit correlation and principal values."""
        _validate_identifier(self.correlation_id, field_name="correlation_id")
        _validate_identifier(self.event_name, field_name="event_name")
        _validate_identifier(self.principal, field_name="principal")
        _validate_timestamp(self.occurred_at)


@final
class LocalTelemetrySink:
    """Thread-safe, process-local sink with a hard record limit."""

    def __init__(self) -> None:
        """Create an empty sink whose state is private to this process."""
        self._telemetry: list[TelemetryRecord] = []
        self._audit: list[AuditRecord] = []
        self._lock = threading.Lock()

    def record_telemetry(self, record: TelemetryRecord) -> None:
        """Append one validated telemetry record or fail closed when full."""
        if type(record) is not TelemetryRecord:
            message = "record must be a TelemetryRecord"
            raise TypeError(message)
        with self._lock:
            if len(self._telemetry) >= _MAX_RECORDS:
                message = "local telemetry record limit reached"
                raise RuntimeError(message)
            self._telemetry.append(record)

    def record_audit(self, record: AuditRecord) -> None:
        """Append one validated audit record or fail closed when full."""
        if type(record) is not AuditRecord:
            message = "record must be an AuditRecord"
            raise TypeError(message)
        with self._lock:
            if len(self._audit) >= _MAX_RECORDS:
                message = "local audit record limit reached"
                raise RuntimeError(message)
            self._audit.append(record)

    def snapshot(self) -> tuple[tuple[TelemetryRecord, ...], tuple[AuditRecord, ...]]:
        """Return detached immutable record collections."""
        with self._lock:
            return tuple(self._telemetry), tuple(self._audit)


@final
@dataclass(frozen=True, slots=True)
class LocalTelemetryProbeAdapter:
    """Normalize a synthetic sink without exposing raw telemetry text."""

    sink: LocalTelemetrySink
    canary: str = field(repr=False)
    collected_at: datetime
    max_age: timedelta

    @property
    def metadata(self) -> PluginMetadata:
        """Declare the exact local probe capability."""
        return PluginMetadata(
            name="local-telemetry-probe",
            api_version=PLUGIN_API_VERSION,
            capabilities=("probe.local-telemetry",),
        )

    def collect_evidence(self, request: ProbeRequest, /) -> ProbeResult:
        """Return canary presence and pseudonymous correlated audit records."""
        if not isinstance(request.probe, LocalTelemetryProbe):
            message = "local telemetry probe requires a localTelemetry declaration"
            raise TypeError(message)
        if request.probe.action_ref != request.action_result.action_id:
            message = "local telemetry probe action reference does not match its result"
            raise ValueError(message)
        telemetry, audit = self.sink.snapshot()
        correlations = set(request.action_result.correlation_ids)
        correlated_telemetry = tuple(
            record for record in telemetry if record.correlation_id in correlations
        )
        correlated_audit = tuple(
            record for record in audit if record.correlation_id in correlations
        )
        observations: list[Observation] = []
        for kind in request.probe.observations:
            if kind is ObservationKind.TELEMETRY_CANARY:
                observations.append(
                    Observation(
                        observation_id=f"{request.probe.id}.telemetry-canary",
                        kind=kind.value,
                        observed=RedactedValue(
                            {
                                "present": any(
                                    self.canary in record.message
                                    for record in correlated_telemetry
                                ),
                                "records_considered": len(correlated_telemetry),
                            },
                        ),
                        limitations=(
                            "Checks one explicitly synthetic canary in the local sink.",
                        ),
                    ),
                )
            elif kind is ObservationKind.AUDIT_EVENT:
                events: list[JsonValue] = [
                    {
                        "correlation_id": record.correlation_id,
                        "event_name": record.event_name,
                        "principal_pseudonym": pseudonymize_principal(
                            record.principal,
                        ),
                    }
                    for record in sorted(
                        correlated_audit,
                        key=lambda item: (
                            item.correlation_id,
                            item.event_name,
                            item.principal,
                        ),
                    )
                ]
                observations.append(
                    Observation(
                        observation_id=f"{request.probe.id}.audit-event",
                        kind=kind.value,
                        observed=RedactedValue({"events": events}),
                        limitations=(
                            "Audit principals are deterministic synthetic pseudonyms.",
                        ),
                    ),
                )

        source_times = [record.occurred_at for record in correlated_telemetry]
        source_times.extend(record.occurred_at for record in correlated_audit)
        return ProbeResult(
            probe_id=request.probe.id,
            source=EvidenceSource(
                name="local-synthetic-telemetry",
                version="1.0.0",
            ),
            freshness=EvidenceFreshness(
                collected_at=self.collected_at,
                source_time=min(source_times) if source_times else None,
                max_age=self.max_age,
            ),
            observations=tuple(observations),
        )


def pseudonymize_principal(principal: str) -> str:
    """Return a stable synthetic-demo pseudonym, never the source principal."""
    if not isinstance(principal, str) or not principal:
        message = "principal must be a non-empty string"
        raise ValueError(message)
    digest = hashlib.sha256(_PSEUDONYM_DOMAIN + principal.encode()).hexdigest()
    return f"principal-{digest[:16]}"


def _validate_identifier(value: object, *, field_name: str) -> None:
    if not isinstance(value, str) or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        message = f"{field_name} must be a valid identifier"
        raise ValueError(message)


def _validate_timestamp(value: object) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        message = "occurred_at must include a UTC offset"
        raise ValueError(message)
