"""Loopback-only synthetic application and telemetry support."""

from cai_verify.local.application import (
    SyntheticAiApplication,
    SyntheticTelemetryMode,
)
from cai_verify.local.identity import SyntheticScopedIdentity
from cai_verify.local.telemetry import (
    AuditRecord,
    LocalTelemetryProbeAdapter,
    LocalTelemetrySink,
    TelemetryRecord,
    pseudonymize_principal,
)

__all__ = [
    "AuditRecord",
    "LocalTelemetryProbeAdapter",
    "LocalTelemetrySink",
    "SyntheticAiApplication",
    "SyntheticScopedIdentity",
    "SyntheticTelemetryMode",
    "TelemetryRecord",
    "pseudonymize_principal",
]
