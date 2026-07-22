"""Narrow, versioned contracts shared by in-process plugins.

The records in this module are deliberately transport- and cloud-neutral. They
carry only the normalized values core orchestration needs to coordinate a
plugin. Plugins remain trusted in-process Python code; these contracts prevent
accidental mutation and disclosure but are not a security sandbox.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol, cast, final, runtime_checkable

from cai_verify.core.results import AssertionResult, RedactedValue

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cai_verify.config import (
        Action,
        Assertion,
        ControlReference,
        Identity,
        Probe,
        Target,
    )
    from cai_verify.core.results import JsonValue

PLUGIN_API_VERSION = "1"

_NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_API_VERSION_PATTERN = re.compile(r"[0-9]+(?:\.[0-9]+){0,2}\Z")
_CAPABILITY_PATTERN = re.compile(
    r"[a-z][a-z0-9]*(?:[._:/-][a-z0-9]+)*\Z",
)
_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_MEDIA_TYPE_PATTERN = re.compile(
    r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+\Z",
)


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class PluginMetadata:
    """Compatibility and capability metadata declared by every plugin."""

    name: str
    api_version: str
    capabilities: tuple[str, ...]

    def __post_init__(self) -> None:
        """Validate names and make capability ordering deterministic."""
        _validate_name(self.name, field_name="plugin name")
        if (
            not isinstance(self.api_version, str)
            or _API_VERSION_PATTERN.fullmatch(self.api_version) is None
        ):
            message = "plugin api_version must contain one to three numeric parts"
            raise ValueError(message)
        capabilities = _validate_string_tuple(
            self.capabilities,
            field_name="plugin capabilities",
            allow_empty=False,
            pattern=_CAPABILITY_PATTERN,
        )
        object.__setattr__(self, "capabilities", tuple(sorted(capabilities)))


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionContext:
    """Stable run, scenario, and target context supplied to execution plugins."""

    run_id: str
    scenario_id: str
    target: Target

    def __post_init__(self) -> None:
        """Require evidence-safe identifiers for correlation."""
        _validate_identifier(self.run_id, field_name="run_id")
        _validate_identifier(self.scenario_id, field_name="scenario_id")


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class IdentityRequest:
    """Request for one configured, scenario-scoped identity."""

    context: ExecutionContext
    identity: Identity


@runtime_checkable
class ScopedIdentity(Protocol):
    """Opaque, closeable identity lease returned by an identity provider."""

    @property
    def identity_id(self) -> str:
        """Return the configured identity identifier without secret material."""
        ...

    @property
    def expires_at(self) -> datetime | None:
        """Return the lease expiry when the source supplies one."""
        ...

    def close(self) -> None:
        """Release or invalidate transient identity material."""
        ...


class ActionOutcome(StrEnum):
    """Transport-neutral outcome of an attempted declared action."""

    SUCCEEDED = "SUCCEEDED"
    DENIED = "DENIED"
    ERROR = "ERROR"


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class ActionExecutionResult:
    """Normalized action result safe to pass to probes and evaluators."""

    action_id: str
    outcome: ActionOutcome
    started_at: datetime
    completed_at: datetime
    observed: RedactedValue
    correlation_ids: tuple[str, ...]
    limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        """Validate timing and normalized, non-secret output metadata."""
        _validate_identifier(self.action_id, field_name="action_id")
        if not isinstance(self.outcome, ActionOutcome):
            message = "outcome must be an ActionOutcome"
            raise TypeError(message)
        if type(self.observed) is not RedactedValue:
            message = "observed must be a RedactedValue"
            raise TypeError(message)
        started_at = _normalize_timestamp(self.started_at, field_name="started_at")
        completed_at = _normalize_timestamp(
            self.completed_at,
            field_name="completed_at",
        )
        if completed_at < started_at:
            message = "completed_at cannot precede started_at"
            raise ValueError(message)
        object.__setattr__(self, "started_at", started_at)
        object.__setattr__(self, "completed_at", completed_at)
        correlation_ids = _validate_string_tuple(
            self.correlation_ids,
            field_name="correlation_ids",
            allow_empty=True,
            pattern=_IDENTIFIER_PATTERN,
        )
        limitations = _validate_string_tuple(
            self.limitations,
            field_name="limitations",
            allow_empty=False,
        )
        object.__setattr__(self, "correlation_ids", tuple(sorted(correlation_ids)))
        object.__setattr__(self, "limitations", tuple(sorted(limitations)))


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class ActionRequest:
    """One declared action and the scoped identity used to perform it."""

    context: ExecutionContext
    action: Action
    identity: ScopedIdentity


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceSource:
    """Adapter and source version provenance reported by an evidence probe."""

    name: str
    version: str

    def __post_init__(self) -> None:
        """Validate source provenance without accepting ambiguous blanks."""
        _validate_name(self.name, field_name="evidence source name")
        _validate_nonempty_string(self.version, field_name="evidence source version")


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class EvidenceFreshness:
    """Times and freshness limit a probe reports for core evaluation."""

    collected_at: datetime
    source_time: datetime | None
    max_age: timedelta

    def __post_init__(self) -> None:
        """Normalize timestamps while leaving freshness decisions to core."""
        collected_at = _normalize_timestamp(
            self.collected_at,
            field_name="collected_at",
        )
        source_time = self.source_time
        if source_time is not None:
            source_time = _normalize_timestamp(source_time, field_name="source_time")
        if not isinstance(self.max_age, timedelta):
            message = "max_age must be a timedelta"
            raise TypeError(message)
        if self.max_age <= timedelta(0):
            message = "max_age must be positive"
            raise ValueError(message)
        object.__setattr__(self, "collected_at", collected_at)
        object.__setattr__(self, "source_time", source_time)

    @property
    def freshness_limit(self) -> datetime:
        """Return the reported freshness boundary without deciding status."""
        anchor = self.source_time or self.collected_at
        return anchor + self.max_age


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class Observation:
    """One normalized and explicitly redacted fact returned by a probe."""

    observation_id: str
    kind: str
    observed: RedactedValue
    limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        """Validate normalized observation metadata."""
        _validate_identifier(self.observation_id, field_name="observation_id")
        _validate_identifier(self.kind, field_name="observation kind")
        if type(self.observed) is not RedactedValue:
            message = "observed must be a RedactedValue"
            raise TypeError(message)
        limitations = _validate_string_tuple(
            self.limitations,
            field_name="limitations",
            allow_empty=False,
        )
        object.__setattr__(self, "limitations", tuple(sorted(limitations)))


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class ProbeResult:
    """A probe's normalized observations with mandatory source and freshness."""

    probe_id: str
    source: EvidenceSource
    freshness: EvidenceFreshness
    observations: tuple[Observation, ...]

    def __post_init__(self) -> None:
        """Reject ambiguous provenance or mutable observation collections."""
        _validate_identifier(self.probe_id, field_name="probe_id")
        if type(self.source) is not EvidenceSource:
            message = "source must be EvidenceSource"
            raise TypeError(message)
        if type(self.freshness) is not EvidenceFreshness:
            message = "freshness must be EvidenceFreshness"
            raise TypeError(message)
        if not isinstance(self.observations, tuple) or not all(
            type(item) is Observation for item in self.observations
        ):
            message = "observations must be a tuple of Observation values"
            raise TypeError(message)


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class ProbeRequest:
    """A declared probe correlated with one completed action."""

    context: ExecutionContext
    probe: Probe
    action_result: ActionExecutionResult
    identity: ScopedIdentity


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class AssertionEvaluationRequest:
    """Immutable normalized inputs supplied to a deterministic evaluator."""

    assertion: Assertion
    action_results: tuple[ActionExecutionResult, ...]
    probe_results: tuple[ProbeResult, ...]

    def __post_init__(self) -> None:
        """Require tuples of the exact normalized result types."""
        if not isinstance(self.action_results, tuple) or not all(
            type(item) is ActionExecutionResult for item in self.action_results
        ):
            message = "action_results must be a tuple of ActionExecutionResult values"
            raise TypeError(message)
        if not isinstance(self.probe_results, tuple) or not all(
            type(item) is ProbeResult for item in self.probe_results
        ):
            message = "probe_results must be a tuple of ProbeResult values"
            raise TypeError(message)


@final
@dataclass(frozen=True, slots=True, init=False)
class ReportResultView:
    """Detached, immutable serialization view provided to reporters."""

    _canonical_json: bytes = field(repr=False)

    def __init__(self, result: AssertionResult) -> None:
        """Snapshot one validated result without sharing nested containers."""
        if type(result) is not AssertionResult:
            message = "result must be an AssertionResult"
            raise TypeError(message)
        object.__setattr__(self, "_canonical_json", result.to_json_bytes())

    def to_dict(self) -> dict[str, JsonValue]:
        """Return a new, detached mapping for each reporter access."""
        decoded: object = json.loads(self._canonical_json)
        if not isinstance(decoded, dict):
            message = "stored assertion result is not a JSON object"
            raise TypeError(message)
        return cast("dict[str, JsonValue]", decoded)

    def to_json_bytes(self) -> bytes:
        """Return the canonical immutable bytes of the result snapshot."""
        return self._canonical_json


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class ReportRequest:
    """Detached assertion-result snapshots supplied to a reporter."""

    run_id: str
    results: tuple[ReportResultView, ...]

    def __post_init__(self) -> None:
        """Validate the run correlation and immutable result collection."""
        _validate_identifier(self.run_id, field_name="run_id")
        if not isinstance(self.results, tuple) or not all(
            type(item) is ReportResultView for item in self.results
        ):
            message = "results must be a tuple of ReportResultView values"
            raise TypeError(message)

    @classmethod
    def from_results(
        cls,
        *,
        run_id: str,
        results: Iterable[AssertionResult],
    ) -> ReportRequest:
        """Detach assertion results before any reporter receives them."""
        return cls(
            run_id=run_id,
            results=tuple(ReportResultView(result) for result in results),
        )


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class ReportArtifact:
    """Rendered report bytes and their declared media type."""

    media_type: str
    content: bytes

    def __post_init__(self) -> None:
        """Keep report output immutable and explicitly typed."""
        if (
            not isinstance(self.media_type, str)
            or _MEDIA_TYPE_PATTERN.fullmatch(self.media_type) is None
        ):
            message = "media_type must be a lowercase type/subtype"
            raise ValueError(message)
        if not isinstance(self.content, bytes):
            message = "content must be bytes"
            raise TypeError(message)


@final
@dataclass(frozen=True, slots=True, init=False)
class FinalizedManifest:
    """Immutable manifest bytes eligible for signing."""

    _canonical_bytes: bytes = field(repr=False)
    sha256: str

    def __init__(self, canonical_bytes: bytes) -> None:
        """Copy finalized bytes and bind them to their SHA-256 digest."""
        if not isinstance(canonical_bytes, bytes):
            message = "canonical_bytes must be bytes"
            raise TypeError(message)
        if not canonical_bytes:
            message = "canonical_bytes must not be empty"
            raise ValueError(message)
        detached = bytes(canonical_bytes)
        object.__setattr__(self, "_canonical_bytes", detached)
        object.__setattr__(self, "sha256", hashlib.sha256(detached).hexdigest())

    def to_bytes(self) -> bytes:
        """Return the immutable exact bytes covered by the digest."""
        return self._canonical_bytes


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class SignatureArtifact:
    """Detached signature returned for one finalized manifest."""

    algorithm: str
    key_id: str
    signature: bytes

    def __post_init__(self) -> None:
        """Validate public signature metadata and immutable signature bytes."""
        _validate_identifier(self.algorithm, field_name="signature algorithm")
        _validate_identifier(self.key_id, field_name="signature key_id")
        if not isinstance(self.signature, bytes):
            message = "signature must be bytes"
            raise TypeError(message)
        if not self.signature:
            message = "signature must not be empty"
            raise ValueError(message)


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class ControlProfileRequest:
    """Request for one exact version of a control profile."""

    profile_id: str
    profile_version: str

    def __post_init__(self) -> None:
        """Require an unambiguous profile identity and version."""
        _validate_identifier(self.profile_id, field_name="profile_id")
        _validate_nonempty_string(
            self.profile_version,
            field_name="profile_version",
        )


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class ControlProfileSource:
    """Official source identity and version underlying a control profile."""

    source_id: str
    source_version: str

    def __post_init__(self) -> None:
        """Reject profiles with missing source provenance."""
        _validate_nonempty_string(self.source_id, field_name="source_id")
        _validate_nonempty_string(self.source_version, field_name="source_version")


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class ControlProfile:
    """Versioned mappings and limitations supplied by a profile plugin."""

    profile_id: str
    profile_version: str
    source: ControlProfileSource
    mappings: tuple[ControlReference, ...]
    limitations: tuple[str, ...]

    def __post_init__(self) -> None:
        """Require explicit profile provenance, mappings, and limitations."""
        _validate_identifier(self.profile_id, field_name="profile_id")
        _validate_nonempty_string(
            self.profile_version,
            field_name="profile_version",
        )
        if type(self.source) is not ControlProfileSource:
            message = "source must be ControlProfileSource"
            raise TypeError(message)
        if not isinstance(self.mappings, tuple) or not self.mappings:
            message = "mappings must be a non-empty tuple"
            raise TypeError(message)
        limitations = _validate_string_tuple(
            self.limitations,
            field_name="limitations",
            allow_empty=False,
        )
        object.__setattr__(self, "limitations", tuple(sorted(limitations)))


@runtime_checkable
class IdentityProvider(Protocol):
    """Obtain a scoped identity lease for one configured identity."""

    @property
    def metadata(self) -> PluginMetadata:
        """Return compatibility and supported-capability metadata."""
        ...

    def provide_identity(self, request: IdentityRequest, /) -> ScopedIdentity:
        """Obtain the requested identity without serializing its secrets."""
        ...


@runtime_checkable
class ActionExecutor(Protocol):
    """Perform one bounded, declared action under a scoped identity."""

    @property
    def metadata(self) -> PluginMetadata:
        """Return compatibility and supported-capability metadata."""
        ...

    def execute_action(self, request: ActionRequest, /) -> ActionExecutionResult:
        """Execute and normalize one declared action."""
        ...


@runtime_checkable
class EvidenceProbe(Protocol):
    """Collect normalized observations with source and freshness metadata."""

    @property
    def metadata(self) -> PluginMetadata:
        """Return compatibility and supported-capability metadata."""
        ...

    def collect_evidence(self, request: ProbeRequest, /) -> ProbeResult:
        """Collect source-attributed observations for one declared probe."""
        ...


@runtime_checkable
class AssertionEvaluator(Protocol):
    """Deterministically evaluate normalized action and probe results."""

    @property
    def metadata(self) -> PluginMetadata:
        """Return compatibility and supported-capability metadata."""
        ...

    def evaluate_assertion(
        self,
        request: AssertionEvaluationRequest,
        /,
    ) -> AssertionResult:
        """Evaluate one assertion without network or target side effects."""
        ...


@runtime_checkable
class Reporter(Protocol):
    """Render detached existing results without access to mutable originals."""

    @property
    def metadata(self) -> PluginMetadata:
        """Return compatibility and supported-capability metadata."""
        ...

    def render_report(self, request: ReportRequest, /) -> ReportArtifact:
        """Render immutable result snapshots into one report artifact."""
        ...


@runtime_checkable
class Signer(Protocol):
    """Sign only an explicitly finalized manifest value."""

    @property
    def metadata(self) -> PluginMetadata:
        """Return compatibility and supported-capability metadata."""
        ...

    def sign_manifest(self, manifest: FinalizedManifest, /) -> SignatureArtifact:
        """Return a signature over the manifest's exact finalized bytes."""
        ...


@runtime_checkable
class ControlProfileProvider(Protocol):
    """Supply exact-version control mappings and official source metadata."""

    @property
    def metadata(self) -> PluginMetadata:
        """Return compatibility and supported-capability metadata."""
        ...

    def provide_control_profile(
        self,
        request: ControlProfileRequest,
        /,
    ) -> ControlProfile:
        """Return one versioned profile with mapping provenance."""
        ...


def _validate_name(value: object, *, field_name: str) -> None:
    if not isinstance(value, str) or _NAME_PATTERN.fullmatch(value) is None:
        message = f"{field_name} must be a lowercase plugin name"
        raise ValueError(message)


def _validate_identifier(value: object, *, field_name: str) -> None:
    if not isinstance(value, str) or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        message = f"{field_name} must be a valid identifier"
        raise ValueError(message)


def _validate_nonempty_string(value: object, *, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        message = f"{field_name} must be a non-empty string"
        raise ValueError(message)


def _validate_string_tuple(
    value: object,
    *,
    field_name: str,
    allow_empty: bool,
    pattern: re.Pattern[str] | None = None,
) -> tuple[str, ...]:
    if not isinstance(value, tuple) or not all(isinstance(item, str) for item in value):
        message = f"{field_name} must be a tuple of strings"
        raise TypeError(message)
    if not allow_empty and not value:
        message = f"{field_name} must contain at least one value"
        raise ValueError(message)
    if len(value) != len(set(value)):
        message = f"{field_name} must not contain duplicates"
        raise ValueError(message)
    for item in value:
        if not item.strip() or (
            pattern is not None and pattern.fullmatch(item) is None
        ):
            message = f"{field_name} contains an invalid value"
            raise ValueError(message)
    return value


def _normalize_timestamp(value: object, *, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        message = f"{field_name} must be a datetime"
        raise TypeError(message)
    if value.tzinfo is None or value.utcoffset() is None:
        message = f"{field_name} must include a UTC offset"
        raise ValueError(message)
    return value.astimezone(UTC)
