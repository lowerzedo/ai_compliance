"""Synthetic, test-only implementation of every public plugin Protocol."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta

from cai_verify.config import ControlReference
from cai_verify.core import (
    AssertionResult,
    AssertionStatus,
    AssertionType,
    RedactedValue,
)
from cai_verify.plugins import (
    PLUGIN_API_VERSION,
    ActionExecutionResult,
    ActionOutcome,
    ActionRequest,
    AssertionEvaluationRequest,
    ControlProfile,
    ControlProfileRequest,
    ControlProfileSource,
    EvidenceFreshness,
    EvidenceSource,
    FinalizedManifest,
    IdentityRequest,
    Observation,
    PluginMetadata,
    ProbeRequest,
    ProbeResult,
    ReportArtifact,
    ReportRequest,
    SignatureArtifact,
)

SAMPLE_PLUGIN_NAME = "sample-plugin"
SAMPLE_SECRET = "literal-sample-plugin-secret-must-not-leak"  # noqa: S105
_SAMPLE_TIME = datetime(2026, 7, 22, 12, tzinfo=UTC)


@dataclass(slots=True)
class SampleScopedIdentity:
    """Synthetic closeable identity without credential material."""

    _identity_id: str
    _expires_at: datetime | None
    closed: bool = False

    @property
    def identity_id(self) -> str:
        """Return the configured synthetic identity identifier."""
        return self._identity_id

    @property
    def expires_at(self) -> datetime | None:
        """Return the deterministic synthetic lease expiry."""
        return self._expires_at

    def close(self) -> None:
        """Mark the synthetic lease closed."""
        self.closed = True


@dataclass(frozen=True, slots=True)
class SamplePlugin:
    """Small synthetic implementation used only by plugin contract tests."""

    metadata: PluginMetadata

    def provide_identity(self, request: IdentityRequest, /) -> SampleScopedIdentity:
        """Return a non-secret synthetic identity lease."""
        return SampleScopedIdentity(
            request.identity.id,
            _SAMPLE_TIME + timedelta(minutes=15),
        )

    def execute_action(self, request: ActionRequest, /) -> ActionExecutionResult:
        """Return a deterministic normalized synthetic action result."""
        return ActionExecutionResult(
            action_id=request.action.id,
            outcome=ActionOutcome.SUCCEEDED,
            started_at=_SAMPLE_TIME,
            completed_at=_SAMPLE_TIME + timedelta(seconds=1),
            observed=RedactedValue({"synthetic": True}),
            correlation_ids=("sample-correlation",),
            limitations=("Synthetic test-only action; no target was contacted.",),
        )

    def collect_evidence(self, request: ProbeRequest, /) -> ProbeResult:
        """Return source-attributed, freshness-bounded synthetic evidence."""
        observation_kind = request.probe.observations[0].value
        return ProbeResult(
            probe_id=request.probe.id,
            source=EvidenceSource(name="sample-source", version="1.0.0"),
            freshness=EvidenceFreshness(
                collected_at=_SAMPLE_TIME + timedelta(seconds=2),
                source_time=_SAMPLE_TIME + timedelta(seconds=1),
                max_age=timedelta(minutes=5),
            ),
            observations=(
                Observation(
                    observation_id=f"{request.probe.id}.observation",
                    kind=observation_kind,
                    observed=RedactedValue({"synthetic": True}),
                    limitations=("Synthetic test-only observation.",),
                ),
            ),
        )

    def evaluate_assertion(
        self,
        request: AssertionEvaluationRequest,
        /,
    ) -> AssertionResult:
        """Evaluate only whether the sample request contains probe evidence."""
        evidence_ids = tuple(
            observation.observation_id
            for probe_result in request.probe_results
            for observation in probe_result.observations
        )
        status = AssertionStatus.PASS if evidence_ids else AssertionStatus.INCONCLUSIVE
        return AssertionResult(
            assertion_id=request.assertion.id,
            assertion_type=AssertionType.EVIDENCE_BACKED,
            status=status,
            expected=True,
            observed=RedactedValue(bool(evidence_ids)),
            evidence_ids=evidence_ids,
            limitations=("Synthetic test-only evaluator.",),
            evaluator_version="1.0.0",
            evaluation_started_at=_SAMPLE_TIME,
            evaluation_completed_at=_SAMPLE_TIME,
        )

    def render_report(self, request: ReportRequest, /) -> ReportArtifact:
        """Render detached sample result views as deterministic JSON."""
        payload = [result.to_dict() for result in request.results]
        content = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        return ReportArtifact(media_type="application/json", content=content)

    def sign_manifest(self, manifest: FinalizedManifest, /) -> SignatureArtifact:
        """Return a deterministic test marker, not a cryptographic signature."""
        marker = hashlib.sha256(b"sample:" + manifest.to_bytes()).digest()
        return SignatureArtifact(
            algorithm="sample-sha256-marker",
            key_id="sample-key",
            signature=marker,
        )

    def provide_control_profile(
        self,
        request: ControlProfileRequest,
        /,
    ) -> ControlProfile:
        """Return a clearly synthetic mapping with complete claim boundaries."""
        mapping = ControlReference.model_validate(
            {
                "source": "Synthetic contract-test source",
                "sourceVersion": request.profile_version,
                "reference": "synthetic-control",
                "relationship": "supports-assessment",
                "rationale": "Exercises the provider contract without a real claim.",
                "scope": "Test-only plugin contract behavior.",
                "limitations": [
                    {
                        "id": "synthetic-only",
                        "description": "Not a real compliance mapping.",
                    },
                ],
                "responsibilities": [
                    {
                        "party": "verifier",
                        "description": "Runs the synthetic contract test.",
                    },
                    {
                        "party": "cloudProvider",
                        "description": "No cloud provider participates.",
                    },
                    {
                        "party": "customer",
                        "description": "No customer system is assessed.",
                    },
                ],
                "review": {
                    "reviewedBy": "Synthetic contract test",
                    "reviewedAt": date(2026, 7, 22),
                },
            },
        )
        return ControlProfile(
            profile_id=request.profile_id,
            profile_version=request.profile_version,
            source=ControlProfileSource(
                source_id="Synthetic contract-test source",
                source_version=request.profile_version,
            ),
            mappings=(mapping,),
            limitations=("Synthetic test-only profile; no compliance claim.",),
        )


def create_plugin() -> SamplePlugin:
    """Create the API-compatible synthetic plugin used by entry-point tests."""
    return SamplePlugin(
        metadata=PluginMetadata(
            name=SAMPLE_PLUGIN_NAME,
            api_version=PLUGIN_API_VERSION,
            capabilities=(
                "action.synthetic",
                "assertion.synthetic",
                "identity.synthetic",
                "probe.synthetic",
                "profile.synthetic",
                "report.synthetic-json",
                "sign.synthetic-marker",
            ),
        ),
    )


def create_incompatible_plugin() -> SamplePlugin:
    """Create a syntactically valid plugin for an unsupported API version."""
    return SamplePlugin(
        metadata=PluginMetadata(
            name=SAMPLE_PLUGIN_NAME,
            api_version="2",
            capabilities=("probe.synthetic",),
        ),
    )


def create_failing_plugin() -> SamplePlugin:
    """Raise a secret-bearing error to exercise discovery redaction."""
    raise RuntimeError(SAMPLE_SECRET)


def create_invalid_version_plugin() -> SamplePlugin:
    """Try to place a secret in version metadata to test boundary validation."""
    return SamplePlugin(
        metadata=PluginMetadata(
            name=SAMPLE_PLUGIN_NAME,
            api_version=SAMPLE_SECRET,
            capabilities=("probe.synthetic",),
        ),
    )
