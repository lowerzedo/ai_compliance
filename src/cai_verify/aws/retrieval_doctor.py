"""Bounded readiness preflight for declared retrieval-boundary chains."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, TypeGuard, cast, final

from cai_verify.aws._retrieval_canary import (
    retrieval_canaries_are_distinct,
    validated_retrieval_canary,
)
from cai_verify.aws.cloudwatch_logs import (
    MAX_BEDROCK_MODEL_ID_BYTES,
    MAX_CLOUDWATCH_EVENT_BYTES,
    _model_id_bytes,
    _valid_model_alias,
)
from cai_verify.aws.identity import (
    AssumedRoleAwsIdentityProvider,
    AwsIdentityError,
    AwsScopedIdentity,
    AwsSessionFactory,
    Boto3AwsSessionFactory,
    CurrentAwsIdentityProvider,
    _AwsSdkUnavailableError,
    _partition_for_region,
)
from cai_verify.config import (
    AssumedRoleIdentity,
    AwsSigV4Action,
    CloudWatchLogsProbe,
    CurrentAwsIdentity,
    EnvironmentReference,
    RetrievalBoundaryAssertion,
    RetrievalCanaryDeclaration,
    VerificationSuite,
)
from cai_verify.config.models import (
    DeploymentEnvironment,
    InputLocation,
    ObservationKind,
)
from cai_verify.plugins import ExecutionContext, IdentityRequest

if TYPE_CHECKING:
    from collections.abc import Callable

    from cai_verify.config import Action, Identity

RETRIEVAL_DOCTOR_SCHEMA_VERSION = "1"
MAX_RETRIEVAL_DOCTOR_SECONDS = 30.0
MAX_RETRIEVAL_ASSERTIONS = 32
MAX_RETRIEVAL_IDENTITIES = 16
MAX_RETRIEVAL_SOURCES = 16
MAX_RETRIEVAL_RETURNED_EVENTS = 1
MAX_RETRIEVAL_RETURNED_MESSAGE_BYTES = 4 * 1024
MAX_RETRIEVAL_RETURNED_TOKEN_BYTES = 8 * 1024
MAX_RETRIEVAL_RETURNED_TEXT_BYTES = 64 * 1024
MAX_RETRIEVAL_FINDINGS = 128

_HTTP_OK = 200
_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_AWS_REGION_PATTERN = re.compile(r"[a-z]{2}(?:-gov)?-[a-z]+-\d\Z")
_LOG_GROUP_PATTERN = re.compile(r"[A-Za-z0-9_./#-]{1,512}\Z")
_FIXED_FILTER_PATTERN = (
    '{ $.schemaVersion = "__cai_verify_retrieval_doctor_nonmatch_v1__" }'
)
_RESERVED_CORRELATION_HEADER = "x-cai-correlation-id"
_RESPONSE_FIELDS = frozenset(
    {"ResponseMetadata", "events", "nextToken", "searchedLogStreams"}
)
_EVENT_FIELDS = frozenset(
    {"eventId", "ingestionTime", "logStreamName", "message", "timestamp"}
)
_SEARCHED_STREAM_FIELDS = frozenset({"logStreamName", "searchedCompletely"})
_RESPONSE_METADATA_FIELDS = frozenset(
    {"HTTPHeaders", "HTTPStatusCode", "HostId", "RequestId", "RetryAttempts"}
)
_RUNTIME_REQUIREMENTS = (
    "baseline_document_retrievability",
    "boundary_document_exclusion",
    "complete_fresh_evidence",
    "exact_action_correlation_echo",
    "exactly_correlated_pre_generation_telemetry",
)
_LIMITATIONS = (
    "READY TO ATTEMPT means only that the declared retrieval chain passed "
    "configuration, identity, canary, and CloudWatch Logs access preflight.",
    "The doctor does not execute or sign an application request and does not "
    "establish runtime correlation.",
    "The doctor does not establish telemetry emission, canary-document "
    "existence, retrieval execution, complete context scanning, tenant "
    "isolation, or compliance.",
    "A later execution must collect complete fresh evidence and evaluate the "
    "declared retrieval boundary.",
)


class RetrievalDoctorIssueCode(StrEnum):
    """Stable non-secret retrieval readiness finding categories."""

    RETRIEVAL_CHECKS_MISSING = "retrieval_checks_missing"
    INVALID_CONFIGURATION = "invalid_configuration"
    UNSUPPORTED_ACTION = "unsupported_action"
    CORRELATION_INCOMPATIBLE = "correlation_incompatible"
    ENVIRONMENT_VALUE_MISSING = "environment_value_missing"
    ENVIRONMENT_VALUE_INVALID = "environment_value_invalid"
    CANARY_VALUES_NOT_DISTINCT = "canary_values_not_distinct"
    IDENTITY_ACQUISITION_FAILED = "identity_acquisition_failed"
    IDENTITY_EXPIRED = "identity_expired"
    ACCOUNT_MISMATCH = "account_mismatch"
    PARTITION_MISMATCH = "partition_mismatch"
    SOURCE_NOT_FOUND = "source_not_found"
    ACCESS_DENIED = "access_denied"
    SDK_TIMEOUT = "sdk_timeout"
    THROTTLED = "throttled"
    SDK_UNAVAILABLE = "aws_sdk_unavailable"
    INVALID_AWS_RESPONSE = "invalid_aws_response"
    RESPONSE_OVERSIZED = "response_oversized"
    SDK_ERROR = "sdk_error"
    LIMIT_EXCEEDED = "limit_exceeded"
    DURATION_EXCEEDED = "duration_exceeded"
    NOT_CHECKED_DUE_TO_LIMIT = "not_checked_due_to_limit"


class RetrievalCorrelationState(StrEnum):
    """Static correlation compatibility without a runtime claim."""

    RUNTIME_REQUIRED = "runtime_required"
    INCOMPATIBLE = "incompatible"


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class RetrievalReadinessCheck:
    """One selected scenario-local retrieval chain's safe readiness state."""

    scenario_id: str
    assertion_id: str
    action_id: str
    probe_id: str
    configuration_compatible: bool
    action_identity_ready: bool | None
    evidence_identity_ready: bool | None
    canary_contract_ready: bool
    source_accessible: bool | None
    correlation_state: RetrievalCorrelationState
    issues: tuple[RetrievalDoctorIssueCode, ...]

    @property
    def ready(self) -> bool:
        """Return whether this chain is ready for a later execution attempt."""
        return (
            self.configuration_compatible
            and self.action_identity_ready is True
            and self.evidence_identity_ready is True
            and self.canary_contract_ready
            and self.source_accessible is True
            and self.correlation_state is RetrievalCorrelationState.RUNTIME_REQUIRED
            and not self.issues
        )

    def to_dict(self) -> dict[str, object]:
        """Return the fixed machine-readable check shape."""
        return {
            "action_id": self.action_id,
            "action_identity_ready": self.action_identity_ready,
            "assertion_id": self.assertion_id,
            "canary_contract_ready": self.canary_contract_ready,
            "configuration_compatible": self.configuration_compatible,
            "correlation_state": self.correlation_state.value,
            "evidence_identity_ready": self.evidence_identity_ready,
            "issues": [issue.value for issue in self.issues],
            "probe_id": self.probe_id,
            "scenario_id": self.scenario_id,
            "source_accessible": self.source_accessible,
        }


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class RetrievalDoctorResult:
    """Version-1 readiness result, separate from verification evidence."""

    target_id: str
    target_environment: str
    region: str | None
    ready: bool
    checks: tuple[RetrievalReadinessCheck, ...]
    issues: tuple[RetrievalDoctorIssueCode, ...]
    runtime_requirements: tuple[str, ...] = _RUNTIME_REQUIREMENTS
    limitations: tuple[str, ...] = _LIMITATIONS

    def to_dict(self) -> dict[str, object]:
        """Return the complete deterministic public report."""
        return {
            "checks": [check.to_dict() for check in self.checks],
            "issues": [issue.value for issue in self.issues],
            "limitations": list(self.limitations),
            "ready": self.ready,
            "region": self.region,
            "runtime_requirements": list(self.runtime_requirements),
            "schema_version": RETRIEVAL_DOCTOR_SCHEMA_VERSION,
            "target_environment": self.target_environment,
            "target_id": self.target_id,
        }

    def to_json_bytes(self) -> bytes:
        """Render canonical JSON without a trailing newline."""
        return json.dumps(
            self.to_dict(),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()

    def to_terminal_bytes(self) -> bytes:
        """Render deterministic text without secret or source-location values."""
        state = "READY TO ATTEMPT" if self.ready else "NOT READY"
        region = self.region or "-"
        lines = [
            f"Retrieval doctor: {state}",
            f"Target: {self.target_id} ({self.target_environment}, {region})",
        ]
        lines.extend(f"Issue: {issue.value}" for issue in self.issues)
        for check in self.checks:
            lines.append(f"Chain: {check.scenario_id} / {check.assertion_id}")
            lines.append(f"  action: {check.action_id}")
            lines.append(f"  probe: {check.probe_id}")
            lines.append(
                "  configuration compatibility: "
                f"{_readiness_text(value=check.configuration_compatible)}"
            )
            lines.append(
                "  action identity readiness: "
                f"{_readiness_text(value=check.action_identity_ready)}"
            )
            lines.append(
                "  evidence identity readiness: "
                f"{_readiness_text(value=check.evidence_identity_ready)}"
            )
            lines.append(
                "  canary contract readiness: "
                f"{_readiness_text(value=check.canary_contract_ready)}"
            )
            lines.append(
                "  source accessibility: "
                f"{_readiness_text(value=check.source_accessible)}"
            )
            lines.append(f"  correlation: {check.correlation_state.value}")
            lines.extend(f"  issue: {issue.value}" for issue in check.issues)
        lines.append("Runtime requirements:")
        lines.extend(f"- {item}" for item in self.runtime_requirements)
        lines.append("Limitations:")
        lines.extend(f"- {item}" for item in self.limitations)
        return ("\n".join(lines) + "\n").encode()


@dataclass(slots=True, repr=False)
class _Chain:
    scenario_id: str
    assertion_id: str
    action_id: str
    probe_id: str
    scenario: object = field(repr=False)
    assertion: RetrievalBoundaryAssertion = field(repr=False)
    action: Action | None = field(default=None, repr=False)
    probe: CloudWatchLogsProbe | None = field(default=None, repr=False)
    action_identity_ref: str | None = field(default=None, repr=False)
    evidence_identity_ref: str | None = field(default=None, repr=False)
    action_identity: Identity | None = field(default=None, repr=False)
    evidence_identity: Identity | None = field(default=None, repr=False)
    source_key: tuple[str, str, str] | None = field(default=None, repr=False)
    configuration_compatible: bool = False
    canary_contract_ready: bool = False
    correlation_state: RetrievalCorrelationState = (
        RetrievalCorrelationState.INCOMPATIBLE
    )
    issues: set[RetrievalDoctorIssueCode] = field(default_factory=set, repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class _IdentityState:
    ready: bool
    issue: RetrievalDoctorIssueCode | None


@dataclass(frozen=True, slots=True, repr=False)
class _SourceState:
    accessible: bool
    issue: RetrievalDoctorIssueCode | None


def run_retrieval_doctor(  # noqa: C901, PLR0912, PLR0915
    suite: VerificationSuite,
    *,
    environment: Mapping[str, str],
    session_factory: AwsSessionFactory | None = None,
    clock: Callable[[], datetime] | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> RetrievalDoctorResult:
    """Preflight selected retrieval chains without executing an application."""
    now = _normalized_time((clock or _utc_now)())
    started = monotonic()
    target_id, target_environment, region = _safe_target_fields(suite)
    chains, selection_overflow = _select_chains(suite)
    top_issues: set[RetrievalDoctorIssueCode] = set()
    if not chains:
        top_issues.add(RetrievalDoctorIssueCode.RETRIEVAL_CHECKS_MISSING)
        return _result(
            target_id=target_id,
            target_environment=target_environment,
            region=region,
            chains=(),
            identity_states={},
            source_states={},
            issues=top_issues,
        )

    identities_by_id = _identities_by_id(suite)
    for chain in chains:
        _resolve_chain(
            chain,
            suite=suite,
            identities_by_id=identities_by_id,
            environment=environment,
            region=region,
        )

    relevant_identity_ids = {
        identity_ref
        for chain in chains
        for identity_ref in (
            chain.action_identity_ref,
            chain.evidence_identity_ref,
        )
        if identity_ref is not None
    }
    source_keys = {chain.source_key for chain in chains if chain.source_key is not None}
    eligible_source_keys = {
        chain.source_key
        for chain in chains
        if chain.source_key is not None
        and chain.configuration_compatible
        and chain.canary_contract_ready
        and chain.correlation_state is RetrievalCorrelationState.RUNTIME_REQUIRED
    }
    preflight_finding_count = sum(len(chain.issues) for chain in chains)
    limit_exceeded = (
        selection_overflow
        or len(relevant_identity_ids) > MAX_RETRIEVAL_IDENTITIES
        or len(source_keys) > MAX_RETRIEVAL_SOURCES
        or preflight_finding_count > MAX_RETRIEVAL_FINDINGS
    )
    if limit_exceeded:
        top_issues.add(RetrievalDoctorIssueCode.LIMIT_EXCEEDED)
        _mark_not_checked(chains)
        return _result(
            target_id=target_id,
            target_environment=target_environment,
            region=region,
            chains=chains,
            identity_states={},
            source_states={},
            issues=top_issues,
        )
    if _duration_limit_reached(monotonic, started):
        top_issues.add(RetrievalDoctorIssueCode.DURATION_EXCEEDED)
        _mark_not_checked(chains)
        return _result(
            target_id=target_id,
            target_environment=target_environment,
            region=region,
            chains=chains,
            identity_states={},
            source_states={},
            issues=top_issues,
        )

    factory = session_factory or Boto3AwsSessionFactory()
    leases: dict[str, AwsScopedIdentity] = {}
    identity_states: dict[str, _IdentityState] = {}
    source_states: dict[tuple[str, str, str], _SourceState] = {}
    duration_exceeded = False
    try:
        for identity_id in sorted(relevant_identity_ids):
            if _duration_limit_reached(monotonic, started):
                duration_exceeded = True
                break
            identity = identities_by_id.get(identity_id)
            if identity is None or not isinstance(
                identity,
                CurrentAwsIdentity | AssumedRoleIdentity,
            ):
                identity_states[identity_id] = _IdentityState(
                    ready=False,
                    issue=RetrievalDoctorIssueCode.INVALID_CONFIGURATION,
                )
                continue
            identity_environment_issue = _identity_environment_issue(
                identity,
                environment,
            )
            if identity_environment_issue is not None:
                identity_states[identity_id] = _IdentityState(
                    ready=False,
                    issue=identity_environment_issue,
                )
                continue
            lease, state = _acquire_identity(
                identity,
                suite=suite,
                environment=environment,
                session_factory=factory,
                evaluated_at=now,
            )
            identity_states[identity_id] = state
            if lease is not None:
                leases[identity_id] = lease
            if (
                _projected_finding_count(chains, identity_states)
                > MAX_RETRIEVAL_FINDINGS
            ):
                top_issues.add(RetrievalDoctorIssueCode.LIMIT_EXCEEDED)
                _mark_not_checked(chains)
                break
            if _duration_limit_reached(monotonic, started):
                duration_exceeded = True
                break

        projected_findings = _projected_finding_count(chains, identity_states)
        if projected_findings > MAX_RETRIEVAL_FINDINGS:
            top_issues.add(RetrievalDoctorIssueCode.LIMIT_EXCEEDED)
            _mark_not_checked(chains)
        elif not duration_exceeded:
            for source_key in sorted(eligible_source_keys):
                if _duration_limit_reached(monotonic, started):
                    duration_exceeded = True
                    break
                identity_id, source_region, _log_group = source_key
                identity_state = identity_states.get(identity_id)
                lease = leases.get(identity_id)
                if identity_state is None or not identity_state.ready or lease is None:
                    continue
                source_states[source_key] = _preflight_source(
                    lease,
                    region=source_region,
                    log_group=source_key[2],
                    evaluated_at=now,
                )
                if (
                    _projected_finding_count(
                        chains,
                        identity_states,
                        source_states,
                        top_issues,
                    )
                    > MAX_RETRIEVAL_FINDINGS
                ):
                    top_issues.add(RetrievalDoctorIssueCode.LIMIT_EXCEEDED)
                    _mark_not_checked(chains)
                    break
                if _duration_limit_reached(monotonic, started):
                    duration_exceeded = True
                    break
    finally:
        for lease in leases.values():
            lease.close()

    if duration_exceeded:
        top_issues.add(RetrievalDoctorIssueCode.DURATION_EXCEEDED)
        _mark_incomplete_checks(chains, identity_states, source_states)
    if (
        _projected_finding_count(
            chains,
            identity_states,
            source_states,
            top_issues,
        )
        > MAX_RETRIEVAL_FINDINGS
    ):
        top_issues.add(RetrievalDoctorIssueCode.LIMIT_EXCEEDED)
        _mark_not_checked(chains)
    return _result(
        target_id=target_id,
        target_environment=target_environment,
        region=region,
        chains=chains,
        identity_states=identity_states,
        source_states=source_states,
        issues=top_issues,
    )


def _select_chains(
    suite: VerificationSuite,
) -> tuple[list[_Chain], bool]:
    selected: list[_Chain] = []
    scenarios = getattr(suite, "scenarios", ())
    if not isinstance(scenarios, tuple):
        scenarios = tuple(scenarios) if isinstance(scenarios, list) else ()
    for scenario_index, scenario in enumerate(scenarios):
        assertions = getattr(scenario, "assertions", ())
        if not isinstance(assertions, tuple):
            assertions = tuple(assertions) if isinstance(assertions, list) else ()
        for assertion_index, assertion in enumerate(assertions):
            if not isinstance(assertion, RetrievalBoundaryAssertion):
                continue
            if len(selected) == MAX_RETRIEVAL_ASSERTIONS:
                return (
                    sorted(selected, key=_chain_sort_key),
                    True,
                )
            selected.append(
                _Chain(
                    scenario_id=_safe_identifier(
                        getattr(scenario, "id", None),
                        fallback=f"invalid-scenario-{scenario_index + 1}",
                    ),
                    assertion_id=_safe_identifier(
                        getattr(assertion, "id", None),
                        fallback=f"invalid-assertion-{assertion_index + 1}",
                    ),
                    action_id=_safe_identifier(
                        getattr(assertion, "action_ref", None),
                        fallback="invalid-action",
                    ),
                    probe_id=_safe_identifier(
                        getattr(assertion, "probe_ref", None),
                        fallback="invalid-probe",
                    ),
                    scenario=scenario,
                    assertion=assertion,
                )
            )
    return sorted(selected, key=_chain_sort_key), False


def _resolve_chain(  # noqa: C901, PLR0912, PLR0915
    chain: _Chain,
    *,
    suite: VerificationSuite,
    identities_by_id: dict[str, Identity],
    environment: Mapping[str, str],
    region: str | None,
) -> None:
    scenario = chain.scenario
    actions = getattr(scenario, "actions", ())
    probes = getattr(scenario, "probes", ())
    if not isinstance(actions, tuple) or not isinstance(probes, tuple):
        chain.issues.add(RetrievalDoctorIssueCode.INVALID_CONFIGURATION)
        actions = tuple(actions) if isinstance(actions, list) else ()
        probes = tuple(probes) if isinstance(probes, list) else ()
    action_ref = getattr(chain.assertion, "action_ref", None)
    probe_ref = getattr(chain.assertion, "probe_ref", None)
    if (
        not _valid_identifier(action_ref)
        or not _valid_identifier(probe_ref)
        or not _valid_identifier(getattr(scenario, "id", None))
    ):
        chain.issues.add(RetrievalDoctorIssueCode.INVALID_CONFIGURATION)
    matching_actions = tuple(
        item for item in actions if getattr(item, "id", None) == action_ref
    )
    matching_probes = tuple(
        item for item in probes if getattr(item, "id", None) == probe_ref
    )
    if len(matching_actions) != 1:
        chain.issues.add(RetrievalDoctorIssueCode.INVALID_CONFIGURATION)
    else:
        chain.action = matching_actions[0]
        chain.action_id = _safe_identifier(
            getattr(chain.action, "id", None),
            fallback=chain.action_id,
        )
    if len(matching_probes) != 1 or not isinstance(
        matching_probes[0] if matching_probes else None,
        CloudWatchLogsProbe,
    ):
        chain.issues.add(RetrievalDoctorIssueCode.INVALID_CONFIGURATION)
    else:
        chain.probe = matching_probes[0]
        chain.probe_id = _safe_identifier(chain.probe.id, fallback=chain.probe_id)
        if (
            chain.probe.action_ref != action_ref
            or ObservationKind.RETRIEVAL_CANARY not in chain.probe.observations
            or not isinstance(chain.probe.retrieval, RetrievalCanaryDeclaration)
        ):
            chain.issues.add(RetrievalDoctorIssueCode.INVALID_CONFIGURATION)

    scenario_identity_ref = getattr(scenario, "identity_ref", None)
    if not _valid_identifier(scenario_identity_ref):
        chain.issues.add(RetrievalDoctorIssueCode.INVALID_CONFIGURATION)
        scenario_identity_ref = None
    if chain.action is not None:
        action_identity_override = getattr(chain.action, "identity_ref", None)
        chain.action_identity_ref = (
            action_identity_override
            if _valid_identifier(action_identity_override)
            else scenario_identity_ref
        )
        if action_identity_override is not None and not _valid_identifier(
            action_identity_override
        ):
            chain.issues.add(RetrievalDoctorIssueCode.INVALID_CONFIGURATION)
    if chain.probe is not None:
        probe_identity_override = getattr(chain.probe, "identity_ref", None)
        chain.evidence_identity_ref = (
            probe_identity_override
            if _valid_identifier(probe_identity_override)
            else scenario_identity_ref
        )
        if probe_identity_override is not None and not _valid_identifier(
            probe_identity_override
        ):
            chain.issues.add(RetrievalDoctorIssueCode.INVALID_CONFIGURATION)

    chain.action_identity = identities_by_id.get(chain.action_identity_ref or "")
    chain.evidence_identity = identities_by_id.get(chain.evidence_identity_ref or "")
    if not isinstance(
        chain.action_identity,
        CurrentAwsIdentity | AssumedRoleIdentity,
    ):
        chain.issues.add(RetrievalDoctorIssueCode.INVALID_CONFIGURATION)
    if not isinstance(
        chain.evidence_identity,
        CurrentAwsIdentity | AssumedRoleIdentity,
    ):
        chain.issues.add(RetrievalDoctorIssueCode.INVALID_CONFIGURATION)

    correlation_compatible = _correlation_compatible(
        chain,
        suite=suite,
        region=region,
    )
    if correlation_compatible:
        chain.correlation_state = RetrievalCorrelationState.RUNTIME_REQUIRED
    else:
        chain.issues.add(RetrievalDoctorIssueCode.CORRELATION_INCOMPATIBLE)

    if chain.action is not None:
        action_environment_issue = _action_environment_issue(
            chain.action,
            environment,
        )
        if action_environment_issue is not None:
            chain.issues.add(action_environment_issue)
    if chain.probe is not None:
        canary_ready, probe_issues = _probe_environment_readiness(
            chain.probe,
            environment,
        )
        chain.canary_contract_ready = canary_ready
        chain.issues.update(probe_issues)
        log_group = chain.probe.log_group
        if (
            chain.evidence_identity_ref is not None
            and region is not None
            and isinstance(log_group, str)
            and _LOG_GROUP_PATTERN.fullmatch(log_group) is not None
        ):
            chain.source_key = (
                chain.evidence_identity_ref,
                region,
                log_group,
            )
        else:
            chain.issues.add(RetrievalDoctorIssueCode.INVALID_CONFIGURATION)
    chain.configuration_compatible = not bool(
        chain.issues
        & {
            RetrievalDoctorIssueCode.INVALID_CONFIGURATION,
            RetrievalDoctorIssueCode.UNSUPPORTED_ACTION,
            RetrievalDoctorIssueCode.ENVIRONMENT_VALUE_MISSING,
            RetrievalDoctorIssueCode.ENVIRONMENT_VALUE_INVALID,
        }
    )


def _identities_by_id(suite: VerificationSuite) -> dict[str, Identity]:
    identities = getattr(suite, "identities", ())
    if not isinstance(identities, tuple):
        identities = tuple(identities) if isinstance(identities, list) else ()
    result: dict[str, Identity] = {}
    duplicates: set[str] = set()
    for identity in identities:
        identity_id = getattr(identity, "id", None)
        if not _valid_identifier(identity_id):
            continue
        if identity_id in result:
            duplicates.add(identity_id)
        result[identity_id] = identity
    for identity_id in duplicates:
        result.pop(identity_id, None)
    return result


def _correlation_compatible(
    chain: _Chain,
    *,
    suite: VerificationSuite,
    region: str | None,
) -> bool:
    action = chain.action
    if (
        not isinstance(action, AwsSigV4Action)
        or getattr(action, "type", None) != "awsSigV4"
    ):
        chain.issues.add(RetrievalDoctorIssueCode.UNSUPPORTED_ACTION)
        return False
    if action.service != "execute-api":
        chain.issues.add(RetrievalDoctorIssueCode.UNSUPPORTED_ACTION)
        return False
    if (
        region is None
        or (action.region is not None and action.region != region)
        or action.mutating is not False
        or suite.target.environment is DeploymentEnvironment.LOCAL
        or not isinstance(
            chain.action_identity,
            CurrentAwsIdentity | AssumedRoleIdentity,
        )
    ):
        chain.issues.add(RetrievalDoctorIssueCode.INVALID_CONFIGURATION)
        return False
    for item in action.inputs:
        if (
            item.location is InputLocation.HEADER
            and isinstance(item.name, str)
            and item.name.lower() == _RESERVED_CORRELATION_HEADER
        ):
            return False
    return True


def _action_environment_issue(
    action: Action,
    environment: Mapping[str, str],
) -> RetrievalDoctorIssueCode | None:
    inputs = getattr(action, "inputs", ())
    if not isinstance(inputs, tuple):
        return RetrievalDoctorIssueCode.INVALID_CONFIGURATION
    issues = [
        _environment_value_issue(item.value, environment)
        for item in inputs
        if isinstance(getattr(item, "value", None), EnvironmentReference)
    ]
    return _primary_environment_issue(issues)


def _probe_environment_readiness(  # noqa: C901, PLR0912
    probe: CloudWatchLogsProbe,
    environment: Mapping[str, str],
) -> tuple[bool, set[RetrievalDoctorIssueCode]]:
    issues: set[RetrievalDoctorIssueCode] = set()
    declaration = probe.retrieval
    if not isinstance(declaration, RetrievalCanaryDeclaration):
        return False, {RetrievalDoctorIssueCode.INVALID_CONFIGURATION}
    baseline, baseline_issue = _resolved_retrieval_canary(
        declaration.baseline_canary,
        environment,
    )
    boundary, boundary_issue = _resolved_retrieval_canary(
        declaration.boundary_canary,
        environment,
    )
    if baseline_issue is not None:
        issues.add(baseline_issue)
    if boundary_issue is not None:
        issues.add(boundary_issue)
    if (
        baseline is not None
        and boundary is not None
        and not retrieval_canaries_are_distinct(baseline, boundary)
    ):
        issues.add(RetrievalDoctorIssueCode.CANARY_VALUES_NOT_DISTINCT)

    if ObservationKind.TELEMETRY_CANARY in probe.observations:
        reference = probe.canary
        if not isinstance(reference, EnvironmentReference):
            issues.add(RetrievalDoctorIssueCode.INVALID_CONFIGURATION)
        else:
            value, issue = _resolved_environment_value(reference, environment)
            if issue is not None:
                issues.add(issue)
            elif not _bounded_utf8_string(value, MAX_CLOUDWATCH_EVENT_BYTES):
                issues.add(RetrievalDoctorIssueCode.ENVIRONMENT_VALUE_INVALID)
    if ObservationKind.BEDROCK_INVOCATION in probe.observations:
        declaration_value = probe.bedrock
        if declaration_value is None:
            issues.add(RetrievalDoctorIssueCode.INVALID_CONFIGURATION)
        else:
            model_id, issue = _resolved_environment_value(
                declaration_value.model_id,
                environment,
            )
            if issue is not None:
                issues.add(issue)
            else:
                model_id_bytes = _model_id_bytes(model_id)
                if model_id_bytes is None or len(model_id_bytes) > (
                    MAX_BEDROCK_MODEL_ID_BYTES
                ):
                    issues.add(RetrievalDoctorIssueCode.ENVIRONMENT_VALUE_INVALID)
                elif (
                    declaration_value.model_alias is not None
                    and not _valid_model_alias(
                        declaration_value.model_alias,
                        model_id=model_id_bytes,
                    )
                ):
                    issues.add(RetrievalDoctorIssueCode.INVALID_CONFIGURATION)
    return not issues, issues


def _resolved_retrieval_canary(
    reference: object,
    environment: Mapping[str, str],
) -> tuple[bytes | None, RetrievalDoctorIssueCode | None]:
    if not isinstance(reference, EnvironmentReference):
        return None, RetrievalDoctorIssueCode.INVALID_CONFIGURATION
    value, issue = _resolved_environment_value(reference, environment)
    if issue is not None:
        return None, issue
    encoded, failure = validated_retrieval_canary(value)
    if failure is not None:
        return None, RetrievalDoctorIssueCode.ENVIRONMENT_VALUE_INVALID
    return encoded, None


def _identity_environment_issue(
    identity: Identity,
    environment: Mapping[str, str],
) -> RetrievalDoctorIssueCode | None:
    reference: EnvironmentReference | None
    if isinstance(identity, CurrentAwsIdentity):
        reference = identity.profile
    elif isinstance(identity, AssumedRoleIdentity):
        reference = identity.external_id
    else:
        return RetrievalDoctorIssueCode.INVALID_CONFIGURATION
    if reference is None:
        return None
    _, issue = _resolved_environment_value(reference, environment)
    return issue


def _resolved_environment_value(
    reference: EnvironmentReference,
    environment: Mapping[str, str],
) -> tuple[object | None, RetrievalDoctorIssueCode | None]:
    try:
        value: object = environment[reference.name]
    except KeyError:
        return None, RetrievalDoctorIssueCode.ENVIRONMENT_VALUE_MISSING
    except Exception:  # noqa: BLE001 - environment mappings are untrusted.
        return None, RetrievalDoctorIssueCode.ENVIRONMENT_VALUE_INVALID
    if not isinstance(value, str) or not value:
        return None, RetrievalDoctorIssueCode.ENVIRONMENT_VALUE_INVALID
    return value, None


def _environment_value_issue(
    reference: EnvironmentReference,
    environment: Mapping[str, str],
) -> RetrievalDoctorIssueCode | None:
    _, issue = _resolved_environment_value(reference, environment)
    return issue


def _primary_environment_issue(
    issues: list[RetrievalDoctorIssueCode | None],
) -> RetrievalDoctorIssueCode | None:
    populated = {issue for issue in issues if issue is not None}
    if RetrievalDoctorIssueCode.ENVIRONMENT_VALUE_MISSING in populated:
        return RetrievalDoctorIssueCode.ENVIRONMENT_VALUE_MISSING
    if RetrievalDoctorIssueCode.ENVIRONMENT_VALUE_INVALID in populated:
        return RetrievalDoctorIssueCode.ENVIRONMENT_VALUE_INVALID
    return None


def _acquire_identity(  # noqa: PLR0911
    identity: CurrentAwsIdentity | AssumedRoleIdentity,
    *,
    suite: VerificationSuite,
    environment: Mapping[str, str],
    session_factory: AwsSessionFactory,
    evaluated_at: datetime,
) -> tuple[AwsScopedIdentity | None, _IdentityState]:
    context = ExecutionContext(
        run_id="retrieval-doctor",
        scenario_id="retrieval-preflight",
        target=suite.target,
    )
    request = IdentityRequest(context=context, identity=identity)
    try:
        if isinstance(identity, CurrentAwsIdentity):
            lease = CurrentAwsIdentityProvider(
                environment=environment,
                session_factory=session_factory,
            ).provide_identity(request)
        else:
            lease = AssumedRoleAwsIdentityProvider(
                environment=environment,
                session_factory=session_factory,
            ).provide_identity(request)
    except AwsIdentityError as error:
        issue = (
            RetrievalDoctorIssueCode.SDK_UNAVAILABLE
            if error.code.value == RetrievalDoctorIssueCode.SDK_UNAVAILABLE.value
            else RetrievalDoctorIssueCode.IDENTITY_ACQUISITION_FAILED
        )
        return None, _IdentityState(ready=False, issue=issue)
    except Exception:  # noqa: BLE001 - provider diagnostics are discarded.
        return (
            None,
            _IdentityState(
                ready=False,
                issue=RetrievalDoctorIssueCode.IDENTITY_ACQUISITION_FAILED,
            ),
        )
    target = suite.target
    if lease.closed:
        return (
            lease,
            _IdentityState(
                ready=False,
                issue=RetrievalDoctorIssueCode.IDENTITY_ACQUISITION_FAILED,
            ),
        )
    expires_at = lease.expires_at
    if expires_at is not None and (
        not isinstance(expires_at, datetime)
        or expires_at.tzinfo is None
        or expires_at.utcoffset() is None
        or expires_at.astimezone(UTC) <= evaluated_at
    ):
        return (
            lease,
            _IdentityState(
                ready=False,
                issue=RetrievalDoctorIssueCode.IDENTITY_EXPIRED,
            ),
        )
    account_id = target.aws_account_id
    if not isinstance(account_id, str) or not lease.matches_account(account_id):
        return (
            lease,
            _IdentityState(
                ready=False,
                issue=RetrievalDoctorIssueCode.ACCOUNT_MISMATCH,
            ),
        )
    region = target.aws_region
    if not isinstance(region, str) or not lease.matches_partition(
        _partition_for_region(region)
    ):
        return (
            lease,
            _IdentityState(
                ready=False,
                issue=RetrievalDoctorIssueCode.PARTITION_MISMATCH,
            ),
        )
    return lease, _IdentityState(ready=True, issue=None)


def _preflight_source(
    identity: AwsScopedIdentity,
    *,
    region: str,
    log_group: str,
    evaluated_at: datetime,
) -> _SourceState:
    try:
        client = identity._cloudwatch_logs_client(  # noqa: SLF001
            region=region,
            evaluated_at=evaluated_at,
        )
    except ModuleNotFoundError, _AwsSdkUnavailableError:
        return _SourceState(
            accessible=False,
            issue=RetrievalDoctorIssueCode.SDK_UNAVAILABLE,
        )
    except Exception:  # noqa: BLE001 - SDK diagnostics are discarded.
        return _SourceState(
            accessible=False,
            issue=RetrievalDoctorIssueCode.SDK_ERROR,
        )
    end_milliseconds = int(evaluated_at.timestamp() * 1000)
    start_milliseconds = max(0, end_milliseconds - 1000)
    try:
        response = client.filter_log_events(
            logGroupName=log_group,
            startTime=start_milliseconds,
            endTime=end_milliseconds,
            filterPattern=_FIXED_FILTER_PATTERN,
            limit=1,
            interleaved=True,
            startFromHead=True,
            unmask=False,
        )
    except Exception as error:  # noqa: BLE001 - SDK diagnostics are discarded.
        return _SourceState(accessible=False, issue=_source_sdk_failure(error))
    try:
        try:
            issue = _validate_source_response(response)
        except Exception:  # noqa: BLE001 - response diagnostics are discarded.
            issue = RetrievalDoctorIssueCode.INVALID_AWS_RESPONSE
    finally:
        del response
    return _SourceState(accessible=issue is None, issue=issue)


def _validate_source_response(  # noqa: C901, PLR0911, PLR0912
    response: object,
) -> RetrievalDoctorIssueCode | None:
    if not isinstance(response, Mapping) or not set(response) <= _RESPONSE_FIELDS:
        return RetrievalDoctorIssueCode.INVALID_AWS_RESPONSE
    total_text_bytes = _bounded_returned_text_bytes(response)
    if total_text_bytes == -1:
        return RetrievalDoctorIssueCode.INVALID_AWS_RESPONSE
    if total_text_bytes is None:
        return RetrievalDoctorIssueCode.RESPONSE_OVERSIZED
    events = response.get("events")
    if events is not None:
        if not isinstance(events, list):
            return RetrievalDoctorIssueCode.INVALID_AWS_RESPONSE
        if len(events) > MAX_RETRIEVAL_RETURNED_EVENTS:
            return RetrievalDoctorIssueCode.RESPONSE_OVERSIZED
        for event in events:
            if not _valid_event_outer_shape(event):
                return RetrievalDoctorIssueCode.INVALID_AWS_RESPONSE
            event = cast("Mapping[str, object]", event)
            message = event.get("message")
            if (
                isinstance(message, str)
                and _utf8_length(message) > MAX_RETRIEVAL_RETURNED_MESSAGE_BYTES
            ):
                return RetrievalDoctorIssueCode.RESPONSE_OVERSIZED
    token = response.get("nextToken")
    if token is not None:
        if not isinstance(token, str) or not token:
            return RetrievalDoctorIssueCode.INVALID_AWS_RESPONSE
        if _utf8_length(token) > MAX_RETRIEVAL_RETURNED_TOKEN_BYTES:
            return RetrievalDoctorIssueCode.RESPONSE_OVERSIZED
    searched = response.get("searchedLogStreams")
    if searched is not None:
        if not isinstance(searched, list):
            return RetrievalDoctorIssueCode.INVALID_AWS_RESPONSE
        for item in searched:
            if not _valid_searched_stream_shape(item):
                return RetrievalDoctorIssueCode.INVALID_AWS_RESPONSE
    metadata = response.get("ResponseMetadata")
    if metadata is not None:
        if not isinstance(metadata, Mapping) or not set(metadata) <= (
            _RESPONSE_METADATA_FIELDS
        ):
            return RetrievalDoctorIssueCode.INVALID_AWS_RESPONSE
        status = metadata.get("HTTPStatusCode")
        if type(status) is not int or status != _HTTP_OK:
            return RetrievalDoctorIssueCode.INVALID_AWS_RESPONSE
        headers = metadata.get("HTTPHeaders")
        if headers is not None and (
            not isinstance(headers, Mapping)
            or not all(
                isinstance(key, str) and isinstance(value, str)
                for key, value in headers.items()
            )
        ):
            return RetrievalDoctorIssueCode.INVALID_AWS_RESPONSE
        retry_attempts = metadata.get("RetryAttempts")
        if retry_attempts is not None and (
            type(retry_attempts) is not int or retry_attempts < 0
        ):
            return RetrievalDoctorIssueCode.INVALID_AWS_RESPONSE
        for field_name in ("HostId", "RequestId"):
            if field_name in metadata and not isinstance(metadata[field_name], str):
                return RetrievalDoctorIssueCode.INVALID_AWS_RESPONSE
    return None


def _valid_event_outer_shape(value: object) -> bool:
    if not isinstance(value, Mapping) or not set(value) <= _EVENT_FIELDS:
        return False
    for field_name in ("eventId", "logStreamName", "message"):
        if field_name in value and not isinstance(value[field_name], str):
            return False
    for field_name in ("ingestionTime", "timestamp"):
        if field_name in value and (
            type(value[field_name]) is not int or value[field_name] < 0
        ):
            return False
    return True


def _valid_searched_stream_shape(value: object) -> bool:
    if not isinstance(value, Mapping) or not set(value) <= _SEARCHED_STREAM_FIELDS:
        return False
    return (
        "logStreamName" not in value or isinstance(value["logStreamName"], str)
    ) and (
        "searchedCompletely" not in value or type(value["searchedCompletely"]) is bool
    )


def _bounded_returned_text_bytes(value: object) -> int | None:
    total = 0
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            length = _utf8_length(item)
            if length < 0:
                return -1
            total += length
            if total > MAX_RETRIEVAL_RETURNED_TEXT_BYTES:
                return None
        elif isinstance(item, Mapping):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list | tuple):
            pending.extend(item)
    return total


def _source_sdk_failure(error: Exception) -> RetrievalDoctorIssueCode:
    if isinstance(error, TimeoutError) or type(error).__name__ in {
        "ConnectTimeoutError",
        "ReadTimeoutError",
    }:
        return RetrievalDoctorIssueCode.SDK_TIMEOUT
    response = getattr(error, "response", None)
    if isinstance(response, Mapping):
        details = response.get("Error")
        code = details.get("Code") if isinstance(details, Mapping) else None
        if code in {
            "AccessDenied",
            "AccessDeniedException",
            "UnauthorizedOperation",
        }:
            return RetrievalDoctorIssueCode.ACCESS_DENIED
        if code in {"ResourceNotFound", "ResourceNotFoundException"}:
            return RetrievalDoctorIssueCode.SOURCE_NOT_FOUND
        if code in {
            "Throttling",
            "ThrottlingException",
            "TooManyRequestsException",
        }:
            return RetrievalDoctorIssueCode.THROTTLED
    return RetrievalDoctorIssueCode.SDK_ERROR


def _result(  # noqa: PLR0913
    *,
    target_id: str,
    target_environment: str,
    region: str | None,
    chains: tuple[_Chain, ...] | list[_Chain],
    identity_states: Mapping[str, _IdentityState],
    source_states: Mapping[tuple[str, str, str], _SourceState],
    issues: set[RetrievalDoctorIssueCode],
) -> RetrievalDoctorResult:
    checks: list[RetrievalReadinessCheck] = []
    for chain in sorted(chains, key=_chain_sort_key):
        check_issues = set(chain.issues)
        action_state = (
            identity_states.get(chain.action_identity_ref)
            if chain.action_identity_ref is not None
            else None
        )
        evidence_state = (
            identity_states.get(chain.evidence_identity_ref)
            if chain.evidence_identity_ref is not None
            else None
        )
        if action_state is not None and action_state.issue is not None:
            check_issues.add(action_state.issue)
        if evidence_state is not None and evidence_state.issue is not None:
            check_issues.add(evidence_state.issue)
        source_state = (
            source_states.get(chain.source_key)
            if chain.source_key is not None
            else None
        )
        if source_state is not None and source_state.issue is not None:
            check_issues.add(source_state.issue)
        checks.append(
            RetrievalReadinessCheck(
                scenario_id=chain.scenario_id,
                assertion_id=chain.assertion_id,
                action_id=chain.action_id,
                probe_id=chain.probe_id,
                configuration_compatible=chain.configuration_compatible,
                action_identity_ready=(
                    action_state.ready if action_state is not None else None
                ),
                evidence_identity_ready=(
                    evidence_state.ready if evidence_state is not None else None
                ),
                canary_contract_ready=chain.canary_contract_ready,
                source_accessible=(
                    source_state.accessible if source_state is not None else None
                ),
                correlation_state=chain.correlation_state,
                issues=tuple(sorted(check_issues, key=lambda item: item.value)),
            )
        )
    ordered_checks = tuple(checks)
    bounded_issues = set(issues)
    if (
        len(bounded_issues) + sum(len(check.issues) for check in ordered_checks)
        > MAX_RETRIEVAL_FINDINGS
    ):
        bounded_issues.add(RetrievalDoctorIssueCode.LIMIT_EXCEEDED)
        ordered_checks = _bounded_check_findings(
            ordered_checks,
            top_issue_count=len(bounded_issues),
        )
    ordered_issues = tuple(sorted(bounded_issues, key=lambda item: item.value))
    ready = (
        bool(ordered_checks)
        and not ordered_issues
        and all(check.ready for check in ordered_checks)
    )
    return RetrievalDoctorResult(
        target_id=target_id,
        target_environment=target_environment,
        region=region,
        ready=ready,
        checks=ordered_checks,
        issues=ordered_issues,
    )


def _bounded_check_findings(
    checks: tuple[RetrievalReadinessCheck, ...],
    *,
    top_issue_count: int,
) -> tuple[RetrievalReadinessCheck, ...]:
    budget = max(0, MAX_RETRIEVAL_FINDINGS - top_issue_count)
    bounded: list[RetrievalReadinessCheck] = []
    for position, check in enumerate(checks):
        remaining_checks = len(checks) - position - 1
        full_issues = check.issues
        if len(full_issues) <= max(0, budget - remaining_checks):
            selected = full_issues
        elif budget > 0:
            retained_count = max(0, budget - remaining_checks - 1)
            retained = tuple(
                issue
                for issue in full_issues
                if issue is not RetrievalDoctorIssueCode.NOT_CHECKED_DUE_TO_LIMIT
            )[:retained_count]
            selected = tuple(
                sorted(
                    {
                        *retained,
                        RetrievalDoctorIssueCode.NOT_CHECKED_DUE_TO_LIMIT,
                    },
                    key=lambda item: item.value,
                )
            )
        else:
            selected = ()
        budget -= len(selected)
        bounded.append(replace(check, issues=selected))
    return tuple(bounded)


def _projected_finding_count(
    chains: list[_Chain],
    identity_states: Mapping[str, _IdentityState],
    source_states: Mapping[tuple[str, str, str], _SourceState] | None = None,
    top_issues: set[RetrievalDoctorIssueCode] | None = None,
) -> int:
    total = len(top_issues or ())
    sources = source_states or {}
    for chain in chains:
        findings = set(chain.issues)
        for identity_ref in (
            chain.action_identity_ref,
            chain.evidence_identity_ref,
        ):
            state = identity_states.get(identity_ref or "")
            if state is not None and state.issue is not None:
                findings.add(state.issue)
        source = sources.get(chain.source_key) if chain.source_key is not None else None
        if source is not None and source.issue is not None:
            findings.add(source.issue)
        total += len(findings)
    return total


def _mark_not_checked(chains: list[_Chain]) -> None:
    for chain in chains:
        chain.issues.add(RetrievalDoctorIssueCode.NOT_CHECKED_DUE_TO_LIMIT)


def _mark_incomplete_checks(
    chains: list[_Chain],
    identity_states: Mapping[str, _IdentityState],
    source_states: Mapping[tuple[str, str, str], _SourceState],
) -> None:
    for chain in chains:
        action_checked = chain.action_identity_ref in identity_states
        evidence_checked = chain.evidence_identity_ref in identity_states
        source_checked = (
            chain.source_key in source_states if chain.source_key is not None else False
        )
        if not action_checked or not evidence_checked or not source_checked:
            chain.issues.add(RetrievalDoctorIssueCode.NOT_CHECKED_DUE_TO_LIMIT)


def _safe_target_fields(
    suite: VerificationSuite,
) -> tuple[str, str, str | None]:
    target = getattr(suite, "target", None)
    target_id = _safe_identifier(
        getattr(target, "id", None),
        fallback="invalid-target",
    )
    environment = getattr(target, "environment", None)
    target_environment = (
        environment.value
        if isinstance(environment, DeploymentEnvironment)
        else "unknown"
    )
    region_value = getattr(target, "aws_region", None)
    region = (
        region_value
        if isinstance(region_value, str)
        and _AWS_REGION_PATTERN.fullmatch(region_value) is not None
        else None
    )
    return target_id, target_environment, region


def _duration_limit_reached(
    monotonic: Callable[[], float],
    started: float,
) -> bool:
    return monotonic() - started > MAX_RETRIEVAL_DOCTOR_SECONDS


def _chain_sort_key(chain: _Chain) -> tuple[str, str, str, str]:
    return (
        chain.scenario_id,
        chain.assertion_id,
        chain.action_id,
        chain.probe_id,
    )


def _bounded_utf8_string(value: object, maximum_bytes: int) -> bool:
    return isinstance(value, str) and 0 < _utf8_length(value) <= maximum_bytes


def _utf8_length(value: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError:
        return -1


def _valid_identifier(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and _IDENTIFIER_PATTERN.fullmatch(value) is not None


def _safe_identifier(value: object, *, fallback: str) -> str:
    return value if _valid_identifier(value) else fallback


def _readiness_text(*, value: bool | None) -> str:
    if value is True:
        return "READY"
    if value is False:
        return "NOT READY"
    return "NOT CHECKED"


def _normalized_time(value: object) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        message = "retrieval doctor clock must return an offset-aware datetime"
        raise ValueError(message)
    return value.astimezone(UTC)


def _utc_now() -> datetime:
    return datetime.now(UTC)
