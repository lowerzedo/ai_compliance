"""Focused reciprocal AWS retrieval-boundary execution and evidence persistence."""

from __future__ import annotations

import hashlib
import math
import re
import time
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Never, cast, final

from cai_verify.assertions import (
    RETRIEVAL_BOUNDARY_EVALUATOR_VERSION,
    RETRIEVAL_BOUNDARY_FIXED_LIMITATIONS,
    RetrievalBoundaryEvaluator,
)
from cai_verify.aws._reciprocal_evidence import (
    InvalidAwsReciprocalEvidenceError,
    serialize_aws_reciprocal_run,
    serialize_aws_retrieval_action,
    serialize_aws_retrieval_probe,
)
from cai_verify.aws._retrieval_canary import (
    retrieval_canaries_are_distinct,
    validated_retrieval_canary,
)
from cai_verify.aws.action import AwsSigV4ActionAdapter
from cai_verify.aws.cloudwatch_logs import CloudWatchLogsProbeAdapter
from cai_verify.aws.execution_policy import (
    AwsExecutionPolicy,
    AwsExecutionPolicyError,
    authorize_aws_execution,
)
from cai_verify.aws.identity import (
    AssumedRoleAwsIdentityProvider,
    AwsIdentityError,
    AwsScopedIdentity,
    AwsSessionFactory,
    Boto3AwsSessionFactory,
    CurrentAwsIdentityProvider,
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
from cai_verify.config.models import DeploymentEnvironment, ObservationKind
from cai_verify.core import (
    AssertionResult,
    AssertionStatus,
    CliExitCode,
    aggregate_results,
    exit_code_for_results,
)
from cai_verify.evidence import (
    RunAlreadyExistsError,
    Sensitivity,
    create_run_directory,
    verify_run_integrity,
)
from cai_verify.plugins import (
    ActionExecutionResult,
    ActionOutcome,
    ActionRequest,
    AssertionEvaluationRequest,
    ExecutionContext,
    IdentityRequest,
    ProbeRequest,
    ProbeResult,
    ReportRequest,
)
from cai_verify.reporters import JsonReporter, TerminalReporter

if TYPE_CHECKING:
    import os
    from collections.abc import Callable, Iterable, Mapping, Sequence
    from pathlib import Path

    from cai_verify.config import Scenario
    from cai_verify.evidence import RunDirectory

MAX_AWS_RECIPROCAL_ORCHESTRATION_SECONDS = 5 * 60.0

_FRESHNESS_PATTERN = re.compile(
    r"PT(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?"
    r"(?:(?P<seconds>\d+)S)?\Z"
)
_DIGEST_PREFIX_PATTERN = re.compile(r"[0-9a-f]{16}\Z")
_RECIPROCAL_CHAIN_COUNT = 2
_RECIPROCAL_IDENTITY_COUNT = 3
_RECIPROCAL_ARTIFACT_COUNT = 9


class AwsReciprocalRetrievalRunFailureCode(StrEnum):
    """Stable categories for operational failures outside assertion semantics."""

    INVALID_CONFIGURATION = "invalid_configuration"
    INVALID_ENVIRONMENT = "invalid_environment"
    IDENTITY_UNAVAILABLE = "identity_unavailable"
    DURATION_EXHAUSTED = "duration_exhausted"
    INVALID_NORMALIZED_RESULT = "invalid_normalized_result"
    EVIDENCE_RUN_COLLISION = "evidence_run_collision"
    EVIDENCE_PERSISTENCE_FAILED = "evidence_persistence_failed"
    INTEGRITY_VERIFICATION_FAILED = "integrity_verification_failed"


class AwsReciprocalRetrievalRunStage(StrEnum):
    """Fixed non-sensitive progress stages for operator-facing coordination."""

    VALIDATION = "validation"
    AUTHORIZATION = "authorization"
    IDENTITY_ACQUISITION = "identity_acquisition"
    DIRECTION_ONE = "direction_one"
    DIRECTION_TWO = "direction_two"
    EVALUATION = "evaluation"
    FINALIZATION = "finalization"
    INTEGRITY_VERIFICATION = "integrity_verification"
    COMPLETE = "complete"
    FAILED = "failed"


class AwsReciprocalRetrievalRunError(RuntimeError):
    """A redacted reciprocal-run operational failure."""

    def __init__(self, code: AwsReciprocalRetrievalRunFailureCode) -> None:
        """Construct one error without paths, policy values, or diagnostics."""
        self.code = code
        super().__init__(f"AWS reciprocal retrieval run failed ({code.value})")


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class AwsReciprocalRetrievalRunOptions:
    """Explicit selection, storage, authorization, and injected runtime seams."""

    run_id: str
    scenario_id: str
    evidence_root: str | os.PathLike[str] = field(repr=False)
    execution_policy: AwsExecutionPolicy = field(repr=False)
    environment: Mapping[str, str] = field(repr=False)
    session_factory: AwsSessionFactory = field(
        default_factory=Boto3AwsSessionFactory,
        repr=False,
    )
    clock: Callable[[], datetime] = field(
        default=lambda: datetime.now(UTC),
        repr=False,
    )
    monotonic: Callable[[], float] = field(default=time.monotonic, repr=False)
    action_adapter: AwsSigV4ActionAdapter | None = field(default=None, repr=False)
    probe_adapter: CloudWatchLogsProbeAdapter | None = field(
        default=None,
        repr=False,
    )
    progress: Callable[[AwsReciprocalRetrievalRunStage], None] | None = field(
        default=None,
        repr=False,
    )


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class AwsReciprocalRetrievalRunResult:
    """Two evaluated directions plus verified immutable evidence."""

    run_id: str
    scenario_id: str
    status: AssertionStatus
    exit_code: CliExitCode
    evidence_path: Path = field(repr=False)
    assertion_results: tuple[AssertionResult, AssertionResult] = field(repr=False)
    terminal_report: bytes = field(repr=False)
    json_report: bytes = field(repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class _ReciprocalChain:
    assertion: RetrievalBoundaryAssertion
    action: AwsSigV4Action
    probe: CloudWatchLogsProbe
    requester_identity: CurrentAwsIdentity | AssumedRoleIdentity


@dataclass(frozen=True, slots=True, repr=False)
class _SelectedReciprocal:
    scenario: Scenario
    chains: tuple[_ReciprocalChain, _ReciprocalChain]
    evidence_identity: CurrentAwsIdentity | AssumedRoleIdentity
    region: str


@dataclass(frozen=True, slots=True, repr=False)
class _ArtifactPaths:
    run: str
    actions: dict[str, str]
    probes: dict[str, str]
    results: dict[str, str]
    json_report: str
    terminal_report: str

    @property
    def inventory(self) -> tuple[str, ...]:
        """Return the exact precomputed non-manifest artifact inventory."""
        return (
            self.run,
            *self.actions.values(),
            *self.probes.values(),
            *self.results.values(),
            self.json_report,
            self.terminal_report,
        )


@dataclass(slots=True, repr=False)
class _SchedulingBudget:
    monotonic: Callable[[], float] = field(repr=False)
    started_at: float
    last_checked_at: float

    @classmethod
    def start(cls, monotonic: Callable[[], float]) -> _SchedulingBudget:
        """Start the fixed orchestration budget from an injected clock."""
        started = _monotonic_value(monotonic)
        return cls(
            monotonic=monotonic,
            started_at=started,
            last_checked_at=started,
        )

    def check(self) -> None:
        """Fail closed for invalid, reversing, or exhausted schedules."""
        current = _monotonic_value(self.monotonic)
        if (
            current < self.last_checked_at
            or current - self.started_at >= MAX_AWS_RECIPROCAL_ORCHESTRATION_SECONDS
        ):
            raise AwsReciprocalRetrievalRunError(
                AwsReciprocalRetrievalRunFailureCode.DURATION_EXHAUSTED
            )
        self.last_checked_at = current


def run_aws_reciprocal_retrieval(
    suite: VerificationSuite,
    options: AwsReciprocalRetrievalRunOptions,
) -> AwsReciprocalRetrievalRunResult:
    """Run the reciprocal path while emitting only fixed safe progress stages."""
    _notify_progress(options, AwsReciprocalRetrievalRunStage.VALIDATION)
    try:
        return _run_aws_reciprocal_retrieval(suite, options)
    except Exception:
        _notify_progress(options, AwsReciprocalRetrievalRunStage.FAILED)
        raise


def validated_aws_reciprocal_retrieval_slice(
    suite: VerificationSuite,
    scenario_id: str,
) -> VerificationSuite:
    """Return only the exact bounded identities and scenario used by this runner."""
    try:
        selected = _selected_reciprocal(suite, scenario_id)
        identities = tuple(
            sorted(
                {
                    identity.id: identity
                    for identity in (
                        selected.chains[0].requester_identity,
                        selected.chains[1].requester_identity,
                        selected.evidence_identity,
                    )
                }.values(),
                key=lambda identity: identity.id,
            )
        )
        if len(identities) != _RECIPROCAL_IDENTITY_COUNT:
            _invalid_configuration()
        identity_ids = {identity.id for identity in identities}
        scenario_identity = (
            selected.scenario.identity_ref
            if selected.scenario.identity_ref in identity_ids
            else selected.chains[0].requester_identity.id
        )
        scenario = selected.scenario.model_copy(
            update={"identity_ref": scenario_identity}
        )
        return suite.model_copy(
            update={
                "identities": identities,
                "scenarios": (scenario,),
            }
        )
    except AwsReciprocalRetrievalRunError:
        raise
    except Exception:  # noqa: BLE001 - configuration details stay redacted.
        raise AwsReciprocalRetrievalRunError(
            AwsReciprocalRetrievalRunFailureCode.INVALID_CONFIGURATION
        ) from None


def _run_aws_reciprocal_retrieval(  # noqa: C901, PLR0912, PLR0915
    suite: VerificationSuite,
    options: AwsReciprocalRetrievalRunOptions,
) -> AwsReciprocalRetrievalRunResult:
    """Run exactly two reciprocal retrieval chains and verify their bundle."""
    try:
        selected = _selected_reciprocal(suite, options.scenario_id)
        resolved_environment = _resolve_required_environment(
            selected,
            environment=options.environment,
        )
        _notify_progress(options, AwsReciprocalRetrievalRunStage.AUTHORIZATION)
        authorize_aws_execution(
            options.execution_policy,
            target=suite.target,
            identities=(
                selected.chains[0].requester_identity,
                selected.chains[1].requester_identity,
                selected.evidence_identity,
            ),
            actions=(selected.chains[0].action, selected.chains[1].action),
            cloudwatch_log_groups=(
                selected.chains[0].probe.log_group,
                selected.chains[1].probe.log_group,
            ),
        )
        artifact_paths = _artifact_paths(selected)
        suite_max_age = _duration(suite.evidence_policy.max_age)
        clock_skew = _duration(suite.evidence_policy.clock_skew_tolerance)
        action_adapter = options.action_adapter
        if action_adapter is None:
            action_adapter = AwsSigV4ActionAdapter(
                environment=resolved_environment,
                clock=options.clock,
            )
        elif type(action_adapter) is AwsSigV4ActionAdapter:
            action_adapter = replace(
                action_adapter,
                environment=resolved_environment,
            )
        probe_adapter = options.probe_adapter
        if probe_adapter is None:
            probe_adapter = CloudWatchLogsProbeAdapter(
                environment=resolved_environment,
                suite_max_age=suite_max_age,
                clock_skew_tolerance=clock_skew,
                clock=options.clock,
                monotonic=options.monotonic,
            )
        elif type(probe_adapter) is CloudWatchLogsProbeAdapter:
            probe_adapter = replace(
                probe_adapter,
                environment=resolved_environment,
            )
    except AwsExecutionPolicyError:
        raise
    except AwsReciprocalRetrievalRunError:
        raise
    except Exception:  # noqa: BLE001 - configuration diagnostics are redacted.
        raise AwsReciprocalRetrievalRunError(
            AwsReciprocalRetrievalRunFailureCode.INVALID_CONFIGURATION
        ) from None

    try:
        run = create_run_directory(options.evidence_root, options.run_id)
    except RunAlreadyExistsError:
        raise AwsReciprocalRetrievalRunError(
            AwsReciprocalRetrievalRunFailureCode.EVIDENCE_RUN_COLLISION
        ) from None
    except Exception:  # noqa: BLE001 - filesystem diagnostics and paths are private.
        raise AwsReciprocalRetrievalRunError(
            AwsReciprocalRetrievalRunFailureCode.EVIDENCE_PERSISTENCE_FAILED
        ) from None

    phase = "execution"
    try:
        with run:
            (
                action_results,
                probe_results,
                action_artifacts,
                probe_artifacts,
            ) = _execute_reciprocal(
                suite,
                selected,
                options=options,
                action_adapter=action_adapter,
                probe_adapter=probe_adapter,
                environment=resolved_environment,
            )
            _notify_progress(options, AwsReciprocalRetrievalRunStage.EVALUATION)
            assertion_results = _evaluate_reciprocal(
                selected,
                action_results=action_results,
                probe_results=probe_results,
                clock=options.clock,
            )
            _validate_evidence_ids(
                assertion_results,
                action_results=action_results,
                probe_results=probe_results,
            )
            status = aggregate_results(assertion_results)
            report_request = ReportRequest.from_results(
                run_id=options.run_id,
                results=assertion_results,
            )
            terminal_report = TerminalReporter().render_report(report_request).content
            json_report = JsonReporter().render_report(report_request).content
            run_artifact = serialize_aws_reciprocal_run(
                run_id=options.run_id,
                scenario_id=selected.scenario.id,
                action_ids=tuple(item.action_id for item in action_results),
                probe_ids=tuple(item.probe_id for item in probe_results),
                assertion_ids=tuple(item.assertion_id for item in assertion_results),
                aggregate_status=status,
                target_id=suite.target.id,
                target_environment=suite.target.environment.value,
                target_region=selected.region,
            )
            _notify_progress(options, AwsReciprocalRetrievalRunStage.FINALIZATION)
            phase = "persistence"
            _write_evidence(
                run,
                artifact_paths,
                run_artifact=run_artifact,
                action_artifacts=action_artifacts,
                probe_artifacts=probe_artifacts,
                assertion_results=assertion_results,
                terminal_report=terminal_report,
                json_report=json_report,
            )
            run.finalize_manifest()
    except AwsReciprocalRetrievalRunError:
        raise
    except InvalidAwsReciprocalEvidenceError:
        raise AwsReciprocalRetrievalRunError(
            AwsReciprocalRetrievalRunFailureCode.INVALID_NORMALIZED_RESULT
        ) from None
    except Exception:  # noqa: BLE001 - all operational diagnostics stay private.
        code = (
            AwsReciprocalRetrievalRunFailureCode.EVIDENCE_PERSISTENCE_FAILED
            if phase == "persistence"
            else AwsReciprocalRetrievalRunFailureCode.INVALID_NORMALIZED_RESULT
        )
        raise AwsReciprocalRetrievalRunError(code) from None

    try:
        _notify_progress(
            options,
            AwsReciprocalRetrievalRunStage.INTEGRITY_VERIFICATION,
        )
        verification = verify_run_integrity(run.path)
    except Exception:  # noqa: BLE001 - integrity implementation details are private.
        raise AwsReciprocalRetrievalRunError(
            AwsReciprocalRetrievalRunFailureCode.INTEGRITY_VERIFICATION_FAILED
        ) from None
    if not verification.valid:
        raise AwsReciprocalRetrievalRunError(
            AwsReciprocalRetrievalRunFailureCode.INTEGRITY_VERIFICATION_FAILED
        )
    _notify_progress(options, AwsReciprocalRetrievalRunStage.COMPLETE)
    return AwsReciprocalRetrievalRunResult(
        run_id=options.run_id,
        scenario_id=selected.scenario.id,
        status=status,
        exit_code=exit_code_for_results(assertion_results),
        evidence_path=run.path,
        assertion_results=assertion_results,
        terminal_report=terminal_report,
        json_report=json_report,
    )


def _notify_progress(
    options: AwsReciprocalRetrievalRunOptions,
    stage: AwsReciprocalRetrievalRunStage,
) -> None:
    """Notify trusted coordination code without affecting verifier semantics."""
    observer = options.progress
    if observer is None:
        return
    try:
        observer(stage)
    except Exception:  # noqa: BLE001 - advisory observers cannot affect a run.
        # Progress is advisory. Observer failure cannot alter execution or evidence.
        return


def _selected_reciprocal(
    suite: VerificationSuite,
    scenario_id: str,
) -> _SelectedReciprocal:
    target = suite.target
    endpoint = target.endpoint
    matches = tuple(
        scenario for scenario in suite.scenarios if scenario.id == scenario_id
    )
    if (
        len(matches) != 1
        or target.environment is DeploymentEnvironment.LOCAL
        or target.aws_account_id is None
        or target.aws_region is None
        or endpoint.scheme != "https"
        or endpoint.username is not None
        or endpoint.password is not None
        or endpoint.query is not None
        or endpoint.fragment is not None
        or endpoint.host not in target.allowed_hosts
    ):
        _invalid_configuration()
    scenario = matches[0]
    if (
        len(scenario.actions) != _RECIPROCAL_CHAIN_COUNT
        or len(scenario.probes) != _RECIPROCAL_CHAIN_COUNT
        or len(scenario.assertions) != _RECIPROCAL_CHAIN_COUNT
        or not all(type(item) is AwsSigV4Action for item in scenario.actions)
        or not all(type(item) is CloudWatchLogsProbe for item in scenario.probes)
        or not all(
            type(item) is RetrievalBoundaryAssertion for item in scenario.assertions
        )
    ):
        _invalid_configuration()

    actions = {item.id: cast("AwsSigV4Action", item) for item in scenario.actions}
    probes = {item.id: cast("CloudWatchLogsProbe", item) for item in scenario.probes}
    if (
        len(actions) != _RECIPROCAL_CHAIN_COUNT
        or len(probes) != _RECIPROCAL_CHAIN_COUNT
    ):
        _invalid_configuration()
    chains: list[_ReciprocalChain] = []
    used_actions: set[str] = set()
    used_probes: set[str] = set()
    for assertion_value in sorted(
        scenario.assertions,
        key=lambda item: item.id,
    ):
        assertion = cast("RetrievalBoundaryAssertion", assertion_value)
        action = actions.get(assertion.action_ref)
        probe = probes.get(assertion.probe_ref)
        if (
            action is None
            or probe is None
            or action.id in used_actions
            or probe.id in used_probes
            or action.service != "execute-api"
            or action.mutating is not False
            or action.region != target.aws_region
            or probe.action_ref != action.id
            or probe.observations != (ObservationKind.RETRIEVAL_CANARY,)
            or type(probe.retrieval) is not RetrievalCanaryDeclaration
            or any(
                limitation.description not in RETRIEVAL_BOUNDARY_FIXED_LIMITATIONS
                for limitation in assertion.limitations
            )
        ):
            _invalid_configuration()
        requester = _identity(
            suite,
            action.identity_ref or scenario.identity_ref,
        )
        used_actions.add(action.id)
        used_probes.add(probe.id)
        chains.append(
            _ReciprocalChain(
                assertion=assertion,
                action=action,
                probe=probe,
                requester_identity=requester,
            )
        )
    if (
        len(chains) != _RECIPROCAL_CHAIN_COUNT
        or used_actions != set(actions)
        or used_probes != set(probes)
    ):
        _invalid_configuration()
    first, second = chains
    if _identity_key(first.requester_identity) == _identity_key(
        second.requester_identity
    ):
        _invalid_configuration()

    first_evidence = _identity(
        suite,
        first.probe.identity_ref or scenario.identity_ref,
    )
    second_evidence = _identity(
        suite,
        second.probe.identity_ref or scenario.identity_ref,
    )
    if (
        first_evidence.id != second_evidence.id
        or _identity_key(first_evidence) != _identity_key(second_evidence)
        or _identity_key(first_evidence)
        in {
            _identity_key(first.requester_identity),
            _identity_key(second.requester_identity),
        }
        or first.probe.log_group != second.probe.log_group
    ):
        _invalid_configuration()
    first_retrieval = cast("RetrievalCanaryDeclaration", first.probe.retrieval)
    second_retrieval = cast("RetrievalCanaryDeclaration", second.probe.retrieval)
    if (
        first_retrieval.baseline_canary != second_retrieval.boundary_canary
        or second_retrieval.baseline_canary != first_retrieval.boundary_canary
    ):
        _invalid_configuration()
    return _SelectedReciprocal(
        scenario=scenario,
        chains=(first, second),
        evidence_identity=first_evidence,
        region=target.aws_region,
    )


def _resolve_required_environment(
    selected: _SelectedReciprocal,
    *,
    environment: Mapping[str, str],
) -> Mapping[str, str]:
    references: list[EnvironmentReference] = []
    for chain in selected.chains:
        references.extend(
            item.value
            for item in chain.action.inputs
            if isinstance(item.value, EnvironmentReference)
        )
        retrieval = chain.probe.retrieval
        if not isinstance(retrieval, RetrievalCanaryDeclaration):
            _invalid_configuration()
        references.extend((retrieval.baseline_canary, retrieval.boundary_canary))
        identity_reference = _identity_environment_reference(chain.requester_identity)
        if identity_reference is not None:
            references.append(identity_reference)
    evidence_reference = _identity_environment_reference(selected.evidence_identity)
    if evidence_reference is not None:
        references.append(evidence_reference)
    resolved: dict[str, str] = {}
    for reference in references:
        if reference.name not in resolved:
            resolved[reference.name] = _environment_value(reference, environment)

    declaration = selected.chains[0].probe.retrieval
    if not isinstance(declaration, RetrievalCanaryDeclaration):
        _invalid_configuration()
    baseline, baseline_failure = validated_retrieval_canary(
        resolved[declaration.baseline_canary.name]
    )
    boundary, boundary_failure = validated_retrieval_canary(
        resolved[declaration.boundary_canary.name]
    )
    if (
        baseline_failure is not None
        or boundary_failure is not None
        or baseline is None
        or boundary is None
        or not retrieval_canaries_are_distinct(baseline, boundary)
    ):
        raise AwsReciprocalRetrievalRunError(
            AwsReciprocalRetrievalRunFailureCode.INVALID_ENVIRONMENT
        )
    return MappingProxyType(resolved)


def _execute_reciprocal(  # noqa: PLR0913 - exact runtime inputs stay explicit.
    suite: VerificationSuite,
    selected: _SelectedReciprocal,
    *,
    options: AwsReciprocalRetrievalRunOptions,
    action_adapter: AwsSigV4ActionAdapter,
    probe_adapter: CloudWatchLogsProbeAdapter,
    environment: Mapping[str, str],
) -> tuple[
    tuple[ActionExecutionResult, ActionExecutionResult],
    tuple[ProbeResult, ProbeResult],
    dict[str, bytes],
    dict[str, bytes],
]:
    context = ExecutionContext(
        run_id=options.run_id,
        scenario_id=selected.scenario.id,
        target=suite.target,
    )
    identity_order = (
        selected.chains[0].requester_identity,
        selected.chains[1].requester_identity,
        selected.evidence_identity,
    )
    leases: dict[str, AwsScopedIdentity] = {}
    budget = _SchedulingBudget.start(options.monotonic)
    try:
        _notify_progress(
            options,
            AwsReciprocalRetrievalRunStage.IDENTITY_ACQUISITION,
        )
        for identity in identity_order:
            budget.check()
            lease = _acquire_identity(
                identity,
                context=context,
                environment=environment,
                session_factory=options.session_factory,
            )
            leases[identity.id] = lease
            _validate_lease(
                lease,
                identity=identity,
                suite=suite,
                evaluated_at=_wall_clock(options.clock),
            )
            budget.check()
        for identity in identity_order:
            _validate_lease(
                leases[identity.id],
                identity=identity,
                suite=suite,
                evaluated_at=_wall_clock(options.clock),
            )

        action_results: list[ActionExecutionResult] = []
        probe_results: list[ProbeResult] = []
        action_artifacts: dict[str, bytes] = {}
        probe_artifacts: dict[str, bytes] = {}
        for position, chain in enumerate(selected.chains):
            _notify_progress(
                options,
                (
                    AwsReciprocalRetrievalRunStage.DIRECTION_ONE
                    if position == 0
                    else AwsReciprocalRetrievalRunStage.DIRECTION_TWO
                ),
            )
            requester_lease = leases[chain.requester_identity.id]
            budget.check()
            try:
                action_result = action_adapter.execute_action(
                    ActionRequest(
                        context=context,
                        action=chain.action,
                        identity=requester_lease,
                    )
                )
            finally:
                _close_lease(requester_lease)
                budget.check()
            action_artifacts[chain.action.id] = serialize_aws_retrieval_action(
                action_result,
                expected_action_id=chain.action.id,
                expected_region=selected.region,
            )
            action_results.append(action_result)
            if len(
                action_results
            ) == _RECIPROCAL_CHAIN_COUNT and _duplicate_successful_correlations(
                action_results
            ):
                raise AwsReciprocalRetrievalRunError(
                    AwsReciprocalRetrievalRunFailureCode.INVALID_NORMALIZED_RESULT
                )

            evidence_lease = leases[selected.evidence_identity.id]
            budget.check()
            try:
                probe_result = probe_adapter.collect_evidence(
                    ProbeRequest(
                        context=context,
                        probe=chain.probe,
                        action_result=action_result,
                        identity=evidence_lease,
                    )
                )
            finally:
                if position == 1:
                    _close_lease(evidence_lease)
                budget.check()
            probe_artifacts[chain.probe.id] = serialize_aws_retrieval_probe(
                probe_result,
                expected_probe_id=chain.probe.id,
                expected_max_age=_duration(
                    chain.probe.max_age or suite.evidence_policy.max_age
                ),
                clock_skew_tolerance=_duration(
                    suite.evidence_policy.clock_skew_tolerance
                ),
            )
            probe_results.append(probe_result)

        if not all(lease.closed for lease in leases.values()):
            raise AwsReciprocalRetrievalRunError(
                AwsReciprocalRetrievalRunFailureCode.IDENTITY_UNAVAILABLE
            )
        return (
            cast(
                "tuple[ActionExecutionResult, ActionExecutionResult]",
                tuple(action_results),
            ),
            cast("tuple[ProbeResult, ProbeResult]", tuple(probe_results)),
            action_artifacts,
            probe_artifacts,
        )
    finally:
        _close_all_leases(leases.values())


def _evaluate_reciprocal(
    selected: _SelectedReciprocal,
    *,
    action_results: tuple[ActionExecutionResult, ActionExecutionResult],
    probe_results: tuple[ProbeResult, ProbeResult],
    clock: Callable[[], datetime],
) -> tuple[AssertionResult, AssertionResult]:
    results: list[AssertionResult] = []
    for chain in selected.chains:
        result = RetrievalBoundaryEvaluator(clock=clock).evaluate_assertion(
            AssertionEvaluationRequest(
                assertion=chain.assertion,
                action_results=action_results,
                probe_results=probe_results,
            )
        )
        if (
            type(result) is not AssertionResult
            or result.assertion_id != chain.assertion.id
            or result.evaluator_version != RETRIEVAL_BOUNDARY_EVALUATOR_VERSION
            or result.limitations != tuple(sorted(RETRIEVAL_BOUNDARY_FIXED_LIMITATIONS))
        ):
            raise AwsReciprocalRetrievalRunError(
                AwsReciprocalRetrievalRunFailureCode.INVALID_NORMALIZED_RESULT
            )
        results.append(result)
    return cast("tuple[AssertionResult, AssertionResult]", tuple(results))


def _validate_evidence_ids(
    assertion_results: Sequence[AssertionResult],
    *,
    action_results: Sequence[ActionExecutionResult],
    probe_results: Sequence[ProbeResult],
) -> None:
    stored_ids = {f"action.{item.action_id}" for item in action_results}
    stored_ids.update(
        observation.observation_id
        for probe in probe_results
        for observation in probe.observations
        if observation.kind == ObservationKind.RETRIEVAL_CANARY.value
    )
    if any(
        evidence_id not in stored_ids
        for result in assertion_results
        for evidence_id in result.evidence_ids
    ):
        raise AwsReciprocalRetrievalRunError(
            AwsReciprocalRetrievalRunFailureCode.INVALID_NORMALIZED_RESULT
        )


def _write_evidence(  # noqa: PLR0913 - exact artifact groups remain explicit.
    run: RunDirectory,
    paths: _ArtifactPaths,
    *,
    run_artifact: bytes,
    action_artifacts: Mapping[str, bytes],
    probe_artifacts: Mapping[str, bytes],
    assertion_results: Sequence[AssertionResult],
    terminal_report: bytes,
    json_report: bytes,
) -> None:
    written: set[str] = set()

    def write(
        path: str,
        content: bytes,
        *,
        sensitivity: Sensitivity,
        media_type: str = "application/json",
    ) -> None:
        run.write_evidence(
            path,
            content,
            media_type=media_type,
            sensitivity=sensitivity,
        )
        written.add(path)

    write(paths.run, run_artifact, sensitivity=Sensitivity.INTERNAL)
    for action_id in sorted(paths.actions):
        write(
            paths.actions[action_id],
            action_artifacts[action_id],
            sensitivity=Sensitivity.INTERNAL,
        )
    for probe_id in sorted(paths.probes):
        write(
            paths.probes[probe_id],
            probe_artifacts[probe_id],
            sensitivity=Sensitivity.INTERNAL,
        )
    results_by_id = {item.assertion_id: item for item in assertion_results}
    for assertion_id in sorted(paths.results):
        write(
            paths.results[assertion_id],
            results_by_id[assertion_id].to_json_bytes(),
            sensitivity=Sensitivity.PUBLIC,
        )
    write(
        paths.json_report,
        json_report,
        sensitivity=Sensitivity.PUBLIC,
    )
    write(
        paths.terminal_report,
        terminal_report,
        media_type="text/plain",
        sensitivity=Sensitivity.PUBLIC,
    )
    if written != set(paths.inventory) or len(written) != _RECIPROCAL_ARTIFACT_COUNT:
        raise AwsReciprocalRetrievalRunError(
            AwsReciprocalRetrievalRunFailureCode.EVIDENCE_PERSISTENCE_FAILED
        )


def _artifact_paths(selected: _SelectedReciprocal) -> _ArtifactPaths:
    identifiers = (
        *(chain.action.id for chain in selected.chains),
        *(chain.probe.id for chain in selected.chains),
        *(chain.assertion.id for chain in selected.chains),
    )
    digest_prefixes = tuple(_digest_prefix(identifier) for identifier in identifiers)
    if len(digest_prefixes) != len(set(digest_prefixes)):
        _invalid_configuration()
    paths = _ArtifactPaths(
        run="run.json",
        actions={
            chain.action.id: _item_path("actions", chain.action.id)
            for chain in selected.chains
        },
        probes={
            chain.probe.id: _item_path("probes", chain.probe.id)
            for chain in selected.chains
        },
        results={
            chain.assertion.id: _item_path("results", chain.assertion.id)
            for chain in selected.chains
        },
        json_report="reports/report.json",
        terminal_report="reports/terminal.txt",
    )
    if (
        len(paths.inventory) != _RECIPROCAL_ARTIFACT_COUNT
        or len(set(paths.inventory)) != _RECIPROCAL_ARTIFACT_COUNT
    ):
        _invalid_configuration()
    return paths


def _item_path(category: str, identifier: str) -> str:
    return f"{category}/item-{_digest_prefix(identifier)}.json"


def _digest_prefix(identifier: str) -> str:
    prefix = hashlib.sha256(identifier.encode()).hexdigest()[:16]
    if _DIGEST_PREFIX_PATTERN.fullmatch(prefix) is None:
        _invalid_configuration()
    return prefix


def _identity(
    suite: VerificationSuite,
    identity_ref: str,
) -> CurrentAwsIdentity | AssumedRoleIdentity:
    matches = tuple(
        identity for identity in suite.identities if identity.id == identity_ref
    )
    if len(matches) != 1 or not isinstance(
        matches[0] if matches else None,
        CurrentAwsIdentity | AssumedRoleIdentity,
    ):
        _invalid_configuration()
    return cast("CurrentAwsIdentity | AssumedRoleIdentity", matches[0])


def _identity_key(
    identity: CurrentAwsIdentity | AssumedRoleIdentity,
) -> tuple[str, ...]:
    if isinstance(identity, CurrentAwsIdentity):
        return ("awsCurrent",)
    return ("awsAssumeRole", identity.role_arn)


def _identity_environment_reference(
    identity: CurrentAwsIdentity | AssumedRoleIdentity,
) -> EnvironmentReference | None:
    if isinstance(identity, CurrentAwsIdentity):
        return identity.profile
    return identity.external_id


def _environment_value(
    reference: EnvironmentReference,
    environment: Mapping[str, str],
) -> str:
    try:
        value: object = environment[reference.name]
    except Exception:  # noqa: BLE001 - mapping diagnostics and names are private.
        raise AwsReciprocalRetrievalRunError(
            AwsReciprocalRetrievalRunFailureCode.INVALID_ENVIRONMENT
        ) from None
    if not isinstance(value, str) or not value:
        raise AwsReciprocalRetrievalRunError(
            AwsReciprocalRetrievalRunFailureCode.INVALID_ENVIRONMENT
        )
    return value


def _acquire_identity(
    identity: CurrentAwsIdentity | AssumedRoleIdentity,
    *,
    context: ExecutionContext,
    environment: Mapping[str, str],
    session_factory: AwsSessionFactory,
) -> AwsScopedIdentity:
    request = IdentityRequest(context=context, identity=identity)
    try:
        if isinstance(identity, CurrentAwsIdentity):
            return CurrentAwsIdentityProvider(
                environment=environment,
                session_factory=session_factory,
            ).provide_identity(request)
        return AssumedRoleAwsIdentityProvider(
            environment=environment,
            session_factory=session_factory,
        ).provide_identity(request)
    except AwsIdentityError:
        raise AwsReciprocalRetrievalRunError(
            AwsReciprocalRetrievalRunFailureCode.IDENTITY_UNAVAILABLE
        ) from None
    except Exception:  # noqa: BLE001 - SDK and credential diagnostics are private.
        raise AwsReciprocalRetrievalRunError(
            AwsReciprocalRetrievalRunFailureCode.IDENTITY_UNAVAILABLE
        ) from None


def _validate_lease(
    lease: AwsScopedIdentity,
    *,
    identity: CurrentAwsIdentity | AssumedRoleIdentity,
    suite: VerificationSuite,
    evaluated_at: datetime,
) -> None:
    account_id = suite.target.aws_account_id
    region = suite.target.aws_region
    expires_at = lease.expires_at
    if (
        type(lease) is not AwsScopedIdentity
        or lease.closed
        or lease.identity_id != identity.id
        or account_id is None
        or region is None
        or not lease.matches_account(account_id)
        or not lease.matches_partition(_partition_for_region(region))
        or (
            expires_at is not None
            and (
                expires_at.tzinfo is None
                or expires_at.utcoffset() is None
                or expires_at.astimezone(UTC) <= evaluated_at
            )
        )
    ):
        raise AwsReciprocalRetrievalRunError(
            AwsReciprocalRetrievalRunFailureCode.IDENTITY_UNAVAILABLE
        )


def _duplicate_successful_correlations(
    results: Sequence[ActionExecutionResult],
) -> bool:
    successful = [
        result.correlation_ids[0]
        for result in results
        if result.outcome is ActionOutcome.SUCCEEDED
        and len(result.correlation_ids) == 1
    ]
    return len(successful) == _RECIPROCAL_CHAIN_COUNT and successful[0] == successful[1]


def _close_lease(lease: AwsScopedIdentity) -> None:
    if not lease.closed:
        lease.close()


def _close_all_leases(leases: Iterable[AwsScopedIdentity]) -> None:
    close_failed = False
    try:
        iterable = tuple(leases)
    except Exception:  # noqa: BLE001 - only defensive cleanup remains.
        iterable = ()
        close_failed = True
    for lease in iterable:
        try:
            _close_lease(lease)
        except Exception:  # noqa: BLE001 - attempt every cleanup before failing.
            close_failed = True
    if close_failed:
        raise AwsReciprocalRetrievalRunError(
            AwsReciprocalRetrievalRunFailureCode.IDENTITY_UNAVAILABLE
        )


def _wall_clock(clock: Callable[[], datetime]) -> datetime:
    try:
        value = clock()
    except Exception:  # noqa: BLE001 - injected clock diagnostics are private.
        raise AwsReciprocalRetrievalRunError(
            AwsReciprocalRetrievalRunFailureCode.IDENTITY_UNAVAILABLE
        ) from None
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise AwsReciprocalRetrievalRunError(
            AwsReciprocalRetrievalRunFailureCode.IDENTITY_UNAVAILABLE
        )
    return value.astimezone(UTC)


def _monotonic_value(monotonic: Callable[[], float]) -> float:
    try:
        value = monotonic()
    except Exception:  # noqa: BLE001 - injected clock diagnostics are private.
        raise AwsReciprocalRetrievalRunError(
            AwsReciprocalRetrievalRunFailureCode.DURATION_EXHAUSTED
        ) from None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise AwsReciprocalRetrievalRunError(
            AwsReciprocalRetrievalRunFailureCode.DURATION_EXHAUSTED
        )
    normalized = float(value)
    if not math.isfinite(normalized):
        raise AwsReciprocalRetrievalRunError(
            AwsReciprocalRetrievalRunFailureCode.DURATION_EXHAUSTED
        )
    return normalized


def _duration(value: str) -> timedelta:
    match = _FRESHNESS_PATTERN.fullmatch(value)
    if match is None or not any(match.groupdict().values()):
        _invalid_configuration()
    return timedelta(
        hours=int(match.group("hours") or 0),
        minutes=int(match.group("minutes") or 0),
        seconds=int(match.group("seconds") or 0),
    )


def _invalid_configuration() -> Never:
    raise AwsReciprocalRetrievalRunError(
        AwsReciprocalRetrievalRunFailureCode.INVALID_CONFIGURATION
    )
