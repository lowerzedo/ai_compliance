"""Minimal AWS execution path for one pre-seeded retrieval-boundary chain."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, cast, final

from cai_verify.assertions import RetrievalBoundaryEvaluator
from cai_verify.aws.action import AwsSigV4ActionAdapter
from cai_verify.aws.cloudwatch_logs import CloudWatchLogsProbeAdapter
from cai_verify.aws.execution_policy import (
    AwsExecutionPolicy,
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
    RetrievalBoundaryAssertion,
    VerificationSuite,
)
from cai_verify.config.models import DeploymentEnvironment, ObservationKind
from cai_verify.core import AssertionResult, CliExitCode, exit_code_for_results
from cai_verify.plugins import (
    ActionExecutionResult,
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
    from collections.abc import Callable, Mapping

    from cai_verify.config import Scenario

_FRESHNESS_PATTERN = re.compile(
    r"PT(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?"
    r"(?:(?P<seconds>\d+)S)?\Z"
)
_SECONDS_PER_MINUTE = 60


class AwsRetrievalRunFailureCode(StrEnum):
    """Stable non-secret failures raised before normalized execution results."""

    IDENTITY_UNAVAILABLE = "identity_unavailable"
    INVALID_CONFIGURATION = "invalid_configuration"
    INVALID_ENVIRONMENT = "invalid_environment"


class AwsRetrievalRunError(RuntimeError):
    """A fixed runner failure that excludes environment and SDK diagnostics."""

    def __init__(self, code: AwsRetrievalRunFailureCode) -> None:
        """Create one stable public failure category."""
        self.code = code
        super().__init__(f"AWS retrieval run failed ({code.value})")


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class AwsRetrievalRunOptions:
    """Explicit selection and runtime dependencies for one chain."""

    run_id: str
    assertion_id: str
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


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class AwsRetrievalRunResult:
    """One evaluated retrieval chain with detached deterministic reports."""

    run_id: str
    scenario_id: str
    action_result: ActionExecutionResult
    probe_result: ProbeResult
    assertion_result: AssertionResult
    exit_code: CliExitCode
    terminal_report: bytes
    json_report: bytes


@dataclass(frozen=True, slots=True, repr=False)
class _SelectedChain:
    scenario: Scenario
    assertion: RetrievalBoundaryAssertion
    action: AwsSigV4Action
    probe: CloudWatchLogsProbe
    action_identity: CurrentAwsIdentity | AssumedRoleIdentity
    evidence_identity: CurrentAwsIdentity | AssumedRoleIdentity


def run_aws_retrieval_chain(
    suite: VerificationSuite,
    options: AwsRetrievalRunOptions,
) -> AwsRetrievalRunResult:
    """Execute, collect, and evaluate exactly one declared retrieval chain."""
    evaluated_at = _normalized_time(options.clock())
    selected = _selected_chain(suite, options.assertion_id)
    context = ExecutionContext(
        run_id=options.run_id,
        scenario_id=selected.scenario.id,
        target=suite.target,
    )
    suite_max_age = _duration(suite.evidence_policy.max_age)
    clock_skew = _duration(suite.evidence_policy.clock_skew_tolerance)
    probe_adapter = options.probe_adapter or CloudWatchLogsProbeAdapter(
        environment=options.environment,
        suite_max_age=suite_max_age,
        clock_skew_tolerance=clock_skew,
        clock=lambda: evaluated_at,
        monotonic=options.monotonic,
    )
    _prevalidate_probe_environment(probe_adapter, selected.probe)
    authorize_aws_execution(
        options.execution_policy,
        target=suite.target,
        identities=(selected.action_identity, selected.evidence_identity),
        actions=(selected.action,),
        cloudwatch_log_groups=(selected.probe.log_group,),
    )
    action_adapter = options.action_adapter or AwsSigV4ActionAdapter(
        environment=options.environment,
        clock=lambda: evaluated_at,
    )

    identities = {
        selected.action_identity.id: selected.action_identity,
        selected.evidence_identity.id: selected.evidence_identity,
    }
    leases: dict[str, AwsScopedIdentity] = {}
    try:
        for identity_id in sorted(identities):
            lease = _acquire_identity(
                identities[identity_id],
                context=context,
                environment=options.environment,
                session_factory=options.session_factory,
            )
            leases[identity_id] = lease
            _validate_lease(lease, suite=suite, evaluated_at=evaluated_at)
        action_result = action_adapter.execute_action(
            ActionRequest(
                context=context,
                action=selected.action,
                identity=leases[selected.action_identity.id],
            )
        )
        probe_result = probe_adapter.collect_evidence(
            ProbeRequest(
                context=context,
                probe=selected.probe,
                action_result=action_result,
                identity=leases[selected.evidence_identity.id],
            )
        )
        assertion_result = RetrievalBoundaryEvaluator(
            clock=lambda: evaluated_at
        ).evaluate_assertion(
            AssertionEvaluationRequest(
                assertion=selected.assertion,
                action_results=(action_result,),
                probe_results=(probe_result,),
            )
        )
    finally:
        for lease in leases.values():
            lease.close()

    report_request = ReportRequest.from_results(
        run_id=options.run_id,
        results=(assertion_result,),
    )
    terminal_report = TerminalReporter().render_report(report_request).content
    json_report = JsonReporter().render_report(report_request).content
    return AwsRetrievalRunResult(
        run_id=options.run_id,
        scenario_id=selected.scenario.id,
        action_result=action_result,
        probe_result=probe_result,
        assertion_result=assertion_result,
        exit_code=exit_code_for_results((assertion_result,)),
        terminal_report=terminal_report,
        json_report=json_report,
    )


def _selected_chain(
    suite: VerificationSuite,
    assertion_id: str,
) -> _SelectedChain:
    matches = tuple(
        (scenario, assertion)
        for scenario in suite.scenarios
        for assertion in scenario.assertions
        if assertion.id == assertion_id
    )
    if len(matches) != 1 or not isinstance(
        matches[0][1] if matches else None,
        RetrievalBoundaryAssertion,
    ):
        raise AwsRetrievalRunError(AwsRetrievalRunFailureCode.INVALID_CONFIGURATION)
    scenario, assertion_value = matches[0]
    assertion = cast("RetrievalBoundaryAssertion", assertion_value)
    actions = tuple(
        action for action in scenario.actions if action.id == assertion.action_ref
    )
    probes = tuple(
        probe for probe in scenario.probes if probe.id == assertion.probe_ref
    )
    if (
        len(actions) != 1
        or len(probes) != 1
        or not isinstance(actions[0], AwsSigV4Action)
        or actions[0].service != "execute-api"
        or actions[0].mutating is not False
        or not isinstance(probes[0], CloudWatchLogsProbe)
        or probes[0].action_ref != actions[0].id
        or ObservationKind.RETRIEVAL_CANARY not in probes[0].observations
        or suite.target.environment is DeploymentEnvironment.LOCAL
        or suite.target.aws_region is None
        or (
            actions[0].region is not None
            and actions[0].region != suite.target.aws_region
        )
    ):
        raise AwsRetrievalRunError(AwsRetrievalRunFailureCode.INVALID_CONFIGURATION)
    action = actions[0]
    probe = probes[0]
    action_identity = _identity(
        suite,
        action.identity_ref or scenario.identity_ref,
    )
    evidence_identity = _identity(
        suite,
        probe.identity_ref or scenario.identity_ref,
    )
    return _SelectedChain(
        scenario=scenario,
        assertion=assertion,
        action=action,
        probe=probe,
        action_identity=action_identity,
        evidence_identity=evidence_identity,
    )


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
        raise AwsRetrievalRunError(AwsRetrievalRunFailureCode.INVALID_CONFIGURATION)
    return cast("CurrentAwsIdentity | AssumedRoleIdentity", matches[0])


def _prevalidate_probe_environment(
    adapter: CloudWatchLogsProbeAdapter,
    probe: CloudWatchLogsProbe,
) -> None:
    _, canary_failure = adapter._canary(probe)  # noqa: SLF001
    _, bedrock_failure = adapter._bedrock(probe)  # noqa: SLF001
    _, retrieval_failure = adapter._retrieval(probe)  # noqa: SLF001
    if canary_failure is not None or bedrock_failure is not None:
        raise AwsRetrievalRunError(AwsRetrievalRunFailureCode.INVALID_ENVIRONMENT)
    if retrieval_failure is not None:
        raise AwsRetrievalRunError(AwsRetrievalRunFailureCode.INVALID_ENVIRONMENT)


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
        raise AwsRetrievalRunError(
            AwsRetrievalRunFailureCode.IDENTITY_UNAVAILABLE
        ) from None
    except Exception:  # noqa: BLE001 - provider diagnostics are discarded.
        raise AwsRetrievalRunError(
            AwsRetrievalRunFailureCode.IDENTITY_UNAVAILABLE
        ) from None


def _validate_lease(
    lease: AwsScopedIdentity,
    *,
    suite: VerificationSuite,
    evaluated_at: datetime,
) -> None:
    target = suite.target
    account_id = target.aws_account_id
    region = target.aws_region
    expires_at = lease.expires_at
    if (
        lease.closed
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
        raise AwsRetrievalRunError(AwsRetrievalRunFailureCode.IDENTITY_UNAVAILABLE)


def _duration(value: str) -> timedelta:
    match = _FRESHNESS_PATTERN.fullmatch(value)
    if match is None or not any(match.groupdict().values()):
        raise AwsRetrievalRunError(AwsRetrievalRunFailureCode.INVALID_CONFIGURATION)
    return timedelta(
        hours=int(match.group("hours") or 0),
        minutes=int(match.group("minutes") or 0),
        seconds=int(match.group("seconds") or 0),
    )


def _normalized_time(value: object) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise AwsRetrievalRunError(AwsRetrievalRunFailureCode.INVALID_CONFIGURATION)
    return value.astimezone(UTC)
