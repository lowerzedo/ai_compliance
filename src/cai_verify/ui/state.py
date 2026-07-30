"""In-memory state and engine coordination for the local security console."""

from __future__ import annotations

import copy
import os
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast, final

from cai_verify.assertions.retrieval import (
    RETRIEVAL_BOUNDARY_EVALUATOR_VERSION,
    RETRIEVAL_BOUNDARY_FIXED_LIMITATIONS,
)
from cai_verify.aws import (
    AwsDoctorResult,
    AwsExecutionPolicy,
    AwsExecutionPolicyError,
    AwsIdentityCheck,
    AwsReciprocalRetrievalRunError,
    AwsReciprocalRetrievalRunOptions,
    AwsReciprocalRetrievalRunResult,
    AwsReciprocalRetrievalRunStage,
    RetrievalDoctorResult,
    RetrievalReadinessCheck,
    authorize_aws_execution,
    load_aws_execution_policy_bytes,
    run_aws_doctor,
    run_aws_reciprocal_retrieval,
    run_retrieval_doctor,
    validated_aws_reciprocal_retrieval_slice,
)
from cai_verify.config import (
    AssumedRoleIdentity,
    AwsSigV4Action,
    CloudWatchLogsProbe,
    CurrentAwsIdentity,
    EnvironmentReference,
    RetrievalBoundaryAssertion,
    VerificationSuite,
    load_suite_bytes,
)
from cai_verify.core import AssertionResult, aggregate_results, exit_code_for_status
from cai_verify.ui.history import (
    EvidenceHistoryRecord,
    EvidenceHistoryState,
    verify_generated_evidence_run,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from cai_verify.config import ActionInput

_READINESS_LIFETIME = timedelta(minutes=5)
_MASK = "••••••••"
_SCHEMA_VERSION = "1"
_MAX_REVEALED_FIELDS = 64
_MAX_FIELD_ID_LENGTH = 32
_MAX_SCENARIO_ID_LENGTH = 256
_SCENARIO_ALIAS = "scenario-01"
_TARGET_ALIAS = "target-01"
_DIRECTION_COUNT = 2
_MAX_RETRIEVED_ITEMS = 10_000
_PROGRESS_POSITION = {
    stage: position
    for position, stage in enumerate(
        (
            AwsReciprocalRetrievalRunStage.VALIDATION,
            AwsReciprocalRetrievalRunStage.AUTHORIZATION,
            AwsReciprocalRetrievalRunStage.IDENTITY_ACQUISITION,
            AwsReciprocalRetrievalRunStage.DIRECTION_ONE,
            AwsReciprocalRetrievalRunStage.DIRECTION_TWO,
            AwsReciprocalRetrievalRunStage.EVALUATION,
            AwsReciprocalRetrievalRunStage.FINALIZATION,
            AwsReciprocalRetrievalRunStage.INTEGRITY_VERIFICATION,
        )
    )
}
_NORMALIZED_STATE_VALUES = frozenset(
    {
        "action_correlation_missing_or_ambiguous",
        "action_denied",
        "action_execution_error",
        "action_missing_or_ambiguous",
        "baseline_not_observed",
        "complete_evidence_missing_source_time",
        "contradictory_complete_evidence",
        "contradictory_incomplete_evidence",
        "declared_boundary_observed",
        "evaluator_error",
        "future_action_evidence",
        "future_probe_collection",
        "future_probe_source",
        "incomplete_evidence_with_source_time",
        "inconsistent_probe_source_time",
        "invalid_normalized_field_set",
        "invalid_normalized_scalar_type",
        "invalid_probe_freshness_policy",
        "invalid_retrieved_item_count",
        "isolated_retrieval_observed",
        "marker_observed_with_zero_retrieved_items",
        "normalized_evidence_incomplete",
        "observation_missing_or_ambiguous",
        "probe_missing_or_ambiguous",
        "retrieval_path_unexercised",
        "stale_action_evidence",
        "stale_probe_evidence",
        "undeclared_marker_observed",
        "unsupported_probe_source",
    }
)


class _AwsDoctor(Protocol):
    def __call__(
        self,
        suite: VerificationSuite,
        *,
        execution_policy: AwsExecutionPolicy,
        environment: Mapping[str, str],
    ) -> AwsDoctorResult: ...


class _RetrievalDoctor(Protocol):
    def __call__(
        self,
        suite: VerificationSuite,
        *,
        execution_policy: AwsExecutionPolicy,
        environment: Mapping[str, str],
    ) -> RetrievalDoctorResult: ...


class _ReciprocalRunner(Protocol):
    def __call__(
        self,
        suite: VerificationSuite,
        options: AwsReciprocalRetrievalRunOptions,
    ) -> AwsReciprocalRetrievalRunResult: ...


class _EvidenceVerifier(Protocol):
    def __call__(
        self,
        evidence_root: str | os.PathLike[str],
        raw_run_id: str,
    ) -> EvidenceHistoryRecord: ...


class ConsoleRunState(StrEnum):
    """Stable local job states returned by the console API."""

    IDLE = "idle"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


@final
@dataclass(frozen=True, slots=True)
class ConsoleRuntime:
    """Injectable engine seams for network-isolated console tests."""

    aws_doctor: _AwsDoctor = run_aws_doctor
    retrieval_doctor: _RetrievalDoctor = run_retrieval_doctor
    reciprocal_runner: _ReciprocalRunner = run_aws_reciprocal_retrieval
    evidence_verifier: _EvidenceVerifier = verify_generated_evidence_run


@final
@dataclass(frozen=True, slots=True)
class _SensitiveField:
    field_id: str
    label: str
    kind: str
    value: str = field(repr=False)

    def masked_view(self) -> dict[str, object]:
        return {
            "id": self.field_id,
            "kind": self.kind,
            "label": self.label,
            "masked": _MASK,
        }

    def revealed_view(self) -> dict[str, object]:
        return {
            "id": self.field_id,
            "label": self.label,
            "value": self.value,
        }


@final
@dataclass(frozen=True, slots=True)
class _ReadinessSnapshot:
    generation: int
    checked_at: datetime
    expires_at: datetime
    checked_monotonic: float
    expires_monotonic: float
    ready: bool
    aws: dict[str, object]
    retrieval: dict[str, object]


@final
@dataclass(slots=True)
class _ActiveRun:
    state: ConsoleRunState = ConsoleRunState.IDLE
    run_id: str | None = None
    scenario_id: str | None = None
    stage: AwsReciprocalRetrievalRunStage | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    failure_category: str | None = None
    result: dict[str, object] | None = field(default=None, repr=False)


class ConsoleState:
    """Own one process-local configuration, readiness result, and active job."""

    def __init__(
        self,
        *,
        evidence_root: Path,
        environment: Mapping[str, str] | None = None,
        runtime: ConsoleRuntime | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Initialize one isolated process-local console state."""
        self.evidence_root = Path(
            os.path.abspath(  # noqa: PTH100 - do not resolve root symlinks.
                os.fspath(evidence_root)
            )
        )
        self._environment = environment if environment is not None else os.environ
        self._runtime = runtime or ConsoleRuntime()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._monotonic = time.monotonic
        self._lock = threading.RLock()
        self._executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="cai-verify-ui",
        )
        self._suite: VerificationSuite | None = None
        self._policy: AwsExecutionPolicy | None = None
        self._sensitive_fields: tuple[_SensitiveField, ...] = ()
        self._generation = 0
        self._readiness: _ReadinessSnapshot | None = None
        self._readiness_running = False
        self._active = _ActiveRun()

    def close(self) -> None:
        """Stop accepting queued work without interrupting an in-flight AWS call."""
        self._executor.shutdown(wait=False, cancel_futures=True)

    def load_suite(self, content: bytes) -> dict[str, object]:
        """Replace suite state only after bounded strict validation succeeds."""
        with self._lock:
            if self._active.state is ConsoleRunState.RUNNING:
                raise ConsoleStateError(ConsoleStateFailureCode.RUN_ALREADY_ACTIVE)
            self._suite = None
            self._configuration_changed()
        suite = load_suite_bytes(content)
        reciprocal_slices: list[VerificationSuite] = []
        for scenario in suite.scenarios:
            try:
                reciprocal_slices.append(
                    validated_aws_reciprocal_retrieval_slice(
                        suite,
                        scenario.id,
                    )
                )
            except AwsReciprocalRetrievalRunError:
                continue
        if len(reciprocal_slices) != 1:
            message = "console requires one unambiguous reciprocal scenario"
            raise ValueError(message)
        suite = reciprocal_slices[0]
        with self._lock:
            self._suite = suite
            self._configuration_changed()
            return self.configuration_view()

    def load_policy(self, content: bytes) -> dict[str, object]:
        """Replace policy state only after bounded strict validation succeeds."""
        with self._lock:
            if self._active.state is ConsoleRunState.RUNNING:
                raise ConsoleStateError(ConsoleStateFailureCode.RUN_ALREADY_ACTIVE)
            self._policy = None
            self._configuration_changed()
        policy = load_aws_execution_policy_bytes(content)
        with self._lock:
            self._policy = policy
            self._configuration_changed()
            return self.configuration_view()

    def configuration_view(self) -> dict[str, object]:
        """Return one redacted configuration review with no sensitive values."""
        with self._lock:
            suite = self._suite
            policy = self._policy
            loaded = suite is not None and policy is not None
            review: dict[str, object] | None = None
            if suite is not None and policy is not None:
                self._sensitive_fields = _build_sensitive_fields(suite, policy)
                review = {
                    "actionCount": _DIRECTION_COUNT,
                    "assertionCount": _DIRECTION_COUNT,
                    "identityCount": len(suite.identities),
                    "plan": _configuration_plan(suite, policy),
                    "probeCount": _DIRECTION_COUNT,
                    "region": suite.target.aws_region,
                    "scenarios": [
                        {
                            "description": "Exact reciprocal retrieval",
                            "directionCount": _DIRECTION_COUNT,
                            "id": _SCENARIO_ALIAS,
                        }
                    ],
                    "sensitiveFields": [
                        item.masked_view() for item in self._sensitive_fields
                    ],
                    "suiteDescription": (
                        "One validated two-direction reciprocal retrieval plan."
                    ),
                    "suiteName": "Validated reciprocal suite",
                    "targetEnvironment": suite.target.environment.value,
                    "targetId": _TARGET_ALIAS,
                }
            return {
                "configurationRevision": self._generation,
                "policyLoaded": policy is not None,
                "readyForReview": loaded,
                "review": review,
                "schemaVersion": _SCHEMA_VERSION,
                "suiteLoaded": suite is not None,
            }

    def reveal(
        self,
        requested: object,
        configuration_revision: object,
    ) -> dict[str, object]:
        """Reveal only opaque allowlisted field identifiers from current models."""
        if (
            not isinstance(requested, list)
            or not requested
            or len(requested) > _MAX_REVEALED_FIELDS
            or type(configuration_revision) is not int
            or any(
                type(item) is not str or len(item) > _MAX_FIELD_ID_LENGTH
                for item in requested
            )
            or len(set(cast("list[str]", requested))) != len(requested)
        ):
            raise ConsoleStateError(ConsoleStateFailureCode.INVALID_REQUEST)
        with self._lock:
            if configuration_revision != self._generation:
                raise ConsoleStateError(ConsoleStateFailureCode.CONFIGURATION_CHANGED)
            allowed = {item.field_id: item for item in self._sensitive_fields}
            if any(item not in allowed for item in requested):
                raise ConsoleStateError(ConsoleStateFailureCode.INVALID_REQUEST)
            return {
                "configurationRevision": self._generation,
                "expiresInSeconds": 30,
                "fields": [allowed[item].revealed_view() for item in requested],
                "schemaVersion": _SCHEMA_VERSION,
            }

    def run_readiness(self) -> dict[str, object]:
        """Run both existing read-only doctors and retain only their safe views."""
        with self._lock:
            suite, policy = self._required_configuration()
            if self._readiness_running:
                raise ConsoleStateError(ConsoleStateFailureCode.READINESS_IN_PROGRESS)
            self._readiness_running = True
            self._readiness = None
            generation = self._generation
        try:
            aws = self._runtime.aws_doctor(
                suite,
                execution_policy=policy,
                environment=self._environment,
            )
            retrieval = self._runtime.retrieval_doctor(
                suite,
                execution_policy=policy,
                environment=self._environment,
            )
            normalized_aws = _normalized_aws_readiness(aws, suite)
            normalized_retrieval = _normalized_retrieval_readiness(
                retrieval,
                suite,
            )
            checked_at = _normalized_clock(self._clock)
            checked_monotonic = self._monotonic()
            snapshot = _ReadinessSnapshot(
                generation=generation,
                checked_at=checked_at,
                expires_at=checked_at + _READINESS_LIFETIME,
                checked_monotonic=checked_monotonic,
                expires_monotonic=checked_monotonic
                + _READINESS_LIFETIME.total_seconds(),
                ready=aws.ready and retrieval.ready,
                aws=normalized_aws,
                retrieval=normalized_retrieval,
            )
        except AwsExecutionPolicyError as error:
            with self._lock:
                self._readiness_running = False
            raise ConsoleStateError(ConsoleStateFailureCode(error.code.value)) from None
        except Exception:  # noqa: BLE001 - SDK and doctor details stay redacted.
            with self._lock:
                self._readiness_running = False
            raise ConsoleStateError(ConsoleStateFailureCode.READINESS_FAILED) from None
        with self._lock:
            if generation != self._generation:
                self._readiness_running = False
                raise ConsoleStateError(ConsoleStateFailureCode.CONFIGURATION_CHANGED)
            self._readiness = snapshot
            self._readiness_running = False
            return _readiness_view(snapshot)

    def start_run(
        self,
        scenario_id: object,
        configuration_revision: object,
    ) -> dict[str, object]:
        """Start one server-generated run only after fresh successful readiness."""
        if (
            type(scenario_id) is not str
            or not scenario_id
            or len(scenario_id) > _MAX_SCENARIO_ID_LENGTH
            or type(configuration_revision) is not int
        ):
            raise ConsoleStateError(ConsoleStateFailureCode.INVALID_REQUEST)
        with self._lock:
            suite, policy = self._required_configuration()
            if self._readiness_running:
                raise ConsoleStateError(ConsoleStateFailureCode.READINESS_IN_PROGRESS)
            if configuration_revision != self._generation:
                raise ConsoleStateError(ConsoleStateFailureCode.CONFIGURATION_CHANGED)
            readiness = self._readiness
            now = _normalized_clock(self._clock)
            if (
                readiness is None
                or readiness.generation != self._generation
                or not readiness.ready
                or self._readiness_expired(readiness, now)
            ):
                raise ConsoleStateError(ConsoleStateFailureCode.READINESS_REQUIRED)
            if scenario_id != _SCENARIO_ALIAS:
                raise ConsoleStateError(ConsoleStateFailureCode.INVALID_REQUEST)
            if self._active.state is ConsoleRunState.RUNNING:
                raise ConsoleStateError(ConsoleStateFailureCode.RUN_ALREADY_ACTIVE)
            run_id = _new_run_id(now)
            self._active = _ActiveRun(
                state=ConsoleRunState.RUNNING,
                run_id=run_id,
                scenario_id=_SCENARIO_ALIAS,
                stage=AwsReciprocalRetrievalRunStage.VALIDATION,
                started_at=now,
            )
            self._executor.submit(
                self._execute_run,
                suite,
                policy,
                run_id,
                suite.scenarios[0].id,
            )
            return self.active_run_view()

    def active_run_view(self) -> dict[str, object]:
        """Return one safe detached snapshot of the active or last local job."""
        with self._lock:
            active = self._active
            return {
                "completedAt": _timestamp_or_none(active.completed_at),
                "failureCategory": active.failure_category,
                "result": copy.deepcopy(active.result),
                "runId": active.run_id,
                "scenarioId": active.scenario_id,
                "schemaVersion": _SCHEMA_VERSION,
                "stage": active.stage.value if active.stage is not None else None,
                "startedAt": _timestamp_or_none(active.started_at),
                "state": active.state.value,
            }

    def readiness_view(self) -> dict[str, object] | None:
        """Return readiness only while it belongs to current configuration."""
        with self._lock:
            snapshot = self._readiness
            if snapshot is None or snapshot.generation != self._generation:
                return None
            if self._readiness_expired(
                snapshot,
                _normalized_clock(self._clock),
            ):
                self._readiness = None
                return None
            return _readiness_view(snapshot)

    def _readiness_expired(
        self,
        snapshot: _ReadinessSnapshot,
        now: datetime,
    ) -> bool:
        """Fail closed for elapsed expiry or a reversing wall clock."""
        monotonic_now = self._monotonic()
        return (
            now < snapshot.checked_at
            or now >= snapshot.expires_at
            or monotonic_now < snapshot.checked_monotonic
            or monotonic_now >= snapshot.expires_monotonic
        )

    def _configuration_changed(self) -> None:
        self._generation += 1
        self._readiness = None
        self._sensitive_fields = ()
        if self._active.state is not ConsoleRunState.RUNNING:
            self._active = _ActiveRun()

    def _required_configuration(
        self,
    ) -> tuple[VerificationSuite, AwsExecutionPolicy]:
        if self._suite is None or self._policy is None:
            raise ConsoleStateError(ConsoleStateFailureCode.CONFIGURATION_REQUIRED)
        return self._suite, self._policy

    def _execute_run(
        self,
        suite: VerificationSuite,
        policy: AwsExecutionPolicy,
        run_id: str,
        scenario_id: str,
    ) -> None:
        def progress(stage: AwsReciprocalRetrievalRunStage) -> None:
            with self._lock:
                current_stage = self._active.stage
                if (
                    self._active.run_id == run_id
                    and type(stage) is AwsReciprocalRetrievalRunStage
                    and stage in _PROGRESS_POSITION
                    and current_stage in _PROGRESS_POSITION
                    and _PROGRESS_POSITION[stage] >= _PROGRESS_POSITION[current_stage]
                ):
                    self._active.stage = stage

        try:
            result = self._runtime.reciprocal_runner(
                suite,
                AwsReciprocalRetrievalRunOptions(
                    run_id=run_id,
                    scenario_id=scenario_id,
                    evidence_root=self.evidence_root,
                    execution_policy=policy,
                    environment=self._environment,
                    progress=progress,
                ),
            )
            normalized_result = _normalized_run_result(
                result,
                expected_run_id=run_id,
                expected_scenario_id=scenario_id,
                expected_evidence_path=self.evidence_root / run_id,
                expected_assertion_ids=cast(
                    "tuple[str, str]",
                    tuple(
                        sorted(
                            assertion.id
                            for assertion in suite.scenarios[0].assertions
                            if isinstance(
                                assertion,
                                RetrievalBoundaryAssertion,
                            )
                        )
                    ),
                ),
            )
        except AwsExecutionPolicyError as error:
            self._fail_run(run_id, error.code.value)
            return
        except AwsReciprocalRetrievalRunError as error:
            self._fail_run(run_id, error.code.value)
            return
        except Exception:  # noqa: BLE001 - worker failures return a stable category.
            self._fail_run(run_id, "execution_failed")
            return
        try:
            verification = self._runtime.evidence_verifier(
                self.evidence_root,
                run_id,
            )
            _require_matching_verified_bundle(
                verification,
                normalized_result=normalized_result,
                expected_run_id=run_id,
                expected_evidence_path=self.evidence_root / run_id,
                expected_region=cast("str", suite.target.aws_region),
            )
        except Exception:  # noqa: BLE001 - integrity diagnostics stay private.
            self._fail_run(run_id, "integrity_verification_failed")
            return
        with self._lock:
            if self._active.run_id != run_id:
                return
            self._active.state = ConsoleRunState.COMPLETE
            self._active.stage = AwsReciprocalRetrievalRunStage.COMPLETE
            self._active.completed_at = _normalized_clock(self._clock)
            self._active.result = normalized_result

    def _fail_run(self, run_id: str, category: str) -> None:
        with self._lock:
            if self._active.run_id != run_id:
                return
            self._active.state = ConsoleRunState.FAILED
            self._active.stage = AwsReciprocalRetrievalRunStage.FAILED
            self._active.completed_at = _normalized_clock(self._clock)
            self._active.failure_category = category
            self._active.result = None


class ConsoleStateFailureCode(StrEnum):
    """Stable UI coordination failures with no source or SDK diagnostics."""

    INVALID_REQUEST = "invalid_request"
    CONFIGURATION_REQUIRED = "configuration_required"
    CONFIGURATION_CHANGED = "configuration_changed"
    READINESS_REQUIRED = "readiness_required"
    READINESS_FAILED = "readiness_failed"
    READINESS_IN_PROGRESS = "readiness_in_progress"
    RUN_ALREADY_ACTIVE = "run_already_active"
    INVALID_EXECUTION_POLICY = "invalid_execution_policy"
    EXECUTION_POLICY_DENIED = "execution_policy_denied"
    UNAUTHORIZED_ACCOUNT = "unauthorized_account"
    UNAUTHORIZED_PARTITION = "unauthorized_partition"
    UNAUTHORIZED_REGION = "unauthorized_region"
    UNAUTHORIZED_ENDPOINT = "unauthorized_endpoint"
    UNAUTHORIZED_ACTION = "unauthorized_action"
    UNAUTHORIZED_IDENTITY = "unauthorized_identity"
    UNAUTHORIZED_EVIDENCE_SOURCE = "unauthorized_evidence_source"


class ConsoleStateError(RuntimeError):
    """One redacted console-state failure."""

    def __init__(self, code: ConsoleStateFailureCode) -> None:
        """Construct one fixed failure without retaining source diagnostics."""
        self.code = code
        super().__init__(f"console operation failed ({code.value})")


def _configuration_plan(
    suite: VerificationSuite,
    policy: AwsExecutionPolicy,
) -> dict[str, object]:
    """Project the exact reciprocal chain with only opaque local aliases."""
    scenario = suite.scenarios[0]
    identity_aliases = {
        identity.id: f"identity-{position:02d}"
        for position, identity in enumerate(
            sorted(suite.identities, key=lambda item: item.id),
            start=1,
        )
    }
    actions = {item.id: item for item in scenario.actions}
    probes = {item.id: item for item in scenario.probes}
    directions: list[dict[str, object]] = []
    for position, assertion in enumerate(
        sorted(scenario.assertions, key=lambda item: item.id),
        start=1,
    ):
        if not isinstance(assertion, RetrievalBoundaryAssertion):
            message = "console plan requires retrieval assertions"
            raise TypeError(message)
        action = actions[assertion.action_ref]
        probe = probes[assertion.probe_ref]
        if not isinstance(action, AwsSigV4Action) or not isinstance(
            probe,
            CloudWatchLogsProbe,
        ):
            message = "console plan requires AWS retrieval chains"
            raise TypeError(message)
        requester_id = action.identity_ref or scenario.identity_ref
        evidence_id = probe.identity_ref or scenario.identity_ref
        path_authorized = any(
            item.method == action.method.value
            and item.path == action.path
            and item.service == action.service
            for item in policy.actions
        )
        directions.append(
            {
                "action": {
                    "environmentInputCount": sum(
                        isinstance(item.value, EnvironmentReference)
                        for item in action.inputs
                    ),
                    "inputCount": len(action.inputs),
                    "label": f"action-{position:02d}",
                    "method": action.method.value,
                    "mutating": action.mutating,
                    "pathAuthorized": path_authorized,
                    "region": action.region,
                    "requester": identity_aliases[requester_id],
                    "service": action.service,
                    "timeoutSeconds": action.timeout_seconds,
                    "type": action.type,
                },
                "assertion": {
                    "controlReferenceCount": len(assertion.control_refs),
                    "label": f"assertion-{position:02d}",
                    "limitationCount": len(assertion.limitations),
                    "type": assertion.type,
                },
                "evidence": {
                    "freshness": probe.max_age,
                    "label": f"probe-{position:02d}",
                    "logGroupAuthorized": (
                        probe.log_group in policy.cloudwatch_log_groups
                    ),
                    "observations": [
                        observation.value for observation in probe.observations
                    ],
                    "reader": identity_aliases[evidence_id],
                    "retrievalContractConfigured": probe.retrieval is not None,
                    "type": probe.type,
                },
                "id": f"direction-{position:02d}",
            }
        )
    authorization_matched = _plan_authorization_matches(suite, policy)
    return {
        "authorizationMatched": authorization_matched,
        "directions": directions,
        "evidenceFreshness": {
            "clockSkewTolerance": suite.evidence_policy.clock_skew_tolerance,
            "maxAge": suite.evidence_policy.max_age,
        },
        "identities": [
            {
                "label": identity_aliases[identity.id],
                "type": identity.type,
            }
            for identity in sorted(suite.identities, key=lambda item: item.id)
        ],
        "policy": {
            "actionCount": len(policy.actions),
            "allowCurrentIdentity": policy.allow_current_identity,
            "evidenceSourceCount": len(policy.cloudwatch_log_groups),
            "partition": policy.partition,
            "region": policy.region,
            "roleCount": len(policy.assumed_role_arns),
        },
        "scenario": _SCENARIO_ALIAS,
        "target": {
            "environment": suite.target.environment.value,
            "label": _TARGET_ALIAS,
            "region": suite.target.aws_region,
        },
    }


def _plan_authorization_matches(
    suite: VerificationSuite,
    policy: AwsExecutionPolicy,
) -> bool:
    scenario = suite.scenarios[0]
    try:
        authorize_aws_execution(
            policy,
            target=suite.target,
            identities=suite.identities,
            actions=cast("tuple[AwsSigV4Action, ...]", scenario.actions),
            cloudwatch_log_groups=tuple(
                probe.log_group
                for probe in scenario.probes
                if isinstance(probe, CloudWatchLogsProbe)
            ),
        )
    except AwsExecutionPolicyError:
        return False
    return True


def _identity_aliases(suite: VerificationSuite) -> dict[str, str]:
    return {
        identity.id: f"identity-{position:02d}"
        for position, identity in enumerate(
            sorted(suite.identities, key=lambda item: item.id),
            start=1,
        )
    }


def _direction_aliases(
    suite: VerificationSuite,
) -> dict[str, tuple[str, str, str]]:
    scenario = suite.scenarios[0]
    aliases: dict[str, tuple[str, str, str]] = {}
    for position, assertion in enumerate(
        sorted(scenario.assertions, key=lambda item: item.id),
        start=1,
    ):
        if not isinstance(assertion, RetrievalBoundaryAssertion):
            message = "console readiness requires retrieval assertions"
            raise TypeError(message)
        aliases[assertion.id] = (
            f"direction-{position:02d}",
            assertion.action_ref,
            assertion.probe_ref,
        )
    return aliases


def _normalized_aws_readiness(
    result: object,
    suite: VerificationSuite,
) -> dict[str, object]:
    if type(result) is not AwsDoctorResult:
        message = "AWS doctor returned an invalid result"
        raise TypeError(message)
    identity_aliases = _identity_aliases(suite)
    configured_types = {identity.id: identity.type for identity in suite.identities}
    if (
        result.target_id != suite.target.id
        or result.target_environment != suite.target.environment.value
        or result.region != suite.target.aws_region
        or type(result.ready) is not bool
        or len(result.identities) != len(identity_aliases)
        or {item.identity_id for item in result.identities} != set(identity_aliases)
    ):
        message = "AWS doctor result conflicts with the selected plan"
        raise ValueError(message)
    identities = []
    for check in sorted(result.identities, key=lambda item: item.identity_id):
        if type(check) is not AwsIdentityCheck:
            message = "AWS doctor returned an invalid identity check"
            raise TypeError(message)
        identities.append(
            {
                "accountMatches": check.account_matches,
                "expiresAt": _timestamp_or_none(check.expires_at),
                "issues": [issue.value for issue in check.issues],
                "label": identity_aliases[check.identity_id],
                "partitionMatches": check.partition_matches,
                "ready": check.ready,
                "type": configured_types[check.identity_id],
            }
        )
    return {
        "identities": identities,
        "issues": [issue.value for issue in result.issues],
        "ready": result.ready,
        "region": result.region,
    }


def _normalized_retrieval_readiness(
    result: object,
    suite: VerificationSuite,
) -> dict[str, object]:
    if type(result) is not RetrievalDoctorResult:
        message = "retrieval doctor returned an invalid result"
        raise TypeError(message)
    scenario = suite.scenarios[0]
    aliases = _direction_aliases(suite)
    if (
        result.target_id != suite.target.id
        or result.target_environment != suite.target.environment.value
        or result.region != suite.target.aws_region
        or type(result.ready) is not bool
        or len(result.checks) != _DIRECTION_COUNT
        or {item.assertion_id for item in result.checks} != set(aliases)
    ):
        message = "retrieval doctor result conflicts with the selected plan"
        raise ValueError(message)
    checks = []
    for check in sorted(result.checks, key=lambda item: item.assertion_id):
        if type(check) is not RetrievalReadinessCheck:
            message = "retrieval doctor returned an invalid check"
            raise TypeError(message)
        direction, action_id, probe_id = aliases[check.assertion_id]
        if (
            check.scenario_id != scenario.id
            or check.action_id != action_id
            or check.probe_id != probe_id
        ):
            message = "retrieval doctor check conflicts with the selected plan"
            raise ValueError(message)
        checks.append(
            {
                "actionIdentityReady": check.action_identity_ready,
                "canaryContractReady": check.canary_contract_ready,
                "configurationCompatible": check.configuration_compatible,
                "correlationState": check.correlation_state.value,
                "direction": direction,
                "evidenceIdentityReady": check.evidence_identity_ready,
                "issues": [issue.value for issue in check.issues],
                "sourceAccessible": check.source_accessible,
            }
        )
    return {
        "checks": checks,
        "issues": [issue.value for issue in result.issues],
        "ready": result.ready,
        "region": result.region,
    }


def _build_sensitive_fields(  # noqa: C901 - explicit sensitive sources stay visible.
    suite: VerificationSuite,
    policy: AwsExecutionPolicy,
) -> tuple[_SensitiveField, ...]:
    values: list[tuple[str, str, str]] = [
        ("Target account", "account", suite.target.aws_account_id or ""),
        ("Target endpoint", "endpoint", str(suite.target.endpoint)),
        ("Policy account", "account", policy.aws_account_id),
        ("Policy endpoint", "endpoint", str(policy.application_endpoint)),
    ]
    role_number = 0
    environment_names: set[str] = set()
    for identity in sorted(suite.identities, key=lambda item: item.id):
        if isinstance(identity, AssumedRoleIdentity):
            role_number += 1
            values.append(
                (f"Selected assumed role {role_number}", "role", identity.role_arn)
            )
            _add_environment(environment_names, identity.external_id)
        elif isinstance(identity, CurrentAwsIdentity):
            _add_environment(environment_names, identity.profile)
    values.extend(
        (f"Authorized assumed role {position}", "role", role_arn)
        for position, role_arn in enumerate(
            sorted(policy.assumed_role_arns),
            start=1,
        )
    )
    selected_log_groups: set[str] = set()
    for scenario in suite.scenarios:
        for action_number, action in enumerate(
            sorted(scenario.actions, key=lambda item: item.id),
            start=1,
        ):
            values.append(
                (
                    f"Selected action path {action_number}",
                    "endpoint",
                    action.path,
                )
            )
            if isinstance(action, AwsSigV4Action):
                _add_action_environment(environment_names, action.inputs)
        for probe in scenario.probes:
            if not isinstance(probe, CloudWatchLogsProbe):
                continue
            selected_log_groups.add(probe.log_group)
            _add_environment(environment_names, probe.canary)
            if probe.bedrock is not None:
                _add_environment(environment_names, probe.bedrock.model_id)
            if probe.retrieval is not None:
                _add_environment(
                    environment_names,
                    probe.retrieval.baseline_canary,
                )
                _add_environment(
                    environment_names,
                    probe.retrieval.boundary_canary,
                )
    values.extend(
        (f"Selected CloudWatch log group {position}", "log_group", value)
        for position, value in enumerate(sorted(selected_log_groups), start=1)
    )
    values.extend(
        (
            f"Authorized {action.method} {action.service} path {position}",
            "endpoint",
            action.path,
        )
        for position, action in enumerate(
            sorted(
                policy.actions,
                key=lambda item: (item.service, item.method, item.path),
            ),
            start=1,
        )
    )
    values.extend(
        (f"Authorized CloudWatch log group {position}", "log_group", value)
        for position, value in enumerate(
            sorted(policy.cloudwatch_log_groups),
            start=1,
        )
    )
    values.extend(
        (f"Environment reference {position}", "environment_name", value)
        for position, value in enumerate(sorted(environment_names), start=1)
    )
    return tuple(
        _SensitiveField(
            field_id=f"field-{position:02d}",
            label=label,
            kind=kind,
            value=value,
        )
        for position, (label, kind, value) in enumerate(values, start=1)
        if value
    )


def _add_action_environment(
    names: set[str],
    inputs: tuple[ActionInput, ...],
) -> None:
    for item in inputs:
        if isinstance(item.value, EnvironmentReference):
            names.add(item.value.name)


def _add_environment(
    names: set[str],
    value: EnvironmentReference | None,
) -> None:
    if value is not None:
        names.add(value.name)


def _new_run_id(now: datetime) -> str:
    timestamp = now.astimezone(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    return f"ui-{timestamp}-{secrets.token_hex(16)}"


def _normalized_result_report(
    results: object,
    *,
    expected_assertion_ids: tuple[str, str],
) -> dict[str, object]:
    """Expose only the fixed safe reciprocal assertion-result projection."""
    if (
        not isinstance(results, tuple)
        or len(results) != 2  # noqa: PLR2004 - reciprocal contract is exactly two.
        or any(type(result) is not AssertionResult for result in results)
        or len(set(expected_assertion_ids)) != _DIRECTION_COUNT
        or {result.assertion_id for result in results} != set(expected_assertion_ids)
    ):
        message = "reciprocal run returned an invalid result set"
        raise TypeError(message)
    by_assertion = {result.assertion_id: result for result in results}
    normalized: list[dict[str, object]] = []
    for position, assertion_id in enumerate(
        sorted(expected_assertion_ids),
        start=1,
    ):
        result = by_assertion[assertion_id]
        if (
            result.evaluator_version != RETRIEVAL_BOUNDARY_EVALUATOR_VERSION
            or result.limitations != tuple(sorted(RETRIEVAL_BOUNDARY_FIXED_LIMITATIONS))
        ):
            message = "reciprocal result does not match its fixed evaluator"
            raise ValueError(message)
        normalized.append(
            {
                "direction": f"direction-{position:02d}",
                "limitations": list(RETRIEVAL_BOUNDARY_FIXED_LIMITATIONS),
                "observed": _safe_retrieval_observed(result.observed.to_json_value()),
                "status": result.status.value,
            }
        )
    return {"results": normalized}


def _safe_retrieval_observed(value: object) -> dict[str, object]:
    fields = {
        "baseline_canary_observed",
        "boundary_canary_observed",
        "normalized_evidence_state",
        "retrieval_path_exercised",
        "retrieved_item_count",
        "undeclared_synthetic_marker_observed",
    }
    if not isinstance(value, dict) or set(value) != fields:
        message = "reciprocal result has an invalid observed field set"
        raise ValueError(message)
    for field_name in (
        "baseline_canary_observed",
        "boundary_canary_observed",
        "undeclared_synthetic_marker_observed",
    ):
        item = value[field_name]
        if item is not None and type(item) is not bool:
            message = "reciprocal result has an invalid observed boolean"
            raise TypeError(message)
    if type(value["retrieval_path_exercised"]) is not bool:
        message = "reciprocal result has an invalid path fact"
        raise TypeError(message)
    item_count = value["retrieved_item_count"]
    if item_count is not None and (
        type(item_count) is not int or not 0 <= item_count <= _MAX_RETRIEVED_ITEMS
    ):
        message = "reciprocal result has an invalid item count"
        raise ValueError(message)
    normalized_state = value["normalized_evidence_state"]
    if (
        type(normalized_state) is not str
        or normalized_state not in _NORMALIZED_STATE_VALUES
    ):
        message = "reciprocal result has an invalid normalized state"
        raise ValueError(message)
    return {
        field_name: cast("dict[str, object]", value)[field_name]
        for field_name in sorted(fields)
    }


def _normalized_run_result(
    result: object,
    *,
    expected_run_id: str,
    expected_scenario_id: str,
    expected_evidence_path: Path,
    expected_assertion_ids: tuple[str, str],
) -> dict[str, object]:
    """Validate runner compatibility before projecting its safe public facts."""
    if type(result) is not AwsReciprocalRetrievalRunResult:
        message = "reciprocal runner returned an invalid result"
        raise TypeError(message)
    assertions = result.assertion_results
    aggregate = aggregate_results(assertions)
    exit_code = exit_code_for_status(aggregate)
    if (
        result.run_id != expected_run_id
        or result.scenario_id != expected_scenario_id
        or result.status is not aggregate
        or result.exit_code is not exit_code
        or not isinstance(result.evidence_path, Path)
        or result.evidence_path != expected_evidence_path
    ):
        message = "reciprocal runner returned contradictory result metadata"
        raise ValueError(message)
    return {
        "aggregateStatus": aggregate.value,
        "evidencePath": str(result.evidence_path),
        "exitCode": int(exit_code),
        "report": _normalized_result_report(
            assertions,
            expected_assertion_ids=expected_assertion_ids,
        ),
    }


def _require_matching_verified_bundle(
    record: EvidenceHistoryRecord,
    *,
    normalized_result: dict[str, object],
    expected_run_id: str,
    expected_evidence_path: Path,
    expected_region: str,
) -> None:
    """Require the post-run history view to match the returned safe result."""
    report = record.report
    normalized_report = normalized_result.get("report")
    if (
        type(record) is not EvidenceHistoryRecord
        or record.state is not EvidenceHistoryState.VERIFIED
        or record.run_id != expected_run_id
        or record.scenario_id != _SCENARIO_ALIAS
        or record.issues
        or record.evidence_path != str(expected_evidence_path)
        or record.target_region != expected_region
        or record.aggregate_status is None
        or record.aggregate_status.value != normalized_result.get("aggregateStatus")
        or report is None
        or not isinstance(normalized_report, dict)
    ):
        message = "reciprocal evidence verification did not match the run"
        raise ValueError(message)
    normalized_results = normalized_report.get("results")
    if not isinstance(normalized_results, list):
        message = "reciprocal evidence verification did not match the report"
        raise TypeError(message)
    expected_statuses = [
        item.get("status") for item in normalized_results if isinstance(item, dict)
    ]
    if (
        len(expected_statuses) != _DIRECTION_COUNT
        or [item.assertion_id for item in report.results]
        != ["direction-01", "direction-02"]
        or [item.status.value for item in report.results] != expected_statuses
    ):
        message = "reciprocal evidence verification contradicted result statuses"
        raise ValueError(message)


def _readiness_view(snapshot: _ReadinessSnapshot) -> dict[str, object]:
    return {
        "aws": copy.deepcopy(snapshot.aws),
        "checkedAt": _timestamp(snapshot.checked_at),
        "configurationRevision": snapshot.generation,
        "expiresAt": _timestamp(snapshot.expires_at),
        "ready": snapshot.ready,
        "retrieval": copy.deepcopy(snapshot.retrieval),
        "scenarioId": _SCENARIO_ALIAS,
        "schemaVersion": _SCHEMA_VERSION,
    }


def _normalized_clock(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    if value.tzinfo is None or value.utcoffset() is None:
        message = "console clock must return an aware datetime"
        raise ValueError(message)
    return value.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return (
        value.astimezone(UTC)
        .isoformat(timespec="microseconds")
        .replace(
            "+00:00",
            "Z",
        )
    )


def _timestamp_or_none(value: datetime | None) -> str | None:
    return _timestamp(value) if value is not None else None
