"""Shared synthetic runtime seams for loopback-console tests."""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, cast

from cai_verify.assertions.retrieval import (
    RETRIEVAL_BOUNDARY_EVALUATOR_VERSION,
    RETRIEVAL_BOUNDARY_FIXED_LIMITATIONS,
)
from cai_verify.aws import (
    AwsDoctorResult,
    AwsExecutionPolicy,
    AwsIdentityCheck,
    AwsReciprocalRetrievalRunOptions,
    AwsReciprocalRetrievalRunResult,
    AwsReciprocalRetrievalRunStage,
    RetrievalCorrelationState,
    RetrievalDoctorResult,
    RetrievalReadinessCheck,
)
from cai_verify.config import RetrievalBoundaryAssertion
from cai_verify.core import (
    AssertionResult,
    AssertionStatus,
    CliExitCode,
    RedactedValue,
)
from cai_verify.ui.history import (
    EvidenceHistoryRecord,
    EvidenceHistoryReport,
    EvidenceHistoryResultSummary,
    EvidenceHistoryState,
)
from cai_verify.ui.state import ConsoleRuntime, ConsoleState

if TYPE_CHECKING:
    import os
    from collections.abc import Mapping

    from cai_verify.config import VerificationSuite

ROOT = Path(__file__).parents[2]
SUITE_BYTES = (ROOT / "examples/aws/reciprocal-retrieval-suite.json").read_bytes()
POLICY_BYTES = (ROOT / "examples/aws/reciprocal-retrieval-policy.json").read_bytes()
SCENARIO_ID = "scenario-01"
RAW_SCENARIO_ID = "reciprocal-requester-retrieval"
FIXED_NOW = datetime(2031, 4, 5, 6, 7, 8, 901234, tzinfo=UTC)
SYNTHETIC_ENVIRONMENT = {
    "CAI_REQUESTER_A_CANARY": "canary-a-value-must-never-leak",
    "CAI_REQUESTER_B_CANARY": "canary-b-value-must-never-leak",
    "AWS_SECRET_ACCESS_KEY": "synthetic-credential-must-never-leak",
}
SENSITIVE_CONFIGURATION_VALUES = (
    "111122223333",
    "arn:aws:iam::111122223333:role/cai-verify-alpha-requester-a",
    "arn:aws:iam::111122223333:role/cai-verify-alpha-requester-b",
    "arn:aws:iam::111122223333:role/cai-verify-alpha-evidence-reader",
    "https://retrieval.sandbox.example.test/v1",
    "/aws/cai-verify/synthetic-retrieval",
    "CAI_REQUESTER_A_CANARY",
    "CAI_REQUESTER_B_CANARY",
)


@dataclass(slots=True)
class MutableClock:
    """Controllable aware clock for freshness and timestamp assertions."""

    value: datetime = FIXED_NOW

    def __call__(self) -> datetime:
        """Return the current synthetic instant."""
        return self.value

    def advance(self, duration: timedelta) -> None:
        """Advance by one explicit duration."""
        self.value += duration


@dataclass(slots=True)
class RuntimeHarness:
    """Injected doctors and reciprocal runner with no AWS or socket access."""

    ready: bool = True
    doctor_error: Exception | None = None
    run_error: Exception | None = None
    verification_error: Exception | None = None
    block_doctor: bool = False
    block_runner: bool = False
    create_unfinalized_directory: bool = False
    started: threading.Event = field(default_factory=threading.Event)
    release: threading.Event = field(default_factory=threading.Event)
    finished: threading.Event = field(default_factory=threading.Event)
    doctor_started: threading.Event = field(default_factory=threading.Event)
    doctor_release: threading.Event = field(default_factory=threading.Event)
    aws_calls: int = 0
    retrieval_calls: int = 0
    suites: list[VerificationSuite] = field(default_factory=list)
    policies: list[AwsExecutionPolicy] = field(default_factory=list)
    environments: list[Mapping[str, str]] = field(default_factory=list)
    run_options: list[AwsReciprocalRetrievalRunOptions] = field(default_factory=list)

    def as_runtime(self) -> ConsoleRuntime:
        """Expose the exact production injection contract."""
        return ConsoleRuntime(
            aws_doctor=self.aws_doctor,
            retrieval_doctor=self.retrieval_doctor,
            reciprocal_runner=self.reciprocal_runner,
            evidence_verifier=self.evidence_verifier,
        )

    def evidence_verifier(
        self,
        evidence_root: str | os.PathLike[str],
        raw_run_id: str,
    ) -> EvidenceHistoryRecord:
        """Return a fixed verified view for runner-isolation unit tests."""
        if self.verification_error is not None:
            raise self.verification_error
        return EvidenceHistoryRecord(
            run_id=raw_run_id,
            state=EvidenceHistoryState.VERIFIED,
            aggregate_status=AssertionStatus.PASS,
            scenario_id=SCENARIO_ID,
            target_region="eu-west-2",
            evidence_path=str(Path(evidence_root) / raw_run_id),
            report=EvidenceHistoryReport(
                results=tuple(
                    EvidenceHistoryResultSummary(
                        assertion_id=f"direction-{position:02d}",
                        status=AssertionStatus.PASS,
                    )
                    for position in (1, 2)
                )
            ),
        )

    def aws_doctor(
        self,
        suite: VerificationSuite,
        *,
        execution_policy: AwsExecutionPolicy,
        environment: Mapping[str, str],
    ) -> AwsDoctorResult:
        """Return a fixed safe AWS readiness result."""
        self.aws_calls += 1
        self.suites.append(suite)
        self.policies.append(execution_policy)
        self.environments.append(environment)
        if self.block_doctor:
            self.doctor_started.set()
            if not self.doctor_release.wait(timeout=5):
                message = "test doctor release timed out"
                raise RuntimeError(message)
        if self.doctor_error is not None:
            raise self.doctor_error
        return AwsDoctorResult(
            target_id=suite.target.id,
            target_environment=suite.target.environment.value,
            region=suite.target.aws_region,
            ready=self.ready,
            identities=tuple(
                AwsIdentityCheck(
                    identity_id=identity.id,
                    identity_type=identity.type,
                    ready=self.ready,
                    account_matches=self.ready,
                    partition_matches=self.ready,
                    expires_at=None,
                    issues=(),
                )
                for identity in sorted(
                    suite.identities,
                    key=lambda item: item.id,
                )
            ),
            issues=(),
            limitations=("Synthetic readiness result; no live AWS call.",),
        )

    def retrieval_doctor(
        self,
        suite: VerificationSuite,
        *,
        execution_policy: AwsExecutionPolicy,
        environment: Mapping[str, str],
    ) -> RetrievalDoctorResult:
        """Return a fixed safe retrieval readiness result."""
        self.retrieval_calls += 1
        self.suites.append(suite)
        self.policies.append(execution_policy)
        self.environments.append(environment)
        if self.doctor_error is not None:
            raise self.doctor_error
        scenario = suite.scenarios[0]
        assertions = tuple(
            assertion
            for assertion in sorted(
                scenario.assertions,
                key=lambda item: item.id,
            )
            if isinstance(assertion, RetrievalBoundaryAssertion)
        )
        return RetrievalDoctorResult(
            target_id=suite.target.id,
            target_environment=suite.target.environment.value,
            region=suite.target.aws_region,
            ready=self.ready,
            checks=tuple(
                RetrievalReadinessCheck(
                    scenario_id=scenario.id,
                    assertion_id=assertion.id,
                    action_id=assertion.action_ref,
                    probe_id=assertion.probe_ref,
                    configuration_compatible=self.ready,
                    action_identity_ready=self.ready,
                    evidence_identity_ready=self.ready,
                    canary_contract_ready=self.ready,
                    source_accessible=self.ready,
                    correlation_state=(
                        RetrievalCorrelationState.RUNTIME_REQUIRED
                        if self.ready
                        else RetrievalCorrelationState.INCOMPATIBLE
                    ),
                    issues=(),
                )
                for assertion in assertions
            ),
            issues=(),
            runtime_requirements=("Synthetic runtime requirement.",),
            limitations=("Synthetic readiness result; no live AWS call.",),
        )

    def reciprocal_runner(
        self,
        suite: VerificationSuite,
        options: AwsReciprocalRetrievalRunOptions,
    ) -> AwsReciprocalRetrievalRunResult:
        """Emit fixed safe progress and return or raise as configured."""
        del suite
        self.run_options.append(options)
        if options.progress is not None:
            options.progress(AwsReciprocalRetrievalRunStage.AUTHORIZATION)
            options.progress(AwsReciprocalRetrievalRunStage.IDENTITY_ACQUISITION)
            options.progress(AwsReciprocalRetrievalRunStage.DIRECTION_ONE)
        run_directory = Path(options.evidence_root) / options.run_id
        if self.create_unfinalized_directory:
            run_directory.mkdir(parents=True)
        self.started.set()
        if self.block_runner and not self.release.wait(timeout=5):
            message = "test runner release timed out"
            raise RuntimeError(message)
        try:
            if self.run_error is not None:
                raise self.run_error
            if options.progress is not None:
                options.progress(AwsReciprocalRetrievalRunStage.DIRECTION_TWO)
                options.progress(AwsReciprocalRetrievalRunStage.EVALUATION)
                options.progress(AwsReciprocalRetrievalRunStage.FINALIZATION)
                options.progress(AwsReciprocalRetrievalRunStage.INTEGRITY_VERIFICATION)
            report = {
                "assertions": [
                    {"assertion_id": "requester-a", "status": "PASS"},
                    {"assertion_id": "requester-b", "status": "PASS"},
                ],
                "limitations": ["Synthetic result; no compliance claim."],
                "schema_version": "1",
                "status": "PASS",
            }
            assertion_results = tuple(
                AssertionResult(
                    assertion_id=f"requester-{requester}-retrieval-boundary",
                    status=AssertionStatus.PASS,
                    evidence_ids=(f"evidence-{requester}",),
                    limitations=RETRIEVAL_BOUNDARY_FIXED_LIMITATIONS,
                    evaluator_version=RETRIEVAL_BOUNDARY_EVALUATOR_VERSION,
                    evaluation_started_at=FIXED_NOW,
                    evaluation_completed_at=FIXED_NOW,
                    expected={"synthetic_fixed_contract": True},
                    observed=RedactedValue(
                        {
                            "baseline_canary_observed": True,
                            "boundary_canary_observed": False,
                            "normalized_evidence_state": (
                                "isolated_retrieval_observed"
                            ),
                            "retrieval_path_exercised": True,
                            "retrieved_item_count": 1,
                            "undeclared_synthetic_marker_observed": False,
                        }
                    ),
                )
                for requester in ("a", "b")
            )
            return AwsReciprocalRetrievalRunResult(
                assertion_results=cast(
                    "tuple[AssertionResult, AssertionResult]",
                    assertion_results,
                ),
                evidence_path=run_directory,
                exit_code=CliExitCode.SUCCESS,
                json_report=json.dumps(
                    report,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode(),
                run_id=options.run_id,
                scenario_id=options.scenario_id,
                status=AssertionStatus.PASS,
                terminal_report=b"Reciprocal retrieval boundary: PASS\n",
            )
        finally:
            self.finished.set()


def configured_state(
    evidence_root: Path,
    *,
    clock: MutableClock | None = None,
    harness: RuntimeHarness | None = None,
) -> tuple[ConsoleState, MutableClock, RuntimeHarness]:
    """Construct and load one console state with synthetic configuration."""
    selected_clock = clock or MutableClock()
    selected_harness = harness or RuntimeHarness()
    state = ConsoleState(
        evidence_root=evidence_root,
        environment=SYNTHETIC_ENVIRONMENT,
        runtime=selected_harness.as_runtime(),
        clock=selected_clock,
    )
    state.load_suite(SUITE_BYTES)
    state.load_policy(POLICY_BYTES)
    return state, selected_clock, selected_harness


def wait_for_terminal_state(
    state: ConsoleState,
    *,
    timeout_seconds: float = 2,
) -> dict[str, object]:
    """Poll bounded process-local state until one run becomes terminal."""
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        view = state.active_run_view()
        if view["state"] in {"complete", "failed"}:
            return view
        time.sleep(0.005)
    message = "console run did not reach a terminal state"
    raise AssertionError(message)
