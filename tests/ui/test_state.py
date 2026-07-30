"""Process-local state tests for the bounded operator console."""

from __future__ import annotations

import json
import re
import threading
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from cai_verify.aws import (
    AwsReciprocalRetrievalRunError,
    AwsReciprocalRetrievalRunFailureCode,
    AwsReciprocalRetrievalRunStage,
)
from cai_verify.ui.state import (
    ConsoleRunState,
    ConsoleState,
    ConsoleStateError,
    ConsoleStateFailureCode,
)
from tests.ui._console_fakes import (
    FIXED_NOW,
    POLICY_BYTES,
    RAW_SCENARIO_ID,
    SCENARIO_ID,
    SENSITIVE_CONFIGURATION_VALUES,
    SUITE_BYTES,
    SYNTHETIC_ENVIRONMENT,
    MutableClock,
    RuntimeHarness,
    configured_state,
    wait_for_terminal_state,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

_RUN_ID_PATTERN = re.compile(r"ui-20310405T060708901234Z-[0-9a-f]{32}\Z")
_EXPECTED_IDENTITY_COUNT = 3
_EXPECTED_CHAIN_COUNT = 2
_REVEAL_SECONDS = 30


def _configuration_revision(state: ConsoleState) -> int:
    value = state.configuration_view()["configurationRevision"]
    assert type(value) is int
    return value


@pytest.fixture
def console_state(
    tmp_path: Path,
) -> Iterator[tuple[ConsoleState, MutableClock, RuntimeHarness]]:
    """Yield one loaded state and always stop its worker."""
    state, clock, harness = configured_state(tmp_path)
    try:
        yield state, clock, harness
    finally:
        harness.release.set()
        harness.doctor_release.set()
        state.close()


def test_configuration_review_masks_every_allowlisted_identifier(
    console_state: tuple[ConsoleState, MutableClock, RuntimeHarness],
) -> None:
    """The ordinary review contains structure but no revealable value."""
    state, _clock, _harness = console_state

    view = state.configuration_view()

    assert view["schemaVersion"] == "1"
    assert view["suiteLoaded"] is True
    assert view["policyLoaded"] is True
    assert view["readyForReview"] is True
    review = view["review"]
    assert isinstance(review, dict)
    assert review["suiteName"] == "Validated reciprocal suite"
    assert review["targetId"] == "target-01"
    assert review["targetEnvironment"] == "sandbox"
    assert review["region"] == "eu-west-2"
    assert review["identityCount"] == _EXPECTED_IDENTITY_COUNT
    assert review["actionCount"] == _EXPECTED_CHAIN_COUNT
    assert review["probeCount"] == _EXPECTED_CHAIN_COUNT
    assert review["assertionCount"] == _EXPECTED_CHAIN_COUNT
    fields = review["sensitiveFields"]
    assert isinstance(fields, list)
    assert fields
    assert all(
        isinstance(item, dict) and item["masked"] == "••••••••" for item in fields
    )
    serialized = json.dumps(view, sort_keys=True)
    for sensitive in (
        *SENSITIVE_CONFIGURATION_VALUES,
        *SYNTHETIC_ENVIRONMENT.values(),
        "security-team@example.test",
        "Synthetic public-alpha reciprocal retrieval-boundary verification.",
        "reciprocal-requester-retrieval",
        "retrieve-as-requester-a",
        "requester-a-retrieval-evidence",
        "requester-a-retrieval-boundary",
    ):
        assert sensitive not in serialized


def test_reveal_returns_only_selected_allowlisted_configuration_values(
    console_state: tuple[ConsoleState, MutableClock, RuntimeHarness],
) -> None:
    """Opaque field IDs can reveal identifiers but never environment values."""
    state, _clock, _harness = console_state
    review = state.configuration_view()["review"]
    assert isinstance(review, dict)
    masked_fields = review["sensitiveFields"]
    assert isinstance(masked_fields, list)
    field_ids = [item["id"] for item in masked_fields if isinstance(item, dict)]

    revealed = state.reveal(field_ids, _configuration_revision(state))

    assert revealed["schemaVersion"] == "1"
    assert revealed["expiresInSeconds"] == _REVEAL_SECONDS
    fields = revealed["fields"]
    assert isinstance(fields, list)
    assert [item["id"] for item in fields if isinstance(item, dict)] == field_ids
    values = {item["value"] for item in fields if isinstance(item, dict)}
    assert "111122223333" in values
    assert "https://retrieval.sandbox.example.test/v1" in values
    assert "/aws/cai-verify/synthetic-retrieval" in values
    assert "CAI_REQUESTER_A_CANARY" in values
    assert "CAI_REQUESTER_B_CANARY" in values
    serialized = json.dumps(revealed, sort_keys=True)
    for secret in SYNTHETIC_ENVIRONMENT.values():
        assert secret not in serialized


def test_review_masks_and_reveals_every_policy_authorization(
    tmp_path: Path,
) -> None:
    """Unused policy authorizations remain visible in the exact masked review."""
    policy = json.loads(POLICY_BYTES)
    assert isinstance(policy, dict)
    policy["actions"].append(
        {
            "method": "GET",
            "path": "/authorized-but-unused",
            "service": "execute-api",
        }
    )
    policy["assumedRoleArns"].append(
        "arn:aws:iam::111122223333:role/authorized-but-unused"
    )
    policy["cloudwatchLogGroups"].append("/aws/cai-verify/authorized-but-unused")
    state = ConsoleState(evidence_root=tmp_path)
    try:
        state.load_suite(SUITE_BYTES)
        view = state.load_policy(
            json.dumps(policy, separators=(",", ":"), sort_keys=True).encode()
        )
        review = view["review"]
        assert isinstance(review, dict)
        plan = review["plan"]
        assert isinstance(plan, dict)
        policy_summary = plan["policy"]
        assert policy_summary == {
            "actionCount": 2,
            "allowCurrentIdentity": False,
            "evidenceSourceCount": 2,
            "partition": "aws",
            "region": "eu-west-2",
            "roleCount": 4,
        }
        fields = review["sensitiveFields"]
        assert isinstance(fields, list)
        serialized = json.dumps(view, sort_keys=True)
        for sensitive in (
            "/authorized-but-unused",
            "arn:aws:iam::111122223333:role/authorized-but-unused",
            "/aws/cai-verify/authorized-but-unused",
        ):
            assert sensitive not in serialized
        selected_ids = [
            item["id"]
            for item in fields
            if isinstance(item, dict)
            and item["label"]
            in {
                "Authorized GET execute-api path 1",
                "Authorized assumed role 1",
                "Authorized assumed role 2",
                "Authorized assumed role 3",
                "Authorized assumed role 4",
                "Authorized CloudWatch log group 1",
                "Authorized CloudWatch log group 2",
            }
        ]
        revealed = state.reveal(selected_ids, _configuration_revision(state))
    finally:
        state.close()

    revealed_fields = revealed["fields"]
    assert isinstance(revealed_fields, list)
    revealed_values = {
        item["value"] for item in revealed_fields if isinstance(item, dict)
    }
    assert "/authorized-but-unused" in revealed_values
    assert "arn:aws:iam::111122223333:role/authorized-but-unused" in revealed_values
    assert "/aws/cai-verify/authorized-but-unused" in revealed_values


@pytest.mark.parametrize(
    "selection",
    [
        None,
        [],
        ["field-01", "field-01"],
        ["unknown-field"],
        [1],
        ["x" * 33],
        [f"field-{index:02d}" for index in range(65)],
    ],
)
def test_reveal_rejects_non_allowlisted_or_unbounded_requests(
    console_state: tuple[ConsoleState, MutableClock, RuntimeHarness],
    selection: object,
) -> None:
    """Reveal selection has one small exact identifier contract."""
    state, _clock, _harness = console_state

    with pytest.raises(ConsoleStateError) as caught:
        state.reveal(selection, _configuration_revision(state))

    assert caught.value.code is ConsoleStateFailureCode.INVALID_REQUEST
    assert repr(caught.value).find("unknown-field") == -1


def test_reveal_is_bound_to_exact_configuration_revision(
    console_state: tuple[ConsoleState, MutableClock, RuntimeHarness],
) -> None:
    """A stale browser review cannot reveal identifiers from newer inputs."""
    state, _clock, _harness = console_state
    review = state.configuration_view()["review"]
    assert isinstance(review, dict)
    fields = review["sensitiveFields"]
    assert isinstance(fields, list)
    field = fields[0]
    assert isinstance(field, dict)
    field_id = field["id"]
    stale_revision = _configuration_revision(state)
    state.load_policy(POLICY_BYTES)

    with pytest.raises(ConsoleStateError) as caught:
        state.reveal([field_id], stale_revision)

    assert caught.value.code is ConsoleStateFailureCode.CONFIGURATION_CHANGED


def test_readiness_uses_fixed_clock_and_injected_configuration(
    console_state: tuple[ConsoleState, MutableClock, RuntimeHarness],
) -> None:
    """Both doctors receive the loaded models and produce five-minute state."""
    state, _clock, harness = console_state

    readiness = state.run_readiness()

    assert readiness["ready"] is True
    assert readiness["checkedAt"] == "2031-04-05T06:07:08.901234Z"
    assert readiness["expiresAt"] == "2031-04-05T06:12:08.901234Z"
    assert harness.aws_calls == 1
    assert harness.retrieval_calls == 1
    assert harness.suites[0] is harness.suites[1]
    assert harness.policies[0] is harness.policies[1]
    assert harness.environments == [
        SYNTHETIC_ENVIRONMENT,
        SYNTHETIC_ENVIRONMENT,
    ]
    serialized = json.dumps(readiness, sort_keys=True)
    for secret in SYNTHETIC_ENVIRONMENT.values():
        assert secret not in serialized


@pytest.mark.parametrize("changed_input", ["suite", "policy"])
def test_configuration_change_invalidates_readiness(
    console_state: tuple[ConsoleState, MutableClock, RuntimeHarness],
    changed_input: str,
) -> None:
    """Either validated input replacement clears the prior preflight."""
    state, _clock, _harness = console_state
    state.run_readiness()
    assert state.readiness_view() is not None

    if changed_input == "suite":
        state.load_suite(SUITE_BYTES)
    else:
        state.load_policy(POLICY_BYTES)

    assert state.readiness_view() is None
    with pytest.raises(ConsoleStateError) as caught:
        state.start_run(SCENARIO_ID, _configuration_revision(state))
    assert caught.value.code is ConsoleStateFailureCode.READINESS_REQUIRED


def test_failed_or_expired_readiness_cannot_authorize_execution(
    tmp_path: Path,
) -> None:
    """Not-ready and five-minute-old findings both fail closed."""
    clock = MutableClock()
    not_ready_harness = RuntimeHarness(ready=False)
    state, _clock, _harness = configured_state(
        tmp_path / "not-ready",
        clock=clock,
        harness=not_ready_harness,
    )
    try:
        assert state.run_readiness()["ready"] is False
        with pytest.raises(ConsoleStateError) as not_ready:
            state.start_run(SCENARIO_ID, _configuration_revision(state))
        assert not_ready.value.code is ConsoleStateFailureCode.READINESS_REQUIRED
    finally:
        state.close()

    ready_harness = RuntimeHarness()
    state, _clock, _harness = configured_state(
        tmp_path / "expired",
        clock=clock,
        harness=ready_harness,
    )
    try:
        state.run_readiness()
        clock.advance(timedelta(minutes=5))
        assert state.readiness_view() is None
        with pytest.raises(ConsoleStateError) as expired:
            state.start_run(SCENARIO_ID, _configuration_revision(state))
        assert expired.value.code is ConsoleStateFailureCode.READINESS_REQUIRED
    finally:
        state.close()


def test_doctor_exception_is_reduced_to_one_stable_category(
    tmp_path: Path,
) -> None:
    """Readiness does not retain an injected SDK-style exception message."""
    diagnostic = "sdk diagnostic with synthetic-credential-must-never-leak"
    harness = RuntimeHarness(doctor_error=RuntimeError(diagnostic))
    state, _clock, _harness = configured_state(tmp_path, harness=harness)
    try:
        with pytest.raises(ConsoleStateError) as caught:
            state.run_readiness()
    finally:
        state.close()

    assert caught.value.code is ConsoleStateFailureCode.READINESS_FAILED
    assert diagnostic not in str(caught.value)
    assert diagnostic not in repr(caught.value)


def test_failed_recheck_clears_previous_ready_snapshot(tmp_path: Path) -> None:
    """A later readiness failure cannot leave an older authorization usable."""
    harness = RuntimeHarness()
    state, _clock, _harness = configured_state(tmp_path, harness=harness)
    try:
        state.run_readiness()
        harness.doctor_error = RuntimeError("private SDK failure")

        with pytest.raises(ConsoleStateError) as failed:
            state.run_readiness()

        assert failed.value.code is ConsoleStateFailureCode.READINESS_FAILED
        assert state.readiness_view() is None
        with pytest.raises(ConsoleStateError) as start:
            state.start_run(SCENARIO_ID, _configuration_revision(state))
        assert start.value.code is ConsoleStateFailureCode.READINESS_REQUIRED
    finally:
        state.close()


def test_readiness_is_serialized_and_configuration_change_wins(
    tmp_path: Path,
) -> None:
    """Concurrent checks and stale snapshots fail closed deterministically."""
    harness = RuntimeHarness(block_doctor=True)
    state, _clock, _harness = configured_state(tmp_path, harness=harness)
    outcome: list[ConsoleStateError] = []

    def execute() -> None:
        try:
            state.run_readiness()
        except ConsoleStateError as error:
            outcome.append(error)

    worker = threading.Thread(target=execute, daemon=True)
    try:
        worker.start()
        assert harness.doctor_started.wait(timeout=2)
        with pytest.raises(ConsoleStateError) as duplicate:
            state.run_readiness()
        assert duplicate.value.code is ConsoleStateFailureCode.READINESS_IN_PROGRESS
        with pytest.raises(ConsoleStateError) as premature:
            state.start_run(SCENARIO_ID, _configuration_revision(state))
        assert premature.value.code is ConsoleStateFailureCode.READINESS_IN_PROGRESS

        state.load_policy(POLICY_BYTES)
        harness.doctor_release.set()
        worker.join(timeout=2)
        assert not worker.is_alive()
        assert len(outcome) == 1
        assert outcome[0].code is ConsoleStateFailureCode.CONFIGURATION_CHANGED
        assert state.readiness_view() is None
    finally:
        harness.doctor_release.set()
        worker.join(timeout=2)
        state.close()


def test_stale_confirmation_revision_is_rejected(tmp_path: Path) -> None:
    """Confirmation is bound to the exact reviewed configuration generation."""
    state, _clock, _harness = configured_state(tmp_path)
    try:
        stale_revision = _configuration_revision(state)
        state.load_policy(POLICY_BYTES)
        state.run_readiness()

        with pytest.raises(ConsoleStateError) as caught:
            state.start_run(SCENARIO_ID, stale_revision)

        assert caught.value.code is ConsoleStateFailureCode.CONFIGURATION_CHANGED
    finally:
        state.close()


def test_configuration_change_clears_completed_active_result(tmp_path: Path) -> None:
    """A result from configuration A cannot appear under configuration B."""
    state, _clock, _harness = configured_state(tmp_path)
    try:
        state.run_readiness()
        state.start_run(SCENARIO_ID, _configuration_revision(state))
        assert wait_for_terminal_state(state)["state"] == ConsoleRunState.COMPLETE

        state.load_policy(POLICY_BYTES)

        active = state.active_run_view()
        assert active["state"] == ConsoleRunState.IDLE
        assert active["runId"] is None
        assert active["scenarioId"] is None
        assert active["result"] is None
    finally:
        state.close()


def test_wall_clock_rollback_invalidates_readiness(tmp_path: Path) -> None:
    """A reversing wall clock cannot extend the five-minute readiness lease."""
    state, clock, _harness = configured_state(tmp_path)
    try:
        state.run_readiness()
        clock.advance(-timedelta(microseconds=1))

        assert state.readiness_view() is None
    finally:
        state.close()


def test_suite_with_one_reciprocal_and_one_unrelated_scenario_is_accepted(
    tmp_path: Path,
) -> None:
    """Unrelated suite scenarios are ignored when one reciprocal slice is exact."""
    payload = json.loads(SUITE_BYTES)
    assert isinstance(payload, dict)
    scenarios = payload["scenarios"]
    assert isinstance(scenarios, list)
    unrelated = json.loads(json.dumps(scenarios[0]))
    unrelated["id"] = "unrelated-audit-scenario"
    action_ids = {
        action["id"]: f"unrelated-{action['id']}" for action in unrelated["actions"]
    }
    probe_ids = {
        probe["id"]: f"unrelated-{probe['id']}" for probe in unrelated["probes"]
    }
    for action in unrelated["actions"]:
        action["id"] = action_ids[action["id"]]
    for probe in unrelated["probes"]:
        probe["id"] = probe_ids[probe["id"]]
        if "actionRef" in probe:
            probe["actionRef"] = action_ids[probe["actionRef"]]
    for assertion in unrelated["assertions"]:
        assertion["type"] = "auditCorrelation"
        assertion["id"] = f"unrelated-{assertion['id']}"
        assertion["actionRef"] = action_ids[assertion["actionRef"]]
        assertion["probeRef"] = probe_ids[assertion["probeRef"]]
        for limitation in assertion["limitations"]:
            limitation["id"] = f"unrelated-{limitation['id']}"
        for control in assertion["controlRefs"]:
            for limitation in control["limitations"]:
                limitation["id"] = f"unrelated-{limitation['id']}"
    scenarios.append(unrelated)
    state = ConsoleState(evidence_root=tmp_path)
    try:
        view = state.load_suite(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        )
    finally:
        state.close()

    assert view["suiteLoaded"] is True


def test_successful_run_uses_server_id_and_propagates_safe_progress_and_result(
    tmp_path: Path,
) -> None:
    """One worker receives bounded options and exposes a normalized result."""
    harness = RuntimeHarness(block_runner=True)
    state, clock, _harness = configured_state(tmp_path, harness=harness)
    try:
        state.run_readiness()

        started = state.start_run(SCENARIO_ID, _configuration_revision(state))

        assert started["state"] == ConsoleRunState.RUNNING.value
        run_id = started["runId"]
        assert isinstance(run_id, str)
        assert _RUN_ID_PATTERN.fullmatch(run_id)
        assert run_id != SCENARIO_ID
        assert harness.started.wait(timeout=2)
        in_progress = state.active_run_view()
        assert in_progress["stage"] == AwsReciprocalRetrievalRunStage.DIRECTION_ONE
        assert in_progress["startedAt"] == "2031-04-05T06:07:08.901234Z"

        harness.release.set()
        complete = wait_for_terminal_state(state)
    finally:
        harness.release.set()
        state.close()

    assert complete["state"] == ConsoleRunState.COMPLETE.value
    assert complete["stage"] == AwsReciprocalRetrievalRunStage.COMPLETE.value
    assert complete["completedAt"] == "2031-04-05T06:07:08.901234Z"
    assert complete["failureCategory"] is None
    result = complete["result"]
    assert isinstance(result, dict)
    assert result["aggregateStatus"] == "PASS"
    assert result["exitCode"] == 0
    assert result["evidencePath"] == str(tmp_path / run_id)
    assert isinstance(result["report"], dict)
    assert harness.run_options[0].run_id == run_id
    assert harness.run_options[0].scenario_id == RAW_SCENARIO_ID
    assert Path(harness.run_options[0].evidence_root) == tmp_path
    assert harness.run_options[0].environment is SYNTHETIC_ENVIRONMENT
    assert clock.value == FIXED_NOW


def test_only_one_reciprocal_run_can_be_active(tmp_path: Path) -> None:
    """The second start request is rejected while the sole worker is busy."""
    harness = RuntimeHarness(block_runner=True)
    state, _clock, _harness = configured_state(tmp_path, harness=harness)
    try:
        state.run_readiness()
        revision = _configuration_revision(state)
        first = state.start_run(SCENARIO_ID, revision)
        assert harness.started.wait(timeout=2)

        with pytest.raises(ConsoleStateError) as caught:
            state.start_run(SCENARIO_ID, revision)

        assert caught.value.code is ConsoleStateFailureCode.RUN_ALREADY_ACTIVE
        with pytest.raises(ConsoleStateError) as replacement:
            state.load_policy(POLICY_BYTES)
        assert replacement.value.code is ConsoleStateFailureCode.RUN_ALREADY_ACTIVE
        assert _configuration_revision(state) == revision
        assert state.active_run_view()["runId"] == first["runId"]
    finally:
        harness.release.set()
        wait_for_terminal_state(state)
        state.close()


@pytest.mark.parametrize(
    ("run_error", "expected_category"),
    [
        (
            AwsReciprocalRetrievalRunError(
                AwsReciprocalRetrievalRunFailureCode.EVIDENCE_RUN_COLLISION
            ),
            "evidence_run_collision",
        ),
        (
            AwsReciprocalRetrievalRunError(
                AwsReciprocalRetrievalRunFailureCode.INTEGRITY_VERIFICATION_FAILED
            ),
            "integrity_verification_failed",
        ),
        (
            RuntimeError("SDK error containing synthetic-credential-must-never-leak"),
            "execution_failed",
        ),
    ],
)
def test_run_failures_are_stable_and_redacted(
    tmp_path: Path,
    run_error: Exception,
    expected_category: str,
) -> None:
    """Operational and unexpected failures expose only fixed categories."""
    harness = RuntimeHarness(run_error=run_error)
    state, _clock, _harness = configured_state(tmp_path, harness=harness)
    try:
        state.run_readiness()
        state.start_run(SCENARIO_ID, _configuration_revision(state))
        failed = wait_for_terminal_state(state)
    finally:
        state.close()

    assert failed["state"] == ConsoleRunState.FAILED.value
    assert failed["stage"] == AwsReciprocalRetrievalRunStage.FAILED.value
    assert failed["failureCategory"] == expected_category
    assert failed["result"] is None
    serialized = json.dumps(failed, sort_keys=True)
    assert str(run_error) not in serialized
    for secret in SYNTHETIC_ENVIRONMENT.values():
        assert secret not in serialized


def test_post_run_integrity_failure_suppresses_result_and_path(
    tmp_path: Path,
) -> None:
    """The worker exposes nothing when its independent bundle check fails."""
    diagnostic = "tampered-bundle-private-path"
    harness = RuntimeHarness(verification_error=RuntimeError(diagnostic))
    state, _clock, _harness = configured_state(tmp_path, harness=harness)
    try:
        state.run_readiness()
        state.start_run(SCENARIO_ID, _configuration_revision(state))
        failed = wait_for_terminal_state(state)
    finally:
        state.close()

    assert failed["state"] == ConsoleRunState.FAILED.value
    assert failed["failureCategory"] == "integrity_verification_failed"
    assert failed["result"] is None
    assert diagnostic not in json.dumps(failed, sort_keys=True)


def test_worker_failure_preserves_existing_unfinalized_directory(
    tmp_path: Path,
) -> None:
    """Shutdown-style partial evidence is neither deleted nor presented."""
    harness = RuntimeHarness(
        create_unfinalized_directory=True,
        run_error=RuntimeError("synthetic interruption"),
    )
    state, _clock, _harness = configured_state(tmp_path, harness=harness)
    try:
        state.run_readiness()
        started = state.start_run(SCENARIO_ID, _configuration_revision(state))
        failed = wait_for_terminal_state(state)
    finally:
        state.close()

    run_id = started["runId"]
    assert isinstance(run_id, str)
    assert (tmp_path / run_id).is_dir()
    assert failed["result"] is None
