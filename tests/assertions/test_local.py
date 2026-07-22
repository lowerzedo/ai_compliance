"""Fail-closed tests for local synthetic assertion evaluators."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from cai_verify.assertions import (
    ApplicationStatusEvaluator,
    AuditEventPresentEvaluator,
    AuditPrincipalCorrelatedEvaluator,
    TelemetryCanaryAbsentEvaluator,
)
from cai_verify.core import (
    AssertionStatus,
    CliExitCode,
    RedactedValue,
    exit_code_for_results,
)
from cai_verify.local.runner import DETERMINISTIC_TIME, load_suite
from cai_verify.plugins import (
    ActionExecutionResult,
    ActionOutcome,
    AssertionEvaluationRequest,
    EvidenceFreshness,
    EvidenceSource,
    Observation,
    ProbeResult,
)

_SUITE_PATH = Path(__file__).parents[2] / "examples" / "local" / "synthetic-suite.json"


def test_canary_absence_is_inconclusive_when_evidence_is_missing() -> None:
    """Absence of a probe result never becomes proof of canary absence."""
    assertion = load_suite(_SUITE_PATH).scenarios[0].assertions[1]
    evaluator = TelemetryCanaryAbsentEvaluator(DETERMINISTIC_TIME)

    result = evaluator.evaluate_assertion(
        AssertionEvaluationRequest(
            assertion=assertion,
            action_results=(),
            probe_results=(),
        ),
    )

    assert result.status is AssertionStatus.INCONCLUSIVE
    assert result.evidence_ids == ()


def test_canary_absence_is_inconclusive_and_cites_stale_evidence() -> None:
    """An explicit absence in stale telemetry cannot satisfy the assertion."""
    assertion = load_suite(_SUITE_PATH).scenarios[0].assertions[1]
    evaluator = TelemetryCanaryAbsentEvaluator(DETERMINISTIC_TIME)
    observation = Observation(
        observation_id="stale-probe.telemetry-canary",
        kind="telemetryCanary",
        observed=RedactedValue({"present": False, "records_considered": 1}),
        limitations=("Synthetic stale observation.",),
    )
    probe = ProbeResult(
        probe_id="local-telemetry",
        source=EvidenceSource(name="local-synthetic-telemetry", version="1.0.0"),
        freshness=EvidenceFreshness(
            collected_at=DETERMINISTIC_TIME,
            source_time=DETERMINISTIC_TIME - timedelta(minutes=10),
            max_age=timedelta(minutes=5),
        ),
        observations=(observation,),
    )

    result = evaluator.evaluate_assertion(
        AssertionEvaluationRequest(
            assertion=assertion,
            action_results=(),
            probe_results=(probe,),
        ),
    )

    assert result.status is AssertionStatus.INCONCLUSIVE
    assert result.evidence_ids == (observation.observation_id,)


def test_canary_observation_with_malformed_shape_is_error() -> None:
    """Malformed normalized telemetry is an evaluation error, never a pass."""
    assertion = load_suite(_SUITE_PATH).scenarios[0].assertions[1]
    evaluator = TelemetryCanaryAbsentEvaluator(DETERMINISTIC_TIME)
    observation = Observation(
        observation_id="malformed-probe.telemetry-canary",
        kind="telemetryCanary",
        observed=RedactedValue({"present": "no"}),
        limitations=("Synthetic malformed observation.",),
    )
    probe = ProbeResult(
        probe_id="local-telemetry",
        source=EvidenceSource(name="local-synthetic-telemetry", version="1.0.0"),
        freshness=EvidenceFreshness(
            collected_at=DETERMINISTIC_TIME,
            source_time=DETERMINISTIC_TIME,
            max_age=timedelta(minutes=5),
        ),
        observations=(observation,),
    )

    result = evaluator.evaluate_assertion(
        AssertionEvaluationRequest(
            assertion=assertion,
            action_results=(),
            probe_results=(probe,),
        ),
    )

    assert result.status is AssertionStatus.ERROR
    assert result.evidence_ids == (observation.observation_id,)


def test_future_collection_time_is_inconclusive_even_with_current_source_time() -> None:
    """A plausible source timestamp cannot hide an impossible collection clock."""
    assertion = load_suite(_SUITE_PATH).scenarios[0].assertions[1]
    observation = Observation(
        observation_id="future-probe.telemetry-canary",
        kind="telemetryCanary",
        observed=RedactedValue({"present": False, "records_considered": 1}),
        limitations=("Synthetic future-collected observation.",),
    )
    probe = ProbeResult(
        probe_id="local-telemetry",
        source=EvidenceSource(name="local-synthetic-telemetry", version="1.0.0"),
        freshness=EvidenceFreshness(
            collected_at=DETERMINISTIC_TIME + timedelta(minutes=1),
            source_time=DETERMINISTIC_TIME,
            max_age=timedelta(minutes=5),
        ),
        observations=(observation,),
    )

    result = TelemetryCanaryAbsentEvaluator(
        DETERMINISTIC_TIME,
    ).evaluate_assertion(
        AssertionEvaluationRequest(
            assertion=assertion,
            action_results=(),
            probe_results=(probe,),
        ),
    )

    assert result.status is AssertionStatus.INCONCLUSIVE
    assert result.evidence_ids == (observation.observation_id,)


def test_canary_absence_with_zero_records_is_inconclusive() -> None:
    """A normalized empty query cannot prove that telemetry omitted a canary."""
    assertion = load_suite(_SUITE_PATH).scenarios[0].assertions[1]
    observation = Observation(
        observation_id="empty-probe.telemetry-canary",
        kind="telemetryCanary",
        observed=RedactedValue({"present": False, "records_considered": 0}),
        limitations=("Synthetic empty observation.",),
    )
    probe = _fresh_probe(observation)

    result = TelemetryCanaryAbsentEvaluator(
        DETERMINISTIC_TIME,
    ).evaluate_assertion(
        AssertionEvaluationRequest(
            assertion=assertion,
            action_results=(),
            probe_results=(probe,),
        ),
    )

    assert result.status is AssertionStatus.INCONCLUSIVE
    assert result.evidence_ids == (observation.observation_id,)


def test_action_error_cannot_become_pass_or_be_masked_by_audit_failure() -> None:
    """Execution failures retain exit 2 when correlation evidence is unavailable."""
    assertions = load_suite(_SUITE_PATH).scenarios[0].assertions
    action = ActionExecutionResult(
        action_id="synthetic-inference",
        outcome=ActionOutcome.ERROR,
        started_at=DETERMINISTIC_TIME,
        completed_at=DETERMINISTIC_TIME,
        observed=RedactedValue(
            {
                "http_status": 200,
                "principal_pseudonym": "principal-synthetic",
            },
        ),
        correlation_ids=(),
        limitations=("Synthetic failed action.",),
    )
    audit = Observation(
        observation_id="local-telemetry.audit-event",
        kind="auditEvent",
        observed=RedactedValue({"events": []}),
        limitations=("Synthetic empty audit evidence.",),
    )
    probe = _fresh_probe(audit)
    status_result = ApplicationStatusEvaluator(
        DETERMINISTIC_TIME,
    ).evaluate_assertion(
        AssertionEvaluationRequest(
            assertion=assertions[0],
            action_results=(action,),
            probe_results=(probe,),
        ),
    )
    audit_result = AuditEventPresentEvaluator(
        DETERMINISTIC_TIME,
    ).evaluate_assertion(
        AssertionEvaluationRequest(
            assertion=assertions[2],
            action_results=(action,),
            probe_results=(probe,),
        ),
    )

    assert status_result.status is AssertionStatus.ERROR
    assert audit_result.status is AssertionStatus.ERROR
    assert exit_code_for_results((status_result, audit_result)) is (
        CliExitCode.EXECUTION_ERROR
    )


def test_audit_principal_mismatch_is_a_fail() -> None:
    """Fresh correlated evidence with a different pseudonym contradicts the claim."""
    assertion = load_suite(_SUITE_PATH).scenarios[0].assertions[3]
    action = ActionExecutionResult(
        action_id="synthetic-inference",
        outcome=ActionOutcome.SUCCEEDED,
        started_at=DETERMINISTIC_TIME,
        completed_at=DETERMINISTIC_TIME,
        observed=RedactedValue(
            {
                "http_status": 200,
                "principal_pseudonym": "principal-expected",
            },
        ),
        correlation_ids=("local-correlation",),
        limitations=("Synthetic action.",),
    )
    audit = Observation(
        observation_id="local-telemetry.audit-event",
        kind="auditEvent",
        observed=RedactedValue(
            {
                "events": [
                    {
                        "correlation_id": "local-correlation",
                        "event_name": "SyntheticInference",
                        "principal_pseudonym": "principal-other",
                    },
                ],
            },
        ),
        limitations=("Synthetic mismatched audit evidence.",),
    )

    result = AuditPrincipalCorrelatedEvaluator(
        DETERMINISTIC_TIME,
    ).evaluate_assertion(
        AssertionEvaluationRequest(
            assertion=assertion,
            action_results=(action,),
            probe_results=(_fresh_probe(audit),),
        ),
    )

    assert result.status is AssertionStatus.FAIL


def test_stale_action_cannot_support_audit_passes() -> None:
    """Fresh probe data cannot revive stale action evidence used for correlation."""
    assertions = load_suite(_SUITE_PATH).scenarios[0].assertions
    action = ActionExecutionResult(
        action_id="synthetic-inference",
        outcome=ActionOutcome.SUCCEEDED,
        started_at=DETERMINISTIC_TIME - timedelta(minutes=10),
        completed_at=DETERMINISTIC_TIME - timedelta(minutes=10),
        observed=RedactedValue(
            {
                "http_status": 200,
                "principal_pseudonym": "principal-expected",
            },
        ),
        correlation_ids=("local-correlation",),
        limitations=("Synthetic stale action.",),
    )
    audit = Observation(
        observation_id="local-telemetry.audit-event",
        kind="auditEvent",
        observed=RedactedValue(
            {
                "events": [
                    {
                        "correlation_id": "local-correlation",
                        "event_name": "SyntheticInference",
                        "principal_pseudonym": "principal-expected",
                    },
                ],
            },
        ),
        limitations=("Synthetic audit evidence.",),
    )
    request_values = ((action,), (_fresh_probe(audit),))

    event_result = AuditEventPresentEvaluator(
        DETERMINISTIC_TIME,
    ).evaluate_assertion(
        AssertionEvaluationRequest(
            assertion=assertions[2],
            action_results=request_values[0],
            probe_results=request_values[1],
        ),
    )
    principal_result = AuditPrincipalCorrelatedEvaluator(
        DETERMINISTIC_TIME,
    ).evaluate_assertion(
        AssertionEvaluationRequest(
            assertion=assertions[3],
            action_results=request_values[0],
            probe_results=request_values[1],
        ),
    )

    assert event_result.status is AssertionStatus.INCONCLUSIVE
    assert principal_result.status is AssertionStatus.INCONCLUSIVE


def _fresh_probe(observation: Observation) -> ProbeResult:
    return ProbeResult(
        probe_id="local-telemetry",
        source=EvidenceSource(name="local-synthetic-telemetry", version="1.0.0"),
        freshness=EvidenceFreshness(
            collected_at=DETERMINISTIC_TIME,
            source_time=DETERMINISTIC_TIME,
            max_age=timedelta(minutes=5),
        ),
        observations=(observation,),
    )
