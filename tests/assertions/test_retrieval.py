"""Tests for deterministic paired-canary retrieval-boundary evaluation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

from cai_verify.assertions import (
    RETRIEVAL_BOUNDARY_EVALUATOR_VERSION,
    RetrievalBoundaryEvaluator,
)
from cai_verify.config import RetrievalBoundaryAssertion, VerificationSuite
from cai_verify.core import AssertionResult, AssertionStatus, JsonValue, RedactedValue
from cai_verify.plugins import (
    PLUGIN_API_VERSION,
    ActionExecutionResult,
    ActionOutcome,
    AssertionEvaluationRequest,
    AssertionEvaluator,
    EvidenceFreshness,
    EvidenceSource,
    Observation,
    ProbeResult,
)
from tests.plugins.contract_suite import assert_assertion_evaluator_contract

_FIXTURE = (
    Path(__file__).parents[1]
    / "fixtures"
    / "suites"
    / "valid"
    / "reciprocal-retrieval.yaml"
)
_NOW = datetime(2026, 7, 26, 12, tzinfo=UTC)
_ACTION_ID = "retrieve-as-requester-a"
_PROBE_ID = "requester-a-retrieval"
_OBSERVATION_ID = f"{_PROBE_ID}.retrieval-canary"
_EXPECTED_EVIDENCE_ID_COUNT = 2


def _suite() -> VerificationSuite:
    loaded = yaml.safe_load(_FIXTURE.read_text(encoding="utf-8"))
    return VerificationSuite.model_validate(cast("dict[str, Any]", loaded))


def _assertion(index: int = 0) -> RetrievalBoundaryAssertion:
    assertion = _suite().scenarios[0].assertions[index]
    assert isinstance(assertion, RetrievalBoundaryAssertion)
    return assertion


def _complete_observed(
    *,
    baseline: bool = True,
    boundary: bool = False,
    undeclared: bool = False,
    item_count: int = 1,
) -> dict[str, Any]:
    return {
        "accepted_correlated_records": 1,
        "ambiguous": False,
        "baseline_canary_observed": baseline,
        "boundary_canary_observed": boundary,
        "complete_context_scan_succeeded": True,
        "complete_correlated_retrieval_record_found": True,
        "error_category": None,
        "evidence_complete": True,
        "future_dated": False,
        "malformed": False,
        "oversized": False,
        "partial": False,
        "pre_generation_phase_matched": True,
        "retrieval_succeeded": True,
        "retrieved_item_count": item_count,
        "stale": False,
        "undeclared_synthetic_marker_observed": undeclared,
    }


def _incomplete_observed(
    *,
    error_category: str | None = "retrieval_record_missing",
    flag: str | None = None,
) -> dict[str, Any]:
    observed = {
        "accepted_correlated_records": 0,
        "ambiguous": False,
        "baseline_canary_observed": None,
        "boundary_canary_observed": None,
        "complete_context_scan_succeeded": None,
        "complete_correlated_retrieval_record_found": False,
        "error_category": error_category,
        "evidence_complete": False,
        "future_dated": False,
        "malformed": False,
        "oversized": False,
        "partial": False,
        "pre_generation_phase_matched": None,
        "retrieval_succeeded": None,
        "retrieved_item_count": None,
        "stale": False,
        "undeclared_synthetic_marker_observed": None,
    }
    if flag is not None:
        observed[flag] = True
    return observed


def _action(  # noqa: PLR0913 - test states stay explicit at call sites.
    *,
    action_id: str = _ACTION_ID,
    outcome: ActionOutcome = ActionOutcome.SUCCEEDED,
    correlations: tuple[str, ...] = ("requester-a-correlation",),
    started_at: datetime = _NOW - timedelta(minutes=1),
    completed_at: datetime = _NOW - timedelta(seconds=45),
    observed: dict[str, Any] | None = None,
    limitations: tuple[str, ...] = ("Synthetic action result.",),
) -> ActionExecutionResult:
    return ActionExecutionResult(
        action_id=action_id,
        outcome=outcome,
        started_at=started_at,
        completed_at=completed_at,
        observed=RedactedValue(observed or {"request_executed": True}),
        correlation_ids=correlations,
        limitations=limitations,
    )


def _probe(  # noqa: PLR0913 - test states stay explicit at call sites.
    *,
    probe_id: str = _PROBE_ID,
    observed: dict[str, Any] | None = None,
    observations: tuple[Observation, ...] | None = None,
    source_name: str = "aws-cloudwatch-logs",
    source_version: str = "1.2.0",
    collected_at: datetime = _NOW - timedelta(seconds=5),
    source_time: datetime | None = _NOW - timedelta(seconds=30),
    max_age: timedelta = timedelta(minutes=3),
    observation_id: str = _OBSERVATION_ID,
    observation_limitations: tuple[str, ...] = ("Synthetic observation.",),
) -> ProbeResult:
    resolved_observations = observations
    if resolved_observations is None:
        resolved_observations = (
            Observation(
                observation_id=observation_id,
                kind="retrievalCanary",
                observed=RedactedValue(observed or _complete_observed()),
                limitations=observation_limitations,
            ),
        )
    return ProbeResult(
        probe_id=probe_id,
        source=EvidenceSource(name=source_name, version=source_version),
        freshness=EvidenceFreshness(
            collected_at=collected_at,
            source_time=source_time,
            max_age=max_age,
        ),
        observations=resolved_observations,
    )


def _evaluate(
    *,
    assertion: RetrievalBoundaryAssertion | None = None,
    action_results: tuple[ActionExecutionResult, ...] | None = None,
    probe_results: tuple[ProbeResult, ...] | None = None,
) -> AssertionResult:
    request = AssertionEvaluationRequest(
        assertion=assertion or _assertion(),
        action_results=action_results if action_results is not None else (_action(),),
        probe_results=probe_results if probe_results is not None else (_probe(),),
    )
    return RetrievalBoundaryEvaluator(clock=lambda: _NOW).evaluate_assertion(request)


def _result_observed(result: AssertionResult) -> dict[str, JsonValue]:
    observed = result.observed.to_json_value()
    assert isinstance(observed, dict)
    return observed


def test_evaluator_conforms_to_plugin_contract_and_exact_provenance() -> None:
    """The evaluator keeps plugin API 1 and starts at evaluator version 1.0.0."""
    evaluator = RetrievalBoundaryEvaluator(clock=lambda: _NOW)
    request = AssertionEvaluationRequest(
        assertion=_assertion(),
        action_results=(_action(),),
        probe_results=(_probe(),),
    )

    assert isinstance(evaluator, AssertionEvaluator)
    result = assert_assertion_evaluator_contract(evaluator, request)

    assert evaluator.metadata.name == "retrieval-boundary-evaluator"
    assert evaluator.metadata.api_version == PLUGIN_API_VERSION == "1"
    assert evaluator.metadata.capabilities == ("assertion.retrieval-boundary",)
    assert result.evaluator_version == RETRIEVAL_BOUNDARY_EVALUATOR_VERSION == "1.0.0"
    assert result.to_dict()["schema_version"] == "1"


def test_pass_is_deterministic_and_cites_both_evidence_inputs() -> None:
    """Fresh complete isolated evidence serializes with one fixed truth table."""
    first = _evaluate()
    second = _evaluate()

    assert first.status is AssertionStatus.PASS
    assert first.evidence_ids == (
        "action.retrieve-as-requester-a",
        "requester-a-retrieval.retrieval-canary",
    )
    assert first.expected == {
        "baseline_canary_observed": True,
        "boundary_canary_observed": False,
        "complete_context_scan_succeeded": True,
        "exactly_one_correlated_retrieval_record": True,
        "pre_generation_phase_matched": True,
        "retrieval_path_exercised": True,
        "retrieval_succeeded": True,
        "undeclared_synthetic_marker_observed": False,
    }
    assert first.observed.to_json_value() == {
        "baseline_canary_observed": True,
        "boundary_canary_observed": False,
        "normalized_evidence_state": "isolated_retrieval_observed",
        "retrieval_path_exercised": True,
        "retrieved_item_count": 1,
        "undeclared_synthetic_marker_observed": False,
    }
    assert first.to_json_bytes() == second.to_json_bytes()
    assert first.limitations == tuple(sorted(first.limitations))
    assert {
        "The test uses synthetic paired canaries.",
        "The retrieval evidence is application-reported.",
        (
            "A compromised or incorrectly instrumented application can report "
            "false facts."
        ),
        (
            "One passing scenario does not prove isolation for every identity, "
            "query, document, cache, memory layer, or production path."
        ),
        (
            "The result supports a technical assessment and does not establish "
            "compliance."
        ),
    } <= set(first.limitations)


@pytest.mark.parametrize(
    ("baseline", "outcome"),
    [
        (True, ActionOutcome.SUCCEEDED),
        (False, ActionOutcome.SUCCEEDED),
        (True, ActionOutcome.DENIED),
        (False, ActionOutcome.ERROR),
    ],
)
def test_declared_boundary_is_a_direct_failure(
    baseline: bool,  # noqa: FBT001 - explicit parametrized evidence fact.
    outcome: ActionOutcome,
) -> None:
    """Boundary evidence survives absent baselines and later action outcomes."""
    result = _evaluate(
        action_results=(_action(outcome=outcome),),
        probe_results=(
            _probe(observed=_complete_observed(baseline=baseline, boundary=True)),
        ),
    )

    assert result.status is AssertionStatus.FAIL
    assert (
        _result_observed(result)["normalized_evidence_state"]
        == "declared_boundary_observed"
    )


def test_both_canaries_present_is_a_failure() -> None:
    """A valid baseline cannot erase a directly observed boundary canary."""
    result = _evaluate(
        probe_results=(
            _probe(observed=_complete_observed(baseline=True, boundary=True)),
        ),
    )

    assert result.status is AssertionStatus.FAIL


@pytest.mark.parametrize(
    ("observed", "expected_state"),
    [
        (
            _complete_observed(baseline=False, boundary=False),
            "baseline_not_observed",
        ),
        (
            _complete_observed(undeclared=True),
            "undeclared_marker_observed",
        ),
        (
            _complete_observed(
                baseline=False,
                boundary=False,
                item_count=0,
            ),
            "baseline_not_observed",
        ),
    ],
)
def test_unproven_or_undeclared_states_are_inconclusive(
    observed: dict[str, Any],
    expected_state: str,
) -> None:
    """Missing positive control and undeclared markers never become PASS."""
    result = _evaluate(probe_results=(_probe(observed=observed),))

    assert result.status is AssertionStatus.INCONCLUSIVE
    assert _result_observed(result)["normalized_evidence_state"] == expected_state


def test_marker_with_zero_retrieved_items_is_an_error() -> None:
    """A normalized marker cannot exist when no item was retrieved."""
    result = _evaluate(
        probe_results=(
            _probe(
                observed=_complete_observed(
                    baseline=True,
                    boundary=False,
                    item_count=0,
                ),
            ),
        ),
    )

    assert result.status is AssertionStatus.ERROR
    assert (
        _result_observed(result)["normalized_evidence_state"]
        == "marker_observed_with_zero_retrieved_items"
    )


@pytest.mark.parametrize("count", [0, 2])
def test_missing_or_ambiguous_action_results_are_inconclusive(count: int) -> None:
    """Exactly one scenario-local action result is required."""
    actions = () if count == 0 else (_action(), _action())

    result = _evaluate(action_results=actions)

    assert result.status is AssertionStatus.INCONCLUSIVE
    assert result.evidence_ids == (("action.retrieve-as-requester-a",) if count else ())


@pytest.mark.parametrize("count", [0, 2])
def test_missing_or_ambiguous_probe_results_are_inconclusive(count: int) -> None:
    """Exactly one referenced probe result is required."""
    probes = () if count == 0 else (_probe(), _probe())

    result = _evaluate(probe_results=probes)

    assert result.status is AssertionStatus.INCONCLUSIVE


@pytest.mark.parametrize("count", [0, 2])
def test_missing_or_ambiguous_retrieval_observations_are_inconclusive(
    count: int,
) -> None:
    """The referenced probe must contain exactly one retrieval observation."""
    observation = Observation(
        observation_id=_OBSERVATION_ID,
        kind="retrievalCanary",
        observed=RedactedValue(_complete_observed()),
        limitations=("Synthetic observation.",),
    )
    observations = () if count == 0 else (observation, observation)

    result = _evaluate(probe_results=(_probe(observations=observations),))

    assert result.status is AssertionStatus.INCONCLUSIVE


@pytest.mark.parametrize(
    "correlations",
    [(), ("first-correlation", "second-correlation")],
)
def test_action_requires_exactly_one_correlation(
    correlations: tuple[str, ...],
) -> None:
    """Missing and multiple application correlations fail closed."""
    result = _evaluate(action_results=(_action(correlations=correlations),))

    assert result.status is AssertionStatus.INCONCLUSIVE
    assert "correlation" in cast("str", result.status_reason).lower()


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        (ActionOutcome.SUCCEEDED, AssertionStatus.PASS),
        (ActionOutcome.DENIED, AssertionStatus.INCONCLUSIVE),
        (ActionOutcome.ERROR, AssertionStatus.ERROR),
    ],
)
def test_action_outcome_semantics(
    outcome: ActionOutcome,
    expected: AssertionStatus,
) -> None:
    """Only success exercises the path; action errors remain execution errors."""
    result = _evaluate(action_results=(_action(outcome=outcome),))

    assert result.status is expected


@pytest.mark.parametrize(
    ("started_at", "completed_at"),
    [
        (
            _NOW - timedelta(minutes=7),
            _NOW - timedelta(minutes=6),
        ),
        (
            _NOW + timedelta(seconds=31),
            _NOW + timedelta(seconds=32),
        ),
    ],
)
def test_stale_or_future_action_evidence_is_inconclusive(
    started_at: datetime,
    completed_at: datetime,
) -> None:
    """Fixed action age and clock-skew policies prevent a positive result."""
    result = _evaluate(
        action_results=(_action(started_at=started_at, completed_at=completed_at),),
    )

    assert result.status is AssertionStatus.INCONCLUSIVE


@pytest.mark.parametrize(
    ("collected_at", "source_time", "max_age"),
    [
        (
            _NOW - timedelta(seconds=5),
            _NOW - timedelta(minutes=4),
            timedelta(minutes=3),
        ),
        (
            _NOW + timedelta(seconds=31),
            _NOW,
            timedelta(minutes=3),
        ),
        (
            _NOW,
            _NOW + timedelta(seconds=31),
            timedelta(minutes=3),
        ),
        (
            _NOW - timedelta(minutes=1),
            _NOW - timedelta(seconds=20),
            timedelta(minutes=3),
        ),
    ],
)
def test_stale_future_or_inconsistent_probe_freshness_is_inconclusive(
    collected_at: datetime,
    source_time: datetime,
    max_age: timedelta,
) -> None:
    """Probe collection and source clocks are checked independently."""
    result = _evaluate(
        probe_results=(
            _probe(
                collected_at=collected_at,
                source_time=source_time,
                max_age=max_age,
            ),
        ),
    )

    assert result.status is AssertionStatus.INCONCLUSIVE


def test_unbounded_probe_freshness_policy_is_an_error() -> None:
    """An adapter cannot expand the suite's 24-hour policy boundary."""
    result = _evaluate(
        probe_results=(_probe(max_age=timedelta(hours=25)),),
    )

    assert result.status is AssertionStatus.ERROR


def test_complete_evidence_without_source_time_is_inconclusive() -> None:
    """Completeness claims need source time before they can support a PASS."""
    result = _evaluate(probe_results=(_probe(source_time=None),))

    assert result.status is AssertionStatus.INCONCLUSIVE
    assert (
        _result_observed(result)["normalized_evidence_state"]
        == "complete_evidence_missing_source_time"
    )


@pytest.mark.parametrize(
    "flag",
    [None, "ambiguous", "future_dated", "malformed", "oversized", "partial", "stale"],
)
def test_incomplete_source_states_are_inconclusive(flag: str | None) -> None:
    """Adapter-reported incompleteness suppresses facts and never becomes PASS."""
    result = _evaluate(
        probe_results=(
            _probe(
                observed=_incomplete_observed(flag=flag),
                source_time=None,
            ),
        ),
    )

    assert result.status is AssertionStatus.INCONCLUSIVE
    assert (
        _result_observed(result)["normalized_evidence_state"]
        == "normalized_evidence_incomplete"
    )


def test_incomplete_evidence_with_source_time_is_an_error() -> None:
    """Suppressed facts and retained source time are contradictory."""
    result = _evaluate(
        probe_results=(_probe(observed=_incomplete_observed()),),
    )

    assert result.status is AssertionStatus.ERROR


@pytest.mark.parametrize(
    "field_name",
    [
        "baseline_canary_observed",
        "boundary_canary_observed",
        "complete_context_scan_succeeded",
        "pre_generation_phase_matched",
        "retrieval_succeeded",
        "retrieved_item_count",
        "undeclared_synthetic_marker_observed",
    ],
)
def test_complete_evidence_rejects_nullable_facts(field_name: str) -> None:
    """A complete claim paired with unknown facts is a normalized-shape error."""
    observed = _complete_observed()
    observed[field_name] = None

    result = _evaluate(probe_results=(_probe(observed=observed),))

    assert result.status is AssertionStatus.ERROR


@pytest.mark.parametrize(
    ("mutation", "expected_state"),
    [
        ({"extra_field": False}, "invalid_normalized_field_set"),
        ({"accepted_correlated_records": True}, "invalid_normalized_scalar_type"),
        ({"ambiguous": 0}, "invalid_normalized_scalar_type"),
        ({"baseline_canary_observed": 1}, "invalid_normalized_scalar_type"),
        ({"error_category": 7}, "invalid_normalized_scalar_type"),
        ({"retrieved_item_count": True}, "invalid_retrieved_item_count"),
        ({"retrieved_item_count": 10_001}, "invalid_retrieved_item_count"),
    ],
)
def test_invalid_fields_and_scalar_types_are_errors(
    mutation: dict[str, Any],
    expected_state: str,
) -> None:
    """Unknown fields, wrong types, and boolean integers are never guessed."""
    observed = _complete_observed()
    observed.update(mutation)

    result = _evaluate(probe_results=(_probe(observed=observed),))

    assert result.status is AssertionStatus.ERROR
    assert _result_observed(result)["normalized_evidence_state"] == expected_state


def test_missing_normalized_field_is_an_error() -> None:
    """The evaluator requires the exact current adapter field set."""
    observed = _complete_observed()
    observed.pop("partial")

    result = _evaluate(probe_results=(_probe(observed=observed),))

    assert result.status is AssertionStatus.ERROR


@pytest.mark.parametrize(
    "mutation",
    [
        {"accepted_correlated_records": 0},
        {"complete_correlated_retrieval_record_found": False},
        {"complete_context_scan_succeeded": False},
        {"error_category": "invalid_event"},
        {"malformed": True},
        {"pre_generation_phase_matched": False},
        {"retrieval_succeeded": False},
    ],
)
def test_contradictory_complete_states_are_errors(
    mutation: dict[str, Any],
) -> None:
    """Complete evidence cannot contradict completion facts or state flags."""
    observed = _complete_observed()
    observed.update(mutation)

    result = _evaluate(probe_results=(_probe(observed=observed),))

    assert result.status is AssertionStatus.ERROR


@pytest.mark.parametrize(
    "mutation",
    [
        {"accepted_correlated_records": 1},
        {"baseline_canary_observed": False},
        {"complete_correlated_retrieval_record_found": True},
        {"retrieved_item_count": 0},
    ],
)
def test_contradictory_incomplete_states_are_errors(
    mutation: dict[str, Any],
) -> None:
    """Incomplete evidence must suppress counts and every nullable fact."""
    observed = _incomplete_observed()
    observed.update(mutation)

    result = _evaluate(
        probe_results=(_probe(observed=observed, source_time=None),),
    )

    assert result.status is AssertionStatus.ERROR


def test_probe_source_must_match_cloudwatch_logs_1_2_0() -> None:
    """Only the normalized source contract inspected by this evaluator is used."""
    wrong_name = _evaluate(
        probe_results=(_probe(source_name="synthetic-source"),),
    )
    wrong_version = _evaluate(
        probe_results=(_probe(source_version="1.1.0"),),
    )

    assert wrong_name.status is AssertionStatus.INCONCLUSIVE
    assert wrong_version.status is AssertionStatus.INCONCLUSIVE


def test_evaluator_failure_is_redacted_and_deterministic() -> None:
    """An injected clock failure becomes a fixed safe ERROR result."""

    def failing_clock() -> datetime:
        message = "credential-secret-must-not-leak"
        raise RuntimeError(message)

    evaluator = RetrievalBoundaryEvaluator(clock=failing_clock)
    request = AssertionEvaluationRequest(
        assertion=_assertion(),
        action_results=(_action(),),
        probe_results=(_probe(),),
    )

    result = evaluator.evaluate_assertion(request)

    assert result.status is AssertionStatus.ERROR
    assert result.evaluation_started_at == datetime(1970, 1, 1, tzinfo=UTC)
    assert b"credential-secret-must-not-leak" not in result.to_json_bytes()


def test_evaluator_accepts_only_retrieval_boundary_assertions() -> None:
    """Another strict assertion union member cannot enter this evaluator."""
    evaluator = RetrievalBoundaryEvaluator(clock=lambda: _NOW)
    local_fixture = (
        Path(__file__).parents[2] / "examples" / "local" / "synthetic-suite.json"
    )
    other_suite = VerificationSuite.model_validate_json(local_fixture.read_bytes())
    request = AssertionEvaluationRequest(
        assertion=other_suite.scenarios[0].assertions[0],
        action_results=(_action(),),
        probe_results=(_probe(),),
    )

    with pytest.raises(TypeError, match="requires retrievalBoundary"):
        evaluator.evaluate_assertion(request)


def test_result_never_serializes_sensitive_input_material() -> None:
    """Raw content and identifiers cannot cross the result redaction boundary."""
    sensitive_values = (
        "literal-canary-value",
        "document-identifier-secret",
        "tenant-identifier-secret",
        "identity-identifier-secret",
        "correlation-secret",
        "credential-secret",
        "environment-value-secret",
        "arn:aws:iam::111122223333:role/secret",
    )
    action = _action(
        correlations=("correlation-secret",),
        observed={"raw_values": list(sensitive_values)},
        limitations=("credential-secret",),
    )
    observed = _complete_observed()
    observed["raw"] = list(sensitive_values)
    probe = _probe(
        observed=observed,
        observation_limitations=("tenant-identifier-secret",),
    )

    result = _evaluate(action_results=(action,), probe_results=(probe,))
    serialized = result.to_json()

    assert result.status is AssertionStatus.ERROR
    assert all(value not in serialized for value in sensitive_values)


def test_reciprocal_two_requester_contract_evaluates_isolated_and_vulnerable() -> None:
    """One validated suite drives two actions, probes, and evaluator calls."""
    suite = _suite()
    assertions = cast(
        "tuple[RetrievalBoundaryAssertion, RetrievalBoundaryAssertion]",
        suite.scenarios[0].assertions,
    )
    actions = (
        _action(action_id="retrieve-as-requester-a"),
        _action(
            action_id="retrieve-as-requester-b",
            correlations=("requester-b-correlation",),
        ),
    )
    isolated_probes = (
        _probe(),
        _probe(
            probe_id="requester-b-retrieval",
            observation_id="requester-b-retrieval.retrieval-canary",
        ),
    )

    isolated = tuple(
        _evaluate(
            assertion=assertion,
            action_results=actions,
            probe_results=isolated_probes,
        )
        for assertion in assertions
    )
    vulnerable_probes = tuple(
        _probe(
            probe_id=probe.probe_id,
            observation_id=probe.observations[0].observation_id,
            observed=_complete_observed(boundary=True),
        )
        for probe in isolated_probes
    )
    vulnerable = tuple(
        _evaluate(
            assertion=assertion,
            action_results=actions,
            probe_results=vulnerable_probes,
        )
        for assertion in assertions
    )

    assert [result.status for result in isolated] == [
        AssertionStatus.PASS,
        AssertionStatus.PASS,
    ]
    assert [result.status for result in vulnerable] == [
        AssertionStatus.FAIL,
        AssertionStatus.FAIL,
    ]
    assert all(
        len(result.evidence_ids) == _EXPECTED_EVIDENCE_ID_COUNT
        for result in isolated + vulnerable
    )
