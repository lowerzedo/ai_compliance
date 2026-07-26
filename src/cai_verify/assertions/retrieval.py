"""Deterministic paired-canary retrieval-boundary evaluation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, final

from cai_verify.config import RetrievalBoundaryAssertion
from cai_verify.config.models import ObservationKind
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
    AssertionEvaluationRequest,
    Observation,
    PluginMetadata,
    ProbeResult,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from cai_verify.core import JsonValue

RETRIEVAL_BOUNDARY_EVALUATOR_VERSION = "1.0.0"

_EXPECTED_SOURCE_NAME = "aws-cloudwatch-logs"
_EXPECTED_SOURCE_VERSION = "1.2.0"
_ACTION_MAX_AGE = timedelta(minutes=5)
_CLOCK_SKEW_TOLERANCE = timedelta(seconds=30)
_MAX_PROBE_AGE = timedelta(hours=24)
_MAX_RETRIEVED_ITEMS = 10_000
_ERROR_CATEGORY_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,127}\Z")
_RETRIEVAL_FIELDS = frozenset(
    {
        "accepted_correlated_records",
        "ambiguous",
        "baseline_canary_observed",
        "boundary_canary_observed",
        "complete_context_scan_succeeded",
        "complete_correlated_retrieval_record_found",
        "error_category",
        "evidence_complete",
        "future_dated",
        "malformed",
        "oversized",
        "partial",
        "pre_generation_phase_matched",
        "retrieval_succeeded",
        "retrieved_item_count",
        "stale",
        "undeclared_synthetic_marker_observed",
    },
)
_STATE_FLAG_FIELDS = (
    "ambiguous",
    "future_dated",
    "malformed",
    "oversized",
    "partial",
    "stale",
)
_NULLABLE_BOOLEAN_FIELDS = (
    "baseline_canary_observed",
    "boundary_canary_observed",
    "complete_context_scan_succeeded",
    "pre_generation_phase_matched",
    "retrieval_succeeded",
    "undeclared_synthetic_marker_observed",
)
_EXPECTED: JsonValue = {
    "baseline_canary_observed": True,
    "boundary_canary_observed": False,
    "complete_context_scan_succeeded": True,
    "exactly_one_correlated_retrieval_record": True,
    "pre_generation_phase_matched": True,
    "retrieval_path_exercised": True,
    "retrieval_succeeded": True,
    "undeclared_synthetic_marker_observed": False,
}
_FIXED_LIMITATIONS = (
    "The test uses synthetic paired canaries.",
    "The retrieval evidence is application-reported.",
    "A compromised or incorrectly instrumented application can report false facts.",
    "One passing scenario does not prove isolation for every identity, query, "
    "document, cache, memory layer, or production path.",
    "The result supports a technical assessment and does not establish compliance.",
)
_ERROR_TIME = datetime(1970, 1, 1, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class _RetrievalFacts:
    baseline_observed: bool | None
    boundary_observed: bool | None
    complete: bool
    retrieved_item_count: int | None
    undeclared_marker_observed: bool | None


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class RetrievalBoundaryEvaluator:
    """Evaluate one fixed paired-canary retrieval-boundary assertion."""

    clock: Callable[[], datetime] = field(
        default=lambda: datetime.now(UTC),
        repr=False,
    )

    @property
    def metadata(self) -> PluginMetadata:
        """Declare the exact built-in evaluator capability."""
        return PluginMetadata(
            name="retrieval-boundary-evaluator",
            api_version=PLUGIN_API_VERSION,
            capabilities=("assertion.retrieval-boundary",),
        )

    def evaluate_assertion(
        self,
        request: AssertionEvaluationRequest,
        /,
    ) -> AssertionResult:
        """Evaluate only normalized facts; never resolve canaries or telemetry."""
        assertion = request.assertion
        if not isinstance(assertion, RetrievalBoundaryAssertion):
            message = "evaluator requires retrievalBoundary"
            raise TypeError(message)
        try:
            evaluated_at = _normalized_time(self.clock())
        except Exception:  # noqa: BLE001 - clock diagnostics are not result data.
            return _result(
                assertion,
                evaluated_at=_ERROR_TIME,
                status=AssertionStatus.ERROR,
                observed=_observed(state="evaluator_error"),
                status_reason="The evaluator clock failed.",
            )
        try:
            return self._evaluate(
                request,
                assertion=assertion,
                evaluated_at=evaluated_at,
            )
        except Exception:  # noqa: BLE001 - evaluator diagnostics are always redacted.
            return _result(
                assertion,
                evaluated_at=evaluated_at,
                status=AssertionStatus.ERROR,
                observed=_observed(state="evaluator_error"),
                status_reason="Deterministic retrieval evaluation failed.",
            )

    @staticmethod
    def _evaluate(  # noqa: C901, PLR0911, PLR0912 - precedence stays explicit.
        request: AssertionEvaluationRequest,
        *,
        assertion: RetrievalBoundaryAssertion,
        evaluated_at: datetime,
    ) -> AssertionResult:
        actions = tuple(
            result
            for result in request.action_results
            if result.action_id == assertion.action_ref
        )
        probes = tuple(
            result
            for result in request.probe_results
            if result.probe_id == assertion.probe_ref
        )
        if len(actions) != 1:
            return _result(
                assertion,
                evaluated_at=evaluated_at,
                status=AssertionStatus.INCONCLUSIVE,
                observed=_observed(state="action_missing_or_ambiguous"),
                evidence_ids=_evidence_ids(actions=actions),
                status_reason="Referenced action evidence is missing or ambiguous.",
            )
        action = actions[0]
        if len(probes) != 1:
            return _result(
                assertion,
                evaluated_at=evaluated_at,
                status=AssertionStatus.INCONCLUSIVE,
                observed=_observed(
                    state="probe_missing_or_ambiguous",
                    action=action,
                ),
                evidence_ids=_evidence_ids(actions=(action,), probes=probes),
                status_reason="Referenced probe evidence is missing or ambiguous.",
            )
        probe = probes[0]
        observations = tuple(
            item
            for item in probe.observations
            if item.kind == ObservationKind.RETRIEVAL_CANARY.value
        )
        evidence_ids = _evidence_ids(
            actions=(action,),
            observations=observations,
        )
        if len(observations) != 1:
            return _result(
                assertion,
                evaluated_at=evaluated_at,
                status=AssertionStatus.INCONCLUSIVE,
                observed=_observed(
                    state="observation_missing_or_ambiguous",
                    action=action,
                ),
                evidence_ids=evidence_ids,
                status_reason=("The retrieval observation is missing or ambiguous."),
            )
        observation = observations[0]

        action_freshness_issue = _action_freshness_issue(
            action,
            evaluated_at=evaluated_at,
        )
        if action_freshness_issue is not None:
            return _result(
                assertion,
                evaluated_at=evaluated_at,
                status=AssertionStatus.INCONCLUSIVE,
                observed=_observed(
                    state=action_freshness_issue,
                    action=action,
                ),
                evidence_ids=evidence_ids,
                status_reason="Action evidence is stale or future-dated.",
            )
        if len(action.correlation_ids) != 1:
            return _result(
                assertion,
                evaluated_at=evaluated_at,
                status=AssertionStatus.INCONCLUSIVE,
                observed=_observed(
                    state="action_correlation_missing_or_ambiguous",
                    action=action,
                ),
                evidence_ids=evidence_ids,
                status_reason=("Exactly one usable action correlation is required."),
            )
        if (
            probe.source.name != _EXPECTED_SOURCE_NAME
            or probe.source.version != _EXPECTED_SOURCE_VERSION
        ):
            return _result(
                assertion,
                evaluated_at=evaluated_at,
                status=AssertionStatus.INCONCLUSIVE,
                observed=_observed(
                    state="unsupported_probe_source",
                    action=action,
                ),
                evidence_ids=evidence_ids,
                status_reason=(
                    "Probe provenance does not match the retrieval evidence contract."
                ),
            )
        probe_freshness_issue = _probe_freshness_issue(
            probe,
            evaluated_at=evaluated_at,
        )
        if probe_freshness_issue is not None:
            status = (
                AssertionStatus.ERROR
                if probe_freshness_issue == "invalid_probe_freshness_policy"
                else AssertionStatus.INCONCLUSIVE
            )
            return _result(
                assertion,
                evaluated_at=evaluated_at,
                status=status,
                observed=_observed(
                    state=probe_freshness_issue,
                    action=action,
                ),
                evidence_ids=evidence_ids,
                status_reason=(
                    "Probe freshness metadata is invalid."
                    if status is AssertionStatus.ERROR
                    else "Probe evidence is stale, future-dated, or time-inconsistent."
                ),
            )

        value = observation.observed.to_json_value()
        facts, shape_issue = _retrieval_facts(value)
        if shape_issue is not None:
            return _result(
                assertion,
                evaluated_at=evaluated_at,
                status=AssertionStatus.ERROR,
                observed=_observed(
                    state=shape_issue,
                    action=action,
                ),
                evidence_ids=evidence_ids,
                status_reason=(
                    "The retrieval observation has an invalid normalized shape."
                ),
            )
        if facts is None:
            message = "validated retrieval facts are unexpectedly unavailable"
            raise RuntimeError(message)
        if facts.complete and probe.freshness.source_time is None:
            return _result(
                assertion,
                evaluated_at=evaluated_at,
                status=AssertionStatus.INCONCLUSIVE,
                observed=_observed(
                    state="complete_evidence_missing_source_time",
                    action=action,
                    facts=facts,
                ),
                evidence_ids=evidence_ids,
                status_reason="Complete retrieval evidence is missing source time.",
            )
        if not facts.complete and probe.freshness.source_time is not None:
            return _result(
                assertion,
                evaluated_at=evaluated_at,
                status=AssertionStatus.ERROR,
                observed=_observed(
                    state="incomplete_evidence_with_source_time",
                    action=action,
                    facts=facts,
                ),
                evidence_ids=evidence_ids,
                status_reason=(
                    "Incomplete retrieval evidence contradicts its source time."
                ),
            )
        if not facts.complete:
            return _result(
                assertion,
                evaluated_at=evaluated_at,
                status=AssertionStatus.INCONCLUSIVE,
                observed=_observed(
                    state="normalized_evidence_incomplete",
                    action=action,
                    facts=facts,
                ),
                evidence_ids=evidence_ids,
                status_reason="Retrieval evidence is incomplete or unusable.",
            )

        if facts.boundary_observed is True:
            return _result(
                assertion,
                evaluated_at=evaluated_at,
                status=AssertionStatus.FAIL,
                observed=_observed(
                    state="declared_boundary_observed",
                    action=action,
                    facts=facts,
                ),
                evidence_ids=evidence_ids,
                status_reason=(
                    "Fresh complete evidence directly observed the declared "
                    "boundary canary."
                ),
            )
        if action.outcome is ActionOutcome.ERROR:
            return _result(
                assertion,
                evaluated_at=evaluated_at,
                status=AssertionStatus.ERROR,
                observed=_observed(
                    state="action_execution_error",
                    action=action,
                    facts=facts,
                ),
                evidence_ids=evidence_ids,
                status_reason=(
                    "The action failed without a declared boundary contradiction."
                ),
            )
        if action.outcome is ActionOutcome.DENIED:
            return _result(
                assertion,
                evaluated_at=evaluated_at,
                status=AssertionStatus.INCONCLUSIVE,
                observed=_observed(
                    state="action_denied",
                    action=action,
                    facts=facts,
                ),
                evidence_ids=evidence_ids,
                status_reason=(
                    "The denied action did not exercise the positive-control "
                    "retrieval path."
                ),
            )
        if facts.baseline_observed is not True:
            return _result(
                assertion,
                evaluated_at=evaluated_at,
                status=AssertionStatus.INCONCLUSIVE,
                observed=_observed(
                    state="baseline_not_observed",
                    action=action,
                    facts=facts,
                ),
                evidence_ids=evidence_ids,
                status_reason=(
                    "The baseline canary was not observed, so isolation was not "
                    "established."
                ),
            )
        if facts.undeclared_marker_observed is True:
            return _result(
                assertion,
                evaluated_at=evaluated_at,
                status=AssertionStatus.INCONCLUSIVE,
                observed=_observed(
                    state="undeclared_marker_observed",
                    action=action,
                    facts=facts,
                ),
                evidence_ids=evidence_ids,
                status_reason=(
                    "An undeclared synthetic marker prevents a positive boundary "
                    "result."
                ),
            )
        if facts.retrieved_item_count == 0:
            return _result(
                assertion,
                evaluated_at=evaluated_at,
                status=AssertionStatus.INCONCLUSIVE,
                observed=_observed(
                    state="retrieval_path_unexercised",
                    action=action,
                    facts=facts,
                ),
                evidence_ids=evidence_ids,
                status_reason="The positive-control retrieval path was not exercised.",
            )
        return _result(
            assertion,
            evaluated_at=evaluated_at,
            status=AssertionStatus.PASS,
            observed=_observed(
                state="isolated_retrieval_observed",
                action=action,
                facts=facts,
            ),
            evidence_ids=evidence_ids,
            status_reason=(
                "Fresh complete paired-canary evidence supports the declared "
                "retrieval boundary."
            ),
        )


def _retrieval_facts(  # noqa: PLR0911 - shape failures remain explicit.
    value: JsonValue,
) -> tuple[_RetrievalFacts | None, str | None]:
    if not isinstance(value, dict) or set(value) != _RETRIEVAL_FIELDS:
        return None, "invalid_normalized_field_set"
    accepted = value["accepted_correlated_records"]
    complete_record = value["complete_correlated_retrieval_record_found"]
    evidence_complete = value["evidence_complete"]
    error_category = value["error_category"]
    if (
        type(accepted) is not int
        or accepted not in {0, 1}
        or type(complete_record) is not bool
        or type(evidence_complete) is not bool
        or any(type(value[field_name]) is not bool for field_name in _STATE_FLAG_FIELDS)
        or any(
            value[field_name] is not None and type(value[field_name]) is not bool
            for field_name in _NULLABLE_BOOLEAN_FIELDS
        )
        or (
            error_category is not None
            and (
                type(error_category) is not str
                or _ERROR_CATEGORY_PATTERN.fullmatch(error_category) is None
            )
        )
    ):
        return None, "invalid_normalized_scalar_type"
    item_count = value["retrieved_item_count"]
    if item_count is not None and (
        type(item_count) is not int or not 0 <= item_count <= _MAX_RETRIEVED_ITEMS
    ):
        return None, "invalid_retrieved_item_count"

    state_flags = tuple(bool(value[field_name]) for field_name in _STATE_FLAG_FIELDS)
    nullable_values = tuple(
        value[field_name] for field_name in _NULLABLE_BOOLEAN_FIELDS
    )
    if evidence_complete:
        if (
            accepted != 1
            or complete_record is not True
            or any(state_flags)
            or error_category is not None
            or any(item is None for item in nullable_values)
            or item_count is None
            or value["complete_context_scan_succeeded"] is not True
            or value["pre_generation_phase_matched"] is not True
            or value["retrieval_succeeded"] is not True
        ):
            return None, "contradictory_complete_evidence"
    elif (
        accepted != 0
        or complete_record is not False
        or any(item is not None for item in nullable_values)
        or item_count is not None
    ):
        return None, "contradictory_incomplete_evidence"

    baseline = value["baseline_canary_observed"]
    boundary = value["boundary_canary_observed"]
    undeclared = value["undeclared_synthetic_marker_observed"]
    if (
        evidence_complete
        and item_count == 0
        and (baseline is True or boundary is True or undeclared is True)
    ):
        return None, "marker_observed_with_zero_retrieved_items"
    return (
        _RetrievalFacts(
            baseline_observed=baseline if type(baseline) is bool else None,
            boundary_observed=boundary if type(boundary) is bool else None,
            complete=evidence_complete,
            retrieved_item_count=item_count if type(item_count) is int else None,
            undeclared_marker_observed=(
                undeclared if type(undeclared) is bool else None
            ),
        ),
        None,
    )


def _action_freshness_issue(
    action: ActionExecutionResult,
    *,
    evaluated_at: datetime,
) -> str | None:
    if evaluated_at > action.completed_at + _ACTION_MAX_AGE:
        return "stale_action_evidence"
    if (
        action.started_at > evaluated_at + _CLOCK_SKEW_TOLERANCE
        or action.completed_at > evaluated_at + _CLOCK_SKEW_TOLERANCE
    ):
        return "future_action_evidence"
    return None


def _probe_freshness_issue(
    probe: ProbeResult,
    *,
    evaluated_at: datetime,
) -> str | None:
    freshness = probe.freshness
    if freshness.max_age > _MAX_PROBE_AGE:
        return "invalid_probe_freshness_policy"
    if freshness.collected_at > evaluated_at + _CLOCK_SKEW_TOLERANCE:
        return "future_probe_collection"
    source_time = freshness.source_time
    if source_time is not None:
        if source_time > evaluated_at + _CLOCK_SKEW_TOLERANCE:
            return "future_probe_source"
        if source_time > freshness.collected_at + _CLOCK_SKEW_TOLERANCE:
            return "inconsistent_probe_source_time"
    if evaluated_at > freshness.freshness_limit:
        return "stale_probe_evidence"
    return None


def _observed(
    *,
    state: str,
    action: ActionExecutionResult | None = None,
    facts: _RetrievalFacts | None = None,
) -> JsonValue:
    return {
        "baseline_canary_observed": (
            facts.baseline_observed if facts is not None else None
        ),
        "boundary_canary_observed": (
            facts.boundary_observed if facts is not None else None
        ),
        "normalized_evidence_state": state,
        "retrieval_path_exercised": (
            action.outcome is ActionOutcome.SUCCEEDED if action is not None else False
        ),
        "retrieved_item_count": (
            facts.retrieved_item_count if facts is not None else None
        ),
        "undeclared_synthetic_marker_observed": (
            facts.undeclared_marker_observed if facts is not None else None
        ),
    }


def _evidence_ids(
    *,
    actions: Iterable[ActionExecutionResult] = (),
    probes: Iterable[ProbeResult] = (),
    observations: Iterable[Observation] = (),
) -> tuple[str, ...]:
    identifiers = {f"action.{action.action_id}" for action in actions}
    identifiers.update(
        observation.observation_id
        for probe in probes
        for observation in probe.observations
        if observation.kind == ObservationKind.RETRIEVAL_CANARY.value
    )
    identifiers.update(observation.observation_id for observation in observations)
    return tuple(sorted(identifiers))


def _result(  # noqa: PLR0913 - mirrors the immutable result contract.
    assertion: RetrievalBoundaryAssertion,
    *,
    evaluated_at: datetime,
    status: AssertionStatus,
    observed: JsonValue,
    evidence_ids: tuple[str, ...] = (),
    status_reason: str,
) -> AssertionResult:
    limitations = {
        *(item.description for item in assertion.limitations),
        *_FIXED_LIMITATIONS,
    }
    return AssertionResult(
        assertion_id=assertion.id,
        assertion_type=AssertionType.EVIDENCE_BACKED,
        status=status,
        expected=_EXPECTED,
        observed=RedactedValue(observed),
        evidence_ids=evidence_ids,
        limitations=tuple(sorted(limitations)),
        evaluator_version=RETRIEVAL_BOUNDARY_EVALUATOR_VERSION,
        evaluation_started_at=evaluated_at,
        evaluation_completed_at=evaluated_at,
        status_reason=status_reason,
    )


def _normalized_time(value: object) -> datetime:
    if not isinstance(value, datetime):
        message = "evaluation clock must return a datetime"
        raise TypeError(message)
    if value.tzinfo is None or value.utcoffset() is None:
        message = "evaluation clock must return an offset-aware datetime"
        raise ValueError(message)
    return value.astimezone(UTC)
