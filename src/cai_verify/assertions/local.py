"""Deterministic evaluators for the local synthetic vertical slice."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, cast, final

from cai_verify.config import (
    ApplicationStatusAssertion,
    AuditEventPresentAssertion,
    AuditPrincipalCorrelatedAssertion,
    TelemetryCanaryAbsentAssertion,
)
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
    from datetime import datetime

    from cai_verify.core import JsonValue

type LocalAssertion = (
    ApplicationStatusAssertion
    | TelemetryCanaryAbsentAssertion
    | AuditEventPresentAssertion
    | AuditPrincipalCorrelatedAssertion
)

_EVALUATOR_VERSION = "1.0.0"
_DEFAULT_CLOCK_SKEW_TOLERANCE = timedelta(seconds=30)
_DEFAULT_ACTION_MAX_AGE = timedelta(minutes=5)
_HTTP_STATUS_MIN = 100
_HTTP_STATUS_MAX = 599


@final
@dataclass(frozen=True, slots=True)
class ApplicationStatusEvaluator:
    """Evaluate ``application.status`` against normalized HTTP status evidence."""

    evaluated_at: datetime
    max_age: timedelta = _DEFAULT_ACTION_MAX_AGE
    clock_skew_tolerance: timedelta = _DEFAULT_CLOCK_SKEW_TOLERANCE

    @property
    def metadata(self) -> PluginMetadata:
        """Declare the exact evaluator capability."""
        return _metadata("application-status-evaluator", "application.status")

    def evaluate_assertion(  # noqa: PLR0911 - fail-closed states stay explicit.
        self,
        request: AssertionEvaluationRequest,
        /,
    ) -> AssertionResult:
        """Require the configured action's exact HTTP status."""
        assertion = request.assertion
        if not isinstance(assertion, ApplicationStatusAssertion):
            message = "evaluator requires application.status"
            raise TypeError(message)
        action = _find_action(request, assertion.action_ref)
        if action is None:
            return _result(
                assertion,
                evaluated_at=self.evaluated_at,
                status=AssertionStatus.INCONCLUSIVE,
                expected={"http_status": assertion.expected_status},
                observed={"action": "missing"},
                status_reason="Referenced action evidence is missing.",
            )
        observed = action.observed.to_json_value()
        status_code = (
            observed.get("http_status") if isinstance(observed, dict) else None
        )
        if not isinstance(status_code, int) or isinstance(status_code, bool):
            return _result(
                assertion,
                evaluated_at=self.evaluated_at,
                status=AssertionStatus.ERROR,
                expected={"http_status": assertion.expected_status},
                observed={"http_status": None},
                evidence_ids=(f"action.{action.action_id}",),
                status_reason="Action execution did not establish an HTTP status.",
            )
        if not _HTTP_STATUS_MIN <= status_code <= _HTTP_STATUS_MAX:
            return _result(
                assertion,
                evaluated_at=self.evaluated_at,
                status=AssertionStatus.ERROR,
                expected={"http_status": assertion.expected_status},
                observed={"http_status": None},
                evidence_ids=(f"action.{action.action_id}",),
                status_reason="Action evidence contains an invalid HTTP status.",
            )
        if status_code != assertion.expected_status:
            return _result(
                assertion,
                evaluated_at=self.evaluated_at,
                status=AssertionStatus.FAIL,
                expected={"http_status": assertion.expected_status},
                observed={"http_status": status_code},
                evidence_ids=(f"action.{action.action_id}",),
            )
        if action.outcome is ActionOutcome.ERROR:
            return _result(
                assertion,
                evaluated_at=self.evaluated_at,
                status=AssertionStatus.ERROR,
                expected={"http_status": assertion.expected_status},
                observed={"http_status": status_code},
                evidence_ids=(f"action.{action.action_id}",),
                status_reason=(
                    "The expected status was observed during a failed action."
                ),
            )
        freshness_issue = _action_freshness_issue(
            action,
            evaluated_at=self.evaluated_at,
            max_age=self.max_age,
            clock_skew_tolerance=self.clock_skew_tolerance,
        )
        if freshness_issue is not None:
            return _result(
                assertion,
                evaluated_at=self.evaluated_at,
                status=AssertionStatus.INCONCLUSIVE,
                expected={"http_status": assertion.expected_status},
                observed={"action": freshness_issue},
                evidence_ids=(f"action.{action.action_id}",),
                status_reason="Action evidence is stale or future-dated.",
            )
        return _result(
            assertion,
            evaluated_at=self.evaluated_at,
            status=AssertionStatus.PASS,
            expected={"http_status": assertion.expected_status},
            observed={"http_status": status_code},
            evidence_ids=(f"action.{action.action_id}",),
        )


@final
@dataclass(frozen=True, slots=True)
class TelemetryCanaryAbsentEvaluator:
    """Evaluate ``telemetry.canary-absent`` without retaining the canary."""

    evaluated_at: datetime
    clock_skew_tolerance: timedelta = _DEFAULT_CLOCK_SKEW_TOLERANCE

    @property
    def metadata(self) -> PluginMetadata:
        """Declare the exact evaluator capability."""
        return _metadata(
            "telemetry-canary-absent-evaluator",
            "telemetry.canary-absent",
        )

    def evaluate_assertion(
        self,
        request: AssertionEvaluationRequest,
        /,
    ) -> AssertionResult:
        """Pass only when fresh normalized telemetry explicitly reports absence."""
        assertion = request.assertion
        if not isinstance(assertion, TelemetryCanaryAbsentAssertion):
            message = "evaluator requires telemetry.canary-absent"
            raise TypeError(message)
        _, observation, incomplete = _probe_observation(
            request,
            assertion.probe_ref,
            ObservationKind.TELEMETRY_CANARY.value,
            evaluated_at=self.evaluated_at,
            clock_skew_tolerance=self.clock_skew_tolerance,
        )
        if incomplete is not None:
            return _result(
                assertion,
                evaluated_at=self.evaluated_at,
                status=AssertionStatus.INCONCLUSIVE,
                expected={"canary_present": False},
                observed={"telemetry": incomplete},
                evidence_ids=_observation_ids(observation),
                status_reason="Telemetry evidence is missing, stale, or ambiguous.",
            )
        value = cast("Observation", observation).observed.to_json_value()
        present = value.get("present") if isinstance(value, dict) else None
        records_considered = (
            value.get("records_considered") if isinstance(value, dict) else None
        )
        if (
            not isinstance(present, bool)
            or not isinstance(records_considered, int)
            or isinstance(records_considered, bool)
            or records_considered < 0
        ):
            return _result(
                assertion,
                evaluated_at=self.evaluated_at,
                status=AssertionStatus.ERROR,
                expected={"canary_present": False},
                observed={"canary_present": None},
                evidence_ids=_observation_ids(observation),
                status_reason="Canary observation has an invalid normalized shape.",
            )
        if records_considered == 0:
            return _result(
                assertion,
                evaluated_at=self.evaluated_at,
                status=AssertionStatus.INCONCLUSIVE,
                expected={"canary_present": False},
                observed={
                    "canary_present": present,
                    "records_considered": records_considered,
                },
                evidence_ids=_observation_ids(observation),
                status_reason="No correlated telemetry record was available.",
            )
        return _result(
            assertion,
            evaluated_at=self.evaluated_at,
            status=AssertionStatus.FAIL if present else AssertionStatus.PASS,
            expected={"canary_present": False},
            observed={"canary_present": present},
            evidence_ids=_observation_ids(observation),
        )


@final
@dataclass(frozen=True, slots=True)
class AuditEventPresentEvaluator:
    """Evaluate ``audit.event-present`` for one action correlation."""

    evaluated_at: datetime
    clock_skew_tolerance: timedelta = _DEFAULT_CLOCK_SKEW_TOLERANCE
    action_max_age: timedelta = _DEFAULT_ACTION_MAX_AGE

    @property
    def metadata(self) -> PluginMetadata:
        """Declare the exact evaluator capability."""
        return _metadata("audit-event-present-evaluator", "audit.event-present")

    def evaluate_assertion(
        self,
        request: AssertionEvaluationRequest,
        /,
    ) -> AssertionResult:
        """Require a fresh named audit event matching the action correlation."""
        assertion = request.assertion
        if not isinstance(assertion, AuditEventPresentAssertion):
            message = "evaluator requires audit.event-present"
            raise TypeError(message)
        action = _find_action(request, assertion.action_ref)
        _, observation, incomplete = _probe_observation(
            request,
            assertion.probe_ref,
            ObservationKind.AUDIT_EVENT.value,
            evaluated_at=self.evaluated_at,
            clock_skew_tolerance=self.clock_skew_tolerance,
        )
        if action is None:
            return _result(
                assertion,
                evaluated_at=self.evaluated_at,
                status=AssertionStatus.INCONCLUSIVE,
                expected={"event_name": assertion.event_name, "present": True},
                observed={"audit": "action_missing"},
                evidence_ids=_observation_ids(observation),
                status_reason="Action or fresh audit evidence is unavailable.",
            )
        action_issue = _audit_action_issue(
            action,
            evaluated_at=self.evaluated_at,
            max_age=self.action_max_age,
            clock_skew_tolerance=self.clock_skew_tolerance,
        )
        if action_issue is not None:
            status, reason = action_issue
            return _result(
                assertion,
                evaluated_at=self.evaluated_at,
                status=status,
                expected={"event_name": assertion.event_name, "present": True},
                observed={"action": reason},
                evidence_ids=_audit_evidence_ids(action, observation),
                status_reason="Action evidence is unusable for audit correlation.",
            )
        if incomplete is not None:
            return _result(
                assertion,
                evaluated_at=self.evaluated_at,
                status=AssertionStatus.INCONCLUSIVE,
                expected={"event_name": assertion.event_name, "present": True},
                observed={"audit": incomplete},
                evidence_ids=_audit_evidence_ids(action, observation),
                status_reason="Fresh audit evidence is unavailable.",
            )
        events = _audit_events(observation)
        if events is None:
            return _invalid_audit_result(
                assertion,
                evaluated_at=self.evaluated_at,
                evidence_ids=_audit_evidence_ids(action, observation),
            )
        matching = [
            event
            for event in events
            if event.get("event_name") == assertion.event_name
            and event.get("correlation_id") in action.correlation_ids
        ]
        return _result(
            assertion,
            evaluated_at=self.evaluated_at,
            status=AssertionStatus.PASS if matching else AssertionStatus.FAIL,
            expected={"event_name": assertion.event_name, "present": True},
            observed={"matching_events": len(matching)},
            evidence_ids=_audit_evidence_ids(action, observation),
        )


@final
@dataclass(frozen=True, slots=True)
class AuditPrincipalCorrelatedEvaluator:
    """Evaluate ``audit.principal-correlated`` using pseudonymous principals."""

    evaluated_at: datetime
    clock_skew_tolerance: timedelta = _DEFAULT_CLOCK_SKEW_TOLERANCE
    action_max_age: timedelta = _DEFAULT_ACTION_MAX_AGE

    @property
    def metadata(self) -> PluginMetadata:
        """Declare the exact evaluator capability."""
        return _metadata(
            "audit-principal-correlated-evaluator",
            "audit.principal-correlated",
        )

    def evaluate_assertion(
        self,
        request: AssertionEvaluationRequest,
        /,
    ) -> AssertionResult:
        """Compare action and audit pseudonyms only after correlation."""
        assertion = request.assertion
        if not isinstance(assertion, AuditPrincipalCorrelatedAssertion):
            message = "evaluator requires audit.principal-correlated"
            raise TypeError(message)
        action = _find_action(request, assertion.action_ref)
        _, observation, incomplete = _probe_observation(
            request,
            assertion.probe_ref,
            ObservationKind.AUDIT_EVENT.value,
            evaluated_at=self.evaluated_at,
            clock_skew_tolerance=self.clock_skew_tolerance,
        )
        if action is None:
            return _result(
                assertion,
                evaluated_at=self.evaluated_at,
                status=AssertionStatus.INCONCLUSIVE,
                expected={"principal_correlated": True},
                observed={"audit": "action_missing"},
                evidence_ids=_observation_ids(observation),
                status_reason="Action or fresh audit evidence is unavailable.",
            )
        action_issue = _audit_action_issue(
            action,
            evaluated_at=self.evaluated_at,
            max_age=self.action_max_age,
            clock_skew_tolerance=self.clock_skew_tolerance,
        )
        if action_issue is not None:
            status, reason = action_issue
            return _result(
                assertion,
                evaluated_at=self.evaluated_at,
                status=status,
                expected={"principal_correlated": True},
                observed={"action": reason},
                evidence_ids=_audit_evidence_ids(action, observation),
                status_reason="Action evidence is unusable for audit correlation.",
            )
        if incomplete is not None:
            return _result(
                assertion,
                evaluated_at=self.evaluated_at,
                status=AssertionStatus.INCONCLUSIVE,
                expected={"principal_correlated": True},
                observed={"audit": incomplete},
                evidence_ids=_audit_evidence_ids(action, observation),
                status_reason="Fresh audit evidence is unavailable.",
            )
        action_value = action.observed.to_json_value()
        expected_principal = (
            action_value.get("principal_pseudonym")
            if isinstance(action_value, dict)
            else None
        )
        events = _audit_events(observation)
        if not isinstance(expected_principal, str) or events is None:
            return _invalid_audit_result(
                assertion,
                evaluated_at=self.evaluated_at,
                evidence_ids=_audit_evidence_ids(action, observation),
            )
        correlated = [
            event
            for event in events
            if event.get("correlation_id") in action.correlation_ids
        ]
        if not correlated:
            return _result(
                assertion,
                evaluated_at=self.evaluated_at,
                status=AssertionStatus.INCONCLUSIVE,
                expected={"principal_correlated": True},
                observed={"correlated_events": 0},
                evidence_ids=_audit_evidence_ids(action, observation),
                status_reason="No audit event was available for principal correlation.",
            )
        matches = [
            event.get("principal_pseudonym") == expected_principal
            for event in correlated
        ]
        return _result(
            assertion,
            evaluated_at=self.evaluated_at,
            status=AssertionStatus.PASS if all(matches) else AssertionStatus.FAIL,
            expected={"principal_correlated": True},
            observed={
                "correlated_events": len(correlated),
                "principal_correlated": all(matches),
            },
            evidence_ids=_audit_evidence_ids(action, observation),
        )


def _metadata(name: str, capability: str) -> PluginMetadata:
    return PluginMetadata(
        name=name,
        api_version=PLUGIN_API_VERSION,
        capabilities=(capability,),
    )


def _find_action(
    request: AssertionEvaluationRequest,
    action_ref: str,
) -> ActionExecutionResult | None:
    matching = tuple(
        result for result in request.action_results if result.action_id == action_ref
    )
    return matching[0] if len(matching) == 1 else None


def _probe_observation(  # noqa: PLR0911 - fail-closed states stay explicit.
    request: AssertionEvaluationRequest,
    probe_ref: str,
    kind: str,
    *,
    evaluated_at: datetime,
    clock_skew_tolerance: timedelta,
) -> tuple[ProbeResult | None, Observation | None, str | None]:
    probes = tuple(
        result for result in request.probe_results if result.probe_id == probe_ref
    )
    if len(probes) != 1:
        return None, None, "probe_missing_or_ambiguous"
    probe = probes[0]
    observations = tuple(item for item in probe.observations if item.kind == kind)
    observation = observations[0] if len(observations) == 1 else None
    source_time = probe.freshness.source_time
    if probe.freshness.collected_at > evaluated_at + clock_skew_tolerance:
        return probe, observation, "future_collection_time"
    if source_time is not None and source_time > evaluated_at + clock_skew_tolerance:
        return probe, observation, "future_source_time"
    if source_time is not None and (
        source_time > probe.freshness.collected_at + clock_skew_tolerance
    ):
        return probe, observation, "inconsistent_source_time"
    if evaluated_at > probe.freshness.freshness_limit:
        return probe, observation, "stale"
    if observation is None:
        return probe, None, "observation_missing_or_ambiguous"
    return probe, observation, None


def _action_freshness_issue(
    action: ActionExecutionResult,
    *,
    evaluated_at: datetime,
    max_age: timedelta,
    clock_skew_tolerance: timedelta,
) -> str | None:
    if evaluated_at > action.completed_at + max_age:
        return "stale"
    if action.completed_at > evaluated_at + clock_skew_tolerance:
        return "future_action_time"
    return None


def _audit_action_issue(
    action: ActionExecutionResult,
    *,
    evaluated_at: datetime,
    max_age: timedelta,
    clock_skew_tolerance: timedelta,
) -> tuple[AssertionStatus, str] | None:
    if action.outcome is ActionOutcome.ERROR:
        return AssertionStatus.ERROR, "execution_error"
    freshness_issue = _action_freshness_issue(
        action,
        evaluated_at=evaluated_at,
        max_age=max_age,
        clock_skew_tolerance=clock_skew_tolerance,
    )
    if freshness_issue is not None:
        return AssertionStatus.INCONCLUSIVE, freshness_issue
    if not action.correlation_ids:
        return AssertionStatus.INCONCLUSIVE, "correlation_missing"
    return None


def _audit_events(observation: Observation | None) -> list[dict[str, JsonValue]] | None:
    if observation is None:
        return None
    value = observation.observed.to_json_value()
    events = value.get("events") if isinstance(value, dict) else None
    required_fields = {"correlation_id", "event_name", "principal_pseudonym"}
    if not isinstance(events, list):
        return None
    normalized: list[dict[str, JsonValue]] = []
    for item in events:
        if not isinstance(item, dict) or set(item) != required_fields:
            return None
        if not all(isinstance(item[field], str) for field in required_fields):
            return None
        normalized.append(item)
    return normalized


def _observation_ids(observation: Observation | None) -> tuple[str, ...]:
    return (observation.observation_id,) if observation is not None else ()


def _audit_evidence_ids(
    action: ActionExecutionResult,
    observation: Observation | None,
) -> tuple[str, ...]:
    return (f"action.{action.action_id}", *_observation_ids(observation))


def _invalid_audit_result(
    assertion: LocalAssertion,
    *,
    evaluated_at: datetime,
    evidence_ids: tuple[str, ...],
) -> AssertionResult:
    return _result(
        assertion,
        evaluated_at=evaluated_at,
        status=AssertionStatus.ERROR,
        expected={"valid_audit_observation": True},
        observed={"valid_audit_observation": False},
        evidence_ids=evidence_ids,
        status_reason="Audit observation has an invalid normalized shape.",
    )


def _result(  # noqa: PLR0913 - mirrors the immutable result contract.
    assertion: LocalAssertion,
    *,
    evaluated_at: datetime,
    status: AssertionStatus,
    expected: JsonValue,
    observed: JsonValue,
    evidence_ids: tuple[str, ...] = (),
    status_reason: str | None = None,
) -> AssertionResult:
    limitations = (
        *(item.description for item in assertion.limitations),
        "Local synthetic evidence does not establish production control operation.",
    )
    return AssertionResult(
        assertion_id=assertion.id,
        assertion_type=AssertionType.EVIDENCE_BACKED,
        status=status,
        expected=expected,
        observed=RedactedValue(observed),
        evidence_ids=evidence_ids,
        limitations=limitations,
        evaluator_version=_EVALUATOR_VERSION,
        evaluation_started_at=evaluated_at,
        evaluation_completed_at=evaluated_at,
        status_reason=status_reason,
    )
