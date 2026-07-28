"""Tests for the fixed reciprocal AWS evidence serializers."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from cai_verify.aws._reciprocal_evidence import (
    _EXPECTED_ACTION_RESULT_LIMITATIONS,
    _EXPECTED_RETRIEVAL_OBSERVATION_LIMITATIONS,
    InvalidAwsReciprocalEvidenceError,
    serialize_aws_reciprocal_run,
    serialize_aws_retrieval_action,
    serialize_aws_retrieval_probe,
)
from cai_verify.core import AssertionStatus, RedactedValue
from cai_verify.plugins import (
    ActionExecutionResult,
    ActionOutcome,
    EvidenceFreshness,
    EvidenceSource,
    Observation,
    ProbeResult,
)

_NOW = datetime(2026, 7, 28, 12, tzinfo=UTC)
_ACTION_ID = "retrieve-as-requester-a"
_PROBE_ID = "requester-a-retrieval"
_CORRELATION = "application-correlation-secret"
_AWS_REQUEST_ID = "aws-request-id-secret"
_MAX_AGE = timedelta(minutes=3)
_CLOCK_SKEW = timedelta(seconds=30)


def _complete_retrieval() -> dict[str, Any]:
    return {
        "accepted_correlated_records": 1,
        "ambiguous": False,
        "baseline_canary_observed": True,
        "boundary_canary_observed": False,
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
        "retrieved_item_count": 1,
        "stale": False,
        "undeclared_synthetic_marker_observed": False,
    }


def _action(
    *,
    action_id: str = _ACTION_ID,
    outcome: ActionOutcome = ActionOutcome.SUCCEEDED,
    observed: dict[str, Any] | None = None,
    correlation_ids: tuple[str, ...] = (_CORRELATION,),
    limitations: tuple[str, ...] = _EXPECTED_ACTION_RESULT_LIMITATIONS,
) -> ActionExecutionResult:
    return ActionExecutionResult(
        action_id=action_id,
        outcome=outcome,
        started_at=_NOW,
        completed_at=_NOW + timedelta(seconds=1),
        observed=RedactedValue(
            observed
            or {
                "correlation_state": "MATCHED",
                "http_status": 200,
                "response_too_large": False,
                "service": "execute-api",
                "signing_region": "eu-west-2",
            }
        ),
        correlation_ids=correlation_ids,
        limitations=limitations,
        aws_request_ids=(_AWS_REQUEST_ID,),
    )


def _probe(  # noqa: PLR0913 - malformed contract axes stay explicit in tests.
    *,
    probe_id: str = _PROBE_ID,
    source_name: str = "aws-cloudwatch-logs",
    source_version: str = "1.2.0",
    observations: tuple[Observation, ...] | None = None,
    observed: dict[str, Any] | None = None,
    observation_id: str = f"{_PROBE_ID}.retrieval-canary",
    limitations: tuple[str, ...] = _EXPECTED_RETRIEVAL_OBSERVATION_LIMITATIONS,
    source_time: datetime | None = _NOW,
    max_age: timedelta = _MAX_AGE,
) -> ProbeResult:
    resolved = observations
    if resolved is None:
        resolved = (
            Observation(
                observation_id=observation_id,
                kind="retrievalCanary",
                observed=RedactedValue(observed or _complete_retrieval()),
                limitations=limitations,
            ),
        )
    return ProbeResult(
        probe_id=probe_id,
        source=EvidenceSource(name=source_name, version=source_version),
        freshness=EvidenceFreshness(
            collected_at=_NOW + timedelta(seconds=2),
            source_time=source_time,
            max_age=max_age,
        ),
        observations=resolved,
    )


def test_fixed_serializers_emit_only_allowlisted_redacted_fields() -> None:
    """Transient correlations and AWS identifiers never cross serialization."""
    action = serialize_aws_retrieval_action(
        _action(),
        expected_action_id=_ACTION_ID,
        expected_region="eu-west-2",
    )
    probe = serialize_aws_retrieval_probe(
        _probe(),
        expected_probe_id=_PROBE_ID,
        expected_max_age=_MAX_AGE,
        clock_skew_tolerance=_CLOCK_SKEW,
    )

    action_value = json.loads(action)
    probe_value = json.loads(probe)
    assert set(action_value) == {
        "action_id",
        "application_correlation_established",
        "artifact_kind",
        "completed_at",
        "correlation_state",
        "error_category",
        "evidence_id",
        "http_status",
        "limitations",
        "outcome",
        "response_too_large",
        "schema_version",
        "service",
        "signing_region",
        "started_at",
    }
    assert set(probe_value) == {
        "adapter_name",
        "adapter_version",
        "artifact_kind",
        "collected_at",
        "limitations",
        "maximum_age_seconds",
        "observation",
        "probe_id",
        "schema_version",
        "source_time",
    }
    combined = action + probe
    assert _CORRELATION.encode() not in combined
    assert _AWS_REQUEST_ID.encode() not in combined


@pytest.mark.parametrize(
    "result",
    [
        _action(action_id="other-action"),
        _action(
            observed={
                "correlation_state": "MATCHED",
                "http_status": 200,
                "response_too_large": False,
                "service": "execute-api",
                "signing_region": "eu-west-2",
                "unknown": "secret-arbitrary-field",
            }
        ),
        _action(
            observed={
                "correlation_state": "MATCHED",
                "http_status": 200,
                "response_too_large": False,
                "service": "bedrock-runtime",
                "signing_region": "eu-west-2",
            }
        ),
        _action(limitations=("arbitrary adapter limitation secret",)),
    ],
    ids=(
        "mismatched-id",
        "unknown-field",
        "wrong-service",
        "arbitrary-limitations",
    ),
)
def test_action_serializer_rejects_non_builtin_shapes(
    result: ActionExecutionResult,
) -> None:
    """Unknown fields, provenance, IDs, and strings fail closed."""
    with pytest.raises(InvalidAwsReciprocalEvidenceError) as caught:
        serialize_aws_retrieval_action(
            result,
            expected_action_id=_ACTION_ID,
            expected_region="eu-west-2",
        )

    assert str(caught.value) == "invalid normalized AWS reciprocal retrieval evidence"
    assert "secret" not in repr(caught.value)


@pytest.mark.parametrize(
    "result",
    [
        _action(
            observed={
                "correlation_state": "NOT_CHECKED",
                "http_status": 200,
                "response_too_large": False,
                "service": "execute-api",
                "signing_region": "eu-west-2",
            },
            correlation_ids=(),
        ),
        _action(
            outcome=ActionOutcome.ERROR,
            observed={
                "correlation_state": "MATCHED",
                "error": "transport_error",
                "http_status": 200,
                "response_too_large": False,
                "service": "execute-api",
                "signing_region": "eu-west-2",
            },
        ),
        _action(
            outcome=ActionOutcome.ERROR,
            observed={
                "correlation_state": "MATCHED",
                "error": "invalid_correlation",
                "http_status": 200,
                "response_too_large": False,
                "service": "execute-api",
                "signing_region": "eu-west-2",
            },
        ),
        _action(
            outcome=ActionOutcome.ERROR,
            observed={
                "correlation_state": "NOT_RETURNED",
                "error": "response_too_large",
                "http_status": 200,
                "response_too_large": False,
                "service": "execute-api",
                "signing_region": "eu-west-2",
            },
            correlation_ids=(),
        ),
    ],
    ids=(
        "success-without-response-correlation-state",
        "pre-response-error-with-http-response",
        "invalid-correlation-with-matched-correlation",
        "response-too-large-without-size-state",
    ),
)
def test_action_serializer_rejects_contradictory_builtin_shapes(
    result: ActionExecutionResult,
) -> None:
    """Every action outcome/error/state combination is exact and bidirectional."""
    with pytest.raises(InvalidAwsReciprocalEvidenceError):
        serialize_aws_retrieval_action(
            result,
            expected_action_id=_ACTION_ID,
            expected_region="eu-west-2",
        )


def test_action_serializer_accepts_too_large_mismatched_response_shape() -> None:
    """Response-size precedence permits the adapter's mismatched response state."""
    content = serialize_aws_retrieval_action(
        _action(
            outcome=ActionOutcome.ERROR,
            observed={
                "correlation_state": "MISMATCHED",
                "error": "response_too_large",
                "http_status": 200,
                "response_too_large": True,
                "service": "execute-api",
                "signing_region": "eu-west-2",
            },
            correlation_ids=(),
        ),
        expected_action_id=_ACTION_ID,
        expected_region="eu-west-2",
    )

    assert json.loads(content)["error_category"] == "response_too_large"


def _extra_observations() -> tuple[Observation, Observation]:
    first = _probe().observations[0]
    return (
        first,
        Observation(
            observation_id="requester-a-retrieval.extra",
            kind="retrievalCanary",
            observed=RedactedValue(_complete_retrieval()),
            limitations=_EXPECTED_RETRIEVAL_OBSERVATION_LIMITATIONS,
        ),
    )


@pytest.mark.parametrize(
    "result",
    [
        _probe(probe_id="other-probe"),
        _probe(source_name="other-source"),
        _probe(source_version="9.9.9"),
        _probe(observations=_extra_observations()),
        _probe(observation_id="requester-a-retrieval.wrong"),
        _probe(limitations=("arbitrary adapter limitation secret",)),
        _probe(observed={**_complete_retrieval(), "unknown": "secret"}),
        _probe(
            observed={
                **_complete_retrieval(),
                "accepted_correlated_records": 0,
            }
        ),
        _probe(
            observed={
                **{
                    key: value
                    for key, value in _complete_retrieval().items()
                    if key
                    not in {
                        "baseline_canary_observed",
                        "boundary_canary_observed",
                        "complete_context_scan_succeeded",
                        "pre_generation_phase_matched",
                        "retrieval_succeeded",
                        "retrieved_item_count",
                    }
                },
                "accepted_correlated_records": 0,
                "baseline_canary_observed": None,
                "boundary_canary_observed": None,
                "complete_context_scan_succeeded": None,
                "complete_correlated_retrieval_record_found": False,
                "error_category": None,
                "evidence_complete": False,
                "pre_generation_phase_matched": None,
                "retrieval_succeeded": None,
                "retrieved_item_count": None,
                "undeclared_synthetic_marker_observed": None,
            },
            source_time=None,
        ),
    ],
    ids=(
        "mismatched-probe-id",
        "wrong-source",
        "wrong-version",
        "extra-observation",
        "mismatched-observation-id",
        "arbitrary-limitations",
        "unknown-field",
        "contradictory-complete-shape",
        "incomplete-without-error",
    ),
)
def test_probe_serializer_rejects_nonbuiltin_or_contradictory_shapes(
    result: ProbeResult,
) -> None:
    """Only the exact normalized retrieval contract is persistable."""
    with pytest.raises(InvalidAwsReciprocalEvidenceError) as caught:
        serialize_aws_retrieval_probe(
            result,
            expected_probe_id=_PROBE_ID,
            expected_max_age=_MAX_AGE,
            clock_skew_tolerance=_CLOCK_SKEW,
        )

    assert str(caught.value) == "invalid normalized AWS reciprocal retrieval evidence"
    assert "secret" not in repr(caught.value)


def _incomplete_retrieval(
    error_category: str,
    **states: bool,
) -> dict[str, Any]:
    value = {
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
    value.update(states)
    return value


@pytest.mark.parametrize(
    "result",
    [
        _probe(
            observed=_incomplete_retrieval("access_denied"),
            source_time=None,
        ),
        _probe(
            observed=_incomplete_retrieval("future_action"),
            source_time=None,
        ),
        _probe(
            observed=_incomplete_retrieval("stale_event"),
            source_time=None,
        ),
        _probe(max_age=timedelta(minutes=4)),
        _probe(source_time=_NOW - timedelta(minutes=10)),
        _probe(source_time=_NOW + timedelta(minutes=10)),
    ],
    ids=(
        "access-denied-without-partial",
        "future-error-without-future-flag",
        "stale-error-without-stale-flag",
        "wrong-effective-max-age",
        "complete-source-older-than-max-age",
        "complete-source-beyond-clock-skew",
    ),
)
def test_probe_serializer_rejects_failure_flag_and_freshness_contradictions(
    result: ProbeResult,
) -> None:
    """Failure flags and source freshness stay bound to adapter provenance."""
    with pytest.raises(InvalidAwsReciprocalEvidenceError):
        serialize_aws_retrieval_probe(
            result,
            expected_probe_id=_PROBE_ID,
            expected_max_age=_MAX_AGE,
            clock_skew_tolerance=_CLOCK_SKEW,
        )


def test_run_serializer_uses_only_a_target_pseudonym_and_sorted_ids() -> None:
    """Raw target labels and any AWS boundary values remain absent."""
    content = serialize_aws_reciprocal_run(
        run_id="synthetic-run",
        scenario_id="reciprocal-requester-retrieval",
        action_ids=("z-action", "a-action"),
        probe_ids=("z-probe", "a-probe"),
        assertion_ids=("z-assertion", "a-assertion"),
        aggregate_status=AssertionStatus.PASS,
        target_id="guessable-target-label",
        target_environment="sandbox",
        target_region="eu-west-2",
    )
    value = json.loads(content)

    assert value["action_ids"] == ["a-action", "z-action"]
    assert value["probe_ids"] == ["a-probe", "z-probe"]
    assert value["assertion_ids"] == ["a-assertion", "z-assertion"]
    assert b"guessable-target-label" not in content
    assert b"111122223333" not in content
    assert b"arn:aws:" not in content
