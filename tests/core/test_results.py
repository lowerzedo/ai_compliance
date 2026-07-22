"""Tests for core assertion-result semantics."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from itertools import combinations, permutations

import pytest

from cai_verify.core.results import (
    ASSERTION_RESULT_SCHEMA_VERSION,
    AssertionResult,
    AssertionStatus,
    AssertionType,
    CliExitCode,
    RedactedValue,
    aggregate_results,
    aggregate_statuses,
    exit_code_for_results,
    exit_code_for_status,
)

STARTED_AT = datetime(2026, 7, 22, 9, 10, 11, 123456, tzinfo=UTC)
COMPLETED_AT = datetime(2026, 7, 22, 9, 10, 12, 654321, tzinfo=UTC)
EXPECTED_PRECEDENCE = (
    AssertionStatus.FAIL,
    AssertionStatus.ERROR,
    AssertionStatus.INCONCLUSIVE,
    AssertionStatus.PASS,
    AssertionStatus.SKIPPED,
)


def make_result(  # noqa: PLR0913
    status: AssertionStatus,
    *,
    assertion_id: str = "assertion-1",
    assertion_type: AssertionType = AssertionType.EVIDENCE_BACKED,
    evidence_ids: tuple[str, ...] | None = None,
    limitations: tuple[str, ...] = ("Synthetic observation only.",),
    expected: object = True,
    observed: object = True,
    status_reason: str | None = None,
    started_at: datetime = STARTED_AT,
    completed_at: datetime = COMPLETED_AT,
) -> AssertionResult:
    """Build a valid synthetic result for a requested status."""
    if evidence_ids is None:
        evidence_ids = ("evidence-1",) if status is AssertionStatus.PASS else ()
    if status is AssertionStatus.SKIPPED and status_reason is None:
        status_reason = "Assertion is not applicable to this synthetic target."
    return AssertionResult(
        assertion_id=assertion_id,
        assertion_type=assertion_type,
        status=status,
        evidence_ids=evidence_ids,
        limitations=limitations,
        evaluator_version="1.2.3",
        evaluation_started_at=started_at,
        evaluation_completed_at=completed_at,
        expected=expected,  # type: ignore[arg-type]
        observed=RedactedValue(observed),  # type: ignore[arg-type]
        status_reason=status_reason,
    )


@pytest.mark.parametrize("status", list(AssertionStatus))
def test_every_individual_status_round_trips(status: AssertionStatus) -> None:
    """Every defined status is accepted and serialized without reinterpretation."""
    result = make_result(status)

    assert result.status is status
    assert result.to_dict()["status"] == status.value
    assert aggregate_results([result]) is status


def test_all_nonempty_status_combinations_follow_documented_precedence() -> None:
    """Every subset and input ordering uses the same fixed precedence."""
    statuses = tuple(AssertionStatus)
    for length in range(1, len(statuses) + 1):
        for subset in combinations(statuses, length):
            expected = next(
                status for status in EXPECTED_PRECEDENCE if status in subset
            )
            for ordering in permutations(subset):
                assert aggregate_statuses(ordering) is expected


def test_fail_takes_precedence_over_error() -> None:
    """An execution error cannot hide an established contradiction."""
    statuses = [AssertionStatus.ERROR, AssertionStatus.FAIL]

    assert aggregate_statuses(statuses) is AssertionStatus.FAIL
    assert exit_code_for_status(aggregate_statuses(statuses)) == 1


@pytest.mark.parametrize(
    "other_status",
    [AssertionStatus.PASS, AssertionStatus.SKIPPED],
)
def test_inconclusive_prevents_success(other_status: AssertionStatus) -> None:
    """Missing or ambiguous evidence remains visible beside non-failing results."""
    aggregate = aggregate_statuses([other_status, AssertionStatus.INCONCLUSIVE])

    assert aggregate is AssertionStatus.INCONCLUSIVE
    assert exit_code_for_status(aggregate) is CliExitCode.INCONCLUSIVE


def test_empty_result_sets_are_inconclusive() -> None:
    """Running no assertions cannot be reported as a pass."""
    assert aggregate_statuses([]) is AssertionStatus.INCONCLUSIVE
    assert aggregate_results([]) is AssertionStatus.INCONCLUSIVE
    assert exit_code_for_results([]) is CliExitCode.INCONCLUSIVE


@pytest.mark.parametrize(
    ("status", "expected_exit_code"),
    [
        (AssertionStatus.PASS, CliExitCode.SUCCESS),
        (AssertionStatus.FAIL, CliExitCode.ASSERTION_FAILED),
        (AssertionStatus.ERROR, CliExitCode.EXECUTION_ERROR),
        (AssertionStatus.INCONCLUSIVE, CliExitCode.INCONCLUSIVE),
        (AssertionStatus.SKIPPED, CliExitCode.NOTHING_EVALUATED),
    ],
)
def test_every_status_has_a_stable_exit_code(
    status: AssertionStatus,
    expected_exit_code: CliExitCode,
) -> None:
    """CLI callers receive the documented status-specific process code."""
    assert exit_code_for_status(status) is expected_exit_code


def test_serialization_is_deterministic() -> None:
    """Ordering and equivalent timestamp offsets do not affect exact bytes."""
    result_a = make_result(
        AssertionStatus.FAIL,
        evidence_ids=("evidence-z", "evidence-a"),
        limitations=("Second limitation.", "First limitation."),
        expected={"z": [2, 1], "a": {"enabled": True}},
        observed={"z": "[REDACTED]", "a": None},
        status_reason="Observed state contradicted the expected state.",
    )
    result_b = AssertionResult(
        assertion_id="assertion-1",
        status=AssertionStatus.FAIL,
        evidence_ids=("evidence-a", "evidence-z"),
        limitations=("First limitation.", "Second limitation."),
        evaluator_version="1.2.3",
        evaluation_started_at=STARTED_AT.astimezone(timezone(timedelta(hours=-4))),
        evaluation_completed_at=COMPLETED_AT.astimezone(
            timezone(timedelta(hours=5, minutes=30))
        ),
        expected={"a": {"enabled": True}, "z": [2, 1]},
        observed=RedactedValue({"a": None, "z": "[REDACTED]"}),
        status_reason="Observed state contradicted the expected state.",
    )

    assert result_a.to_json_bytes() == result_b.to_json_bytes()
    assert result_a.to_json() == result_a.to_json()
    assert result_a.to_json().startswith('{"assertion_id":"assertion-1"')
    assert result_a.to_dict()["schema_version"] == ASSERTION_RESULT_SCHEMA_VERSION


def test_pass_requires_evidence_by_default() -> None:
    """The evidence-backed default cannot silently produce an unsupported pass."""
    with pytest.raises(ValueError, match="PASS requires evidence_ids"):
        make_result(AssertionStatus.PASS, evidence_ids=())


def test_pure_local_pass_may_explicitly_omit_evidence() -> None:
    """Only the explicit pure-local assertion type has the narrow exemption."""
    result = make_result(
        AssertionStatus.PASS,
        assertion_type=AssertionType.PURE_LOCAL,
        evidence_ids=(),
        expected={"schema_valid": True},
        observed={"schema_valid": True},
    )

    assert result.status is AssertionStatus.PASS
    assert result.evidence_ids == ()
    assert result.assertion_type is AssertionType.PURE_LOCAL


def test_limitations_are_mandatory_for_every_status() -> None:
    """No outcome can omit its assessment boundary."""
    for status in AssertionStatus:
        with pytest.raises(ValueError, match="limitations"):
            make_result(status, limitations=())


def test_skipped_requires_a_reason() -> None:
    """Intentional non-execution is distinguishable from absent results."""
    with pytest.raises(ValueError, match="status_reason"):
        make_result(AssertionStatus.SKIPPED, status_reason="")


def test_timestamps_must_be_ordered_and_timezone_aware() -> None:
    """Evaluation timing cannot be ambiguous or run backwards."""
    with pytest.raises(ValueError, match="UTC offset"):
        make_result(
            AssertionStatus.FAIL,
            started_at=datetime(2026, 7, 22),  # noqa: DTZ001
        )
    with pytest.raises(ValueError, match="cannot precede"):
        make_result(
            AssertionStatus.FAIL,
            started_at=COMPLETED_AT,
            completed_at=STARTED_AT,
        )


def test_observed_value_must_cross_the_redaction_boundary() -> None:
    """Plain observed values cannot be serialized accidentally."""
    with pytest.raises(TypeError, match="RedactedValue"):
        AssertionResult(
            assertion_id="assertion-1",
            status=AssertionStatus.FAIL,
            evidence_ids=(),
            limitations=("Synthetic observation only.",),
            evaluator_version="1.2.3",
            evaluation_started_at=STARTED_AT,
            evaluation_completed_at=COMPLETED_AT,
            expected=True,
            observed=False,  # type: ignore[arg-type]
        )


def test_redacted_value_repr_never_contains_its_payload() -> None:
    """Incidental debug output does not disclose observed result content."""
    value = RedactedValue({"secret-shaped": "[REDACTED]"})

    assert repr(value) == "RedactedValue(<redacted>)"
    assert "secret-shaped" not in repr(value)


def test_assertion_result_cannot_be_subclassed_to_bypass_validation() -> None:
    """Dynamic dispatch cannot suppress PASS evidence validation."""
    with pytest.raises(TypeError, match="AssertionResult cannot be subclassed"):

        class UnvalidatedResult(AssertionResult):  # type: ignore[misc]
            pass


def test_redacted_value_cannot_override_canonical_serialization() -> None:
    """Observed serialization cannot be replaced by an unsafe subclass."""
    with pytest.raises(TypeError, match="RedactedValue cannot be subclassed"):

        class UnsafeObservedValue(RedactedValue):  # type: ignore[misc]
            pass
