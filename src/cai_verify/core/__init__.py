"""Core result semantics for Cloud AI Control Verifier."""

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

__all__ = [
    "ASSERTION_RESULT_SCHEMA_VERSION",
    "AssertionResult",
    "AssertionStatus",
    "AssertionType",
    "CliExitCode",
    "RedactedValue",
    "aggregate_results",
    "aggregate_statuses",
    "exit_code_for_results",
    "exit_code_for_status",
]
