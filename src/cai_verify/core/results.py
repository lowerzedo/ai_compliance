"""Deterministic assertion-result and aggregate-status semantics.

The rules in this module are deliberately conservative: absence of results or
an inconclusive assertion can never produce a successful aggregate status.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from typing import cast, final

ASSERTION_RESULT_SCHEMA_VERSION = "1"
_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]


class AssertionStatus(StrEnum):
    """Outcome of one assertion or an aggregate of assertion outcomes."""

    PASS = "PASS"  # noqa: S105 - assertion outcome, not a credential
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


class AssertionType(StrEnum):
    """Evidence policy applied to an assertion.

    ``PURE_LOCAL`` is limited to deterministic checks of in-memory values that
    do not describe a target system and do not depend on collected evidence.
    It is the sole assertion type permitted to pass without an evidence ID.
    """

    EVIDENCE_BACKED = "EVIDENCE_BACKED"
    PURE_LOCAL = "PURE_LOCAL"


class CliExitCode(IntEnum):
    """Stable process exit codes for aggregate assertion outcomes."""

    SUCCESS = 0
    ASSERTION_FAILED = 1
    EXECUTION_ERROR = 2
    INCONCLUSIVE = 3
    NOTHING_EVALUATED = 4


@final
@dataclass(frozen=True, slots=True, init=False)
class RedactedValue:
    """An observed JSON value explicitly marked safe for result output.

    This type is a trust-boundary marker, not a redaction engine. Callers must
    remove secrets and sensitive source content before constructing it. Its
    representation never includes the marked value, which reduces accidental
    disclosure through debugging and exception output.
    """

    _canonical_json: str = field(repr=False)

    def __init_subclass__(cls) -> None:
        """Prevent subclasses from replacing canonical serialization."""
        del cls
        message = "RedactedValue cannot be subclassed"
        raise TypeError(message)

    def __init__(self, value: JsonValue) -> None:
        """Store a detached, canonical copy of an already-redacted value."""
        object.__setattr__(
            self,
            "_canonical_json",
            _canonical_json(value, field_name="observed"),
        )

    def to_json_value(self) -> JsonValue:
        """Return a detached JSON-compatible copy of the redacted value."""
        return cast("JsonValue", json.loads(self._canonical_json))

    def __repr__(self) -> str:
        """Avoid placing even redacted observations into incidental logs."""
        return "RedactedValue(<redacted>)"


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class AssertionResult:
    """One deterministic assertion evaluation.

    Limitations and evaluation timing are mandatory for every status. A
    ``PASS`` additionally requires evidence unless ``assertion_type`` is the
    narrowly scoped ``PURE_LOCAL`` type.
    """

    assertion_id: str
    status: AssertionStatus
    evidence_ids: tuple[str, ...]
    limitations: tuple[str, ...]
    evaluator_version: str
    evaluation_started_at: datetime
    evaluation_completed_at: datetime
    expected: JsonValue
    observed: RedactedValue
    assertion_type: AssertionType = AssertionType.EVIDENCE_BACKED
    status_reason: str | None = None

    def __init_subclass__(cls) -> None:
        """Prevent subclasses from bypassing result validation hooks."""
        del cls
        message = "AssertionResult cannot be subclassed"
        raise TypeError(message)

    def __post_init__(self) -> None:
        """Validate invariants and normalize semantically unordered values."""
        _validate_identifier(self.assertion_id, field_name="assertion_id")
        _validate_enum(self.status, AssertionStatus, field_name="status")
        _validate_enum(
            self.assertion_type,
            AssertionType,
            field_name="assertion_type",
        )
        if type(self.observed) is not RedactedValue:
            message = "observed must be a RedactedValue"
            raise TypeError(message)

        evidence_ids = _validate_string_tuple(
            self.evidence_ids,
            field_name="evidence_ids",
            allow_empty=True,
            identifiers=True,
        )
        limitations = _validate_string_tuple(
            self.limitations,
            field_name="limitations",
            allow_empty=False,
            identifiers=False,
        )
        object.__setattr__(self, "evidence_ids", tuple(sorted(evidence_ids)))
        object.__setattr__(self, "limitations", tuple(sorted(limitations)))

        _validate_nonempty_string(
            self.evaluator_version,
            field_name="evaluator_version",
        )
        started_at = _normalize_timestamp(
            self.evaluation_started_at,
            field_name="evaluation_started_at",
        )
        completed_at = _normalize_timestamp(
            self.evaluation_completed_at,
            field_name="evaluation_completed_at",
        )
        if completed_at < started_at:
            message = "evaluation_completed_at cannot precede evaluation_started_at"
            raise ValueError(message)
        object.__setattr__(self, "evaluation_started_at", started_at)
        object.__setattr__(self, "evaluation_completed_at", completed_at)

        expected_json = _canonical_json(self.expected, field_name="expected")
        object.__setattr__(
            self,
            "expected",
            cast("JsonValue", json.loads(expected_json)),
        )

        if (
            self.status is AssertionStatus.PASS
            and not self.evidence_ids
            and self.assertion_type is not AssertionType.PURE_LOCAL
        ):
            message = "PASS requires evidence_ids unless assertion_type is PURE_LOCAL"
            raise ValueError(message)

        if self.status is AssertionStatus.SKIPPED or self.status_reason is not None:
            _validate_nonempty_string(self.status_reason, field_name="status_reason")

    def to_dict(self) -> dict[str, JsonValue]:
        """Return the versioned, JSON-compatible result representation."""
        return {
            "assertion_id": self.assertion_id,
            "assertion_type": self.assertion_type.value,
            "evaluation_completed_at": _serialize_timestamp(
                self.evaluation_completed_at
            ),
            "evaluation_started_at": _serialize_timestamp(self.evaluation_started_at),
            "evaluator_version": self.evaluator_version,
            "evidence_ids": list(self.evidence_ids),
            "expected": _detached_json_value(self.expected),
            "limitations": list(self.limitations),
            "observed": self.observed.to_json_value(),
            "schema_version": ASSERTION_RESULT_SCHEMA_VERSION,
            "status": self.status.value,
            "status_reason": self.status_reason,
        }

    def to_json(self) -> str:
        """Serialize as canonical, whitespace-free JSON with sorted keys."""
        return json.dumps(
            self.to_dict(),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    def to_json_bytes(self) -> bytes:
        """Serialize to deterministic UTF-8 bytes without a trailing newline."""
        return self.to_json().encode("utf-8")


_AGGREGATION_PRECEDENCE = (
    AssertionStatus.FAIL,
    AssertionStatus.ERROR,
    AssertionStatus.INCONCLUSIVE,
    AssertionStatus.PASS,
    AssertionStatus.SKIPPED,
)


def aggregate_statuses(statuses: Iterable[AssertionStatus]) -> AssertionStatus:
    """Aggregate statuses using fixed conservative precedence.

    Precedence is ``FAIL``, ``ERROR``, ``INCONCLUSIVE``, ``PASS``, then
    ``SKIPPED``. A known contradiction therefore remains the aggregate outcome
    even when another assertion errors. Skips are neutral when another status
    exists. An empty iterable is ``INCONCLUSIVE`` rather than ``PASS``.
    """
    status_set: set[AssertionStatus] = set()
    for status in statuses:
        _validate_enum(status, AssertionStatus, field_name="status")
        status_set.add(status)
    if not status_set:
        return AssertionStatus.INCONCLUSIVE
    return next(status for status in _AGGREGATION_PRECEDENCE if status in status_set)


def aggregate_results(results: Iterable[AssertionResult]) -> AssertionStatus:
    """Aggregate an iterable of assertion results without changing them."""

    def statuses() -> Iterable[AssertionStatus]:
        for result in results:
            if type(result) is not AssertionResult:
                message = "results must contain only AssertionResult values"
                raise TypeError(message)
            yield result.status

    return aggregate_statuses(statuses())


def exit_code_for_status(status: AssertionStatus) -> CliExitCode:
    """Map one aggregate status to its stable CLI exit code."""
    _validate_enum(status, AssertionStatus, field_name="status")
    return {
        AssertionStatus.PASS: CliExitCode.SUCCESS,
        AssertionStatus.FAIL: CliExitCode.ASSERTION_FAILED,
        AssertionStatus.ERROR: CliExitCode.EXECUTION_ERROR,
        AssertionStatus.INCONCLUSIVE: CliExitCode.INCONCLUSIVE,
        AssertionStatus.SKIPPED: CliExitCode.NOTHING_EVALUATED,
    }[status]


def exit_code_for_results(results: Iterable[AssertionResult]) -> CliExitCode:
    """Aggregate results and return the corresponding CLI exit code."""
    return exit_code_for_status(aggregate_results(results))


def _validate_identifier(value: object, *, field_name: str) -> None:
    if not isinstance(value, str) or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        message = f"{field_name} must be 1-256 identifier characters without whitespace"
        raise ValueError(message)


def _validate_nonempty_string(value: object, *, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        message = f"{field_name} must be a non-empty string"
        raise ValueError(message)


def _validate_string_tuple(
    value: object,
    *,
    field_name: str,
    allow_empty: bool,
    identifiers: bool,
) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        message = f"{field_name} must be a tuple of strings"
        raise TypeError(message)
    if not allow_empty and not value:
        message = f"{field_name} must contain at least one value"
        raise ValueError(message)
    if len(value) != len(set(value)):
        message = f"{field_name} must not contain duplicates"
        raise ValueError(message)
    for item in value:
        if identifiers:
            _validate_identifier(item, field_name=field_name)
        else:
            _validate_nonempty_string(item, field_name=field_name)
    return value


def _validate_enum(
    value: object,
    enum_type: type[AssertionStatus | AssertionType],
    *,
    field_name: str,
) -> None:
    if not isinstance(value, enum_type):
        message = f"{field_name} must be a {enum_type.__name__}"
        raise TypeError(message)


def _normalize_timestamp(value: object, *, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        message = f"{field_name} must be a datetime"
        raise TypeError(message)
    if value.tzinfo is None or value.utcoffset() is None:
        message = f"{field_name} must include a UTC offset"
        raise ValueError(message)
    return value.astimezone(UTC)


def _serialize_timestamp(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _canonical_json(value: object, *, field_name: str) -> str:
    _validate_json_value(value, field_name=field_name)
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _validate_json_value(value: object, *, field_name: str) -> None:
    if value is None or isinstance(value, str | bool | int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            message = f"{field_name} must not contain non-finite numbers"
            raise ValueError(message)
        return
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        _validate_json_array(value, field_name=field_name)
        return
    if isinstance(value, Mapping):
        _validate_json_object(value, field_name=field_name)
        return
    message = f"{field_name} must contain only JSON-compatible values"
    raise TypeError(message)


def _validate_json_array(value: Sequence[object], *, field_name: str) -> None:
    if not isinstance(value, list):
        message = f"{field_name} arrays must use list values"
        raise TypeError(message)
    for item in value:
        _validate_json_value(item, field_name=field_name)


def _validate_json_object(value: Mapping[object, object], *, field_name: str) -> None:
    if not isinstance(value, dict):
        message = f"{field_name} objects must use dict values"
        raise TypeError(message)
    for key, item in value.items():
        if not isinstance(key, str):
            message = f"{field_name} object keys must be strings"
            raise TypeError(message)
        _validate_json_value(item, field_name=field_name)


def _detached_json_value(value: JsonValue) -> JsonValue:
    return cast(
        "JsonValue",
        json.loads(_canonical_json(value, field_name="expected")),
    )
