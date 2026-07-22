"""Orchestrate the deterministic loopback-only verification suite."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, final

from cai_verify.adapters import HttpActionAdapter
from cai_verify.assertions import (
    ApplicationStatusEvaluator,
    AuditEventPresentEvaluator,
    AuditPrincipalCorrelatedEvaluator,
    TelemetryCanaryAbsentEvaluator,
)
from cai_verify.config import (
    ApplicationStatusAssertion,
    AuditEventPresentAssertion,
    AuditPrincipalCorrelatedAssertion,
    SyntheticLocalIdentity,
    Target,
    TelemetryCanaryAbsentAssertion,
    VerificationSuite,
)
from cai_verify.config.models import DeploymentEnvironment
from cai_verify.core import (
    AssertionResult,
    AssertionStatus,
    CliExitCode,
    aggregate_results,
    exit_code_for_results,
)
from cai_verify.evidence import Sensitivity, create_run_directory, verify_run_integrity
from cai_verify.local.application import (
    SyntheticAiApplication,
    SyntheticTelemetryMode,
)
from cai_verify.local.identity import SyntheticScopedIdentity
from cai_verify.local.telemetry import LocalTelemetryProbeAdapter, LocalTelemetrySink
from cai_verify.plugins import (
    ActionExecutionResult,
    ActionRequest,
    AssertionEvaluationRequest,
    ExecutionContext,
    ProbeRequest,
    ProbeResult,
    ReportRequest,
)
from cai_verify.reporters import JsonReporter, TerminalReporter

if TYPE_CHECKING:
    import os
    from collections.abc import Mapping

    from cai_verify.config import Assertion, Scenario

SYNTHETIC_CANARY = "CAI-SYNTHETIC-CANARY-001"
DETERMINISTIC_TIME = datetime(2026, 7, 22, 12, tzinfo=UTC)
_MAX_SUITE_BYTES = 1024 * 1024
_FRESHNESS_PATTERN = re.compile(
    r"PT(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+)S)?\Z",
)


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class LocalRunResult:
    """Completed local run, rendered reports, and finalized evidence location."""

    run_id: str
    status: AssertionStatus
    exit_code: CliExitCode
    evidence_path: Path
    results: tuple[AssertionResult, ...]
    terminal_report: bytes
    json_report: bytes


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class LocalRunOptions:
    """Explicit runtime values for one deterministic local execution."""

    mode: SyntheticTelemetryMode
    evidence_root: str | os.PathLike[str]
    run_id: str
    environment: Mapping[str, str] | None = None
    evaluated_at: datetime = DETERMINISTIC_TIME


def load_suite(path: str | os.PathLike[str]) -> VerificationSuite:
    """Load one bounded, duplicate-free JSON suite through the strict model."""
    suite_path = Path(path)
    with suite_path.open("rb") as stream:
        content = stream.read(_MAX_SUITE_BYTES + 1)
    if len(content) > _MAX_SUITE_BYTES:
        message = "verification suite exceeds the maximum supported size"
        raise ValueError(message)
    try:
        decoded = json.loads(content, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        message = "verification suite must be duplicate-free UTF-8 JSON"
        raise ValueError(message) from error
    return VerificationSuite.model_validate(decoded)


def run_local_suite(
    suite: VerificationSuite,
    options: LocalRunOptions,
) -> LocalRunResult:
    """Execute, report, persist, finalize, and verify one local suite."""
    if suite.target.environment is not DeploymentEnvironment.LOCAL:
        message = "run_local_suite requires a local target"
        raise ValueError(message)
    environment_values = options.environment or {}
    suite.render_resolved_redacted(environment_values)
    sink = LocalTelemetrySink()
    action_results: list[ActionExecutionResult] = []
    probe_results: list[ProbeResult] = []
    assertion_results: list[AssertionResult] = []

    with SyntheticAiApplication(
        mode=options.mode,
        sink=sink,
        occurred_at=options.evaluated_at,
    ) as application:
        runtime_target = _runtime_target(suite.target, application.endpoint)
        action_adapter = HttpActionAdapter(environment_values, options.evaluated_at)
        for scenario in suite.scenarios:
            context = ExecutionContext(
                run_id=options.run_id,
                scenario_id=scenario.id,
                target=runtime_target,
            )
            scenario_actions = _execute_actions(
                suite,
                scenario,
                context,
                action_adapter,
            )
            action_results.extend(scenario_actions)
            scenario_probes = _collect_probes(
                suite,
                scenario,
                context,
                scenario_actions,
                sink,
                evaluated_at=options.evaluated_at,
            )
            probe_results.extend(scenario_probes)
            assertion_results.extend(
                _evaluate_assertions(
                    scenario,
                    scenario_actions,
                    scenario_probes,
                    evaluated_at=options.evaluated_at,
                    action_max_age=_freshness_delta(
                        suite.evidence_policy.max_age,
                    ),
                    clock_skew_tolerance=_freshness_delta(
                        suite.evidence_policy.clock_skew_tolerance,
                    ),
                ),
            )

    ordered_results = tuple(
        sorted(assertion_results, key=lambda result: result.assertion_id),
    )
    report_request = ReportRequest.from_results(
        run_id=options.run_id,
        results=ordered_results,
    )
    terminal_report = TerminalReporter().render_report(report_request)
    json_report = JsonReporter().render_report(report_request)
    evidence_path = _write_evidence(
        options.evidence_root,
        options.run_id,
        action_results=tuple(action_results),
        probe_results=tuple(probe_results),
        assertion_results=ordered_results,
        terminal_report=terminal_report.content,
        json_report=json_report.content,
    )
    verification = verify_run_integrity(evidence_path)
    if not verification.valid:
        message = "finalized local evidence failed immediate integrity verification"
        raise RuntimeError(message)
    status = aggregate_results(ordered_results)
    return LocalRunResult(
        run_id=options.run_id,
        status=status,
        exit_code=exit_code_for_results(ordered_results),
        evidence_path=evidence_path,
        results=ordered_results,
        terminal_report=terminal_report.content,
        json_report=json_report.content,
    )


def _execute_actions(
    suite: VerificationSuite,
    scenario: Scenario,
    context: ExecutionContext,
    adapter: HttpActionAdapter,
) -> tuple[ActionExecutionResult, ...]:
    results: list[ActionExecutionResult] = []
    for action in scenario.actions:
        identity = _identity(
            suite,
            action.identity_ref or scenario.identity_ref,
        )
        lease = SyntheticScopedIdentity(identity.id, identity.principal)
        try:
            results.append(
                adapter.execute_action(
                    ActionRequest(context=context, action=action, identity=lease),
                ),
            )
        finally:
            lease.close()
    return tuple(results)


def _collect_probes(  # noqa: PLR0913 - mirrors explicit scenario boundaries.
    suite: VerificationSuite,
    scenario: Scenario,
    context: ExecutionContext,
    action_results: tuple[ActionExecutionResult, ...],
    sink: LocalTelemetrySink,
    *,
    evaluated_at: datetime,
) -> tuple[ProbeResult, ...]:
    actions = {result.action_id: result for result in action_results}
    results: list[ProbeResult] = []
    for probe in scenario.probes:
        action_result = actions[probe.action_ref]
        identity = _identity(
            suite,
            probe.identity_ref or scenario.identity_ref,
        )
        lease = SyntheticScopedIdentity(identity.id, identity.principal)
        max_age = _freshness_delta(probe.max_age or suite.evidence_policy.max_age)
        adapter = LocalTelemetryProbeAdapter(
            sink=sink,
            canary=SYNTHETIC_CANARY,
            collected_at=evaluated_at,
            max_age=max_age,
        )
        try:
            results.append(
                adapter.collect_evidence(
                    ProbeRequest(
                        context=context,
                        probe=probe,
                        action_result=action_result,
                        identity=lease,
                    ),
                ),
            )
        finally:
            lease.close()
    return tuple(results)


def _evaluate_assertions(  # noqa: PLR0913 - policy inputs remain explicit.
    scenario: Scenario,
    action_results: tuple[ActionExecutionResult, ...],
    probe_results: tuple[ProbeResult, ...],
    *,
    evaluated_at: datetime,
    action_max_age: timedelta,
    clock_skew_tolerance: timedelta,
) -> tuple[AssertionResult, ...]:
    results: list[AssertionResult] = []
    for assertion in scenario.assertions:
        evaluator = _evaluator(
            assertion,
            evaluated_at=evaluated_at,
            action_max_age=action_max_age,
            clock_skew_tolerance=clock_skew_tolerance,
        )
        results.append(
            evaluator.evaluate_assertion(
                AssertionEvaluationRequest(
                    assertion=assertion,
                    action_results=action_results,
                    probe_results=probe_results,
                ),
            ),
        )
    return tuple(results)


def _evaluator(
    assertion: Assertion,
    *,
    evaluated_at: datetime,
    action_max_age: timedelta,
    clock_skew_tolerance: timedelta,
) -> (
    ApplicationStatusEvaluator
    | TelemetryCanaryAbsentEvaluator
    | AuditEventPresentEvaluator
    | AuditPrincipalCorrelatedEvaluator
):
    if isinstance(assertion, ApplicationStatusAssertion):
        return ApplicationStatusEvaluator(
            evaluated_at,
            action_max_age,
            clock_skew_tolerance,
        )
    if isinstance(assertion, TelemetryCanaryAbsentAssertion):
        return TelemetryCanaryAbsentEvaluator(evaluated_at, clock_skew_tolerance)
    if isinstance(assertion, AuditEventPresentAssertion):
        return AuditEventPresentEvaluator(
            evaluated_at,
            clock_skew_tolerance,
            action_max_age,
        )
    if isinstance(assertion, AuditPrincipalCorrelatedAssertion):
        return AuditPrincipalCorrelatedEvaluator(
            evaluated_at,
            clock_skew_tolerance,
            action_max_age,
        )
    message = f"unsupported local assertion type: {assertion.type}"
    raise TypeError(message)


def _identity(
    suite: VerificationSuite,
    identity_ref: str,
) -> SyntheticLocalIdentity:
    matching = tuple(
        identity for identity in suite.identities if identity.id == identity_ref
    )
    if len(matching) != 1 or not isinstance(matching[0], SyntheticLocalIdentity):
        message = "local identity reference is missing or invalid"
        raise ValueError(message)
    return matching[0]


def _runtime_target(target: Target, endpoint: str) -> Target:
    value = target.model_dump(mode="json", by_alias=True)
    value["endpoint"] = endpoint
    return Target.model_validate(value)


def _write_evidence(  # noqa: PLR0913 - each artifact group remains explicit.
    evidence_root: str | os.PathLike[str],
    run_id: str,
    *,
    action_results: tuple[ActionExecutionResult, ...],
    probe_results: tuple[ProbeResult, ...],
    assertion_results: tuple[AssertionResult, ...],
    terminal_report: bytes,
    json_report: bytes,
) -> Path:
    with create_run_directory(evidence_root, run_id) as run:
        for action in sorted(action_results, key=lambda item: item.action_id):
            run.write_evidence(
                f"actions/{_artifact_name(action.action_id)}.json",
                _action_bytes(action),
                media_type="application/json",
                sensitivity=Sensitivity.INTERNAL,
            )
        for probe in sorted(probe_results, key=lambda item: item.probe_id):
            run.write_evidence(
                f"probes/{_artifact_name(probe.probe_id)}.json",
                _probe_bytes(probe),
                media_type="application/json",
                sensitivity=Sensitivity.INTERNAL,
            )
        for result in assertion_results:
            run.write_evidence(
                f"results/{_artifact_name(result.assertion_id)}.json",
                result.to_json_bytes(),
                media_type="application/json",
                sensitivity=Sensitivity.PUBLIC,
            )
        run.write_evidence(
            "reports/report.json",
            json_report,
            media_type="application/json",
            sensitivity=Sensitivity.PUBLIC,
        )
        run.write_evidence(
            "reports/terminal.txt",
            terminal_report,
            media_type="text/plain",
            sensitivity=Sensitivity.PUBLIC,
        )
        run.finalize_manifest()
        return run.path


def _action_bytes(result: ActionExecutionResult) -> bytes:
    return _json_bytes(
        {
            "action_id": result.action_id,
            "completed_at": _timestamp(result.completed_at),
            "correlation_ids": list(result.correlation_ids),
            "evidence_id": f"action.{result.action_id}",
            "limitations": list(result.limitations),
            "observed": result.observed.to_json_value(),
            "outcome": result.outcome.value,
            "schema_version": "1",
            "started_at": _timestamp(result.started_at),
        },
    )


def _probe_bytes(result: ProbeResult) -> bytes:
    return _json_bytes(
        {
            "collected_at": _timestamp(result.freshness.collected_at),
            "max_age_seconds": int(result.freshness.max_age.total_seconds()),
            "observations": [
                {
                    "kind": item.kind,
                    "limitations": list(item.limitations),
                    "observation_id": item.observation_id,
                    "observed": item.observed.to_json_value(),
                }
                for item in sorted(
                    result.observations,
                    key=lambda observation: observation.observation_id,
                )
            ],
            "probe_id": result.probe_id,
            "schema_version": "1",
            "source": {
                "name": result.source.name,
                "version": result.source.version,
            },
            "source_time": (
                _timestamp(result.freshness.source_time)
                if result.freshness.source_time is not None
                else None
            ),
        },
    )


def _freshness_delta(value: str) -> timedelta:
    match = _FRESHNESS_PATTERN.fullmatch(value)
    if match is None:
        message = "invalid validated freshness duration"
        raise ValueError(message)
    return timedelta(
        hours=int(match.group("hours") or 0),
        minutes=int(match.group("minutes") or 0),
        seconds=int(match.group("seconds") or 0),
    )


def _artifact_name(identifier: str) -> str:
    digest = hashlib.sha256(identifier.encode()).hexdigest()[:16]
    return f"item-{digest}"


def _timestamp(value: datetime) -> str:
    return (
        value.astimezone(UTC)
        .isoformat(timespec="microseconds")
        .replace(
            "+00:00",
            "Z",
        )
    )


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            message = "verification suite contains a duplicate object field"
            raise ValueError(message)
        value[key] = item
    return value
