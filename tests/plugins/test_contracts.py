"""Contract tests executed against the synthetic test-only plugin."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import yaml

from cai_verify.config import VerificationSuite
from cai_verify.core import (
    AssertionResult,
    AssertionStatus,
    AssertionType,
    RedactedValue,
)
from cai_verify.plugins import (
    ActionExecutionResult,
    ActionOutcome,
    AssertionEvaluationRequest,
    ExecutionContext,
    PluginMetadata,
    ProbeRequest,
    ReportArtifact,
    Reporter,
    ReportRequest,
)
from tests.plugins.contract_suite import (
    assert_assertion_evaluator_contract,
    assert_evidence_probe_contract,
    assert_reporter_contract,
)
from tests.plugins.sample_plugin import (
    SamplePlugin,
    SampleScopedIdentity,
    create_plugin,
)

_SUITE_FIXTURE = (
    Path(__file__).parents[1] / "fixtures" / "suites" / "valid" / "full.yaml"
)
_NOW = datetime(2026, 7, 22, 12, tzinfo=UTC)


def _suite() -> VerificationSuite:
    loaded = yaml.safe_load(_SUITE_FIXTURE.read_text(encoding="utf-8"))
    return VerificationSuite.model_validate(cast("dict[str, Any]", loaded))


def _probe_request() -> ProbeRequest:
    suite = _suite()
    scenario = suite.scenarios[0]
    action = scenario.actions[0]
    identity = SampleScopedIdentity(suite.identities[0].id, None)
    action_result = ActionExecutionResult(
        action_id=action.id,
        outcome=ActionOutcome.SUCCEEDED,
        started_at=_NOW,
        completed_at=_NOW,
        observed=RedactedValue({"synthetic": True}),
        correlation_ids=("sample-correlation",),
        limitations=("Synthetic contract-test action.",),
    )
    return ProbeRequest(
        context=ExecutionContext(
            run_id="contract-run",
            scenario_id=scenario.id,
            target=suite.target,
        ),
        probe=scenario.probes[0],
        action_result=action_result,
        identity=identity,
    )


def _assertion_result() -> AssertionResult:
    return AssertionResult(
        assertion_id="contract-assertion",
        assertion_type=AssertionType.EVIDENCE_BACKED,
        status=AssertionStatus.PASS,
        expected={"providers": ["synthetic"]},
        observed=RedactedValue({"provider": "synthetic"}),
        evidence_ids=("sample-evidence",),
        limitations=("Synthetic contract-test result.",),
        evaluator_version="1.0.0",
        evaluation_started_at=_NOW,
        evaluation_completed_at=_NOW,
    )


def test_sample_probe_reports_source_and_freshness() -> None:
    """The shared probe contract requires explicit provenance and freshness."""
    plugin = create_plugin()

    result = assert_evidence_probe_contract(plugin, _probe_request())

    assert result.source.name == "sample-source"
    assert result.source.version == "1.0.0"


def test_sample_evaluator_returns_the_exact_result_contract() -> None:
    """The shared evaluator contract preserves core result semantics."""
    plugin = create_plugin()
    probe_request = _probe_request()
    probe_result = plugin.collect_evidence(probe_request)
    request = AssertionEvaluationRequest(
        assertion=_suite().scenarios[0].assertions[0],
        action_results=(probe_request.action_result,),
        probe_results=(probe_result,),
    )

    result = assert_assertion_evaluator_contract(plugin, request)

    assert result.status is AssertionStatus.PASS


def test_sample_reporter_cannot_mutate_assertion_results() -> None:
    """Reporters receive snapshots rather than original assertion objects."""
    plugin = create_plugin()
    result = _assertion_result()
    request = ReportRequest.from_results(
        run_id="contract-run",
        results=(result,),
    )

    artifact = assert_reporter_contract(plugin, request, (result,))

    assert artifact.media_type == "application/json"
    assert b'"status":"PASS"' in artifact.content


class _CopyMutatingReporter:
    """Reporter that deliberately mutates the detached dictionary it reads."""

    def __init__(self, delegate: SamplePlugin) -> None:
        self._delegate = delegate

    @property
    def metadata(self) -> PluginMetadata:
        """Return the sample plugin metadata."""
        return self._delegate.metadata

    def render_report(self, request: ReportRequest, /) -> ReportArtifact:
        """Mutate a detached copy, then render the untouched request views."""
        detached = request.results[0].to_dict()
        detached["status"] = "FAIL"
        expected = detached["expected"]
        assert isinstance(expected, dict)
        expected["providers"] = ["tampered"]
        return self._delegate.render_report(request)


def test_even_a_copy_mutating_reporter_cannot_change_results() -> None:
    """Nested report data is detached on every access, not merely frozen outside."""
    result = _assertion_result()
    request = ReportRequest.from_results(run_id="contract-run", results=(result,))
    reporter: Reporter = _CopyMutatingReporter(create_plugin())

    artifact = assert_reporter_contract(reporter, request, (result,))

    assert b'"status":"PASS"' in artifact.content
    assert b"tampered" not in artifact.content
