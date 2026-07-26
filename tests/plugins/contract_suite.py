"""Reusable assertions for plugin implementations maintained in this project."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

from cai_verify.plugins import (
    PLUGIN_API_VERSION,
    ActionExecutionResult,
    ActionExecutor,
    ActionRequest,
    EvidenceProbe,
    ProbeRequest,
    ProbeResult,
    ReportArtifact,
    Reporter,
    ReportRequest,
)

if TYPE_CHECKING:
    from cai_verify.core import AssertionResult


def assert_action_executor_contract(
    executor: ActionExecutor,
    request: ActionRequest,
) -> ActionExecutionResult:
    """Assert mandatory compatibility and exact normalized result behavior."""
    assert executor.metadata.api_version == PLUGIN_API_VERSION
    assert executor.metadata.capabilities

    result = executor.execute_action(request)

    assert type(result) is ActionExecutionResult
    assert result.action_id == request.action.id
    assert result.started_at.utcoffset() is not None
    assert result.completed_at.utcoffset() is not None
    assert result.completed_at >= result.started_at
    assert result.limitations
    return result


def assert_evidence_probe_contract(
    probe: EvidenceProbe,
    request: ProbeRequest,
) -> ProbeResult:
    """Assert mandatory compatibility, provenance, and freshness behavior."""
    assert probe.metadata.api_version == PLUGIN_API_VERSION
    assert probe.metadata.capabilities

    result = probe.collect_evidence(request)

    assert type(result) is ProbeResult
    assert result.source.name
    assert result.source.version
    assert result.freshness.max_age > timedelta(0)
    assert result.freshness.collected_at.utcoffset() is not None
    if result.freshness.source_time is not None:
        assert result.freshness.source_time.utcoffset() is not None
    assert result.freshness.freshness_limit > (
        result.freshness.source_time or result.freshness.collected_at
    )
    return result


def assert_reporter_contract(
    reporter: Reporter,
    request: ReportRequest,
    original_results: tuple[AssertionResult, ...],
) -> ReportArtifact:
    """Assert reporters receive detached views and leave originals unchanged."""
    assert reporter.metadata.api_version == PLUGIN_API_VERSION
    assert reporter.metadata.capabilities
    original_bytes = tuple(result.to_json_bytes() for result in original_results)
    view_bytes = tuple(result.to_json_bytes() for result in request.results)

    artifact = reporter.render_report(request)

    assert type(artifact) is ReportArtifact
    assert (
        tuple(result.to_json_bytes() for result in original_results) == original_bytes
    )
    assert tuple(result.to_json_bytes() for result in request.results) == view_bytes
    return artifact
