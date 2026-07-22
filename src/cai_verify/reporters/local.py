"""Deterministic terminal and JSON rendering of detached result views."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import cast, final

from cai_verify.core import AssertionStatus, aggregate_statuses, exit_code_for_status
from cai_verify.plugins import (
    PLUGIN_API_VERSION,
    PluginMetadata,
    ReportArtifact,
    ReportRequest,
)

_REPORT_SCHEMA_VERSION = "1"


@final
@dataclass(frozen=True, slots=True)
class JsonReporter:
    """Render one canonical machine-readable report."""

    @property
    def metadata(self) -> PluginMetadata:
        """Declare the JSON reporting capability."""
        return PluginMetadata(
            name="json-reporter",
            api_version=PLUGIN_API_VERSION,
            capabilities=("report.json",),
        )

    def render_report(self, request: ReportRequest, /) -> ReportArtifact:
        """Render sorted result snapshots with aggregate status and exit code."""
        payload = _report_payload(request)
        content = json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        return ReportArtifact(media_type="application/json", content=content)


@final
@dataclass(frozen=True, slots=True)
class TerminalReporter:
    """Render stable plain text without ANSI styling or sensitive observations."""

    @property
    def metadata(self) -> PluginMetadata:
        """Declare the terminal reporting capability."""
        return PluginMetadata(
            name="terminal-reporter",
            api_version=PLUGIN_API_VERSION,
            capabilities=("report.terminal",),
        )

    def render_report(self, request: ReportRequest, /) -> ReportArtifact:
        """Render a concise report whose ordering is independent of execution order."""
        payload = _report_payload(request)
        aggregate = cast("str", payload["aggregate_status"])
        exit_code = cast("int", payload["exit_code"])
        lines = [
            f"Run: {request.run_id}",
            f"Overall: {aggregate} (exit {exit_code})",
        ]
        results = cast("list[dict[str, object]]", payload["results"])
        lines.extend(
            f"[{result['status']}] {result['assertion_id']}" for result in results
        )
        return ReportArtifact(
            media_type="text/plain",
            content=("\n".join(lines) + "\n").encode(),
        )


def _report_payload(request: ReportRequest) -> dict[str, object]:
    results = sorted(
        (view.to_dict() for view in request.results),
        key=lambda item: cast("str", item["assertion_id"]),
    )
    statuses: list[AssertionStatus] = []
    for result in results:
        raw_status = result.get("status")
        if not isinstance(raw_status, str):
            message = "report result status must be a string"
            raise TypeError(message)
        statuses.append(AssertionStatus(raw_status))
    aggregate = aggregate_statuses(statuses)
    return {
        "aggregate_status": aggregate.value,
        "exit_code": int(exit_code_for_status(aggregate)),
        "results": results,
        "run_id": request.run_id,
        "schema_version": _REPORT_SCHEMA_VERSION,
    }
