"""Tests for deterministic, fail-closed entry-point plugin discovery."""

from __future__ import annotations

import traceback
from importlib import metadata as package_metadata

import pytest

from cai_verify.plugins import (
    ACTION_EXECUTOR_ENTRY_POINT_GROUP,
    ASSERTION_EVALUATOR_ENTRY_POINT_GROUP,
    CONTROL_PROFILE_PROVIDER_ENTRY_POINT_GROUP,
    EVIDENCE_PROBE_ENTRY_POINT_GROUP,
    IDENTITY_PROVIDER_ENTRY_POINT_GROUP,
    REPORTER_ENTRY_POINT_GROUP,
    SIGNER_ENTRY_POINT_GROUP,
    DuplicatePluginNameError,
    IncompatiblePluginApiVersionError,
    PluginLoadError,
    discover_plugins,
)
from tests.plugins.sample_plugin import SAMPLE_PLUGIN_NAME, SAMPLE_SECRET

_FACTORY = "tests.plugins.sample_plugin:create_plugin"
_INCOMPATIBLE_FACTORY = "tests.plugins.sample_plugin:create_incompatible_plugin"
_FAILING_FACTORY = "tests.plugins.sample_plugin:create_failing_plugin"
_INVALID_VERSION_FACTORY = "tests.plugins.sample_plugin:create_invalid_version_plugin"
_GROUPS = (
    IDENTITY_PROVIDER_ENTRY_POINT_GROUP,
    ACTION_EXECUTOR_ENTRY_POINT_GROUP,
    EVIDENCE_PROBE_ENTRY_POINT_GROUP,
    ASSERTION_EVALUATOR_ENTRY_POINT_GROUP,
    REPORTER_ENTRY_POINT_GROUP,
    SIGNER_ENTRY_POINT_GROUP,
    CONTROL_PROFILE_PROVIDER_ENTRY_POINT_GROUP,
)


def _entry_point(
    *,
    name: str,
    group: str,
    value: str = _FACTORY,
) -> package_metadata.EntryPoint:
    return package_metadata.EntryPoint(name=name, value=value, group=group)


def _install_entry_points(
    monkeypatch: pytest.MonkeyPatch,
    entry_points: tuple[package_metadata.EntryPoint, ...],
) -> None:
    discovered = package_metadata.EntryPoints(entry_points)
    monkeypatch.setattr(package_metadata, "entry_points", lambda: discovered)


def test_entry_point_discovery_loads_each_typed_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every explicit group loads the sample through Python entry points."""
    _install_entry_points(
        monkeypatch,
        tuple(_entry_point(name="sample", group=group) for group in _GROUPS),
    )

    plugins = discover_plugins()

    collections = (
        plugins.identity_providers,
        plugins.action_executors,
        plugins.evidence_probes,
        plugins.assertion_evaluators,
        plugins.reporters,
        plugins.signers,
        plugins.control_profile_providers,
    )
    assert all(len(collection) == 1 for collection in collections)
    assert all(
        collection[0].metadata.name == SAMPLE_PLUGIN_NAME for collection in collections
    )
    assert all(collection[0].metadata.capabilities for collection in collections)


def test_incompatible_plugin_api_version_is_rejected_clearly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Diagnostics identify the plugin and both incompatible API versions."""
    _install_entry_points(
        monkeypatch,
        (
            _entry_point(
                name="incompatible",
                group=EVIDENCE_PROBE_ENTRY_POINT_GROUP,
                value=_INCOMPATIBLE_FACTORY,
            ),
        ),
    )

    with pytest.raises(IncompatiblePluginApiVersionError) as caught:
        discover_plugins()

    message = str(caught.value)
    assert SAMPLE_PLUGIN_NAME in message
    assert "API version '2'" in message
    assert "requires '1'" in message


def test_duplicate_plugin_metadata_names_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Distinct aliases cannot make one contract name ambiguous."""
    _install_entry_points(
        monkeypatch,
        (
            _entry_point(name="first", group=EVIDENCE_PROBE_ENTRY_POINT_GROUP),
            _entry_point(name="second", group=EVIDENCE_PROBE_ENTRY_POINT_GROUP),
        ),
    )

    with pytest.raises(DuplicatePluginNameError, match=SAMPLE_PLUGIN_NAME):
        discover_plugins()


def test_plugin_factory_errors_never_expose_secret_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A plugin's exception text and traceback context are discarded."""
    _install_entry_points(
        monkeypatch,
        (
            _entry_point(
                name="failing",
                group=EVIDENCE_PROBE_ENTRY_POINT_GROUP,
                value=_FAILING_FACTORY,
            ),
        ),
    )

    with pytest.raises(PluginLoadError) as caught:
        discover_plugins()

    rendered = "".join(traceback.format_exception(caught.value))
    assert "failing" in rendered
    assert SAMPLE_SECRET not in rendered
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_invalid_metadata_cannot_turn_version_diagnostics_into_a_secret_channel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only validated numeric versions can reach compatibility diagnostics."""
    _install_entry_points(
        monkeypatch,
        (
            _entry_point(
                name="secret-version",
                group=EVIDENCE_PROBE_ENTRY_POINT_GROUP,
                value=_INVALID_VERSION_FACTORY,
            ),
        ),
    )

    with pytest.raises(PluginLoadError) as caught:
        discover_plugins()

    assert SAMPLE_SECRET not in "".join(traceback.format_exception(caught.value))
    assert caught.value.__context__ is None
