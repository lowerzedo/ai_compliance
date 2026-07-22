"""Deterministic and fail-closed discovery of versioned Python plugins."""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib import metadata as package_metadata
from typing import TYPE_CHECKING, Never, cast, final

from cai_verify.plugins.contracts import (
    PLUGIN_API_VERSION,
    ActionExecutor,
    AssertionEvaluator,
    ControlProfileProvider,
    EvidenceProbe,
    IdentityProvider,
    PluginMetadata,
    Reporter,
    Signer,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

IDENTITY_PROVIDER_ENTRY_POINT_GROUP = "cai_verify.identity_providers"
ACTION_EXECUTOR_ENTRY_POINT_GROUP = "cai_verify.action_executors"
EVIDENCE_PROBE_ENTRY_POINT_GROUP = "cai_verify.evidence_probes"
ASSERTION_EVALUATOR_ENTRY_POINT_GROUP = "cai_verify.assertion_evaluators"
REPORTER_ENTRY_POINT_GROUP = "cai_verify.reporters"
SIGNER_ENTRY_POINT_GROUP = "cai_verify.signers"
CONTROL_PROFILE_PROVIDER_ENTRY_POINT_GROUP = "cai_verify.control_profile_providers"

_ENTRY_POINT_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


class PluginDiscoveryError(RuntimeError):
    """Base class for public, redacted plugin-discovery failures."""


class PluginLoadError(PluginDiscoveryError):
    """An entry point could not be imported or its factory failed."""


class InvalidPluginError(PluginDiscoveryError):
    """An entry point did not expose the contract required by its group."""


class IncompatiblePluginApiVersionError(PluginDiscoveryError):
    """A plugin declares an API version the host cannot safely invoke."""


class DuplicatePluginNameError(PluginDiscoveryError):
    """More than one plugin in a contract group uses the same name."""


@final
@dataclass(frozen=True, slots=True, kw_only=True)
class DiscoveredPlugins:
    """Explicit immutable collections of all supported plugin contracts."""

    identity_providers: tuple[IdentityProvider, ...]
    action_executors: tuple[ActionExecutor, ...]
    evidence_probes: tuple[EvidenceProbe, ...]
    assertion_evaluators: tuple[AssertionEvaluator, ...]
    reporters: tuple[Reporter, ...]
    signers: tuple[Signer, ...]
    control_profile_providers: tuple[ControlProfileProvider, ...]


def discover_plugins() -> DiscoveredPlugins:
    """Load installed entry-point factories into an explicit typed catalog.

    Each entry point must resolve to a zero-argument factory. The returned
    plugin is validated against the Protocol associated with its entry-point
    group, then checked for exact API compatibility and a unique metadata name.
    """
    entry_points = package_metadata.entry_points()
    return DiscoveredPlugins(
        identity_providers=cast(
            "tuple[IdentityProvider, ...]",
            _load_group(
                entry_points.select(group=IDENTITY_PROVIDER_ENTRY_POINT_GROUP),
                group=IDENTITY_PROVIDER_ENTRY_POINT_GROUP,
                kind="identity provider",
                contract=IdentityProvider,
            ),
        ),
        action_executors=cast(
            "tuple[ActionExecutor, ...]",
            _load_group(
                entry_points.select(group=ACTION_EXECUTOR_ENTRY_POINT_GROUP),
                group=ACTION_EXECUTOR_ENTRY_POINT_GROUP,
                kind="action executor",
                contract=ActionExecutor,
            ),
        ),
        evidence_probes=cast(
            "tuple[EvidenceProbe, ...]",
            _load_group(
                entry_points.select(group=EVIDENCE_PROBE_ENTRY_POINT_GROUP),
                group=EVIDENCE_PROBE_ENTRY_POINT_GROUP,
                kind="evidence probe",
                contract=EvidenceProbe,
            ),
        ),
        assertion_evaluators=cast(
            "tuple[AssertionEvaluator, ...]",
            _load_group(
                entry_points.select(group=ASSERTION_EVALUATOR_ENTRY_POINT_GROUP),
                group=ASSERTION_EVALUATOR_ENTRY_POINT_GROUP,
                kind="assertion evaluator",
                contract=AssertionEvaluator,
            ),
        ),
        reporters=cast(
            "tuple[Reporter, ...]",
            _load_group(
                entry_points.select(group=REPORTER_ENTRY_POINT_GROUP),
                group=REPORTER_ENTRY_POINT_GROUP,
                kind="reporter",
                contract=Reporter,
            ),
        ),
        signers=cast(
            "tuple[Signer, ...]",
            _load_group(
                entry_points.select(group=SIGNER_ENTRY_POINT_GROUP),
                group=SIGNER_ENTRY_POINT_GROUP,
                kind="signer",
                contract=Signer,
            ),
        ),
        control_profile_providers=cast(
            "tuple[ControlProfileProvider, ...]",
            _load_group(
                entry_points.select(
                    group=CONTROL_PROFILE_PROVIDER_ENTRY_POINT_GROUP,
                ),
                group=CONTROL_PROFILE_PROVIDER_ENTRY_POINT_GROUP,
                kind="control profile provider",
                contract=ControlProfileProvider,
            ),
        ),
    )


def _load_group(
    entry_points: Iterable[package_metadata.EntryPoint],
    *,
    group: str,
    kind: str,
    contract: type[object],
) -> tuple[object, ...]:
    ordered = tuple(sorted(entry_points, key=lambda entry_point: entry_point.name))
    aliases = tuple(
        _validated_alias(entry_point.name, group=group) for entry_point in ordered
    )
    duplicate_aliases = _duplicates(aliases)
    if duplicate_aliases:
        joined = ", ".join(duplicate_aliases)
        message = f"duplicate {kind} entry-point name: {joined}"
        raise DuplicatePluginNameError(message)

    loaded_with_metadata = tuple(
        _load_entry_point(
            entry_point,
            alias=alias,
            group=group,
            kind=kind,
            contract=contract,
        )
        for entry_point, alias in zip(ordered, aliases, strict=True)
    )
    plugin_names = tuple(metadata.name for _, metadata in loaded_with_metadata)
    duplicate_names = _duplicates(plugin_names)
    if duplicate_names:
        joined = ", ".join(duplicate_names)
        message = f"duplicate {kind} plugin name: {joined}"
        raise DuplicatePluginNameError(message)
    return tuple(plugin for plugin, _ in loaded_with_metadata)


def _load_entry_point(
    entry_point: package_metadata.EntryPoint,
    *,
    alias: str,
    group: str,
    kind: str,
    contract: type[object],
) -> tuple[object, PluginMetadata]:
    loaded = _load_factory(entry_point, alias=alias, group=group)
    factory = _validate_factory(loaded, alias=alias, kind=kind)
    plugin = _invoke_factory(factory, alias=alias, group=group)
    metadata_value = _read_metadata(
        plugin,
        alias=alias,
        group=group,
        kind=kind,
    )
    _validate_api_version(metadata_value, kind=kind)
    _validate_contract(
        plugin,
        alias=alias,
        group=group,
        contract=contract,
        plugin_name=metadata_value.name,
    )
    return plugin, metadata_value


def _load_factory(
    entry_point: package_metadata.EntryPoint,
    *,
    alias: str,
    group: str,
) -> object:
    loaded: object | None = None
    load_failed = False
    try:
        loaded = entry_point.load()
    except Exception:  # noqa: BLE001 - untrusted plugin exceptions are redacted.
        load_failed = True
    if load_failed:
        _raise_redacted_load_error(alias=alias, group=group)
    return loaded


def _validate_factory(
    loaded: object,
    *,
    alias: str,
    kind: str,
) -> Callable[[], object]:
    if not callable(loaded):
        message = f"{kind} entry point {alias!r} must expose a zero-argument factory"
        raise InvalidPluginError(message)
    return loaded


def _invoke_factory(
    factory: Callable[[], object],
    *,
    alias: str,
    group: str,
) -> object:
    plugin: object | None = None
    factory_failed = False
    try:
        plugin = factory()
    except Exception:  # noqa: BLE001 - untrusted plugin exceptions are redacted.
        factory_failed = True
    if factory_failed:
        _raise_redacted_load_error(alias=alias, group=group)
    return plugin


def _read_metadata(
    plugin: object,
    *,
    alias: str,
    group: str,
    kind: str,
) -> PluginMetadata:
    metadata_value: object | None = None
    metadata_failed = False
    try:
        metadata_value = getattr(plugin, "metadata", None)
    except Exception:  # noqa: BLE001 - untrusted plugin exceptions are redacted.
        metadata_failed = True
    if metadata_failed:
        _raise_redacted_load_error(alias=alias, group=group)
    if type(metadata_value) is not PluginMetadata:
        message = f"{kind} entry point {alias!r} must provide PluginMetadata"
        raise InvalidPluginError(message)
    return metadata_value


def _validate_api_version(metadata_value: PluginMetadata, *, kind: str) -> None:
    if metadata_value.api_version != PLUGIN_API_VERSION:
        message = (
            f"{kind} plugin {metadata_value.name!r} uses API version "
            f"{metadata_value.api_version!r}; cai-verify requires "
            f"{PLUGIN_API_VERSION!r}"
        )
        raise IncompatiblePluginApiVersionError(message)


def _validate_contract(
    plugin: object,
    *,
    alias: str,
    group: str,
    contract: type[object],
    plugin_name: str,
) -> None:
    contract_failed = False
    conforms = False
    try:
        conforms = isinstance(plugin, contract)
    except Exception:  # noqa: BLE001 - untrusted plugin exceptions are redacted.
        contract_failed = True
    if contract_failed:
        _raise_redacted_load_error(alias=alias, group=group)
    if not conforms:
        message = f"plugin {plugin_name!r} does not implement its required contract"
        raise InvalidPluginError(message)


def _validated_alias(value: object, *, group: str) -> str:
    if not isinstance(value, str) or _ENTRY_POINT_NAME_PATTERN.fullmatch(value) is None:
        message = f"entry point in group {group!r} has an invalid name"
        raise InvalidPluginError(message)
    return value


def _duplicates(values: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    return tuple(sorted(duplicates))


def _raise_redacted_load_error(*, alias: str, group: str) -> Never:
    message = f"failed to load plugin entry point {alias!r} from group {group!r}"
    raise PluginLoadError(message) from None
