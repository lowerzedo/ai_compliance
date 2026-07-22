"""Opaque synthetic identity lease used only by the local demonstration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, final

if TYPE_CHECKING:
    from datetime import datetime


@final
@dataclass(slots=True)
class SyntheticScopedIdentity:
    """Hold a non-secret synthetic principal for one local scenario."""

    _identity_id: str
    principal: str = field(repr=False)
    _expires_at: datetime | None = None
    closed: bool = False

    @property
    def identity_id(self) -> str:
        """Return the configured identity ID."""
        return self._identity_id

    @property
    def expires_at(self) -> datetime | None:
        """Return no expiry for the process-local identity."""
        return self._expires_at

    def close(self) -> None:
        """Mark the local identity lease closed."""
        self.closed = True
