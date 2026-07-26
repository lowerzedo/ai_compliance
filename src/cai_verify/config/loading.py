"""Bounded loading for untrusted verification-suite files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from cai_verify.config.models import VerificationSuite

if TYPE_CHECKING:
    import os

MAX_SUITE_BYTES = 1024 * 1024


def load_suite(path: str | os.PathLike[str]) -> VerificationSuite:
    """Load one bounded, duplicate-free JSON suite through the strict model."""
    suite_path = Path(path)
    with suite_path.open("rb") as stream:
        content = stream.read(MAX_SUITE_BYTES + 1)
    if len(content) > MAX_SUITE_BYTES:
        message = "verification suite exceeds the maximum supported size"
        raise ValueError(message)
    try:
        decoded = json.loads(content, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        message = "verification suite must be duplicate-free UTF-8 JSON"
        raise ValueError(message) from error
    return VerificationSuite.model_validate(decoded)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            message = "verification suite contains a duplicate object field"
            raise ValueError(message)
        value[key] = item
    return value
