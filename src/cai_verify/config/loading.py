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
    return load_suite_bytes(content)


def load_suite_bytes(content: bytes) -> VerificationSuite:
    """Load bounded, duplicate-free suite bytes through the strict model."""
    if type(content) is not bytes:
        message = "verification suite content must be bytes"
        raise TypeError(message)
    if len(content) > MAX_SUITE_BYTES:
        message = "verification suite exceeds the maximum supported size"
        raise ValueError(message)
    try:
        utf8 = content.decode("utf-8")
        decoded = json.loads(
            utf8,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        RecursionError,
    ) as error:
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


def _reject_json_constant(_value: str) -> None:
    message = "verification suite contains a non-finite number"
    raise ValueError(message)
