"""Contract tests for shared path and in-memory suite loading."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from cai_verify.config import MAX_SUITE_BYTES, load_suite, load_suite_bytes

_ROOT = Path(__file__).parents[2]
_SUITE_PATH = _ROOT / "examples/aws/reciprocal-retrieval-suite.json"


def test_path_and_byte_loaders_return_the_same_validated_suite() -> None:
    """The console upload and CLI path share one strict parsing contract."""
    content = _SUITE_PATH.read_bytes()

    assert load_suite_bytes(content) == load_suite(_SUITE_PATH)


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"\xff", id="invalid-utf8"),
        pytest.param(
            _SUITE_PATH.read_text(encoding="utf-8").encode("utf-16"),
            id="utf16-json",
        ),
        pytest.param(b'{"schemaVersion":NaN}', id="non-finite"),
        pytest.param(
            b'{"schemaVersion":"1alpha1","schemaVersion":"1alpha1"}',
            id="duplicate-root",
        ),
        pytest.param(
            b'{"metadata":{"name":"one","name":"two"}}',
            id="duplicate-nested",
        ),
    ],
)
def test_byte_loader_rejects_malformed_or_duplicate_json(content: bytes) -> None:
    """Untrusted uploads cannot bypass duplicate-free UTF-8 parsing."""
    with pytest.raises((ValueError, ValidationError)):
        load_suite_bytes(content)


def test_byte_loader_rejects_non_bytes_and_one_byte_over_limit() -> None:
    """The upload seam accepts exact bytes within the existing 1 MiB bound."""
    with pytest.raises(TypeError):
        load_suite_bytes("{}")  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="maximum supported size"):
        load_suite_bytes(b" " * (MAX_SUITE_BYTES + 1))
