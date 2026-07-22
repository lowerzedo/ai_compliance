"""Generate committed JSON Schemas from the authoritative Pydantic models."""

from __future__ import annotations

import json
from pathlib import Path

from cai_verify.config import verification_suite_json_schema

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_SUITE_SCHEMA_PATH = (
    _REPOSITORY_ROOT / "schemas" / "verification-suite-1alpha1.schema.json"
)


def main() -> None:
    """Write deterministic, reviewable schema artifacts."""
    rendered = json.dumps(
        verification_suite_json_schema(),
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    _SUITE_SCHEMA_PATH.parent.mkdir(parents=True, exist_ok=True)
    _SUITE_SCHEMA_PATH.write_text(f"{rendered}\n", encoding="utf-8")


if __name__ == "__main__":
    main()
