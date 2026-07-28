"""Generate committed JSON Schemas from the authoritative Pydantic models."""

from __future__ import annotations

import json
from pathlib import Path

from cai_verify.aws import aws_execution_policy_json_schema
from cai_verify.config import verification_suite_json_schema

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_SCHEMAS = (
    (
        "verification-suite-1alpha1.schema.json",
        verification_suite_json_schema,
    ),
    (
        "aws-execution-policy-1alpha1.schema.json",
        aws_execution_policy_json_schema,
    ),
)
_REVIEWED_SCHEMA_DIRECTORY = _REPOSITORY_ROOT / "schemas"
_PACKAGE_SCHEMA_DIRECTORY = _REPOSITORY_ROOT / "src" / "cai_verify" / "schemas"


def main() -> None:
    """Write deterministic reviewed and installed schema resources."""
    for filename, schema_factory in _SCHEMAS:
        rendered = json.dumps(
            schema_factory(),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        for directory in (
            _REVIEWED_SCHEMA_DIRECTORY,
            _PACKAGE_SCHEMA_DIRECTORY,
        ):
            directory.mkdir(parents=True, exist_ok=True)
            (directory / filename).write_text(
                f"{rendered}\n",
                encoding="utf-8",
            )


if __name__ == "__main__":
    main()
