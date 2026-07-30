"""Compare the reproducible Vite build with committed Python package assets."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_BUILD = PROJECT_ROOT / "ui" / "dist"
PACKAGED_BUILD = PROJECT_ROOT / "src" / "cai_verify" / "ui" / "static"


def main() -> None:
    """Require an exact, source-map-free committed copy of the current build."""
    generated = _inventory(FRONTEND_BUILD)
    packaged = _inventory(PACKAGED_BUILD)
    if "index.html" not in generated:
        message = "frontend build omitted index.html"
        raise RuntimeError(message)
    if generated != packaged:
        missing = sorted(generated.keys() - packaged.keys())
        stale = sorted(packaged.keys() - generated.keys())
        changed = sorted(
            path
            for path in generated.keys() & packaged.keys()
            if generated[path] != packaged[path]
        )
        message = (
            "committed UI assets differ from the current Vite build: "
            f"missing={missing!r}, stale={stale!r}, changed={changed!r}"
        )
        raise RuntimeError(message)
    sys.stdout.write(
        f"UI asset validation passed: {len(packaged)} deterministic files\n"
    )


def _inventory(root: Path) -> dict[str, bytes]:
    if not root.is_dir() or root.is_symlink():
        message = f"UI asset directory is unavailable: {root}"
        raise RuntimeError(message)
    inventory: dict[str, bytes] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            message = f"UI asset must not be a symlink: {path}"
            raise RuntimeError(message)
        if path.is_dir():
            continue
        if not path.is_file():
            message = f"UI asset must be a regular file: {path}"
            raise RuntimeError(message)
        relative = path.relative_to(root).as_posix()
        if relative.endswith(".map"):
            message = f"source map is forbidden in packaged UI assets: {relative}"
            raise RuntimeError(message)
        content = path.read_bytes()
        if b"sourceMappingURL=" in content:
            message = f"source-map reference is forbidden in UI asset: {relative}"
            raise RuntimeError(message)
        inventory[relative] = content
    return inventory


if __name__ == "__main__":
    main()
