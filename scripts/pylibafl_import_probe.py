#!/usr/bin/env python3
"""Probe whether pylibafl is importable in the current environment."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path


def try_normal_import() -> tuple[bool, str | None]:
    try:
        import pylibafl.sugar  # noqa: F401

        return True, None
    except Exception as exc:  # pragma: no cover - diagnostic path
        return False, f"{exc.__class__.__name__}: {exc}"


def load_extension(path: Path) -> tuple[bool, str | None]:
    try:
        spec = importlib.util.spec_from_file_location("pylibafl", path)
        if spec is None or spec.loader is None:
            return False, f"could not create import spec for {path}"
        module = importlib.util.module_from_spec(spec)
        sys.modules["pylibafl"] = module
        spec.loader.exec_module(module)
        import pylibafl.sugar  # noqa: F401

        return True, None
    except Exception as exc:  # pragma: no cover - diagnostic path
        sys.modules.pop("pylibafl", None)
        sys.modules.pop("pylibafl.sugar", None)
        return False, f"{exc.__class__.__name__}: {exc}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--so", type=Path)
    args = parser.parse_args()

    normal_ok, normal_error = try_normal_import()
    result: dict[str, object] = {
        "python": sys.executable,
        "normal_import": normal_ok,
        "normal_error": normal_error,
        "loaded_from_extension": False,
        "extension_path": None,
        "extension_error": None,
    }
    if normal_ok:
        print(json.dumps(result, sort_keys=True))
        return 0

    candidates = []
    if args.so:
        candidates.append(args.so)
    candidates.extend(
        [
            args.repo_root / "LibAFL/bindings/pylibafl/target/release/libpylibafl.so",
            args.repo_root / "LibAFL/bindings/pylibafl/target/maturin/libpylibafl.so",
        ]
    )

    for candidate in candidates:
        if not candidate.exists():
            continue
        ok, error = load_extension(candidate)
        if ok:
            result["loaded_from_extension"] = True
            result["extension_path"] = str(candidate)
            print(json.dumps(result, sort_keys=True))
            return 0
        result["extension_path"] = str(candidate)
        result["extension_error"] = error

    print(json.dumps(result, sort_keys=True))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
