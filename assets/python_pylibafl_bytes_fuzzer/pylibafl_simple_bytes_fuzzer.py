#!/usr/bin/env python3
"""Scaffold pylibafl bytes fuzzer for Python-callable harnesses.

This is an asset/template, not a Cisco runtime primitive. Copy or adapt it when
a target can be safely called as harness(data: bytes) inside Python.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import signal
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Callable


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def import_sugar(extension_path: Path | None = None):
    try:
        import pylibafl.sugar as sugar  # type: ignore[import-not-found]

        return sugar
    except ModuleNotFoundError:
        pass

    candidates = []
    if extension_path:
        candidates.append(extension_path)
    candidates.extend(
        [
            repo_root() / "LibAFL/bindings/pylibafl/target/release/libpylibafl.so",
            repo_root() / "LibAFL/bindings/pylibafl/target/maturin/libpylibafl.so",
        ]
    )

    for candidate in candidates:
        if not candidate.exists():
            continue
        spec = importlib.util.spec_from_file_location("pylibafl", candidate)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        sys.modules["pylibafl"] = module
        spec.loader.exec_module(module)
        import pylibafl.sugar as sugar  # type: ignore[import-not-found]

        return sugar

    raise SystemExit("cannot import pylibafl; run scripts/pylibafl_import_probe.py and build/install the binding")


def load_module(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(path.stem, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load harness script: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_harness(path: Path, func_name: str) -> Callable[[bytes], object]:
    module = load_module(path)
    func = getattr(module, func_name, None)
    if not callable(func):
        raise SystemExit(f"{path} does not define callable {func_name}(data: bytes)")
    return func


def ensure_seed_dir(path: Path) -> None:
    if not path.is_dir():
        raise SystemExit(f"seed directory does not exist: {path}")
    if not any(item.is_file() and item.stat().st_size > 0 for item in path.iterdir()):
        raise SystemExit(f"seed directory has no non-empty files: {path}")


def parse_cores(value: str) -> list[int]:
    cores = [int(part) for part in value.split(",") if part.strip()]
    if not cores:
        raise argparse.ArgumentTypeError("at least one core is required")
    return cores


def run_with_watchdog(seconds: int) -> int:
    cmd = [sys.executable, str(Path(__file__).resolve()), *sys.argv[1:], "--child-run"]
    proc = subprocess.Popen(cmd, start_new_session=True)
    try:
        return proc.wait(timeout=seconds)
    except subprocess.TimeoutExpired:
        print(f"wall time reached after {seconds}s; stopping pylibafl process group", flush=True)
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=3)
            return 0
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--harness-script", required=True, type=Path)
    parser.add_argument("--harness-func", default="harness")
    parser.add_argument("--seed-dir", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--iterations", default=1000, type=int)
    parser.add_argument("--broker-port", default=1337, type=int)
    parser.add_argument("--cores", default=[0], type=parse_cores)
    parser.add_argument("--timeout-ms", type=int)
    parser.add_argument("--tokens-file", type=Path)
    parser.add_argument("--pylibafl-extension", type=Path)
    parser.add_argument(
        "--wall-time-sec",
        type=int,
        help="hard wall-clock stop for pylibafl launcher/broker campaigns",
    )
    parser.add_argument("--child-run", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.iterations < 1:
        raise SystemExit("--iterations must be at least 1")
    if args.wall_time_sec is not None:
        if args.wall_time_sec < 1:
            raise SystemExit("--wall-time-sec must be at least 1")
        if not args.child_run:
            return run_with_watchdog(args.wall_time_sec)

    ensure_seed_dir(args.seed_dir)
    args.out_dir.mkdir(parents=True, exist_ok=True)

    harness = load_harness(args.harness_script, args.harness_func)
    sugar = import_sugar(args.pylibafl_extension)
    fuzzer = sugar.InProcessBytesCoverageSugar(
        input_dirs=[str(args.seed_dir)],
        output_dir=str(args.out_dir),
        broker_port=args.broker_port,
        cores=args.cores,
        iterations=args.iterations,
        tokens_file=str(args.tokens_file) if args.tokens_file else None,
        timeout=args.timeout_ms,
    )
    fuzzer.run(harness)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
