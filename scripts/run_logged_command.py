#!/usr/bin/env python3
"""Run a command and append stdout/stderr/exit metadata to a campaign log."""

from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
import time
from pathlib import Path


def timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, type=Path, help="commands.log path")
    parser.add_argument("--cwd", type=Path, default=Path.cwd())
    parser.add_argument("--name", default="")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="command to run, optionally after --")
    args = parser.parse_args()

    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("missing command")

    args.log.parent.mkdir(parents=True, exist_ok=True)
    start = timestamp()
    proc = subprocess.run(command, cwd=args.cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    end = timestamp()

    with args.log.open("a", encoding="utf-8") as log:
        log.write(f"NAME: {args.name}\n" if args.name else "")
        log.write(f"COMMAND: {shlex.join(command)}\n")
        log.write(f"CWD: {args.cwd.resolve()}\n")
        log.write(f"START: {start}\n")
        log.write("STDOUT:\n")
        log.write(proc.stdout.decode("utf-8", "replace"))
        if proc.stdout and not proc.stdout.endswith(b"\n"):
            log.write("\n")
        log.write("STDERR:\n")
        log.write(proc.stderr.decode("utf-8", "replace"))
        if proc.stderr and not proc.stderr.endswith(b"\n"):
            log.write("\n")
        log.write(f"EXIT_CODE: {proc.returncode}\n")
        log.write(f"END: {end}\n\n")

    sys.stdout.buffer.write(proc.stdout)
    sys.stderr.buffer.write(proc.stderr)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
