#!/usr/bin/env python3
"""Small file-input mutation supervisor for local CLI fuzzing smoke tests."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import shlex
import subprocess
import time
from pathlib import Path


def load_seeds(seed_dir: Path) -> list[tuple[str, bytes]]:
    seeds: list[tuple[str, bytes]] = []
    for path in sorted(seed_dir.iterdir()):
        if path.is_file() and path.stat().st_size:
            seeds.append((path.name, path.read_bytes()))
    if not seeds:
        raise SystemExit(f"no non-empty seed files in {seed_dir}")
    return seeds


SANITIZER_MARKERS = (
    b"AddressSanitizer",
    b"UndefinedBehaviorSanitizer",
    b"MemorySanitizer",
    b"LeakSanitizer",
    b"SUMMARY: AddressSanitizer",
    b"SUMMARY: UndefinedBehaviorSanitizer",
    b"runtime error:",
)


def decode_escaped_bytes(text: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(text):
        ch = text[i]
        if ch != 0x5C or i + 1 >= len(text):
            out.append(ch)
            i += 1
            continue
        esc = text[i + 1]
        if esc == ord("x") and i + 3 < len(text):
            pair = text[i + 2 : i + 4]
            if re.fullmatch(rb"[0-9a-fA-F]{2}", pair):
                out.append(int(pair, 16))
                i += 4
                continue
        mapped = {
            ord("0"): 0,
            ord("a"): 7,
            ord("b"): 8,
            ord("f"): 12,
            ord("n"): 10,
            ord("r"): 13,
            ord("t"): 9,
            ord("v"): 11,
            ord("\\"): 92,
            ord('"'): 34,
        }.get(esc)
        if mapped is not None:
            out.append(mapped)
            i += 2
            continue
        out.append(esc)
        i += 2
    return bytes(out)


def afl_dict_value(line: bytes) -> bytes | None:
    first = line.find(b'"')
    if first == -1:
        return None
    escaped = False
    end = -1
    for idx in range(first + 1, len(line)):
        ch = line[idx]
        if escaped:
            escaped = False
        elif ch == 0x5C:
            escaped = True
        elif ch == 0x22:
            end = idx
            break
    if end == -1:
        raise SystemExit(f"unterminated AFL dictionary entry: {line!r}")
    return decode_escaped_bytes(line[first + 1 : end])


def load_tokens(token_args: list[str], token_file: Path | None) -> list[bytes]:
    tokens = [decode_escaped_bytes(token.encode()) for token in token_args]
    if token_file:
        for line in token_file.read_bytes().splitlines():
            line = line.strip()
            if line and not line.startswith(b"#"):
                tokens.append(afl_dict_value(line) or line)
    return tokens


def mutate(data: bytes, tokens: list[bytes], rng: random.Random, max_len: int) -> tuple[bytes, list[dict[str, object]]]:
    buf = bytearray(data)
    ops: list[dict[str, object]] = []
    for _ in range(rng.randint(1, 6)):
        choices = ["flip", "set", "insert", "delete", "repeat"]
        if tokens:
            choices.append("token")
        op = rng.choice(choices)
        if op == "flip" and buf:
            pos = rng.randrange(len(buf))
            bit = 1 << rng.randrange(8)
            old = buf[pos]
            buf[pos] ^= bit
            ops.append({"op": op, "pos": pos, "bit": bit, "old": old, "new": buf[pos]})
        elif op == "set" and buf:
            pos = rng.randrange(len(buf))
            val = rng.choice([0, 1, 2, 7, 15, 16, 31, 32, 63, 64, 127, 128, 254, 255, rng.randrange(256)])
            old = buf[pos]
            buf[pos] = val
            ops.append({"op": op, "pos": pos, "old": old, "new": val})
        elif op == "insert":
            pos = rng.randrange(len(buf) + 1)
            chunk = bytes(rng.randrange(32, 127) for _ in range(rng.randint(1, 16)))
            buf[pos:pos] = chunk
            ops.append({"op": op, "pos": pos, "len": len(chunk)})
        elif op == "delete" and buf:
            pos = rng.randrange(len(buf))
            end = min(len(buf), pos + rng.randint(1, 16))
            del buf[pos:end]
            ops.append({"op": op, "pos": pos, "len": end - pos})
        elif op == "repeat" and buf:
            pos = rng.randrange(len(buf))
            end = min(len(buf), pos + rng.randint(1, 16))
            count = rng.randint(2, 8)
            buf[pos:end] = buf[pos:end] * count
            ops.append({"op": op, "pos": pos, "len": end - pos, "count": count})
        elif op == "token":
            pos = rng.randrange(len(buf) + 1)
            token = rng.choice(tokens)
            buf[pos:pos] = token
            ops.append({"op": op, "pos": pos, "token": token.decode("utf-8", "replace")})
    if len(buf) > max_len:
        del buf[max_len:]
        ops.append({"op": "truncate", "max_len": max_len})
    return bytes(buf), ops


def has_sanitizer_output(stdout: bytes, stderr: bytes) -> bool:
    combined = stdout + b"\n" + stderr
    return any(marker in combined for marker in SANITIZER_MARKERS)


def classify(returncode: int | None, timed_out: bool, stdout: bytes, stderr: bytes) -> str:
    if timed_out:
        return "timeout"
    if has_sanitizer_output(stdout, stderr):
        return "sanitizer"
    if returncode is None:
        return "unknown"
    if returncode < 0:
        return "signal"
    if returncode >= 128:
        return "crash_like_exit"
    if returncode != 0:
        return "nonzero"
    return "ok"


def write_jsonl(path: Path, obj: dict[str, object]) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cmd-template", required=True, help="command string containing @@ as the generated file path")
    parser.add_argument("--seed-dir", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--case-extension", default=".bin")
    parser.add_argument("--cases", type=int, default=200)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--rng-seed", type=int, default=1)
    parser.add_argument("--max-len", type=int, default=4096)
    parser.add_argument("--max-findings", type=int, default=0, help="stop after this many unique non-ok signatures; 0 disables")
    parser.add_argument("--stop-on-crash", action="store_true")
    parser.add_argument("--token", action="append", default=[])
    parser.add_argument("--token-file", type=Path)
    args = parser.parse_args()

    if "@@" not in args.cmd_template:
        raise SystemExit("--cmd-template must contain @@")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    cases_dir = args.out_dir / "cases"
    cases_dir.mkdir(exist_ok=True)
    results_path = args.out_dir / "results.jsonl"
    findings_path = args.out_dir / "findings.jsonl"
    for path in (results_path, findings_path):
        if path.exists():
            path.unlink()

    seeds = load_seeds(args.seed_dir)
    tokens = load_tokens(args.token, args.token_file)
    rng = random.Random(args.rng_seed)
    base_cmd = shlex.split(args.cmd_template)
    seen: set[str] = set()

    manifest = {
        "cmd_template": args.cmd_template,
        "seed_dir": str(args.seed_dir),
        "out_dir": str(args.out_dir),
        "case_extension": args.case_extension,
        "cases": args.cases,
        "timeout": args.timeout,
        "rng_seed": args.rng_seed,
        "max_len": args.max_len,
        "max_findings": args.max_findings,
        "stop_on_crash": args.stop_on_crash,
        "token": args.token,
        "token_file": str(args.token_file) if args.token_file else None,
        "token_count": len(tokens),
        "token_sha256": hashlib.sha256(b"\0".join(tokens)).hexdigest() if tokens else "",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    (args.out_dir / "run_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    for idx in range(args.cases):
        seed_name, seed = rng.choice(seeds)
        payload, ops = mutate(seed, tokens, rng, args.max_len)
        case_path = cases_dir / f"id_{idx:06d}{args.case_extension}"
        case_path.write_bytes(payload)

        cmd = [part.replace("@@", str(case_path)) for part in base_cmd]
        timed_out = False
        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=args.timeout)
            returncode = proc.returncode
            stdout = proc.stdout
            stderr = proc.stderr
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            returncode = None
            stdout = exc.stdout or b""
            stderr = exc.stderr or b""

        status = classify(returncode, timed_out, stdout, stderr)
        record: dict[str, object] = {
            "case_id": f"{idx:06d}",
            "seed": seed_name,
            "case": str(case_path),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "payload_len": len(payload),
            "returncode": returncode,
            "status": status,
            "stdout_prefix": stdout[:300].decode("utf-8", "replace"),
            "stderr_prefix": stderr[:300].decode("utf-8", "replace"),
            "repro": shlex.join(cmd),
            "mutation": ops,
        }
        write_jsonl(results_path, record)

        signature = repr((status, returncode, stderr.splitlines()[:2]))
        if status != "ok" and signature not in seen:
            seen.add(signature)
            write_jsonl(findings_path, record)
            print(json.dumps(record, sort_keys=True), flush=True)
            if args.stop_on_crash and status in {"signal", "crash_like_exit", "timeout", "sanitizer"}:
                return 2
            if args.max_findings and len(seen) >= args.max_findings:
                return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
