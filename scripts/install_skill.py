#!/usr/bin/env python3
"""Install the portable Cisco fuzzing skill files into a local skill directory."""

from __future__ import annotations

import argparse
import fnmatch
import os
import shutil
import sys
from pathlib import Path


INCLUDE_PATTERNS = [
    ".gitignore",
    "SKILL.md",
    "README.md",
    "LICENSE",
    "references/**",
    "scripts/*.py",
    "assets/README.md",
    "assets/campaign_manifest.template.json",
    "assets/python_pylibafl_bytes_fuzzer/README.md",
    "assets/python_pylibafl_bytes_fuzzer/*.py",
    "assets/local_cli_smoke_fuzzer/README.md",
    "assets/local_cli_smoke_fuzzer/*.py",
    "assets/rust_libafl_cli_command_fuzzer/Cargo.toml",
    "assets/rust_libafl_cli_command_fuzzer/Cargo.lock",
    "assets/rust_libafl_cli_command_fuzzer/src/**",
    "assets/rust_libafl_afl_forkserver_fuzzer/Cargo.toml",
    "assets/rust_libafl_afl_forkserver_fuzzer/Cargo.lock",
    "assets/rust_libafl_afl_forkserver_fuzzer/src/**",
]

EXCLUDE_PATTERNS = [
    ".git/**",
    "**/__pycache__/**",
    "**/*.pyc",
    "**/.pytest_cache/**",
    "**/target/**",
    "**/debug/**",
    "**/release/**",
    "**/.mypy_cache/**",
    "**/.ruff_cache/**",
    "Fuzzing101/**",
    "LibAFL/**",
    "fuzzingbook-notebooks/**",
    "validation/**",
    "targets/**",
    "agents/**",
    "skills/**",
    "tmp_shared_preflight/**",
]

MANAGER_ROOTS = {
    "codex": Path("~/.codex/skills"),
    "claude": Path("~/.claude/skills"),
}


def parse_skill_name(skill_md: Path) -> str:
    text = skill_md.read_text(encoding="utf-8")
    in_frontmatter = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line == "---":
            if not in_frontmatter:
                in_frontmatter = True
                continue
            break
        if in_frontmatter and line.startswith("name:"):
            return line.split(":", 1)[1].strip().strip('"\'')
    raise ValueError(f"could not find frontmatter name in {skill_md}")


def relpath(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def matches_any(rel: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(rel, pattern) for pattern in patterns)


def should_copy(path: Path, root: Path) -> bool:
    if not path.is_file():
        return False
    rel = relpath(path, root)
    return matches_any(rel, INCLUDE_PATTERNS) and not matches_any(rel, EXCLUDE_PATTERNS)


def iter_portable_files(root: Path) -> list[Path]:
    files = [path for path in root.rglob("*") if should_copy(path, root)]
    return sorted(files, key=lambda item: relpath(item, root))


def default_dest_roots(manager: str) -> list[Path]:
    if manager == "both":
        return [MANAGER_ROOTS["codex"], MANAGER_ROOTS["claude"]]
    return [MANAGER_ROOTS[manager]]


def remove_stale_files(dest: Path, wanted: set[str], dry_run: bool) -> list[str]:
    removed: list[str] = []
    if not dest.exists():
        return removed
    for path in sorted(dest.rglob("*"), reverse=True):
        if path.is_dir():
            try:
                if not dry_run:
                    path.rmdir()
            except OSError:
                pass
            continue
        rel = relpath(path, dest)
        if rel not in wanted:
            removed.append(rel)
            if not dry_run:
                path.unlink()
    return removed


def install_to(root: Path, dest_root: Path, skill_name: str, dry_run: bool, force: bool) -> tuple[int, int]:
    src_files = iter_portable_files(root)
    if not src_files:
        raise RuntimeError("no portable skill files found")

    dest = dest_root.expanduser() / skill_name
    wanted = {relpath(path, root) for path in src_files}

    print(f"install target: {dest}")
    print(f"portable files: {len(src_files)}")

    if dest.exists() and not dest.is_dir():
        raise RuntimeError(f"install target exists and is not a directory: {dest}")

    removed = remove_stale_files(dest, wanted, dry_run) if force else []
    if removed:
        print(f"removed stale files: {len(removed)}")

    copied = 0
    for src in src_files:
        rel = relpath(src, root)
        dst = dest / rel
        print(f"{'would copy' if dry_run else 'copy'} {rel}")
        copied += 1
        if dry_run:
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    return copied, len(removed)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="skill source root; default is this script's parent repository",
    )
    parser.add_argument(
        "--manager",
        choices=["codex", "claude", "both"],
        default="codex",
        help="default skill manager destination root",
    )
    parser.add_argument(
        "--dest-root",
        type=Path,
        action="append",
        help="custom skill root, e.g. ~/.codex/skills; may be repeated and overrides --manager",
    )
    parser.add_argument("--skill-name", help="override install directory name; defaults to SKILL.md frontmatter name")
    parser.add_argument("--dry-run", action="store_true", help="print planned copies without writing")
    parser.add_argument(
        "--force",
        action="store_true",
        help="remove stale files from an existing installed copy before copying portable files",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.source_root.expanduser().resolve()
    skill_md = root / "SKILL.md"
    if not skill_md.is_file():
        print(f"error: SKILL.md not found under {root}", file=sys.stderr)
        return 2

    try:
        skill_name = args.skill_name or parse_skill_name(skill_md)
        dest_roots = args.dest_root or default_dest_roots(args.manager)
        total = 0
        for dest_root in dest_roots:
            copied, removed = install_to(root, dest_root, skill_name, args.dry_run, args.force)
            total += copied
            if removed:
                total += removed
        print(f"done: {'planned' if args.dry_run else 'installed'} {skill_name}")
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
