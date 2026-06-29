# IoT Fuzz Skill

This skill is designed for IoT devices such as Cisco IOS XE devices. It guides
threat-model-first attack-surface selection, reverse analysis, dynamic Rust
LibAFL fuzzer generation, live-device replay, crash triage, and vulnerability
reporting.

# Install

Install for Codex by default:

```bash
python3 scripts/install_skill.py --force
```

Install for Claude Code instead:

```bash
python3 scripts/install_skill.py --manager claude --force
```

Preview what will be copied without writing:

```bash
python3 scripts/install_skill.py --dry-run
```

The installer copies only portable skill files and reusable scaffolds. It does not copy `LibAFL/`, `Fuzzing101/`, `validation/`, `targets/`, `skills/`, or campaign outputs.

# Quick Start

LibAFL and a Rust toolchain are needed:

```bash
git clone https://github.com/AFLplusplus/LibAFL
cargo build --release
```

IDA Pro MCP, Ghidra, or equivalent reverse-engineering tooling is recommended
for binary and shared-library target selection.
