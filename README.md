# IoT Fuzz Skill

This skill is designed for IoT devices such as Cisco IOS XE serials devices vulnerabilities discovery. The skill employ libafl as fuzz toolkit, training on fuzzing101 project and several private Cisco vulnerabilities.

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

Libafl environment is needed:

```bash
git clone https://github.com/AFLplusplus/LibAFL
cargo build --release
```

Then follow `LibAFL/bindings/pylibafl` for python bindings. What's more, IDA Pro MCP or other equal tools for reverse are needed.
