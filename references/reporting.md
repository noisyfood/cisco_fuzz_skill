# Vulnerability Reporting

Generate `vulnerability_report.md` only after replay succeeds or the report is explicitly marked unconfirmed.

Use the bundled generator so reports keep the same structure:

```bash
python3 scripts/generate_vulnerability_report.py \
  --report-json report_input.json \
  --manifest campaign_manifest.json \
  --out vulnerability_report.md
```

For confirmed reports, the generator requires a campaign manifest with campaign type and output directory. Use `--check-local-evidence` for local training and offline harnesses where evidence files should exist in the workspace.
When crash artifacts are listed as `path, SHA-256 <64 hex>, <N> bytes`, `--check-local-evidence` verifies the hash and size.

The report status controls confirmation semantics. Use a status that starts with `confirmed` only when replayable crash evidence exists. Status values containing `unconfirmed`, `blocked`, `rejected`, or `needs_permission` do not trigger confirmed-report handling.

## Required Sections

```markdown
# Title

## Summary

## Affected Target

## Environment

## Input Surface

## Reproduction

## Crash Evidence

## Root Cause

## Security Impact

## Exploitability Notes

## Fix or Mitigation

## Evidence Files

## Status
```

## Evidence Requirements

Confirmed reports need:

- Exact target version/build.
- Validated `campaign_manifest.json` path and campaign type.
- `preflight.log` and `commands.log` with command lines and exit codes.
- `decision_log.md` for confirmed live-device findings.
- Exact command or network reproducer.
- Minimal crashing input or protocol transcript.
- SHA-256 and size for crash and minimized inputs.
- `replay_summary.tsv` with at least three nonzero crash/sanitizer exits.
- Crash trace evidence such as ASan/UBSan/QASAN output, GDB backtrace, core summary, device traceback, or crashinfo.
- `root_cause.md`.
- Crash signal, sanitizer trace, core/backtrace, process restart, or device log evidence.
- Root-cause mapping to source line, binary address, or decompiled function.
- Scope statement: local training target, offline firmware harness, or live Cisco device.

For Cisco live-device reports, include:

- Safety scope and whether any config/file/service state changed.
- Device health before and after.
- Core/crashinfo/system-report paths if present.
- Whether shell/gdbserver/core collection was approved.
- The live decision log: preflight facts, why each target interaction was allowed, why any DoS/reload trigger was armed, and why the evidence is sufficient or insufficient.

For Cisco live-device DoS/reload reports, a single explicitly armed trigger can
substitute for `replay_summary.tsv` only when the report includes strong reload
evidence: before/after health, exact trigger bytes and timestamp, persistent
liveness failure after the trigger, recovery CLI or console return reason,
and a core/crashinfo/system-report delta when available. Without that evidence,
use status `unconfirmed` or `needs_permission`.

If the evidence is only a response anomaly or static suspicion, use status `unconfirmed` or `needs_permission`, not `confirmed`.

For blocked reports, include:

- Failed preflight command and exit code.
- Missing target/tool/dependency list.
- Commands intentionally not executed.
- Next human action required to unblock the campaign.
