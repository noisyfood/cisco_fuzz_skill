---
name: cisco-device-fuzz
description: Use when fuzzing Cisco IOS XE or similar Cisco network devices, or when training a local parser fuzzing workflow before applying it to Cisco. Guides an agent through environment preflight, IDA input-surface discovery, fuzzer design, pylibafl/Rust LibAFL construction, no-instrumentation live-device probing/replay, crash collection, minimization, root-cause analysis, and vulnerability reporting.
metadata:
  short-description: Cisco device fuzzing workflow
---

# Cisco Device Fuzzing

## Hard Gate: Preflight First

Before doing any fuzzing, confirm the user has explicitly provided all required environment details. If any item is missing, stop and ask for it; do not start scanning, fuzzing, shell access, or target traffic.

Create `campaign_manifest.json` from [assets/campaign_manifest.template.json](assets/campaign_manifest.template.json), fill it with user-provided facts, then run:

```bash
python3 scripts/campaign_preflight.py --manifest campaign_manifest.json --create-dirs
```

Save this command's stdout, stderr, and exit code in `preflight.log`, and add the command line to `commands.log`. `scripts/run_logged_command.py` is only an audit primitive for this logging; it is not a fuzzer and is optional when another command logger is already in use.

If this command fails, stop. Do not start inventory, fuzzing, shell access, debugger attachment, or target traffic.

Required:

- Device target: IP/hostname, reachable interfaces/VRF, allowed ports/protocols, credentials if authenticated testing is allowed, and an explicit safety scope.
- Shell/debug path: whether a shell exists, how it is reached, whether `gdbserver`/GDB/core collection is allowed, and which actions require human approval.
- Reverse-engineering context: firmware path or extraction root, main binaries/libraries, IDA/Ghidra/MCP availability, symbols or base addresses if known.
- Output location: campaign directory under the workspace for seeds, cases, health logs, crash bundles, and reports.
- Recovery plan for real devices: maintenance window, console/OOB access, reload or power-cycle authority, config backup status, and the human responsible for recovery.

If the provided shell helper writes files, deploys payloads, changes services, attaches debuggers, or starts listeners on the device, treat it as privileged and require explicit user approval before use.

For local training targets, replace the device requirement with: target source/binary path, allowed dependency installs, allowed instrumentation mode, expected input format, and output directory.

## Default Strategy

Use layered fuzzing. Every campaign must define this design record before code or traffic:

- Input model: bytes, file, TLV sequence, HTTP request, XML/JSON tree, CLI command, or protocol transcript.
- Seed source: real samples, captured traffic, IDA-recovered constants, schemas, or minimized proof input.
- Mutator: byte mutation first, then token/grammar/field-aware mutation when structure is known.
- Executor: Python callable, forked CLI process, Rust LibAFL executor, offline binary harness, Rust LibAFL/pylibafl live driver, or gated replay/probe helper.
- Observer: coverage when available; otherwise exit status, signal, timeout, response class, logs, PID/core/crashinfo deltas.
- Feedback: keep inputs only when they add coverage/state/response novelty or improve reachability.
- Objective: crash, sanitizer finding, signal, hang, device traceback, process restart, new core, or confirmed health regression.
- Reducer: minimize first by syntax/protocol units, then by bytes.

- For text or tagged formats, add a dictionary/token layer early. Include syntax tokens, magic values, boundary integers, command keywords, protocol field names, and recovered constants from IDA/Ghidra.
- For CLI tools with security-relevant options, fuzz only a bounded argument profile. Keep required reachability flags fixed and mutate a small allowlist of optional flags; never pass arbitrary generated shell arguments.
- For large modular applications, prefer a narrow parser harness over full application startup. Feed memory buffers directly into the target parser when possible, and use allowlist/partial instrumentation or module-scoped coverage to avoid rewarding unrelated dispatch paths.
- For source-built local campaigns, use `local_training.target.kind=source_build` or `planned_harness` in the manifest. Preflight then validates source/materials and planned output location before build, instead of requiring the final binary to already exist.
- For binary-only offline targets, use QEMU/Frida only after architecture, loader, library root, target ELF, and legal/operational authorization are validated. Persistent mode requires a documented function-boundary loop address and a stability check.
- Local training target: use instrumentation when available to learn corpus growth, crash triage, reduction, and report generation.
- Cisco offline harness: use extracted firmware and reverse engineering to isolate parsers or libraries, then fuzz those locally when practical.
- Cisco live device: use low-rate black-box or semi-graybox fuzzing with response classification, liveness probes, health snapshots, anomaly freezing, replay, minimization, and crash triage.
- Static support: use IDA Pro MCP/Ghidra/angr to identify parser state machines, length fields, message types, dangerous sinks, and PC-to-function crash mapping.

For real Cisco IOS XE systems, do not assume full-device QEMU emulation is viable. Prefer protocol-aware low-speed fuzzing against confirmed entry points.

## Training-To-Cisco Bridge

Fuzzing101 teaches the mechanics of corpus growth, dictionaries, parser
harnesses, sanitizer crashes, minimization, and report writing. Real Cisco
device work keeps those mechanics but changes the observer and safety model:

- Coverage feedback is often unavailable on hardware, so use response classes,
  timing, service liveness, process/core deltas, logs, and recovery evidence as
  feedback.
- Local parser crashes can be replayed repeatedly; live reload/DoS triggers
  must be isolated into explicit one-shot reproducers with recovery planning.
- File-format dictionaries become protocol dictionaries: magic values, TLV
  types, length sentinels, method IDs, transaction IDs, CLI/YANG constants, and
  IDA-recovered string or enum values.
- Tutorial harnesses can run fast and parallel; live protocol drivers should be
  low-rate, single-case on anomaly, and bound to a manifest that names the
  target, permitted ports, recovery path, and stop conditions.
- A finding is not confirmed by a socket timeout alone. It needs a bridge from
  input field to parser state to crash/reload evidence, such as uptime reset,
  return reason, traceback, core/crashinfo, or a new system report.

## Selected Fuzzers

Choose the fuzzer by target shape:

- Fuzzer construction rule: build campaign fuzzers with `pylibafl` or Rust LibAFL. AFL++ tools such as `afl-clang-fast`, `afl-qemu-trace`, and QASAN may be used for instrumentation, binary execution support, replay, and triage, but not as the campaign fuzzer (`afl-fuzz` is not a selected fuzzer path for this skill).
- Simple local harness: use `assets/python_pylibafl_bytes_fuzzer/pylibafl_simple_bytes_fuzzer.py` as a scaffold, or use `pylibafl` sugar directly, when the target is a Python-callable parser or a small in-process function. This is for local training and tiny safe parsers, not for live Cisco device traffic.
- Complex local harness: write Rust with LibAFL when custom input types, command execution, forkserver, QEMU/Frida, persistent mode, multi-process scaling, or structured mutators are needed; use `assets/rust_libafl_cli_command_fuzzer` for file-input CLI targets.
- AFL-instrumented forkserver target: build the target or harness with `afl-clang-fast`/`afl-clang-lto` and optional allowlist/partial instrumentation, then run it with `assets/rust_libafl_afl_forkserver_fuzzer`; do not switch to `afl-fuzz`.
- Local CLI smoke test: use `scripts/local_cli_mutation_fuzzer.py` only to validate case generation, execution, finding capture, and reproduction before building a heavier fuzzer. A smoke finding is confirmed only after three clean replays, debugger/crash evidence, minimization notes, root-cause mapping, and a report.
- Source-built large parser: create a small harness, build with ASan/coverage if available, use dictionary tokens, and run multiple independent seeds/RNG instances before concluding a target is not reached.
- Binary-only offline parser: use LibAFL QEMU/Frida in an offline lab after preflight validates toolchain, architecture, loader, libraries, and persistent-loop evidence. AFL++ QEMU/QASAN remains auxiliary replay/triage tooling.
- Live Cisco target: if fuzzing is authorized, build a Rust LibAFL or pylibafl protocol driver with low-rate scheduling, response/health feedback, and strict stop conditions. `scripts/live_probe_executor.py` is only a gated baseline/replay/probe helper, not the campaign fuzzer.
- Protocol-specific live drivers and replay helpers must call `scripts/live_driver_gate.py` before traffic, then collect the same evidence and stop on the same health conditions.
- Known or suspected high-impact live reproducers must be separated from normal mutation queues. Default to dry-run, baseline, or non-destructive boundary probes; send a reload/DoS trigger only through an explicit armed one-shot option and stop immediately for health collection.

Do not make instrumentation a hard dependency for Cisco device work. Instrumentation is a training/offline acceleration technique, not the live-device assumption.

Read [references/fuzzer_usage.md](references/fuzzer_usage.md), [references/libafl_workflow.md](references/libafl_workflow.md), and [references/script_inventory.md](references/script_inventory.md) before running or adapting a fuzzer.

## IDA Input-Surface Discovery

Before writing a fuzzer for a binary target, identify input surfaces. Use [references/ida_input_surface.md](references/ida_input_surface.md).

Minimum output:

- Candidate entry function and caller chain.
- Input source: file, socket, HTTP route, CLI command, IPC, YANG/RPC/action, SNMP/BER, TLV, or environment.
- Input buffer pointer and length source.
- Framing fields: magic, command type, length, count, checksum, padding, transaction ID.
- Sink class: memcpy/strcpy/format, allocator/free, parser recursion, table index, integer conversion, shell/CLI invocation, file path.
- Fuzzer mode recommendation: pylibafl, Rust LibAFL command/forkserver/QEMU/Frida, or Rust LibAFL/pylibafl live protocol driver. Mark gated live probes as replay/health helpers, not fuzzer mode.

## Workflow

1. Run the preflight gate above and validate the campaign manifest with [scripts/campaign_preflight.py](scripts/campaign_preflight.py).
2. Inventory the attack surface from firmware, configs, CLI help, YANG, nginx/OpenResty routes, protocol ports, IDA strings/xrefs, and prior evidence.
3. Use IDA/Ghidra/angr as needed to identify input surfaces and choose one narrow target.
4. Select fuzzer mode: pylibafl for simple local harnesses, Rust LibAFL for complex/offline/live harnesses, and only use live probe helpers for gated baseline/replay.
5. For local training, use the same manifest, seed, fuzzer, crash triage, and report flow on a local target before applying the workflow to Cisco.
6. Build seeds from real messages, valid files, protocol notes, YANG schemas, HTTP routes, CLI output, or prior proof-of-concept traffic. Add dictionary tokens when syntax or magic values matter.
7. Capture a baseline: local target version or live-device liveness, response class, process list, filtered logs, and core/crash directories. For live protocols, prove parser reachability with a safe request before any malformed field or length sweep.
8. Fuzz with a bounded budget. For live devices, fuzz at low rate and run health probes after each case or small batch.
9. On crash/anomaly, stop immediately. Save input, response, timing, health delta, logs, and core/crash listings. Treat a network timeout as a lead until a reload, process restart, traceback, or new core/crash artifact is collected.
10. Replay the case at least three times. If reproducible, minimize the input.
11. Map the crash: ASan/GDB/core locally, or PC/backtrace/core/logs on Cisco if allowed. Prefer `bt 80`, `info registers`, and `thread apply all bt` when practical. Connect input fields to parser paths.
12. Generate a vulnerability report using [references/reporting.md](references/reporting.md) and `scripts/generate_vulnerability_report.py`. Confirm only with replayable evidence; otherwise mark rejected, blocked, or needs-permission.

For a known live reload reproducer, replace broad replay with the approved
reproducer plan: baseline, one explicitly armed trigger, recovery, evidence
collection, and protocol-field minimization. Do not loop a reload trigger to
satisfy the three-replay rule unless the user separately authorizes repeated
service impact.

## Multi-Agent Pattern

Use subagents when the user has allowed multi-agent work and tasks can run independently:

- Surface agent: inventories firmware/IDA/YANG/routes and proposes fuzzing targets.
- Harness agent: writes pylibafl or Rust LibAFL harnesses for one selected target.
- Crash agent: replays, minimizes, debugs, and maps crashes.
- Review agent: independently reruns the reproducer and checks the report evidence.
- Cisco live agent: manages real-device safety gates, health checks, and non-destructive traffic.

## Safety Defaults

- Do not modify device configuration, users, files, services, or package state without explicit approval.
- Do not fuzz state-changing HTTP methods, RESTCONF/NETCONF operations, CLI config commands, file uploads, reload/action RPCs, or destructive diagnostics unless the user explicitly authorizes each class.
- Do not use high concurrency until a stable baseline and rollback/recovery procedure exist.
- Do not run `get_shell.py`, `gdbserver`, `gcore`, service restarts, reloads, or destructive cleanup without explicit approval.
- Treat DoS, reload, watchdog, CPUHOG, process restart, and persistent service degradation as stop conditions.
- For pre-auth live services, keep authentication state, device configuration, and unrelated protocols unchanged. A protocol driver may open a socket and send scoped test frames only after the live gate passes.
- For DoS/reload reproducers, require an explicit command-line arm flag, a case count of one for the trigger, and an immediate post-trigger health/recovery phase.
- Keep every campaign reproducible: save seeds, generated cases, exact command lines, timestamps, and health snapshots.
- Keep `preflight.log` and `commands.log` in the campaign directory. Record each preflight, build, fuzzer, replay, debugger, minimizer, and report-generation command with exit code.

## Evidence Format

Each campaign should create:

- `campaign_manifest.json`
- `preflight.log`
- `commands.log`
- `seeds/`
- `cases/`
- `responses/`
- `health/health_before.json`
- `health/health_after.json`
- `anomalies/*.jsonl`
- `crashes/`
- `minimized/`
- `root_cause.md`
- `reports/gdb_or_crash_trace.txt`
- `reports/vulnerability_report.md`

Use [references/crash_triage.md](references/crash_triage.md) when a crash, reset, traceback, core file, or process restart is observed.
