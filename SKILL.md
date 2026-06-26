---
name: cisco-device-fuzz
description: Use when fuzzing Cisco IOS XE or similar Cisco network devices, extracted Cisco firmware parsers, or Cisco shared libraries, or when training a local parser fuzzing workflow before applying it to Cisco. Guides an agent through environment preflight, IDA input-surface discovery, shared-library harness planning, fuzzer design, pylibafl/Rust LibAFL construction, no-instrumentation live-device probing/replay, crash collection, minimization, root-cause analysis, and vulnerability reporting.
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

For `cisco_live`, set `live_profile` before preflight:

- `production_conservative`: read-only or non-destructive first contact. Requires recovery, shell/debug policy, maintenance details, and conservative acknowledgements.
- `lab_minimal_one_shot`: scoped lab traffic with a small first-contact budget. Useful when the device is a lab target but destructive actions are not yet authorized.
- `destructive_lab`: user-authorized lab device where large-scale fuzzing, configuration changes, shell/debugger actions, reload/service disruption, and destructive replay may be allowed. This profile replaces conservative recovery blockers with explicit action allowlists, campaign budget, required observers, evidence capture, stop rules, and crash attribution readiness.

Required:

- Device target: IP/hostname, reachable interfaces/VRF, allowed ports/protocols, credentials if authenticated testing is allowed, and an explicit safety scope.
- Shell/debug path: whether a shell exists, how it is reached, whether `gdbserver`/GDB/core collection is allowed, and which actions require human approval.
- Reverse-engineering context: firmware path or extraction root, main binaries/libraries, shared-library candidates if applicable, IDA/Ghidra/MCP availability, symbols or base addresses if known.
- Output location: campaign directory under the workspace for seeds, cases, health logs, crash bundles, and reports.
- Recovery plan for real devices: maintenance window, console/OOB access, reload or power-cycle authority, config backup status, and the human responsible for recovery.

If the provided shell helper writes files, deploys payloads, changes services, attaches debuggers, or starts listeners on the device, treat it as privileged and require explicit user approval before use.

For local training targets, replace the device requirement with: target source/binary path, allowed dependency installs, allowed instrumentation mode, expected input format, and output directory.

For pure `cisco_offline` firmware, parser, or `.so` harness campaigns, replace live device and shell requirements with `offline_scope`: source materials, local execution authorization, whether a live device is available, and whether device context is required. Do not invent device or shell values when the campaign is offline-only.

## Default Strategy

Use layered fuzzing. Every campaign must define this design record before code or traffic:

- Input model: bytes, file, TLV sequence, HTTP request, XML/JSON tree, CLI command, protocol transcript, or shared-library function call.
- Seed source: real samples, captured traffic, IDA-recovered constants, schemas, or minimized proof input.
- Mutator: byte mutation first, then token/grammar/field-aware mutation when structure is known.
- Executor: Python callable, forked CLI process, Rust LibAFL executor, offline binary harness, shared-library harness, Rust LibAFL/pylibafl live driver, or gated replay/probe helper.
- Observer: coverage when available; otherwise exit status, signal, timeout, response class, logs, PID/core/crashinfo deltas.
- Feedback: keep inputs only when they add coverage/state/response novelty or improve reachability.
- Objective: crash, sanitizer finding, signal, hang, device traceback, process restart, new core, or confirmed health regression.
- Reducer: minimize first by syntax/protocol units, then by bytes.
- Live profile: for real devices, choose whether the campaign is conservative, lab one-shot, or destructive lab before any traffic. In `destructive_lab`, runtime evidence can outrank additional static confirmation once crash attribution and observers are ready.

- For text or tagged formats, add a dictionary/token layer early. Include syntax tokens, magic values, boundary integers, command keywords, protocol field names, and recovered constants from IDA/Ghidra.
- For CLI tools with security-relevant options, fuzz only a bounded argument profile. Keep required reachability flags fixed and mutate a small allowlist of optional flags; never pass arbitrary generated shell arguments.
- For large modular applications, prefer a narrow parser harness over full application startup. Feed memory buffers directly into the target parser when possible, and use allowlist/partial instrumentation or module-scoped coverage to avoid rewarding unrelated dispatch paths.
- For extracted Cisco `.so` libraries, use `offline_execution.target_kind=shared_library_harness`. Do not fuzz until the manifest records the target library, dependency root, candidate functions, ABI/calling-convention notes, execution strategy, seed directory, and state-reset plan.
- For source-built local campaigns, use `local_training.target.kind=source_build` or `planned_harness` in the manifest. Preflight then validates source/materials and planned output location before build, instead of requiring the final binary to already exist.
- For binary-only offline targets, use QEMU/Frida only after architecture, loader, library root, target ELF, and legal/operational authorization are validated. Persistent mode requires a documented function-boundary loop address and a stability check.
- Local training target: use instrumentation when available to learn corpus growth, crash triage, reduction, and report generation.
- Cisco offline harness: use extracted firmware and reverse engineering to isolate parsers or libraries, then fuzz those locally when practical. For `.so` libraries, separate library selection/reachability analysis from harness execution and use [references/shared_library_harness.md](references/shared_library_harness.md).
- Cisco live device: use low-rate black-box or semi-graybox fuzzing with response classification, liveness probes, health snapshots, anomaly freezing, replay, minimization, and crash triage.
- Static support: use IDA Pro MCP/Ghidra/angr to identify parser state machines, length fields, message types, dangerous sinks, and PC-to-function crash mapping.

For real Cisco IOS XE systems, do not assume full-device QEMU emulation is viable. Prefer protocol-aware low-speed fuzzing against confirmed entry points.

## Technique Gates

Before building or running a campaign fuzzer, apply these gates:

- Harness gate: read [references/harness_design.md](references/harness_design.md), then prove that at least one valid seed reaches the intended parser, function, route, or protocol state. Do not fuzz an unproven harness.
- Dictionary gate: read [references/dictionary_strategy.md](references/dictionary_strategy.md), then record token sources and expected parser barriers before enabling token mutations.
- Coverage/reachability gate: read [references/coverage_and_reachability.md](references/coverage_and_reachability.md), then define whether progress is measured by local coverage, LibAFL observer state, QEMU/Frida evidence, or live response/health deltas.
- Obstacle gate: read [references/fuzzing_obstacles.md](references/fuzzing_obstacles.md), then choose seed improvement, token help, field fixups, environment setup, or a documented local-only patch. Do not patch live devices or treat patched-only crashes as confirmed production bugs.
- Shared-library gate: for extracted `.so` targets, read [references/shared_library_harness.md](references/shared_library_harness.md) and record ABI, loader, dependency root, candidate functions, state reset, and isolation strategy before fuzzing.
- Crash attribution gate: for aggressive live testing, read [references/crash_attribution.md](references/crash_attribution.md) and record the controlled fields, parser path, suspected sink, fault oracle, symbolization plan, and replay plan.
- Destructive lab gate: before large-scale live testing or destructive actions, read [references/destructive_lab.md](references/destructive_lab.md), set `live_profile=destructive_lab`, and fill the action allowlist, observers, evidence capture, stop rules, and campaign budget.

## Training-To-Cisco Bridge

Fuzzing101 teaches the mechanics of corpus growth, dictionaries, parser
harnesses, sanitizer crashes, minimization, and report writing. Real Cisco
device work keeps those mechanics but changes the observer and safety model:

- Coverage feedback is often unavailable on hardware, so use response classes,
  timing, service liveness, process/core deltas, logs, and recovery evidence as
  feedback.
- Local parser crashes can be replayed repeatedly; live reload/DoS triggers
  are one-shot in conservative profiles but can become budgeted destructive
  lab evidence when the manifest authorizes repeated crash/reload replay.
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
- Local CLI smoke test: use `assets/local_cli_smoke_fuzzer/local_cli_mutation_fuzzer.py` only to validate case generation, execution, finding capture, and reproduction before building a heavier fuzzer. A smoke finding is confirmed only after three clean replays, debugger/crash evidence, minimization notes, root-cause mapping, and a report.
- Source-built large parser: create a small harness, build with ASan/coverage if available, use dictionary tokens, and run multiple independent seeds/RNG instances before concluding a target is not reached.
- Cisco shared-library harness: for extracted `.so` targets, prefer a narrow Rust LibAFL harness with fork isolation, forkserver, QEMU, or Frida when native crashes can corrupt process state. Use instrumentation when the harness or rebuilt library supports it, but record whether coverage observes the library internals or only the harness glue.
- Binary-only offline parser: use LibAFL QEMU/Frida in an offline lab after preflight validates toolchain, architecture, loader, libraries, and persistent-loop evidence. AFL++ QEMU/QASAN remains auxiliary replay/triage tooling.
- Live Cisco target: if fuzzing is authorized, build a Rust LibAFL or pylibafl protocol driver with low-rate scheduling, response/health feedback, and strict stop conditions. `scripts/live_probe_executor.py` is only a gated baseline/seed-replay helper, not the campaign fuzzer.
- Protocol-specific live drivers and replay helpers must call `scripts/live_driver_gate.py` before traffic, then collect the same evidence and stop on the same health conditions.
- Known or suspected high-impact live reproducers must be separated from normal mutation queues. In `production_conservative` and `lab_minimal_one_shot`, default to dry-run, baseline, or non-destructive boundary probes; send a reload/DoS trigger only through an explicit armed one-shot option and stop immediately for health collection. In `destructive_lab`, known crash/reload triggers may be part of the campaign queue when the action is allowed by the manifest and the observer/evidence chain remains intact.

Do not make instrumentation a hard dependency for Cisco device work. Instrumentation is a training/offline acceleration technique, not the live-device assumption.

Read [references/fuzzer_usage.md](references/fuzzer_usage.md), [references/libafl_workflow.md](references/libafl_workflow.md), [references/harness_design.md](references/harness_design.md), [references/dictionary_strategy.md](references/dictionary_strategy.md), [references/coverage_and_reachability.md](references/coverage_and_reachability.md), [references/fuzzing_obstacles.md](references/fuzzing_obstacles.md), [references/shared_library_harness.md](references/shared_library_harness.md), [references/crash_attribution.md](references/crash_attribution.md), [references/destructive_lab.md](references/destructive_lab.md), and [references/script_inventory.md](references/script_inventory.md) before running or adapting a fuzzer.

## IDA Input-Surface Discovery

Before writing a fuzzer for a binary target, identify input surfaces. Use [references/ida_input_surface.md](references/ida_input_surface.md).

Minimum output:

- Candidate entry function and caller chain.
- Target binary or shared library, dependency root, and exported/internal function status.
- Input source: file, socket, HTTP route, CLI command, IPC, YANG/RPC/action, SNMP/BER, TLV, or environment.
- Input buffer pointer and length source.
- Framing fields: magic, command type, length, count, checksum, padding, transaction ID.
- Sink class: memcpy/strcpy/format, allocator/free, parser recursion, table index, integer conversion, shell/CLI invocation, file path.
- Fuzzer mode recommendation: pylibafl, Rust LibAFL command/forkserver/QEMU/Frida, shared-library harness, or Rust LibAFL/pylibafl live protocol driver. Mark gated live probes as replay/health helpers, not fuzzer mode.

## Workflow

1. Run the preflight gate above and validate the campaign manifest with [scripts/campaign_preflight.py](scripts/campaign_preflight.py).
2. Inventory the attack surface from firmware, configs, CLI help, YANG, nginx/OpenResty routes, protocol ports, shared libraries, IDA strings/xrefs, and prior evidence.
3. Use IDA/Ghidra/angr as needed to identify input surfaces and choose one narrow target.
4. Select fuzzer mode: pylibafl for simple local harnesses, Rust LibAFL for complex/offline/live harnesses, shared-library harness mode for extracted `.so` targets, and only use live probe helpers for gated baseline/replay.
5. Apply the technique gates for harness design, dictionary strategy, reachability, and fuzzing obstacles. For `.so` targets, apply the shared-library gate as well.
6. For local training, use the same manifest, seed, fuzzer, crash triage, and report flow on a local target before applying the workflow to Cisco.
7. Build seeds from real messages, valid files, protocol notes, YANG schemas, HTTP routes, CLI output, or prior proof-of-concept traffic. Add dictionary tokens when syntax or magic values matter.
8. Capture a baseline: local target version or live-device liveness, response class, process list, filtered logs, and core/crash directories. For live protocols, prove parser reachability with a safe request before any malformed field or length sweep.
9. Fuzz with a bounded budget. For live devices, use the selected `live_profile`: conservative and one-shot profiles run low-rate health checks after each case or small batch; `destructive_lab` may run large-scale mutation, configuration changes, and destructive replay within the manifest budget once crash attribution and required observers are ready.
10. On crash/anomaly, save input, response, timing, health delta, logs, and core/crash listings. In conservative and one-shot profiles, stop and triage before continuing. In `destructive_lab`, treat reloads, watchdogs, process restarts, and new core/crashinfo as evidence sources; continue while observers remain valid, budget remains, and no `destructive_lab.stop_when` rule fires.
11. Replay the case at least three times. If reproducible, minimize the input.
12. Map the crash: ASan/GDB/core locally, or PC/backtrace/core/logs on Cisco if allowed. Prefer `bt 80`, `info registers`, and `thread apply all bt` when practical. Connect input fields to parser paths.
13. Generate a vulnerability report using [references/reporting.md](references/reporting.md) and `scripts/generate_vulnerability_report.py`. Confirm only with replayable evidence; otherwise mark rejected, blocked, or needs-permission.

For a known live reload reproducer in conservative or one-shot profiles, replace
broad replay with the approved reproducer plan: baseline, one explicitly armed
trigger, recovery, evidence collection, and protocol-field minimization. In
`destructive_lab`, repeated reload or crash replay is allowed only when listed
in `destructive_lab.allowed_destructive_actions` and bounded by
`destructive_lab.campaign_budget`.

## Multi-Agent Pattern

Use subagents when the user has allowed multi-agent work and tasks can run independently:

- Surface agent: inventories firmware/IDA/YANG/routes and proposes fuzzing targets.
- Harness agent: writes pylibafl or Rust LibAFL harnesses for one selected target.
- Shared-library harness agent: plans ABI-safe wrappers, loader environment, state reset, and fork/QEMU/Frida isolation for one selected `.so`.
- Crash agent: replays, minimizes, debugs, and maps crashes.
- Review agent: independently reruns the reproducer and checks the report evidence.
- Cisco live agent: manages real-device profile gates, health checks, destructive-action allowlists, and evidence capture.
- Destructive lab agent: when `live_profile=destructive_lab`, prioritizes runtime experiments after attribution readiness, stops low-value static branches, and tracks budget/observer loss.

## Safety Defaults

- Safety is profile-aware. Do not apply conservative production defaults to an explicitly authorized destructive lab campaign.
- In `production_conservative`, do not modify device configuration, users, files, services, package state, authentication state, or unrelated protocols. Do not run `get_shell.py`, `gdbserver`, `gcore`, service restarts, reloads, or destructive cleanup without separate approval. Treat DoS, reload, watchdog, CPUHOG, process restart, and persistent service degradation as stop conditions.
- In `lab_minimal_one_shot`, send only scoped test frames through the live gate, keep case counts at or below the manifest first-contact limit, and stop on anomaly for triage.
- In `destructive_lab`, configuration changes, state-changing HTTP/RESTCONF/NETCONF/CLI/RPC operations, file uploads, shell commands, debugger attachment, service restart, reload, crash replay, and large-scale fuzzing are allowed only when the matching action class is listed in `destructive_lab.allowed_destructive_actions`.
- In `destructive_lab`, treat DoS, reload, watchdog, CPUHOG, process restart, and new core/crashinfo as evidence sources rather than automatic stop conditions. Stop when the campaign budget is exhausted, required observers are lost, non-target impact appears, attribution can no longer be updated, or a `destructive_lab.stop_when` rule fires.
- For pre-auth live services, a protocol driver may open a socket and send scoped test frames only after the live gate passes. In destructive lab mode, the same driver may send malformed or disruptive frames within the action allowlist and budget.
- For DoS/reload reproducers outside `destructive_lab`, require an explicit command-line arm flag, a case count of one for the trigger, and an immediate post-trigger health/recovery phase.
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
- `reports/crash_attribution.md`
- `reports/coverage_or_reachability.md`
- `reports/gdb_or_crash_trace.txt`
- `reports/vulnerability_report.md`

Use [references/crash_triage.md](references/crash_triage.md) when a crash, reset, traceback, core file, or process restart is observed.
