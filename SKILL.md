---
name: cisco-device-fuzz
description: Use when fuzzing Cisco IOS XE or similar Cisco network devices, extracted Cisco firmware parsers, or Cisco shared libraries, or when training a local parser fuzzing workflow before applying it to Cisco. Guides an agent through campaign context capture, IDA input-surface discovery, shared-library harness planning, dynamic LibAFL fuzzer construction, real-device reproduction, crash collection, minimization, root-cause analysis, and vulnerability reporting.
metadata:
  short-description: Cisco device fuzzing workflow
---

# Cisco Device Fuzzing

## Campaign Manifest First

Before doing campaign work, create or read `campaign_manifest.md`. This file is
free-form campaign context, not a schema. Use it to understand the device,
available resources, and explicit forbidden operations.

Create it from [assets/campaign_manifest.template.md](assets/campaign_manifest.template.md)
when the user has not provided one:

```bash
cp assets/campaign_manifest.template.md campaign_manifest.md
```

Fill it with user-provided facts and evidence gathered during the campaign.
Do not invent credentials, firmware paths, tool availability, shell access, or
forbidden operations. If a detail is unknown, mark it unknown and proceed with
the best available non-conflicting workflow.

Keep `commands.log` and campaign notes current when running setup, analysis,
fuzzing, replay, debugging, minimization, or report-generation commands.

## Threat Model First

Before fuzzing or reverse engineering, define the attacker model. Do not start
from binaries or protocols in isolation; start from the actor that can reach the
device.

Record in `campaign_manifest.md`:

- Attacker identity: unauthenticated network client, authenticated low-privilege
  WebUI user, Telnet/SSH user, CLI operator, adjacent LAN host, local shell
  user, firmware/update provider, or another campaign-specific role.
- Attacker permissions: available credentials, session type, privilege level,
  reachable management surfaces, writable settings, upload/import abilities,
  and commands or APIs callable by that role.
- Trust boundary: network location, VRF/interface, exposed ports, management
  plane path, serial/local access, or offline firmware access.
- Attacker-controlled input: HTTP routes, REST/NETCONF/YANG actions, CLI
  arguments, config files, uploaded packages, protocol messages, TLVs, XML/JSON
  bodies, SNMP/BER payloads, or shared-library inputs.
- Observability: responses, logs, console, crashinfo/core files, process
  status, reload evidence, timing, and health checks available for that role.

Then enumerate attack surfaces only from that role's perspective. For each
surface, record reachability, required state, parser/function/binary candidates,
input format, seed source, expected feedback, and likely impact. Select one or a
small number of candidates before doing deep reverse engineering or generating a
LibAFL fuzzer.

Prefer candidates where the attacker has strong input control, the parser is
reachable, seeds can be produced, and failures can be observed. If a promising
surface requires a different attacker identity or privilege level, record that
as a separate threat model instead of mixing assumptions.

## Default Strategy

Use one fuzzer path: dynamically create a LibAFL fuzzer for the selected target
and campaign context. Do not select or describe alternative fuzzer frameworks as
campaign fuzzers. Replay, debugger, sanitizer, and emulation tools
may support a campaign, but they are not the campaign fuzzer.

Before writing code or sending traffic, record the target surface in
`campaign_manifest.md`: input source, seed source, available resources,
forbidden operations, observation method, evidence directory, and the generated
LibAFL fuzzer path.

- For local or offline targets, generate a narrow LibAFL harness or executor
  that reaches the parser, file handler, CLI wrapper, binary entry point, or
  shared-library function selected from analysis.
- Start `.so` or binary fuzz analysis when threat-model-based attack-surface
  enumeration shows that attacker-controlled data is handled by that object.
  First confirm the object's input constraints and call path: caller chain,
  expected buffer/file/protocol shape, length fields, initialization state,
  ABI/calling convention, dependency root, environment, and reset behavior.
  Collect real seeds from the reachable attack surface when possible. A crash
  found only in an offline `.so` or binary harness is a candidate finding until
  it is replayed successfully through the equivalent path on the real device.
- For extracted Cisco `.so` libraries, record the library path, dependency root,
  candidate functions, ABI notes, state-reset plan, and seed material before
  generating the LibAFL harness. Use [references/shared_library_harness.md](references/shared_library_harness.md).
- For binary-only offline targets, use LibAFL with the appropriate executor,
  QEMU/Frida support, or command wrapper only after architecture, loader,
  library root, and reachable entry point are understood.
- For live Cisco devices, generate a LibAFL protocol driver that mutates
  bounded protocol fields and observes response class, timing, logs,
  liveness, PID/core/crashinfo deltas, or other available health evidence.
- For CLI tools with security-relevant options, generate a wrapper that keeps
  required reachability flags fixed and mutates only a small allowlist of input
  fields or optional arguments.
- For large modular applications, prefer a narrow parser harness over full
  application startup. Feed memory buffers directly into the target parser when
  possible, and keep feedback focused on the selected parser path.
- Use IDA Pro MCP/Ghidra to identify parser state machines, length fields,
  message types, dangerous sinks, and PC-to-function crash mapping.

For real Cisco IOS XE systems, do not assume full-device QEMU emulation is viable. Prefer protocol-aware low-speed fuzzing against confirmed entry points.

## Technique Gates

Before building or running a campaign fuzzer, apply these gates:

- Harness gate: read [references/harness_design.md](references/harness_design.md), then prove that at least one valid seed reaches the intended parser, function, route, or protocol state. Do not fuzz an unproven harness.
- Dictionary gate: read [references/dictionary_strategy.md](references/dictionary_strategy.md), then record token sources and expected parser barriers before enabling token mutations.
- Coverage/reachability gate: read [references/coverage_and_reachability.md](references/coverage_and_reachability.md), then define whether progress is measured by local coverage, LibAFL observer state, QEMU/Frida evidence, or live response/health deltas.
- Obstacle gate: read [references/fuzzing_obstacles.md](references/fuzzing_obstacles.md), then choose seed improvement, token help, field fixups, environment setup, or a documented local-only patch. Do not patch live devices or treat patched-only crashes as confirmed production bugs.
- Shared-library gate: for extracted `.so` targets, read [references/shared_library_harness.md](references/shared_library_harness.md) and record ABI, loader, dependency root, candidate functions, state reset, and isolation strategy before fuzzing.
- Crash attribution gate: for destructive or crash-oriented live testing, read [references/crash_attribution.md](references/crash_attribution.md) and record the controlled fields, parser path, suspected sink, fault oracle, symbolization plan, and replay plan.
- Disruptive live testing gate: before large-scale live testing, reload/DoS
  replay, service restart, debugger attachment, shell actions, file upload, or
  persistent configuration changes, read [references/disruptive_live_testing.md](references/disruptive_live_testing.md)
  and record the allowed action class, evidence plan, stop conditions, and
  recovery expectations in `campaign_manifest.md`.

## Training-To-Cisco Bridge

Fuzzing101 teaches the mechanics of corpus growth, dictionaries, parser
harnesses, sanitizer crashes, minimization, and report writing. Real Cisco
device work keeps those mechanics but changes the observer and safety model:

- Coverage feedback is often unavailable on hardware, so use response classes,
  timing, service liveness, process/core deltas, logs, and recovery evidence as
  feedback.
- Local parser crashes can be replayed repeatedly; live reload/DoS triggers
  can be single-use in conservative campaign notes or budgeted disruptive lab
  evidence when `campaign_manifest.md` records repeated crash/reload replay.
- File-format dictionaries become protocol dictionaries: magic values, TLV
  types, length sentinels, method IDs, transaction IDs, CLI/YANG constants, and
  IDA-recovered string or enum values.
- Tutorial harnesses can run fast and parallel; real-device runs should preserve
  enough campaign notes to identify the target, selected attack surface,
  recovery path, stop conditions, and evidence expectations.
- A finding is not confirmed by a socket timeout alone. It needs a bridge from
  input field to parser state to crash/reload evidence, such as uptime reset,
  return reason, traceback, core/crashinfo, or a new system report.

## LibAFL Fuzzer Construction

Every campaign fuzzer must be generated or adapted as LibAFL code for the
current target. Choose the LibAFL executor, input type, mutator, observer,
feedback, objective, and corpus layout from [references/libafl_workflow.md](references/libafl_workflow.md).

- Generate a small target-specific LibAFL project under the campaign or target
  work area; do not treat auxiliary replay, debugging, or evidence scripts as
  campaign fuzzers.
- Prefer byte mutation first, then add token, grammar, field-aware, or stateful
  mutators when the input structure is known.
- Use coverage feedback when the target exposes it. For live devices or opaque
  binaries, build LibAFL feedback from response classes, timing, liveness,
  logs, process/core deltas, or other reachable evidence.
- Store crashes, anomalies, generated cases, minimized inputs, and run metadata
  in the campaign evidence directory.
- Known or suspected high-impact live reproducers must stay out of normal
  mutation queues unless the forbidden list and campaign notes explicitly allow
  that class of test.

Do not make instrumentation a hard dependency for Cisco device work.
Instrumentation is an offline acceleration technique, not the live-device
assumption.

Load references only when they are relevant to the current target and action.
Read [references/libafl_workflow.md](references/libafl_workflow.md) before
generating a LibAFL fuzzer. Read [references/harness_design.md](references/harness_design.md),
[references/dictionary_strategy.md](references/dictionary_strategy.md),
[references/coverage_and_reachability.md](references/coverage_and_reachability.md),
and [references/fuzzing_obstacles.md](references/fuzzing_obstacles.md) as their
gates become relevant. Read [references/shared_library_harness.md](references/shared_library_harness.md)
for `.so` targets, [references/crash_attribution.md](references/crash_attribution.md)
and [references/disruptive_live_testing.md](references/disruptive_live_testing.md)
for crash-oriented or disruptive live work, [references/crash_triage.md](references/crash_triage.md)
after an anomaly, [references/reporting.md](references/reporting.md) before
writing a report, and [references/script_inventory.md](references/script_inventory.md)
before using bundled scripts.

## IDA Input-Surface Discovery

Before writing a fuzzer for a binary target, identify input surfaces that are
reachable from the selected threat model. Use [references/ida_input_surface.md](references/ida_input_surface.md).

Minimum output:

- Candidate entry function and caller chain.
- Target binary or shared library, dependency root, and exported/internal function status.
- Input source: file, socket, HTTP route, CLI command, IPC, YANG/RPC/action, SNMP/BER, TLV, or environment.
- Input buffer pointer and length source.
- Framing fields: magic, command type, length, count, checksum, padding, transaction ID.
- Sink class: memcpy/strcpy/format, allocator/free, parser recursion, table index, integer conversion, shell/CLI invocation, file path.
- Fuzzer recommendation: generated LibAFL harness, command executor,
  forkserver, QEMU/Frida executor, shared-library harness, or live protocol
  path. Mark replay, debugging, and evidence collection as support work, not
  campaign fuzzers.

## Workflow

1. Read or create `campaign_manifest.md` and use it as the source of truth for device settings, resources, and forbidden operations.
2. Define the threat model: attacker identity, permissions, trust boundary, controlled inputs, and observability.
3. Enumerate attack surfaces reachable by that attacker from firmware, configs, CLI help, YANG, nginx/OpenResty routes, protocol ports, shared libraries, IDA strings/xrefs, and prior evidence.
4. Rank reachable surfaces and select one narrow candidate for vulnerability research or fuzzing.
5. Use IDA/Ghidra/angr as needed to map the selected candidate to parser functions, binaries, libraries, data structures, and sink classes.
6. Design and generate the target-specific LibAFL fuzzer; keep replay, debugging, and evidence collection as support work rather than separate fuzzer modes.
7. Apply the technique gates for harness design, dictionary strategy, reachability, and fuzzing obstacles. For `.so` targets, apply the shared-library gate as well.
8. For local training, use the same manifest, seed, fuzzer, crash triage, and report flow on a local target before applying the workflow to Cisco.
9. Build seeds from real messages, valid files, protocol notes, YANG schemas, HTTP routes, CLI output, or prior proof-of-concept traffic. Add dictionary tokens when syntax or magic values matter.
10. Capture a baseline: local target version or live-device liveness, response class, process list, filtered logs, and core/crash directories. For live protocols, prove parser reachability with a safe request before any malformed field or length sweep.
11. Fuzz with a bounded budget appropriate to the target and threat model. For
live devices, send cases through the selected attack-surface path and collect
health evidence around each case or batch.
12. On crash/anomaly, save input, response, timing, health delta, logs, and
core/crash listings. Offline `.so` or binary crashes remain candidate findings
until reproduced through the equivalent path on the real device.
13. Replay the case at least three times. If reproducible, minimize the input.
14. Map the crash: ASan/GDB/core locally, or PC/backtrace/core/logs on Cisco if allowed. Prefer `bt 80`, `info registers`, and `thread apply all bt` when practical. Connect input fields to parser paths.
15. Generate a vulnerability report using [references/reporting.md](references/reporting.md) and `scripts/generate_vulnerability_report.py`. Confirm only with replayable evidence; otherwise mark rejected, blocked, or needs-permission.

For a known live reload or DoS reproducer, replace broad replay with a recorded
plan in `campaign_manifest.md`: baseline, trigger command or case, recovery,
evidence collection, and protocol-field minimization. Do not run actions listed
under `Forbidden`.

## Multi-Agent Pattern

Use subagents when the user has allowed multi-agent work and tasks can run independently:

- Surface agent: inventories firmware/IDA/YANG/routes and proposes fuzzing targets.
- Harness agent: writes a generated LibAFL harness or real-device execution path
  for one selected target.
- Shared-library harness agent: plans ABI-safe wrappers, loader environment, state reset, and fork/QEMU/Frida isolation for one selected `.so`.
- Crash agent: replays, minimizes, debugs, and maps crashes.
- Review agent: independently reruns the reproducer and checks the report evidence.
- Cisco live agent: manages real-device campaign notes, health checks, allowed
  disruptive action classes, and evidence capture.
- Live evidence agent: tracks health checks, disruptive-action evidence,
  recovery state, observer loss, and real-device reproduction status.

## Safety Defaults

- Treat `campaign_manifest.md` `Forbidden` entries as hard deny rules.
- For pre-auth live services, a protocol driver may open a socket and send
  scoped test frames when that surface is reachable by the selected threat
  model.
- Configuration changes, state-changing HTTP/RESTCONF/NETCONF/CLI/RPC
  operations, file uploads, shell commands, debugger attachment, service
  restart, reload, crash replay, and large-scale fuzzing require an explicit
  campaign note that names the action class, expected impact, observers, and
  recovery path.
- Do not change administrator passwords when that action appears in `Forbidden`.
- Keep every campaign reproducible: save seeds, generated cases, exact command lines, timestamps, and health snapshots.
- Keep `commands.log` in the campaign directory. Record each setup, build,
  fuzzer, replay, debugger, minimizer, and report-generation command with exit
  code.

## Evidence Format

Each campaign should create:

- `campaign_manifest.md`
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
