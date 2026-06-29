# Shared Library Harnesses

Use this when an extracted Cisco firmware contains `.so` libraries that should
be fuzzed through a local harness. This is an offline workflow. It does not
modify device firmware and it does not send live device traffic.

The detailed reverse-engineering process for selecting `.so` candidates is a
separate skill section. This document only defines the gate and harness shape
needed before fuzzing starts.

## When To Analyze A `.so`

Start shared-library analysis when threat-model-based attack-surface inventory
shows that attacker-controlled data is handled by an extracted `.so`. Do not
choose a library only because it has interesting strings or loads cleanly.

Before fuzzing, record in `campaign_manifest.md`:

- Which reachable attack surface feeds the library.
- Library path, dependency root, architecture, loader, and environment.
- Candidate exported or internal functions and the caller chain from the attack
  surface.
- Input constraints: buffer shape, file format, protocol framing, length/count
  fields, state prerequisites, and validation barriers.
- Calling convention, ABI, ownership rules, initialization sequence, and state
  reset plan.
- Real seed source when available: captured traffic, WebUI request, CLI/config
  artifact, uploaded file, protocol transcript, or minimized proof input.

Offline crashes in a `.so` harness are candidate findings. Promote them to
confirmed vulnerabilities only after the minimized case or equivalent protocol
sequence reproduces through the real-device attack surface and produces device
evidence.

## Design Record

Before writing code, record:

- Library role and dependency closure.
- Candidate function, caller chain, and why external input can reach it.
- Whether the function is exported, resolved through a table, or internal-only.
- Input pointer, input length, output buffers, allocator ownership, and return
  convention.
- Required process initialization, environment variables, config files, and
  library search path.
- State reset plan and isolation mode.
- Instrumentation mode: harness-only, rebuilt source, LibAFL forkserver,
  LibAFL QEMU/Frida, sanitizer replay, or none.
- Dictionary source: strings/xrefs, enum values, magic bytes, TLV types, route
  names, CLI/YANG constants, or real samples.

Do not fuzz a `.so` because it loads successfully. First prove that a seed
reaches the candidate parser or mark reachability as blocked.

## Harness Shapes

Use the narrowest viable harness:

- Exported parser: `dlopen`/`dlsym` or direct link, then call
  `parse(buf, len)` or equivalent.
- Context parser: initialize the required context once, reset or recreate it per
  iteration, and call the parser with a memory buffer.
- File-like parser: read `@@` into memory and use `fmemopen`, temp files, or a
  wrapper only when the target API requires a file path or descriptor.
- Internal function: use only after the function boundary, calling convention,
  register/state requirements, and dependency initialization are documented.
- Stateful protocol library: use a structured input that can express setup,
  message, and teardown phases, but keep unrelated operations in separate
  harnesses.

Prefer fork isolation, forkserver, QEMU, or Frida when a crash could corrupt the
agent process. Use in-process execution only for stable, deterministic, small
targets.

## Instrumentation

Instrumentation is allowed in offline `.so` work when it is technically valid:

- Rebuilt harness and wrappers may use ASan/UBSan and coverage.
- Rebuilt source libraries may use compiler instrumentation and be driven by a
  LibAFL forkserver.
- Binary-only libraries may use LibAFL QEMU/Frida coverage or hooks when the
  loader, dependency root, and function boundary are validated.
When only the harness is instrumented, record that coverage does not represent
library internals. Use it only for harness health, not target reachability.

## Smoke Checks

Before fuzzing:

- `file`/`readelf` identify architecture and dynamic dependencies.
- The configured loader/library root can load the `.so`.
- One valid seed reaches the selected function.
- One malformed non-crashing seed returns cleanly.
- The harness exits cleanly under the chosen timeout.
- Repeated runs of the same seed are deterministic.
- Expected parser rejections are normalized and do not look like findings.
- Crash isolation produces a saved case, trace, or signal when a deliberate
  local fault is injected into the harness path.

If any smoke check fails, fix the harness or mark the campaign blocked. Do not
increase mutation volume to compensate for an unproven harness.

## Crash Mapping

For crashes, preserve:

- Crashing input and seed lineage.
- Harness command and environment.
- Loader/library path, module base, and `/proc/<pid>/maps` or equivalent.
- Signal, sanitizer report, QEMU/Frida report, core, or GDB backtrace.
- Candidate function and basic block from IDA/Ghidra.
- Input field to parser state to crash-site mapping.

If a crash is inside harness glue, dependency loading, or an impossible patched
state, reject it or mark it as harness bug instead of a Cisco vulnerability.
