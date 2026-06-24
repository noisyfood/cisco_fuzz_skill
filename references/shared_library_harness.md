# Shared Library Harnesses

Use this when an extracted Cisco firmware contains `.so` libraries that should
be fuzzed through a local harness. This is an offline workflow. It does not
modify device firmware and it does not send live device traffic.

The detailed reverse-engineering process for selecting `.so` candidates is a
separate skill section. This document only defines the gate and harness shape
needed before fuzzing starts.

## Manifest Gate

For Cisco offline shared-library work, set:

```json
{
  "campaign_type": "cisco_offline",
  "offline_execution": {
    "target_kind": "shared_library_harness"
  }
}
```

The preflight requires:

- `shared_library.library_path`: extracted `.so` file.
- `shared_library.candidate_functions`: exported symbols, internal addresses,
  wrappers, or parser entry candidates.
- `shared_library.input_format`: bytes, file buffer, TLV, JSON/XML, CLI token
  stream, protocol message, or custom struct.
- `shared_library.harness_plan`: how the harness calls the library.
- `shared_library.harness_execution`: native, QEMU user-mode, Frida/QEMU hook,
  source-rebuilt wrapper, forkserver, or analysis-only blocked state.
- `shared_library.abi_notes`: architecture, calling convention, struct layout,
  ownership rules, and required initialization.
- `shared_library.state_reset_plan`: how each iteration avoids persistent global
  state, leaked allocations, stale handles, or non-determinism.
- `shared_library.seed_dir`: at least one non-empty seed.
- `offline_execution.architecture`, `loader`, `library_root`, `required_env`,
  and `license_or_authorization`. `offline_execution.required_env` must be present as a JSON object; use `{}` when no extra environment variables are required.

If `qemu_helper` or `sanitizer_helper` is set, its architecture must match
`offline_execution.architecture`.

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
- Instrumentation mode: harness-only, rebuilt source, AFL-compatible forkserver,
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
- Rebuilt source libraries may use AFL-compatible instrumentation and be driven
  by Rust LibAFL forkserver.
- Binary-only libraries may use LibAFL QEMU/Frida coverage or hooks when the
  loader, dependency root, and function boundary are validated.
- AFL++ compiler wrappers, `afl-qemu-trace`, CMPLOG, and QASAN remain auxiliary
  tooling. Do not use `afl-fuzz` as the campaign fuzzer.

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
