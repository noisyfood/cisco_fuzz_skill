# Harness Design

Use this before writing or adapting any local, offline, shared-library, or live
protocol harness. A fuzzer is only as useful as the harness reachability and
reproducibility it provides.

This reference absorbs general harness-writing practice into the Cisco workflow.
It is not a generic libFuzzer guide; campaign fuzzers remain `pylibafl` or Rust
LibAFL unless this skill explicitly says otherwise.

## Harness Gate

Do not fuzz until the harness design record answers:

- What exact parser, function, route, command, or protocol state is targeted?
- What input bytes or structured fields are controlled by the fuzzer?
- What valid seed reaches the target path?
- What malformed non-crashing seed returns cleanly?
- How are expected parser rejections distinguished from crashes?
- What state is initialized once, reset per case, or recreated per process?
- What timeout, memory limit, and isolation mode are used?
- What evidence proves repeated runs of the same seed are deterministic?

If the harness cannot demonstrate target reachability, mark the campaign as
blocked or analysis-only. Do not compensate with more mutation volume.

## Core Rules

- Handle empty, tiny, maximum-size, and malformed inputs without harness crashes.
- Keep the target narrow. Do not mix unrelated formats or unrelated protocol
  operations in one corpus.
- Avoid blocking I/O in the hot path. Prefer memory buffers, temp files, or
  wrappers with short timeouts.
- Do not call `exit()` from harness glue. Return cleanly for expected rejects
  and let real crashes surface as signals, sanitizer findings, or objective
  events.
- Reset global state, parser contexts, caches, file descriptors, environment
  changes, and threads between cases.
- Disable or redirect noisy logging. Save structured decision logs outside the
  hot path when evidence is needed.
- Free harness-owned allocations and close handles before returning.
- Keep all required initialization explicit in the campaign notes.

## Target Shapes

For local parser functions:

- Prefer `harness(data: bytes)` or `parse(buf, len)` style calls.
- Reject unhelpful sizes early, but keep boundary sizes in scope.
- Use ASan/UBSan and coverage when the target can be rebuilt.

For CLI/file parsers:

- Wrap the target so normal parse errors exit `0`.
- Preserve signal-like exits, sanitizer reports, core files, and timeouts.
- Record the exact resolved command and environment for each finding.

For large applications:

- Move parser/demux/decode calls out of full startup when practical.
- Initialize expensive runtime state only if it is required for reachability.
- Scope coverage to the parser module or selected functions where available.

For extracted `.so` libraries:

- Follow [shared_library_harness.md](shared_library_harness.md).
- Record ABI, ownership, initialization, dependency root, and state reset.
- Prefer fork isolation, forkserver, QEMU, or Frida for unstable native code.

For live Cisco protocol drivers:

- Call the manifest/live gate before opening a socket.
- Provide `baseline`, bounded `sweep`, and one-case `oneshot` modes.
- Stop on anomaly and collect health evidence before continuing.
- Treat response novelty as guidance, not vulnerability proof.

## Manual Smoke Tests

Before a fuzzing run, execute and save results for:

- Valid seed: reaches the intended parser path.
- Malformed non-crashing seed: returns as expected.
- Repeated seed: same input produces the same class, timing band, and artifacts.
- Timeout seed if applicable: timeout is classified separately from crash.
- Local deliberate-fault test when practical: proves crash capture works.

For Cisco live targets, replace deliberate faults with non-destructive baseline
and liveness probes. Do not intentionally trigger reload or DoS behavior unless
the manifest and user authorization explicitly allow a one-shot reproducer.

## Failure Classification

Classify failures before fuzzing:

- `harness_bug`: crash in glue, bad ABI, missing dependency, bad wrapper, or
  impossible patched state.
- `reachability_blocked`: seed cannot reach the selected parser or required
  state is unavailable.
- `target_reject`: expected parse error or access control result.
- `target_anomaly`: signal, sanitizer finding, hang, response/liveness anomaly,
  new core/crashinfo, process restart, traceback, or reload evidence.

Only `target_anomaly` enters crash triage.
