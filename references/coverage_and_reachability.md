# Coverage And Reachability

Coverage is a harness and campaign-quality signal. It is not vulnerability
proof. On real Cisco devices, direct coverage is usually unavailable, so this
skill uses reachability evidence and health observations as the live-device
substitute.

## Gate

Before a campaign, define which signal proves progress:

- Source/local harness: LLVM/gcov coverage, sanitizer coverage, LibAFL coverage
  observer, or module-scoped instrumentation.
- AFL-instrumented harness: forkserver coverage observed by Rust LibAFL.
- Binary-only offline harness: LibAFL QEMU/Frida observer, dynamic trace, or
  replay evidence when coverage is not practical.
- Shared-library harness: library-internal coverage only if the `.so` or binary
  instrumentation observes it; harness-only coverage is not enough.
- Live Cisco target: response class, timing, liveness, process/core/crashinfo
  deltas, logs, traceback, PID changes, or reload evidence.

If the signal does not prove the selected parser is reached, return to harness
or seed design before fuzzing.

## Local Coverage Workflow

Use coverage after a short fuzzing or seed-replay run:

1. Build a separate coverage binary or harness variant.
2. Execute the saved corpus, not only one seed.
3. Filter out harness glue where possible.
4. Compare against the previous run or the seed-only baseline.
5. Record uncovered barriers that need better seeds, dictionaries, field fixups,
   or narrower harnessing.

For C/C++ source harnesses, use LLVM profile coverage or gcov/gcovr. Keep the
coverage binary separate from the campaign fuzzer build when toolchain flags
conflict.

For Rust or LibAFL harnesses, use Rust/LLVM coverage when available, or record
LibAFL observer statistics plus corpus and objective growth.

## Cisco Live Reachability

For live devices, record per case or per small batch:

- Send status: success, send error, reset, refused, timeout.
- Response class: status code, protocol error, response length, prefix hash.
- Elapsed time and timeout band.
- Liveness result before and after.
- Process or service evidence if read-only shell/CLI checks are approved.
- New core, crashinfo, traceback, watchdog, CPUHOG, memory, or reload evidence.

A timeout is a lead. It becomes crash-like only when paired with persistence,
liveness loss, process restart, traceback, core/crashinfo delta, or recovery
evidence.

## Shared-Library Reachability

For `.so` harnesses, distinguish:

- `load_reached`: loader and dependencies succeed.
- `wrapper_reached`: harness calls the wrapper.
- `candidate_reached`: selected function or internal hook is executed.
- `parser_reached`: input-dependent parser branch is executed.
- `sink_reached`: input-derived copy, allocation, index, recursion, or conversion
  path is reached.

Only `candidate_reached` or deeper should justify mutation. If only
`load_reached` or `wrapper_reached` is proven, fix the harness.

## Plateau Response

When coverage or reachability plateaus:

- Add focused dictionary tokens from xrefs and real samples.
- Improve seeds to pass shallow validation.
- Add field-aware mutators for length, count, type, checksum, or optional
  sections.
- Narrow the harness to the parser instead of application dispatch.
- Check whether a checksum, signature, environment, license, authentication, or
  config gate blocks the path.
- For live targets, reduce risk rather than increasing rate; prove state and
  authorization first.

## Evidence To Save

Save:

- Baseline coverage or reachability summary.
- Corpus path used for measurement.
- Toolchain, command, and build mode.
- Dictionary and seed changes between runs.
- Screenshots or reports only when useful; prefer machine-readable summaries.
- For live targets, health snapshots and anomaly logs.

Coverage can support a root-cause report, but a confirmed vulnerability still
needs replay, minimization, and fault mapping.
