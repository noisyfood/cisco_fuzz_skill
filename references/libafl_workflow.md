# LibAFL Workflow

LibAFL is a component library. Build the fuzzer by selecting input, corpus, scheduler, mutator, executor, observer, feedback, objective, and monitor.

Before wiring those components, use [harness_design.md](harness_design.md) to prove reachability, [dictionary_strategy.md](dictionary_strategy.md) to define tokens, [coverage_and_reachability.md](coverage_and_reachability.md) to choose feedback evidence, and [fuzzing_obstacles.md](fuzzing_obstacles.md) to handle checksums, global state, and validation barriers.

## Local Documentation Index

Use these local LibAFL paths as the implementation index:

| Need | Path |
| --- | --- |
| Core concepts | `LibAFL/docs/src/core_concepts/{corpus,executor,feedback,mutator,observer}.md` |
| Step-by-step bytes fuzzer | `LibAFL/docs/listings/baby_fuzzer/listing-01` through `listing-06` |
| Simple Rust fuzzer | `LibAFL/fuzzers/baby/baby_fuzzer/` |
| Custom input and mutator | `LibAFL/fuzzers/baby/tutorial/src/{input.rs,mutator.rs,lib.rs}` |
| Command executor | `LibAFL/fuzzers/baby/backtrace_baby_fuzzers/command_executor/` and `LibAFL/crates/libafl/src/executors/command.rs` |
| Fork isolation | `LibAFL/fuzzers/baby/backtrace_baby_fuzzers/*fork*` and `LibAFL/crates/libafl/src/executors/inprocess_fork/` |
| Forkserver | `LibAFL/fuzzers/forkserver/` and `LibAFL/crates/libafl/src/executors/forkserver.rs` |
| Forkserver asset | `assets/rust_libafl_afl_forkserver_fuzzer/` |
| Binary-only offline harness | `LibAFL/fuzzers/binary_only/{frida_executable_libpng,qemu_coverage,qemu_launcher}` |
| Component source | `LibAFL/crates/libafl/src/{corpus,feedbacks,observers,mutators}/` |

## Selection Rule

Generate a Rust LibAFL fuzzer for the current target. Choose the executor and
input type by target shape:

- Use in-process execution only for stable local parser harnesses with reliable
  state reset.
- Use fork, forkserver, command, QEMU, or Frida execution when native crashes,
  binary-only code, architecture mismatch, or process-global state require
  isolation.
- You need custom input structs, grammar/stateful mutators, custom feedbacks, or multi-core scaling.
- The target is a large application and you can expose a narrow parser harness instead of repeatedly starting the full program.
- The target is an extracted Cisco `.so` and the harness needs ABI control,
  loader environment control, fork/QEMU/Frida isolation, or module-scoped
  observations.

Use live black-box fuzzing when:

- The target is a real Cisco device or service without instrumentation.
- Firmware cannot be repacked.
- A full emulated runtime is unavailable.

## Rust LibAFL Pattern

Start from `LibAFL/docs/listings/baby_fuzzer/listing-06` for an in-process fuzzer. Verify the local LibAFL baseline with:

```bash
cargo check --manifest-path LibAFL/docs/listings/baby_fuzzer/listing-06/Cargo.toml
```

The required components are:

- `BytesInput` or a custom `Input`.
- Corpus: `InMemoryCorpus` for interesting inputs and `OnDiskCorpus` for crashes.
- Executor: `InProcessExecutor`, `InProcessForkExecutor`, `ForkserverExecutor`, or QEMU/Frida executor.
- Observer: coverage map, cmp log, stdout/stderr, timing, or custom response observer.
- Feedback: `MaxMapFeedback` for coverage-like novelty, custom feedback for response/state novelty.
- Objective: `CrashFeedback`, timeout feedback, sanitizer finding, or custom live-device anomaly.
- Stage: `StdMutationalStage` with havoc mutations, token/grammar mutators, or custom protocol mutator.

For file or CLI targets, start from `LibAFL/fuzzers/baby/backtrace_baby_fuzzers/command_executor/src/main.rs` or a forkserver example. The adaptation point is `spawn_child`: write the input to stdin or a temp file, pass that file path where the target expects `@@`, set a short timeout, and store crashes in `OnDiskCorpus`.

This skill also bundles a minimal command-template project at [assets/rust_libafl_cli_command_fuzzer](../assets/rust_libafl_cli_command_fuzzer). It uses:

- `CommandExecutor::builder().parse_afl_cmdline(...)` for command-template `@@` file input.
- `ConstFeedback(false)` for no-coverage command targets, so the corpus does not grow from fake feedback.
- `CrashFeedback` with `OnDiskCorpus` for signal crashes.
- A bounded `--iterations` loop for smoke and regression testing.

Build check:

```bash
cargo check --manifest-path assets/rust_libafl_cli_command_fuzzer/Cargo.toml
```

Run shape:

```bash
cargo run --manifest-path assets/rust_libafl_cli_command_fuzzer/Cargo.toml -- \
  --in campaigns/local/seeds \
  --out campaigns/local/rust-libafl-run001 \
  --token-file campaigns/local/format.dict \
  --iterations 20 \
  --timeout-ms 1000 \
  -- ./target_wrapper.sh @@
```

On Unix, LibAFL `CommandExecutor` treats signal termination as `Crash`; a normal nonzero exit code is not enough. For CLI parsers, wrap the target so ordinary parse errors exit 0 and real signals/timeouts remain observable.

For forkserver targets, use [assets/rust_libafl_afl_forkserver_fuzzer](../assets/rust_libafl_afl_forkserver_fuzzer)
as a LibAFL implementation reference:

```bash
cargo run --manifest-path assets/rust_libafl_afl_forkserver_fuzzer/Cargo.toml -- \
  --in campaigns/local/seeds \
  --out campaigns/local/libafl-forkserver-run001 \
  --token-file campaigns/local/format.dict \
  --iterations 1000 \
  --timeout-ms 1200 \
  -- ./instrumented_harness @@
```

Compile the harness with coverage-compatible instrumentation when available,
then let LibAFL own scheduling, mutation, crash corpus, and reporting.

For structured inputs, implement:

- owned serializable input type
- `Input`
- `HasTargetBytes`
- `HasLen`
- `Hash`
- fixup logic for length/checksum fields

For token-heavy formats, use LibAFL token/encoded-input mutators or load tokens into custom mutators. Seed these from dictionaries, magic values, GUIDs, and constants recovered from reverse engineering.

## LibAFL Triage Enhancements

For local or offline campaigns, add these when the target shape justifies them:

- Backtrace or crash-signature deduplication: add a backtrace observer or hash feedback when repeated crashes flood `OnDiskCorpus`. Keep the raw crashing input even when deduplicating.
- Token mutators: load the dictionary from [dictionary_strategy.md](dictionary_strategy.md) into LibAFL token metadata and combine token mutations with havoc mutations.
- AutoTokens or comparison-derived tokens: when the build can extract
  comparison strings, save the generated token file and record the build that
  produced it. Treat build-specific tokens as campaign evidence.
- Single-process debug mode: when debugging fuzzer logic, run one client without the launcher/multi-process manager, then restore isolation before campaign fuzzing.
- Coverage scope: for large apps or `.so` harnesses, prefer module/function-scoped observers or allowlists so feedback rewards the selected parser rather than unrelated dispatch.

Do not use deduplication or AutoTokens as a substitute for replay, minimization, and root-cause mapping.

## Large Source-Built Harness Pattern

Use this when a full program starts slowly or has many unrelated modules:

- Move the target parser/demux/decode call into a small harness that accepts bytes and length.
- Initialize process-global state once only if the state is reset safely between iterations.
- Prefer `InProcessForkExecutor`, forkserver, or persistent mode over repeated process startup.
- Keep coverage focused on the parser module or selected functions. In
  LibAFL/QEMU/Frida this means module/function scoped coverage or custom
  feedback.
- Use ASan/UBSan locally when building from source, and treat sanitizer output as a crash objective.

Exercise 7 style VLC/ASF lessons:

- Convert file input to a memory buffer and call the demux/parser entry point directly.
- Keep VLC/application initialization outside the hot path only when that state is required.
- Use a parser file/function allowlist so coverage rewards ASF demuxing, not unrelated media-player dispatch.
- Feed ASF object/GUID dictionaries into LibAFL token mutators.
- Prefer forkserver or in-process-fork isolation unless persistent mode has a documented state reset.

## Shared Library Harness Pattern

Use this when attack-surface analysis shows attacker-controlled data reaches an
extracted `.so`.

Choose execution by risk:

- `InProcessForkExecutor` or forkserver when a C/C++ harness can link or
  `dlopen` the `.so` and native crashes must be isolated.
- `CommandExecutor` when a wrapper binary is easier to audit and should accept
  an `@@` file path.
- LibAFL QEMU/Frida when the library architecture is not native, when internal
  function hooks are required, or when binary-only coverage is practical.
- Plain in-process only for stable, deterministic libraries with a narrow
  exported parser and a proven state reset.

Harness responsibilities:

- Configure `LD_LIBRARY_PATH`, loader root, config files, and environment in one
  reproducible place.
- Convert the LibAFL input into the exact ABI expected by the candidate
  function.
- Own or free output buffers according to the library's contract.
- Reset or recreate contexts between iterations.
- Normalize expected parser rejections so they do not become findings.
- Save module base and library path in crash metadata for IDA/Ghidra mapping.

Instrumentation notes:

- If only the harness is instrumented, coverage proves harness execution, not
  parser reachability inside the `.so`.
- If source or rebuildable adapters are available, use compiler
  instrumentation plus the Rust LibAFL forkserver asset.
- For binary-only libraries, prefer LibAFL QEMU/Frida observers when the loader,
  dependency root, and function boundary are validated.

## Binary-Only Offline Pattern

For extracted Cisco binaries or closed-source training targets:

- Validate architecture, loader, library root, and command template before execution.
- Use LibAFL QEMU/Frida examples under `LibAFL/fuzzers/binary_only/` as starting points.
- Choose a persistent loop or hook only at a documented function boundary.
- Record how the boundary was found: IDA/Ghidra xrefs, callgrind, dynamic traces, or prior validated material.
- Run a short stability check before a long campaign.
- If sanitizer-style replay such as QASAN/Frida fault reporting is unavailable, keep findings unconfirmed until normal replay and root-cause mapping are sufficient.

Exercise 8 style closed-source lessons:

- Resolve launcher scripts to the actual ELF and record required loader/library environment.
- Match target architecture to the QEMU and sanitizer helpers before execution.
- Treat persistent addresses as build-specific evidence; validate the address and register reset before a campaign.
- If the proprietary target or execution authorization is missing, stop at `blocked`/`unconfirmed`; do not simulate a crash result.

## No-Instrumentation Cisco Mode

When coverage is unavailable, do not force LibAFL coverage feedback. Either:

- Use a live driver with custom feedback from responses and health checks, or
- Use LibAFL only in an offline parser harness where QEMU/Frida/coverage is practical.

For real devices, preserve a campaign budget and stop conditions in the manifest. Treat response novelty as a lead, not proof.
