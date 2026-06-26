# Fuzzer Usage

Use only fuzzer paths this skill actually provides: pylibafl for simple Python-callable harnesses, Rust LibAFL for complex/local unsafe targets, Rust LibAFL forkserver for AFL-instrumented source harnesses, LibAFL QEMU/Frida for offline binary-only harnesses, and Rust LibAFL/pylibafl live protocol drivers for authorized Cisco live fuzzing.

Campaign fuzzers must be built with `pylibafl` or Rust LibAFL. AFL++ is allowed as an auxiliary toolchain for `afl-clang-fast` instrumentation, `afl-qemu-trace` execution checks, and QASAN replay/triage. Do not use `afl-fuzz` as the campaign fuzzer.

If the local AFL++ helper environment has been prepared in this workspace, load it before using the compiler/QEMU/QASAN helpers:

```bash
source validation/env_setup_afl_qemu/reports/env_exports.sh
```

## Decision Matrix

| Target shape | Default choice |
| --- | --- |
| Python-callable parser or tiny in-process harness | `assets/python_pylibafl_bytes_fuzzer/pylibafl_simple_bytes_fuzzer.py` scaffold or direct `pylibafl` sugar |
| C/C++/Rust CLI or file parser | `assets/rust_libafl_cli_command_fuzzer` |
| Local CLI smoke or fuzzer-flow validation | `assets/local_cli_smoke_fuzzer/local_cli_mutation_fuzzer.py` scaffold |
| Source-built large parser/application | Narrow ASan/coverage harness, then Rust LibAFL forkserver/in-process-fork |
| Extracted Cisco `.so` library | `shared_library_harness` manifest, narrow Rust LibAFL harness, fork/QEMU/Frida isolation when needed |
| Text/XML/CLI formats | Dictionary/token mutators plus bounded argument-profile fuzzing |
| Cisco offline parser harness | Rust LibAFL with coverage/QEMU/Frida only when practical |
| AFL-instrumented source harness | `assets/rust_libafl_afl_forkserver_fuzzer` |
| Binary-only offline parser | LibAFL QEMU/Frida in a local lab, with AFL++ QEMU/QASAN only for auxiliary execution/replay |
| Cisco live device with no instrumentation | Rust LibAFL/pylibafl protocol driver gated by `scripts/live_driver_gate.py`; `scripts/live_probe_executor.py` only for baseline/seed replay |
| Structured Cisco live protocol | Protocol-aware pylibafl or Rust LibAFL driver with baseline, field sweep, one-shot replay, explicit armed DoS trigger, and health/reload evidence collection |

Do not treat instrumentation as mandatory for Cisco live-device work. Use instrumentation for local and offline harnesses when available; use response/health feedback for live hardware.

Before selecting a campaign fuzzer, apply [harness_design.md](harness_design.md), [dictionary_strategy.md](dictionary_strategy.md), [coverage_and_reachability.md](coverage_and_reachability.md), and [fuzzing_obstacles.md](fuzzing_obstacles.md). These references are gates: an agent should record the harness reachability, token plan, progress signal, and obstacle-handling strategy before starting mutation.

## pylibafl Simple Harness

Use the scaffold only when the target can be called safely as
`harness(data: bytes)` inside Python. This is a local-training scaffold, not a
live-device primitive and not the preferred path for native Cisco binaries.

```bash
python3 scripts/pylibafl_import_probe.py
python3 assets/python_pylibafl_bytes_fuzzer/pylibafl_simple_bytes_fuzzer.py \
  --harness-script validation/pylibafl_demo/noop_harness.py \
  --harness-func harness \
  --seed-dir validation/pylibafl_demo/seeds \
  --out-dir validation/pylibafl_demo/out \
  --iterations 1000 \
  --wall-time-sec 30 \
  --broker-port 2337 \
  --cores 0
```

The harness must return on normal parser rejection and raise only for crash-worthy conditions. Do not run unstable native parsers in-process with Python.

## Rust LibAFL Command Template

Use this when the target is a local file-input command and native crashes must be isolated from the agent process.

```bash
cargo check --manifest-path assets/rust_libafl_cli_command_fuzzer/Cargo.toml
cargo run --manifest-path assets/rust_libafl_cli_command_fuzzer/Cargo.toml -- \
  --in validation/libxml2_demo/seeds \
  --out validation/rust_command_xmllint/run001 \
  --token-file validation/local/format.dict \
  --iterations 20 \
  --timeout-ms 1000 \
  -- validation/libxml2_demo/xmllint_noncrash_wrapper.sh @@
```

For CLI parsers, normalize expected parse errors in a wrapper so routine rejection exits 0 and real signals/timeouts remain observable. On Unix, LibAFL `CommandExecutor` treats signal termination as a crash objective; ordinary nonzero exit codes are not enough.

Minimal wrapper pattern:

```bash
#!/usr/bin/env bash
set -u
target_program "$1" >/tmp/target.stdout 2>/tmp/target.stderr
rc=$?
if [ "$rc" -ge 128 ]; then
  exit "$rc"
fi
exit 0
```

Validate the wrapper on one valid seed and one intentionally malformed non-crashing input before fuzzing.

`--token-file` accepts raw one-token-per-line files and AFL dictionary entries such as `name="\\x30\\x26..."`. These tokens feed LibAFL token mutators, not an external AFL++ fuzzer.

## Rust LibAFL AFL Forkserver Template

Use this when a local source build can be compiled with AFL-compatible instrumentation. This is the preferred path for Fuzzing101 Exercise 7 style large parser harnesses and for extracted Cisco parser code that can be rebuilt in a lab.

Build the target or harness with AFL++ compiler wrappers and optional partial instrumentation:

```bash
source validation/env_setup_afl_qemu/reports/env_exports.sh
export CC="$AFL_PATH/afl-clang-fast"
export CXX="$AFL_PATH/afl-clang-fast++"
export AFL_LLVM_ALLOWLIST="$PWD/campaigns/vlc/Partial_instrumentation"
```

Then run the campaign with Rust LibAFL:

```bash
cargo check --manifest-path assets/rust_libafl_afl_forkserver_fuzzer/Cargo.toml
cargo run --manifest-path assets/rust_libafl_afl_forkserver_fuzzer/Cargo.toml -- \
  --in campaigns/vlc/seeds \
  --out campaigns/vlc/libafl-forkserver-run001 \
  --token-file campaigns/vlc/asf_dictionary.dict \
  --iterations 1000 \
  --timeout-ms 1200 \
  -- ./vlc-demux-run @@
```

The target must start an AFL-compatible forkserver. If the forkserver handshake fails, record it as a build/harness problem and return to instrumentation or harness setup; do not substitute `afl-fuzz`.

## Local CLI Smoke

`assets/local_cli_smoke_fuzzer/local_cli_mutation_fuzzer.py` is a validation scaffold, not the main Cisco fuzzer. Use it to check seeds, mutation plumbing, command execution, result capture, and reproducer formatting before building a pylibafl/Rust LibAFL harness.

```bash
python3 assets/local_cli_smoke_fuzzer/local_cli_mutation_fuzzer.py \
  --cmd-template 'target_program @@' \
  --seed-dir campaigns/local/seeds \
  --out-dir campaigns/local/smoke \
  --case-extension .bin \
  --token-file campaigns/local/format.dict \
  --cases 50 \
  --timeout 3 \
  --max-findings 3
```

`--token-file` accepts either raw one-token-per-line files or AFL dictionary entries such as `name="\\x30\\x26..."`. Use dictionaries for XML/DTD tags, protocol magic values, GUIDs, length sentinels, command keywords, and IDA/Ghidra-recovered constants.

For CLI parsers, use the same wrapper rule as the Rust LibAFL command template. Without a wrapper, ordinary parser rejection exits will be recorded as findings and waste triage time.

Treat a finding as crash-like only for signal exits, timeouts, sanitizer traces, core files, or debugger-confirmed faults. A smoke-stage crash can close a local training exercise only after:

- Three reproducible replays.
- A minimized or explicitly justified minimal proof input.
- GDB/ASan/core evidence tied to source lines, binary addresses, or decompiled functions.
- `root_cause.md` and `reports/vulnerability_report.md`.

For Cisco offline or live work, use smoke findings as triage leads; continue into the selected Rust LibAFL or pylibafl workflow before making a vulnerability claim.

## Argument-Profile Fuzzing

Do not let a mutator generate arbitrary shell arguments. Create a wrapper that reads a small profile file or JSON object, maps known tokens to a fixed allowlist of flags, and always appends the fuzzed input file as `@@`.

Use this when a vulnerable path is gated by command options, for example XML validation flags:

- Keep required reachability flags fixed, such as `--valid`, `--loaddtd`, `--dtdattr`, or protocol mode switches.
- Mutate only bounded optional flags from an allowlist.
- Reject unknown generated tokens inside the wrapper.
- Record the resolved command in each finding/replay log.

## Large Application Harnesses

For targets like media players, web servers, or Cisco daemons with plugin dispatch, avoid fuzzing full startup when a narrower parser function can be reached.

Harness pattern:

- Initialize global/runtime state once.
- Read `@@` into memory and pass `(buffer, length)` directly to the demux/parser/decoder.
- Use persistent mode only if state is reset between iterations; otherwise use forkserver or in-process-fork isolation.
- Scope coverage to the parser module or function allowlist when possible. Rewarding unrelated dispatch paths can pull the fuzzer away from the intended format.
- Keep ASan enabled for local/source builds and disable leak checks unless leak triage is the objective.

Exercise 7 pattern:

- Patch or write a narrow harness that converts the file input to an in-memory buffer and calls the demux/parser directly.
- Use a partial instrumentation allowlist for the target parser files/functions.
- Feed format dictionaries such as ASF GUIDs and object headers into LibAFL token mutators.
- Keep the full application binary out of the hot loop unless startup state is required for reachability.

## Shared Library Harnesses

Use this for extracted Cisco `.so` files with parser-like functions or protocol
helpers. Set `offline_execution.target_kind=shared_library_harness` and read
[shared_library_harness.md](shared_library_harness.md) before building.

Default fuzzer choices:

- Rust LibAFL forkserver or in-process-fork when a C/C++ harness can load the
  library and call a stable parser entry.
- LibAFL QEMU/Frida when the library architecture is not native or binary-only
  internal coverage/hooks are needed.
- Rust LibAFL command executor when the harness is safest as a separate CLI that
  accepts `@@`.
- pylibafl only for a small, deterministic Python-callable wrapper. Do not use
  `ctypes` in-process for unstable native code unless the campaign explicitly
  accepts process-corruption risk and has a replay path.

Required smoke checks:

- Load the `.so` with the planned loader and library root.
- Call the selected function with one valid seed and one malformed non-crashing
  seed.
- Prove repeated runs of the same seed are deterministic.
- Record ABI notes: argument types, ownership, required initialization, and
  return/error convention.
- Record whether instrumentation observes library internals or only the harness.

If a candidate function is internal-only, do not guess the call boundary. Record
the IDA/Ghidra evidence, expected register/state setup, and why the function can
be called safely before adding it to the harness.

## Offline Binary-Only QEMU/Frida

Use this for extracted Cisco binaries or closed-source local training targets, not for live hardware.

Preflight must establish:

- Exact executable path, architecture, loader, library root, and required environment variables.
- Emulator/instrumentation availability: LibAFL QEMU/Frida for fuzzing, plus optional AFL++ `afl-qemu-trace`/QASAN for execution checks and replay.
- Legal/operational authorization to execute the binary and any license prompts already handled by a human.
- Input surface and command template; do not fuzz shell launcher scripts when a real ELF is available underneath.
- Architecture match between target, QEMU helper, and sanitizer helper. For example, an i386 ELF needs i386-compatible QEMU/QASAN support; an x86_64 `afl-qemu-trace` and x86_64 `libqasan.so` are not sufficient evidence.

Persistent mode requires:

- A function-boundary loop address found through IDA, Ghidra, callgrind, or a previously validated trace.
- Stability check before long runs.
- Register/state reset settings such as `AFL_QEMU_PERSISTENT_GPR=1` when using AFL++ QEMU for auxiliary persistent-mode validation or QASAN replay.
- Rejected candidate addresses recorded in `commands.log` or campaign notes.

For binary-only OOB triage, do three normal replays first. Then run QASAN/Frida/QEMU sanitizer-style replay if available. If sanitizer tooling is unavailable, keep status `unconfirmed` or `needs_permission`.

Exercise 8 pattern:

- Identify the real ELF behind any launcher script before fuzzing. For Adobe Reader 9, this is the `intellinux/bin/acroread` executable rather than the shell wrapper.
- Preflight loader/library variables such as install root, config, and `LD_LIBRARY_PATH` before execution.
- Document the persistent-loop address as a function-boundary address recovered from IDA/Ghidra/callgrind/dynamic traces; never cargo-cult a sample address into another build.
- Use QASAN/Frida/QEMU sanitizer replay for crash explanation, not as a substitute for normal replay, minimization, and root-cause mapping.

## Cisco Live Gate And Replay

Before any live Cisco traffic, validate a `cisco_live` manifest. Live fuzz campaigns still need `fuzzer.mode` to name a Rust LibAFL or pylibafl driver; the tools below are safety gates and replay/probe helpers, not campaign fuzzers.

```bash
python3 scripts/campaign_preflight.py --manifest campaigns/<name>/campaign_manifest.json --create-dirs
```

Protocol-specific drivers must call the same gate before sending traffic:

```bash
python3 scripts/live_driver_gate.py \
  --campaign-manifest campaigns/<name>/campaign_manifest.json \
  --target-host 192.168.100.133 \
  --port <port> \
  --proto tcp \
  --seed-dir campaigns/<name>/seeds \
  --baseline-seed-dir campaigns/<name>/baseline \
  --cases 5 \
  --mode sweep
```

For `live_profile=destructive_lab`, add one `--destructive-action <name>` flag
for each destructive class the driver may perform. The gate rejects actions not
listed in `destructive_lab.allowed_destructive_actions`.

For simple TCP/UDP request/response baseline or seed replay, use the bundled executor:

```bash
python3 scripts/live_probe_executor.py \
  --campaign-manifest campaigns/<name>/campaign_manifest.json \
  --target-host 192.168.100.133 \
  --port <port> \
  --proto tcp \
  --seed-dir campaigns/<name>/seeds \
  --baseline-seed-dir campaigns/<name>/baseline \
  --out-dir campaigns/<name>/run001 \
  --cases 5 \
  --delay 1.0 \
  --timeout 2.0 \
  --health-probe-note 'approved before/after health checks' \
  --stop-condition-note 'timeout/reset, TRACEBACK, new core/crashinfo, process restart' \
  --stop-on-timeout \
  --stop-on-reset
```

`live_probe_executor.py` revalidates the full manifest and rejects runs when host, protocol/port, baseline seed directory, fuzz seed directory, or case count diverge. It replays existing seed files; it does not mutate inputs. `--lab-mode` is only for loopback smoke tests unless `--allow-lab-network` is explicitly used for private lab addresses; never use it for a real Cisco campaign.

## Structured Live Protocol Driver Pattern

Use this for authorized live Cisco protocols with known framing, such as TLV,
BER/ASN.1, HTTP-like request/response, YANG/RPC envelopes, or proprietary
binary headers. The campaign fuzzer may be a small protocol-specific pylibafl
or Rust LibAFL driver because instrumentation is unavailable on live hardware.
It still must call `scripts/live_driver_gate.py` or equivalent manifest
validation before opening a socket.

Required modes:

- `baseline`: send a safe seed and record reachability and response class.
- `sweep`: mutate only a bounded allowlist of fields, such as message type,
  declared length, count, flags, value length, or one optional protocol unit.
- `oneshot`: replay exactly one named case.
- `armed-reload`: send a known DoS/reload trigger only when an explicit flag such as `--arm-reload-trigger` is present.

Good default command behavior is non-destructive:

```bash
python3 targets/<protocol>/<driver>.py \
  --campaign-manifest campaigns/<name>/campaign_manifest.json \
  --target-host 192.168.100.133 \
  --port <port> \
  --mode baseline \
  --send \
  --out-dir campaigns/<name>/baseline_run
```

An armed reproducer command must be visibly different and one-shot:

```bash
python3 targets/<protocol>/<driver>.py \
  --campaign-manifest campaigns/<name>/campaign_manifest.json \
  --target-host 192.168.100.133 \
  --port <port> \
  --mode armed-reload \
  --arm-reload-trigger \
  --cases 1 \
  --send \
  --delay 1.0 \
  --out-dir campaigns/<name>/repro_reload_001
```

The driver should save case bytes, response bytes, status class, elapsed time,
health snapshots, and a decision log. In conservative or one-shot profiles, if
the trigger causes a timeout and later liveness loss, stop and collect recovery
evidence. In `destructive_lab`, record the evidence and continue only if the
required observers remain available and the manifest budget/stop rules allow it.

For a TLV protocol, minimization should operate on whole protocol units first:
reduce to one message, one TLV, one type, one declared length, and then byte
minimize only after the field-level hypothesis is stable. For other protocols,
use the equivalent units: header, route/method, count, optional section, or
single object.

## Live Feedback

The live path records:

- send error
- timeout
- connection reset/refused
- response length
- response prefix hash
- elapsed time

An anomaly is only a triage lead. Collect health evidence, replay, minimize, and map the root cause before making any vulnerability claim.

In `production_conservative` and `lab_minimal_one_shot`, stop immediately on
reload, watchdog, CPUHOG, traceback, signal, SegV, memory alerts, target PID
changes, new core/crashinfo, liveness failure, or management-plane instability.
In `destructive_lab`, treat those events as evidence and continue only while the
observer chain, attribution notes, and campaign budget remain valid.
