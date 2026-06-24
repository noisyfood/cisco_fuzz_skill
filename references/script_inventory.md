# Script Inventory

This skill separates small runtime primitives from fuzzer scaffolds:

- `scripts/` contains primitives: validators, gates, probes, report builders,
  and audit helpers. They should do one bounded job and be easy to replace.
- `assets/` contains fuzzer scaffolds/templates. These are meant to be copied,
  adapted, or built into a campaign fuzzer.

Run commands from the skill root unless a tool says otherwise.

## Runtime Primitives

| Script | Directly usable | Purpose | Required preconditions |
| --- | --- | --- | --- |
| `scripts/campaign_preflight.py` | Yes | Validate `campaign_manifest.json` before any target interaction and create the standard campaign directories. | A filled manifest derived from `assets/campaign_manifest.template.json`; local/live seed dirs must already contain at least one non-empty seed. Local target kind may be `existing_file`, `source_build`, or `planned_harness`; Cisco offline target kind may include `shared_library_harness` for extracted `.so` work. |
| `scripts/ida_surface_scan.py` | Yes, inside IDA | Emit JSONL candidates for fuzzing input surfaces through ida-pro-mcp `execute_script`. | IDA database open and autoanalysis complete. |
| `scripts/pylibafl_import_probe.py` | Yes | Check whether `pylibafl` imports normally or from the local LibAFL build artifact. | Local LibAFL tree present. |
| `scripts/run_logged_command.py` | Yes, audit only | Primitive command logger. It appends command line, stdout, stderr, timestamps, cwd, and exit code to a log. It is not a fuzzer and does not enforce policy. | Use when exact audit logs matter and no better logger exists. |
| `scripts/live_driver_gate.py` | Yes | Pre-traffic gate for protocol-specific Cisco live drivers and replay helpers. | Valid `cisco_live` manifest and matching runtime host/proto/port/seed/case arguments. |
| `scripts/live_probe_executor.py` | Yes, with strict gate | Low-rate live baseline/seed-replay executor for TCP/UDP request/response targets; not a campaign fuzzer and does not mutate inputs. | Valid `cisco_live` manifest; `--lab-mode` is only for loopback smoke tests unless private lab mode is explicit. |
| `scripts/generate_vulnerability_report.py` | Yes | Generate a structured vulnerability report from JSON evidence. Confirmed local/offline reports require replay and trace evidence; confirmed `cisco_live` reload reports may use decision-log plus reload/core/health evidence instead of local exit-code replay. | Filled report JSON; confirmed reports require a validated manifest; `--check-local-evidence` verifies listed files and hash/size strings when present. |

## Fuzzer Scaffolds

The Python pylibafl scaffold under `assets/python_pylibafl_bytes_fuzzer/` is
directly runnable for local Python-callable harnesses. Use it for training or
small safe parsers, then copy/adapt the pattern if it becomes campaign code.

The local CLI smoke scaffold under `assets/local_cli_smoke_fuzzer/` is directly
runnable for local command targets. It is useful for plumbing validation before
building a real pylibafl/Rust LibAFL campaign fuzzer.

The Rust LibAFL template under `assets/rust_libafl_cli_command_fuzzer/` is usable after a compatible LibAFL checkout is available at `LibAFL/` or the Cargo dependencies are adjusted. Use it for local file-input CLI targets where a Rust LibAFL executor is warranted; it supports `--token-file` for raw or AFL dictionary tokens.

The Rust LibAFL forkserver template under `assets/rust_libafl_afl_forkserver_fuzzer/` is usable after a compatible LibAFL checkout is available at `LibAFL/` or the Cargo dependencies are adjusted. Use it for targets compiled with AFL-compatible instrumentation, including partial-instrumentation source harnesses. AFL++ provides the compiler/runtime handshake; LibAFL remains the fuzzer.
