# Assets

Assets are portable templates and scaffolds. They are not campaign evidence and
not live-device target code.

| Asset | Use | Dependency status |
| --- | --- | --- |
| `campaign_manifest.template.json` | Base manifest copied into each campaign before preflight, including offline shared-library harness fields. | Core skill asset, no extra dependency. |
| `python_pylibafl_bytes_fuzzer/` | Scaffold for tiny local Python-callable parsers. | Optional; requires `pylibafl` if used. |
| `local_cli_smoke_fuzzer/` | Scaffold for local CLI mutation smoke tests and wrapper validation. | Optional; Python standard library only. |
| `rust_libafl_cli_command_fuzzer/` | Rust LibAFL command-executor scaffold for local file-input targets. | Optional; requires a compatible `LibAFL/` checkout or adjusted Cargo dependencies. |
| `rust_libafl_afl_forkserver_fuzzer/` | Rust LibAFL AFL-forkserver scaffold for instrumented targets. | Optional; requires `LibAFL/` plus an AFL-compatible instrumented target. |

Keep target-specific fuzzers under ignored campaign or target directories, not
inside `assets/`. Promote only reusable scaffolds back into this directory.
Shared-library harnesses for specific Cisco `.so` files are target-specific by
default; keep them in campaign or target work areas until a reusable scaffold
emerges.
