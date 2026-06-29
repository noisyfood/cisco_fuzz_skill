# Assets

Assets are portable templates and scaffolds. They are not campaign evidence and
not live-device target code.

| Asset | Use | Dependency status |
| --- | --- | --- |
| `campaign_manifest.template.md` | Free-form campaign context guide for device settings, resources, and forbidden operations. | Core skill asset, no extra dependency. |
| `rust_libafl_cli_command_fuzzer/` | Rust LibAFL command-executor scaffold for local file-input targets. | Optional; requires a compatible `LibAFL/` checkout or adjusted Cargo dependencies. |
| `rust_libafl_afl_forkserver_fuzzer/` | Rust LibAFL forkserver scaffold for instrumented targets. | Optional; requires `LibAFL/` plus a forkserver-compatible target. |

Keep target-specific fuzzers under ignored campaign or target directories, not
inside `assets/`. Promote only reusable scaffolds back into this directory.
Shared-library harnesses for specific Cisco `.so` files are target-specific by
default; keep them in campaign or target work areas until a reusable scaffold
emerges.
