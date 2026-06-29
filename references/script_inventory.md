# Script Inventory

This skill keeps reusable helpers small. Campaign fuzzers are generated as
target-specific LibAFL projects under a campaign or target work area, not chosen
from a fixed fuzzer list.

Run commands from the skill root unless a tool says otherwise.

## Runtime Primitives

| Script | Directly usable | Purpose | Required context |
| --- | --- | --- | --- |
| `scripts/ida_surface_scan.py` | Yes, inside IDA | Emit JSONL candidates for input surfaces through ida-pro-mcp `execute_script`. | IDA database open, autoanalysis complete, and a selected threat model. |
| `scripts/run_logged_command.py` | Yes, audit only | Append command line, stdout, stderr, timestamps, cwd, and exit code to a log. | Use when exact command evidence matters and no better campaign logger exists. |
| `scripts/generate_vulnerability_report.py` | Yes | Generate a structured vulnerability report from evidence JSON. | Report JSON plus replay, trace, crash, or real-device evidence. |

## LibAFL Assets

The Rust LibAFL templates under `assets/rust_libafl_cli_command_fuzzer/` and
`assets/rust_libafl_afl_forkserver_fuzzer/` are implementation references. Copy
or adapt their LibAFL component patterns only when they fit the selected target.
Generated campaign fuzzers should record their input model, executor, observer,
feedback, objective, corpus paths, and evidence outputs in `campaign_manifest.md`.
