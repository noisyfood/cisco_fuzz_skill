# Campaign Preflight

Before scanning, fuzzing, shell access, debugger attachment, or target traffic, create and validate a campaign manifest.

Start from:

```bash
cp assets/campaign_manifest.template.json campaigns/<name>/campaign_manifest.json
```

Then fill the manifest and run:

```bash
python3 scripts/campaign_preflight.py --manifest campaigns/<name>/campaign_manifest.json --create-dirs
```

Save stdout, stderr, and the exit code in `preflight.log`, and record the exact command in `commands.log`. If no campaign logger is already in use, the audit primitive below can capture the command and exit code:

```bash
python3 scripts/run_logged_command.py \
  --log campaigns/<name>/preflight.log \
  --name preflight \
  -- python3 scripts/campaign_preflight.py --manifest campaigns/<name>/campaign_manifest.json --create-dirs
```

If the command fails, stop and ask the user for the missing information. Do not continue with discovery or fuzzing.

For local training, prepare the seed directory in the workspace before preflight, but do not execute the target before preflight passes. `campaign_preflight.py` validates that the local target exists, seed directories contain at least one non-empty file, live seed directories exist, and campaign output stays under the current workspace.

Every campaign must name a `pylibafl` or Rust LibAFL fuzzer in `fuzzer.mode`. Local training manifests may also keep the legacy `local_training.fuzzer_mode`, but Cisco offline/live campaigns must use the top-level `fuzzer.mode`. AFL++ tools may be listed as auxiliary compiler/QEMU/QASAN tooling, but `afl-fuzz` must not be the selected fuzzer. Smoke/probe helpers such as `local_cli_mutation_fuzzer.py` and `live_probe_executor.py` are not valid campaign fuzzers.

## Campaign Types

- `local_training`: local parser or harness used to validate the workflow. Requires target path or planned build output, input format, allowed dependency installs, instrumentation mode, seed dir, fuzzer mode, output dir, and authorization.
- `cisco_offline`: firmware/extraction analysis and offline parser harnessing. Requires device scope, shell/debug availability, offline execution metadata, firmware/extraction root, main binaries, IDA/MCP availability, symbols/base information, output dir, fuzzer mode, and authorization. If no live device or shell is available, record that explicitly in the manifest instead of leaving fields blank.
- `cisco_live`: real Cisco hardware. Requires device scope, shell/debug policy, reverse-engineering context, output dir, recovery plan, baseline seeds, fuzz seeds, health probes, stop conditions, fuzzer mode, and explicit safety acknowledgements.

For `cisco_live`, `live_safety.max_first_contact_cases` must be `1..10`.

## Local Target Kinds

Set `local_training.target.kind` explicitly when the target is not an already-built file:

- `existing_file` or `existing_binary`: default. `local_training.target.path` must already exist.
- `source_build`: source or archive is available, but the final binary will be built inside the campaign. `source_path` must exist and `build_output` must be under `output.campaign_dir`.
- `planned_harness`: harness materials are available and the final harness will be generated/built inside the campaign. `source_path` must exist and `build_output` must be under `output.campaign_dir`.

This is only for local training/offline lab setup. It does not relax the `cisco_live` gate.

For downloaded source targets, record the source URL and SHA-256 in `campaign_design.md` or `health/source_materials.json`. Downloading public source into the campaign directory is setup work; executing the target, fuzzing, attaching debuggers, or sending traffic still waits for preflight.

Live probe tools must bind their runtime arguments to this manifest. A run should fail before sending traffic if target host, protocol/port, baseline seed directory, fuzz seed directory, or case count do not match the validated manifest.

## Offline Execution Metadata

Set `offline_execution.target_kind` for `cisco_offline` campaigns:

- `binary_only`: an extracted or proprietary ELF will be executed. Preflight requires the real ELF, architecture, loader, library root, required environment, license/authorization, QEMU helper and QEMU architecture. If a sanitizer helper such as QASAN is set, its architecture must match the target. If persistent mode is enabled, the manifest must include the loop address, provenance, and stability plan.
- `source_harness`: source or harness materials will be built locally. Record build/output details in campaign notes and keep the source under the workspace.
- `analysis_only`: no local execution is authorized. Do not fuzz until the user provides execution authorization and a valid fuzzer mode.

## Required Acknowledgements

Set these only after the user explicitly confirms them:

- `authorization.user_authorized_campaign`
- `authorization.no_state_changing_ops_without_explicit_approval`
- `authorization.no_shell_without_explicit_approval`
- `authorization.no_debugger_without_explicit_approval`
- `shell_debug.privileged_actions_require_human_approval`

The manifest is evidence. Keep it with the campaign outputs and copy relevant fields into the final report.
