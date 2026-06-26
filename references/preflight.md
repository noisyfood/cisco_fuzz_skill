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

Every execution campaign must name a `pylibafl` or Rust LibAFL fuzzer in `fuzzer.mode`. `cisco_offline` campaigns with `offline_execution.target_kind=analysis_only` may set `fuzzer.mode` to `none` until execution is authorized. Local training manifests may also keep the legacy `local_training.fuzzer_mode`, but Cisco offline/live campaigns must use the top-level `fuzzer.mode`. AFL++ tools may be listed as auxiliary compiler/QEMU/QASAN tooling, but `afl-fuzz` must not be the selected fuzzer. Smoke/replay helpers such as `local_cli_mutation_fuzzer.py` and `live_probe_executor.py` are not valid campaign fuzzers.

## Offline Scope

For `cisco_offline`, fill `offline_scope` first:

- `source_materials`: firmware image, extraction root, unpacked package, source tree, or analysis bundle being used.
- `execution_authorization`: whether local execution, QEMU/Frida, sanitizer replay, or analysis-only work is authorized.
- `live_device_available`: `yes` only when an entity device is part of this offline campaign.
- `device_context_required`: `yes` only when replay, shell evidence, device-specific configuration, or later live validation is required.

If both `live_device_available` and `device_context_required` are `no`, preflight does not require `device.*` or `shell_debug.*` fields for the offline campaign. Do not invent placeholder device values.

## Campaign Types

- `local_training`: local parser or harness used to validate the workflow. Requires target path or planned build output, input format, allowed dependency installs, instrumentation mode, seed dir, fuzzer mode, output dir, and authorization.
- `cisco_offline`: firmware/extraction analysis and offline parser or shared-library harnessing. Requires `offline_scope`, offline execution metadata, firmware/extraction root, main binaries or libraries, IDA/MCP availability, symbols/base information, output dir, fuzzer mode for execution campaigns, and authorization. Device and shell/debug fields are required only when `offline_scope.live_device_available` or `offline_scope.device_context_required` is `yes`.
- `cisco_live`: real Cisco hardware. Requirements depend on `live_profile`; all profiles require device scope, allowed port/protocol, baseline seeds, fuzz seeds, fuzzer mode, output dir, and explicit campaign authorization.

## Live Profiles

Set `live_profile` for every `cisco_live` manifest:

- `production_conservative`: use for production-like or fragile devices. Requires interface/VRF, credentials policy, shell/debug policy, reverse-engineering context, recovery plan, baseline/fuzz seeds, health probes, stop conditions, `live_safety.max_first_contact_cases <= 10`, and conservative acknowledgements that state-changing ops, shell, and debugger actions need explicit approval.
- `lab_minimal_one_shot`: use for a lab device when only scoped traffic is authorized. Requires target host, allowed port/protocol, safety scope, baseline/fuzz seeds, health probes, stop conditions, authorization, and `live_safety.max_first_contact_cases <= 10`.
- `destructive_lab`: use for an authorized lab device where large-scale fuzzing, config changes, shell/debugger activity, service disruption, reload, or destructive replay may be part of the experiment. Requires `destructive_lab.*` and `crash_attribution.*` fields. Maintenance window, OOB console, config backup, and recovery owner are useful but are not hard blockers in this profile.

For `destructive_lab`, preflight passes only when:

- `destructive_lab.lab_device_authorized=true`
- `destructive_lab.destructive_actions_authorized=true`
- `destructive_lab.allowed_destructive_actions` is a non-empty list
- `destructive_lab.campaign_budget` sets `max_cases` or `max_duration_minutes`
- `destructive_lab.observer_requirements`, `evidence_capture`, and `stop_when` are non-empty lists
- `crash_attribution.attribution_ready=true`
- `crash_attribution.controlled_fields` is non-empty and the parser path, suspected sink, oracle, symbolization plan, and replay plan are filled

When this profile passes, discovering a risk point should normally move to live
experiment and evidence capture before spending more time on static proof.

## Local Target Kinds

Set `local_training.target.kind` explicitly when the target is not an already-built file:

- `existing_file` or `existing_binary`: default. `local_training.target.path` must already exist.
- `source_build`: source or archive is available, but the final binary will be built inside the campaign. `source_path` must exist and `build_output` must be under `output.campaign_dir`.
- `planned_harness`: harness materials are available and the final harness will be generated/built inside the campaign. `source_path` must exist and `build_output` must be under `output.campaign_dir`.

This is only for local training/offline lab setup. It does not relax the `cisco_live` gate.

For downloaded source targets, record the source URL and SHA-256 in `campaign_design.md` or `health/source_materials.json`. Downloading public source into the campaign directory is setup work; executing the target, fuzzing, attaching debuggers, or sending traffic still waits for preflight.

Live probe tools must bind their runtime arguments to this manifest. A run should fail before sending traffic if target host, protocol/port, baseline seed directory, fuzz seed directory, or case count do not match the validated manifest.

For `production_conservative` and `lab_minimal_one_shot`, case count is capped by
`live_safety.max_first_contact_cases`. For `destructive_lab`, case count is
capped by `destructive_lab.campaign_budget.max_cases` for case-counted drivers;
duration-based custom drivers must enforce `max_duration_minutes` themselves.

## Offline Execution Metadata

Set `offline_execution.target_kind` for `cisco_offline` campaigns:

- `binary_only`: an extracted or proprietary ELF will be executed. Preflight requires the real ELF, architecture, loader, library root, `required_env` JSON object (use `{}` when no extra env is needed), license/authorization, QEMU helper and QEMU architecture. If a sanitizer helper such as QASAN is set, its architecture must match the target. If persistent mode is enabled, the manifest must include the loop address, provenance, and stability plan.
- `source_harness`: source or harness materials will be built locally. Record build/output details in campaign notes and keep the source under the workspace.
- `shared_library_harness`: an extracted `.so` will be loaded by a local harness. Preflight requires the library path, candidate functions, input format, harness plan, execution strategy, ABI notes, state-reset plan, seed directory, architecture, loader, library root, `required_env` JSON object (use `{}` when no extra env is needed), and authorization. If QEMU or sanitizer helpers are set, their architecture must match the target. Read [shared_library_harness.md](shared_library_harness.md) before writing or running the harness.
- `analysis_only`: no local execution is authorized. `fuzzer.mode` may be `none`; do not fuzz until the user changes to an execution target kind and provides execution authorization plus a valid pylibafl or Rust LibAFL mode.

For `shared_library_harness`, keep `shared_library.harness_build_output` under
`output.campaign_dir` when it is set. `shared_library.harness_source_path` must
stay under the workspace. The seed directory must already contain at least one
non-empty seed before preflight passes.

## Required Acknowledgements

Set these only after the user explicitly confirms them:

- `authorization.user_authorized_campaign`
- `authorization.no_state_changing_ops_without_explicit_approval`
- `authorization.no_shell_without_explicit_approval`
- `authorization.no_debugger_without_explicit_approval`
- `shell_debug.privileged_actions_require_human_approval`

The three `authorization.no_*` acknowledgements are hard requirements for
`production_conservative`. They are not a substitute for the explicit
`destructive_lab.allowed_destructive_actions` allowlist when
`live_profile=destructive_lab`.

The manifest is evidence. Keep it with the campaign outputs and copy relevant fields into the final report.
