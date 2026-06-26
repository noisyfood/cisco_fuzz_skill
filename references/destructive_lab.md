# Destructive Lab Profile

Use `live_profile=destructive_lab` only for user-owned or explicitly assigned
lab devices where reloads, configuration changes, service disruption, debugger
attachment, shell commands, and large fuzzing budgets are authorized research
outcomes.

This profile exists because Cisco hardware fuzzing often cannot wait for full
static proof. If the agent can track why a crash-like event happened, runtime
experiments on the lab device should take priority over extending static
analysis solely to reduce operational risk.

## Required Manifest Fields

Preflight requires:

- `destructive_lab.lab_device_authorized=true`
- `destructive_lab.destructive_actions_authorized=true`
- `destructive_lab.allowed_destructive_actions`: named action classes such as
  `large_scale_mutation`, `config_change`, `state_changing_rpc`,
  `service_restart`, `reload`, `debugger_attach`, `shell_command`,
  `file_upload`, `crash_replay`, or a campaign-specific action name.
- `destructive_lab.campaign_budget`: at least `max_cases` or
  `max_duration_minutes`, plus explicit reload/config-change limits.
- `destructive_lab.observer_requirements`: the health, log, core, console,
  shell, debugger, or response observers that must remain available.
- `destructive_lab.evidence_capture`: artifacts captured before, during, and
  after the run.
- `destructive_lab.stop_when`: hard stop rules for the campaign.
- `crash_attribution.*`: the input-to-crash attribution plan described in
  [crash_attribution.md](crash_attribution.md).

Maintenance windows, OOB console, config backup, and human recovery owner are
useful, but they are not hard preflight blockers in this profile. Missing them
is a recorded operational risk, not a reason to prefer more static analysis when
crash attribution and observers are ready.

## Agent Behavior

Allowed after preflight:

- Large-scale protocol fuzzing within the budget.
- Configuration changes when `config_change` is in
  `allowed_destructive_actions`.
- State-changing RPCs, CLI actions, uploads, service restarts, reload triggers,
  shell commands, debugger attachment, or crash replay only when the matching
  action class is listed.
- Continuing after a crash-like event when observers still work, budget remains,
  and no `stop_when` condition has fired.

Not allowed:

- Sending traffic outside `device.allowed_ports_protocols`.
- Actions not named in `allowed_destructive_actions`.
- Continuing after observer loss if the missing observer is required to explain
  future crashes.
- Treating a timeout as a vulnerability without crash attribution evidence.

## Stop Semantics

In this profile, crash, reload, watchdog, CPUHOG, timeout, process restart, and
new crashinfo/core files are evidence sources first. They become hard stops only
when the manifest says so or when the agent loses the ability to attribute later
events.

Good `stop_when` examples:

- `observer_lost: console or core listing unavailable`
- `budget_exhausted: max_cases reached`
- `reload_budget_exhausted: max_reloads reached`
- `non_target_service_impact`
- `no_new_evidence_after_N_reloads`
- `device_unrecoverable_without_human_action`

## Evidence Minimum

Each destructive run should save:

- Gate summary from `scripts/live_driver_gate.py`.
- Exact case bytes, seed lineage, mutator mode, and field values.
- Before/after health snapshots.
- Response/timing/status class for every sent case.
- Console, CLI, shell, debugger, core, crashinfo, or system-report deltas.
- Attribution notes tying the event back to controlled input fields.
