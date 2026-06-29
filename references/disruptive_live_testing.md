# Disruptive Live Testing

Use this reference for user-owned or explicitly assigned lab devices where
reloads, configuration changes, service disruption, debugger attachment, shell
commands, and large fuzzing budgets are expected research outcomes.

This reference exists because Cisco hardware fuzzing often cannot wait for full
static proof. If the agent can track why a crash-like event happened, runtime
experiments on the lab device should take priority over extending static
analysis solely to reduce operational risk.

## Campaign Notes

Before a disruptive run, record in `campaign_manifest.md`:

- Allowed action classes, such as `large_scale_mutation`, `config_change`,
  `state_changing_rpc`, `service_restart`, `reload`, `debugger_attach`,
  `shell_command`, `file_upload`, `crash_replay`, or a campaign-specific action.
- Budget: max cases, duration, reloads, config changes, or other campaign
  limits.
- Required observers: health, log, core, console, shell, debugger, response, or
  timing evidence that must remain available.
- Evidence capture: artifacts captured before, during, and after the run.
- Stop rules and recovery expectations.
- Crash attribution notes from [crash_attribution.md](crash_attribution.md).
- Any operation listed under `Forbidden`; these remain disallowed.

## Agent Behavior

- Large-scale protocol fuzzing within the budget.
- Configuration changes when recorded in campaign notes and not forbidden.
- State-changing RPCs, CLI actions, uploads, service restarts, reload triggers,
  shell commands, debugger attachment, or crash replay only when the matching
  action class is recorded.
- Continuing after a crash-like event when observers still work, budget remains,
  and no `stop_when` condition has fired.

Not allowed:

- Actions listed under `Forbidden`.
- Actions not named in campaign notes.
- Continuing after observer loss if the missing observer is required to explain
  future crashes.
- Treating a timeout as a vulnerability without crash attribution evidence.

## Stop Semantics

Crash, reload, watchdog, CPUHOG, timeout, process restart, and new
crashinfo/core files are evidence sources first. They become hard stops only
when campaign notes say so or when the agent loses the ability to attribute
later events.

Good stop-rule examples:

- `observer_lost: console or core listing unavailable`
- `budget_exhausted: max_cases reached`
- `reload_budget_exhausted: max_reloads reached`
- `non_target_service_impact`
- `no_new_evidence_after_N_reloads`
- `device_unrecoverable_without_human_action`

## Evidence Minimum

Each disruptive run should save:

- Run plan from `campaign_manifest.md`, including action class, budget,
  observers, stop rules, and recovery expectations.
- Exact case bytes, seed lineage, mutator mode, and field values.
- Before/after health snapshots.
- Response/timing/status class for every sent case.
- Console, CLI, shell, debugger, core, crashinfo, or system-report deltas.
- Attribution notes tying the event back to controlled input fields.
