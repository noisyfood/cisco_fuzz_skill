# Crash Attribution Gate

Crash attribution is the minimum reasoning chain that lets the agent run
aggressive lab experiments without waiting for complete static proof.

The chain is:

```text
controlled input field -> parser path -> missing or weak validation ->
suspected sink/fault site -> runtime fault oracle -> replay/minimization plan
```

`live_profile=destructive_lab` requires this chain before large-scale live
traffic or destructive actions.

## Manifest Fields

- `crash_attribution.attribution_ready`: set `true` only when the current
  evidence is enough to explain future crash-like events.
- `crash_attribution.input_to_parser_path`: how the selected bytes/fields reach
  the parser, route, handler, shared-library function, or protocol state.
- `crash_attribution.controlled_fields`: field names the fuzzer controls, such
  as `tlv.type`, `tlv.length`, `method_id`, `object_count`, or `json.key`.
- `crash_attribution.suspected_sink`: function, basic block, API class, memory
  operation, allocation, recursion, table index, or service action expected to
  fail.
- `crash_attribution.fault_oracle`: how a fault is observed, such as traceback,
  reload reason, process restart, new core, crashinfo delta, GDB stop, response
  class shift, or watchdog/CPUHOG log.
- `crash_attribution.symbolization_plan`: how addresses map to firmware,
  symbols, IDA/Ghidra functions, module bases, or source/harness locations.
- `crash_attribution.replay_plan`: exact replay mode, case count, minimization
  strategy, and recovery/evidence steps.

## Readiness Levels

- `lead`: response or timeout anomaly exists, but parser path or fault oracle is
  not known. Do not start destructive live fuzzing from this alone.
- `attributable`: the fuzzer controls named fields, a valid seed reaches the
  target path, and at least one oracle can distinguish target faults from normal
  rejects. This is sufficient for `destructive_lab` preflight.
- `root-caused`: replay and trace evidence identify the faulting function or
  unsafe operation. This is needed before claiming a confirmed vulnerability.

## Working Notes

For each crash-like event, write an attribution note:

```text
case_id:
seed:
controlled_fields:
expected_parser_path:
observed_oracle:
address_or_log_evidence:
why_harness_or_network_noise_is_unlikely:
next_replay_or_minimization_step:
```

The note can be incomplete during fuzzing, but it must be good enough to choose
the next experiment. When the agent can no longer update this note after new
events, stop the destructive campaign and restore observability first.
