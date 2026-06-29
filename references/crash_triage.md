# Crash Triage

## First Response

When a crash-like anomaly appears, preserve evidence immediately. Include the coverage or reachability signal defined in [coverage_and_reachability.md](coverage_and_reachability.md), because a timeout or crash artifact without reachability context is usually only a lead.

Treat crash-like events as evidence first. Continue testing only when the event
can still be tied to controlled input fields, required observers still work, and
the next action is not listed under `Forbidden` in `campaign_manifest.md`.

Save:

- Triggering input.
- Original seed.
- Mutation metadata.
- Raw response or timeout/reset state.
- Timestamp and case number.
- Health snapshot before and after.
- Filtered device logs.
- Core/crash directory listings.

Do not continue without updating the campaign's crash attribution notes. If the
agent can no longer explain new events, stop and restore observability before
more traffic.

## Local Sanitizer Replay

For source-built local or offline harnesses, sanitizer replay is preferred when available:

```bash
ASAN_OPTIONS=abort_on_error=1:detect_leaks=0:symbolize=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
./harness ./crashcase > reports/sanitizer_replay.txt 2>&1
```

Use ASan/UBSan for rebuilt source or harness code. Use QASAN, Frida, or QEMU sanitizer-style replay only as auxiliary evidence for binary-only targets, and record architecture, loader, library root, and helper version. If sanitizer tooling is unavailable, keep the case `unconfirmed` until normal replay and root-cause mapping are sufficient.

Disable leak detection during high-throughput fuzzing unless leak triage is the objective. Re-enable targeted leak checks only after crash reproduction is stable.

## Live Device Checks

Use approved read-only CLI commands where available:

```text
show clock
show version | include uptime|System returned|Version
show processes | include <target-service>|CPU|SNMP|HTTP|Confd
show logging | include TRACEBACK|SYS-2|SYS-3|SegV|SIG|crash|Exception|reload|WATCHDOG|CPUHOG|malloc|Memory
dir bootflash:/core
dir harddisk:/core
dir crashinfo:
```

If a shell is explicitly approved:

```text
ps -eo pid,ppid,stat,comm,args
cat /proc/<pid>/status
cat /proc/<pid>/maps
ls -lt /bootflash/core /harddisk/core /var/log
dmesg -T | tail -200
```

Do not attach `gdbserver` or run `gcore` unless the user approved debugger attachment and process pause risk.

## Live Reload Classification

Network symptoms alone are not enough to confirm a Cisco crash:

- A per-case timeout is a lead.
- A persistent connection failure after a trigger is a crash-like anomaly.
- A confirmed reload needs device evidence, such as uptime reset, a system
  return reason, a new core/system-report file, console traceback, watchdog, or
  crashinfo delta.

For a pre-auth live service, collect at minimum:

- Baseline response before the trigger, including status and timestamp.
- Exact trigger bytes and send timestamp.
- Post-trigger liveness result, including timeout/refused/unreachable status.
- Recovery CLI or console evidence showing uptime and system return reason.
- Before/after listings of core or crashinfo directories.

If the device is unavailable after the trigger and recovery evidence is not yet
collected, classify the case as `crash-like availability anomaly` rather than
`confirmed reload`.

A reload, watchdog, CPUHOG, process restart, or new core/crashinfo increments
campaign evidence. Stop when the device cannot be recovered enough to preserve
evidence, attribution is no longer possible, observers are unavailable, or the
next action would violate `Forbidden`.

## Reproduction

Replay the exact case at least three times:

- Once after a short delay.
- Once after a fresh baseline health check.
- Once with the minimal protocol setup needed to reach the parser state.

If replay is not stable, keep it as an anomaly and continue analysis before
larger fuzzing. Unstable replay can still guide the next runtime experiment when
the controlled fields, parser path, and fault oracle remain plausible.

For live DoS/reload reproducers, record the trigger plan, recovery plan, and
evidence goal before replay. Do not repeat a trigger that conflicts with
`Forbidden`.

## Minimization

Minimize by protocol unit, not just bytes:

- Remove whole messages in a sequence.
- Remove optional TLVs, headers, JSON keys, or XML elements.
- Shrink lengths while preserving known framing.
- Test boundary values around the crashing field.
- Keep a copy of every minimized step that still reproduces.

For TLV protocols, minimize whole TLVs before byte-level deletion. Record each
declared length, actual value length, TLV type, and whether the parser response
changed.

## Root Cause Mapping

Use the best available artifact:

- Core file or system report.
- GDB backtrace.
- Process restart logs.
- PC/register dump from logs.
- Response class and timing if no crash artifact exists.

For local GDB triage, cap recursive backtraces and redirect output:

```bash
gdb -q --batch \
  -ex 'set pagination off' \
  -ex 'set backtrace limit 80' \
  -ex run \
  -ex 'bt 40' \
  --args ./target ./crashcase > gdb_bt40.txt 2>&1
```

Map addresses to the extracted firmware and reverse-engineering database. For PIE/ASLR binaries, account for module load bases from `/proc/<pid>/maps` or core metadata.
For shared-library harnesses, always save the `.so` path, loader/library root,
module base, selected symbol or internal function address, and harness command
environment. Reject crashes that are only in harness glue, dependency loading,
or impossible fuzzing-only states.

The report should connect:

```text
input field -> parser state -> function/basic block -> fault or unsafe operation -> impact
```

If that chain is incomplete, mark the candidate as unconfirmed or needs-permission.
