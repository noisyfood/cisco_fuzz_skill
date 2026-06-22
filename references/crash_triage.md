# Crash Triage

## First Response

When a crash-like anomaly appears, stop fuzzing and preserve evidence.

Save:

- Triggering input.
- Original seed.
- Mutation metadata.
- Raw response or timeout/reset state.
- Timestamp and case number.
- Health snapshot before and after.
- Filtered device logs.
- Core/crash directory listings.

Do not continue fuzzing until the case has been replayed and classified.

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

## Reproduction

Replay the exact case at least three times:

- Once after a short delay.
- Once after a fresh baseline health check.
- Once with the minimal protocol setup needed to reach the parser state.

If replay is not stable, keep it as an anomaly and continue static analysis before any larger fuzzing.

For live DoS/reload reproducers, do not repeat the trigger automatically. One
approved trigger plus strong reload evidence can be enough for confirmation;
additional replays require separate user approval because they intentionally
repeat service impact.

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

The report should connect:

```text
input field -> parser state -> function/basic block -> fault or unsafe operation -> impact
```

If that chain is incomplete, mark the candidate as unconfirmed or needs-permission.
