# Python pylibafl Bytes Fuzzer Scaffold

This directory contains a small scaffold for local training or tiny
Python-callable parsers.

Use it only when the target can be safely exposed as:

```python
def harness(data: bytes) -> None:
    ...
```

This is not a live Cisco fuzzer and not a device primitive. It exists to bridge
Fuzzing101-style local parser exercises to later skill steps:

- seed directory handling
- iteration and wall-clock budgets
- crash-like exception capture
- queue output under a campaign directory
- LibAFL import validation

Example:

```bash
python3 scripts/pylibafl_import_probe.py
python3 assets/python_pylibafl_bytes_fuzzer/pylibafl_simple_bytes_fuzzer.py \
  --harness-script validation/pylibafl_demo/noop_harness.py \
  --harness-func harness \
  --seed-dir validation/pylibafl_demo/seeds \
  --out-dir validation/pylibafl_demo/out \
  --iterations 1000 \
  --wall-time-sec 30 \
  --broker-port 2337 \
  --cores 0
```

For extracted Cisco native code, prefer a Rust LibAFL harness, forkserver,
QEMU, or Frida workflow. For live Cisco devices, write a protocol-specific live
driver with preflight gating, response classification, health snapshots, and
strict stop conditions.
