# Local CLI Smoke Fuzzer Scaffold

This scaffold is a small mutation fuzzer for local file-input command targets.
It is useful for training and plumbing checks:

- seed loading
- AFL-style dictionary token decoding
- command-template execution with `@@`
- timeout/sanitizer/signal classification
- reproducer command capture

It is not a final Cisco campaign fuzzer. Confirmed findings still require
replay, minimization, debugger/crash evidence, root-cause mapping, and a
structured report.

Example:

```bash
python3 assets/local_cli_smoke_fuzzer/local_cli_mutation_fuzzer.py \
  --cmd-template 'target_program @@' \
  --seed-dir campaigns/<name>/seeds \
  --out-dir campaigns/<name>/smoke \
  --case-extension .bin \
  --token-file campaigns/<name>/format.dict \
  --cases 50 \
  --timeout 3 \
  --max-findings 3
```

For CLI parsers, use a wrapper that maps normal parser rejection to exit `0`
and preserves signal-like exits, sanitizer output, and timeouts.
