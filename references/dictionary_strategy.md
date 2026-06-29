# Dictionary Strategy

Use dictionaries when syntax, magic values, protocol constants, command tokens,
field names, object types, or hard-coded comparisons block deeper parsing.

Dictionaries guide mutation. They do not replace valid seeds, harness
reachability, or field fixups.

## Gate

Before fuzzing a parser with recognizable structure, create a dictionary record:

- Dictionary path and format.
- Token source for each token group.
- Expected parser barrier the token should help cross.
- Maximum input size and whether long tokens will be ignored.
- Whether tokens are used by LibAFL token mutators, a custom LibAFL mutator, or
  target-specific field fixups.

Keep dictionaries focused. Start with high-signal tokens rather than dumping
every string from a binary.

## Cisco Token Sources

Prefer tokens from:

- IDA/Ghidra strings with xrefs to the selected parser.
- Enum tables, switch cases, TLV types, command IDs, method IDs, and error codes.
- Magic bytes, version fields, object headers, GUIDs, checksums markers, and
  length sentinels.
- YANG modules, RESTCONF/NETCONF action names, CLI command strings, and
  configuration keywords.
- HTTP route names, header names, JSON/XML field names, MIME types, and web UI
  handler constants.
- Captured valid traffic, minimized proof inputs, and vendor sample files.
- Boundary integers encoded as text and binary: `0`, `1`, `-1`, max signed and
  unsigned values, alignment sizes, and common Cisco table limits.

For `.so` harnesses, prefer tokens reachable from the candidate function or its
callers. A global firmware string dump is usually too noisy.

## Format

Use a dictionary format compatible with LibAFL token loading:

```text
# comments are allowed
"GET"
method_post="POST"
tlv_type_1="\x00\x01"
max_u16="\xff\xff"
```

Rules:

- Use raw one-token-per-line entries or named entries.
- Escape quotes and backslashes.
- Use `\xNN` for non-printable bytes.
- Deduplicate tokens.
- Keep most campaign dictionaries around 50-200 high-value entries unless
  coverage/reachability evidence justifies more.

## Validation

Run a short comparison when local coverage or stable reachability exists:

- Seeds only.
- Seeds plus dictionary.
- Seeds plus dictionary and field fixups if the format has length/checksum
  barriers.

Compare target reachability, coverage, response classes, parser logs, or queue
growth. If the dictionary does not change reachability and cannot be tied to a
parser barrier, prune it.

For live Cisco targets, do not use coverage as the metric. Compare safe response
classes, parser-specific logs if available, health deltas, and whether the
driver reaches the intended protocol state without increasing risk.

## Anti-Patterns

- Dumping all `strings` output into a dictionary without xref filtering.
- Including complete sample files instead of atomic tokens.
- Adding thousands of unrelated CLI or web strings.
- Using tokens that exceed the campaign `max_len`.
- Assuming dictionary-driven parser reachability proves a vulnerability.
- Mutating arbitrary shell arguments instead of using a bounded argument profile.
