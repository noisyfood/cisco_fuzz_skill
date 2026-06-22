# IDA Input Surface Discovery

Use this when the target is a binary or firmware component and the fuzzer input surface is not already obvious.

## ida-pro-mcp Entry Point

Before fuzzing a binary target through this skill:

1. Confirm IDA has the correct database open and autoanalysis has completed.
2. Through ida-pro-mcp, run [scripts/ida_surface_scan.py](../scripts/ida_surface_scan.py) inside IDA.
3. Save the generated `ida_surface_candidates.jsonl` into the campaign directory.
4. For each promising candidate, use ida-pro-mcp decompilation, xrefs, and call graph tools to answer the dataflow questions below.
5. Do not fuzz until at least one seed reaches the candidate parser or the report clearly says reachability is blocked.

The scanner is only a triage aid. It finds imports, strings, and xrefs; it does not prove external reachability or vulnerability.

## Search Strategy

Start from imported APIs and strings:

- File parsers: `open`, `read`, `fread`, `mmap`, file extensions, magic constants.
- Network parsers: `recv`, `recvfrom`, socket callbacks, port strings, protocol names, accept/read dispatchers.
- HTTP/WebUI: route strings, nginx/OpenResty Lua routes, handler maps, JSON/XML/YANG names.
- CLI/YANG: command strings, actionpoint names, `tailf:exec`, RESTCONF operation names.
- Binary protocol: magic constants, TLV type tables, error strings, transaction IDs.
- Memory sinks: `memcpy`, `strcpy`, `strncpy`, `snprintf`, allocator/free pairs, vector/table indexing, recursion.

## Dataflow Questions

For each candidate function, answer:

- What external input reaches this function?
- Where is the input pointer and length loaded?
- Are length fields trusted before bounds checks?
- Is there an integer conversion, sign extension, multiplication, or allocation size derived from input?
- Are global row buffers, cached pointers, or free/replace patterns used across requests?
- Does parser state require authentication or configuration before the deep path is reachable?
- Can a valid seed reach this parser without modifying the device?

## Output Record

Write one JSONL record per candidate:

```json
{
  "id": "TARGET-PROTO-FUNCTION",
  "binary": "iosd",
  "entry": "tcp/4788",
  "function": "0x9990ea0",
  "input_source": "XMCP TLV body",
  "fields": ["type_be16", "len_be16", "value", "padding"],
  "reachability": "preauth outer parser, deep parser gated",
  "sink": "cursor advance by declared length",
  "fuzzer_mode": "protocol_live_driver_then_rust_libafl_model",
  "seeds": ["baseline unauth frame", "username TLV frame"],
  "stop_conditions": ["timeout", "reset", "TRACEBACK", "core file"]
}
```

Do not start fuzzing from a decompiler suspicion alone. First produce at least one seed that reaches the parser or explain why the campaign is blocked.

## MCP Analysis Checklist

For each candidate selected from `ida_surface_candidates.jsonl`, collect:

- Decompiler text for the candidate function and one caller above it.
- Xrefs to protocol constants, route strings, command strings, or TLV tables.
- The input buffer variable and the length variable.
- Branches that reject malformed inputs before the sink.
- Any field fixups required for a seed to pass the shallow parser.
- Crash mapping fields: module base, function start, basic block address, and source line if symbols exist.

Use modern `ida_*`/`idautils` APIs for any IDAPython additions. Avoid legacy `idc` helpers.
