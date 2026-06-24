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
- Shared libraries: exported parser symbols, protocol/helper names, vtables,
  function-pointer tables, constructor/init routines, xrefs from daemons, and
  strings that match file extensions, routes, CLI/YANG tokens, or TLV names.
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
- For `.so` targets, is the function exported or internal-only, what
  initialization is required, and what ABI/calling convention evidence supports
  the harness plan?

## Output Record

Write one JSONL record per candidate:

```json
{
  "id": "TARGET-SERVICE-FUNCTION",
  "binary": "iosd",
  "library": "libtarget.so",
  "entry": "tcp/<port>",
  "function": "0xFUNCTION_START",
  "symbol_status": "exported|internal|function-table",
  "input_source": "protocol frame body",
  "fields": ["message_type", "declared_length", "value", "padding_or_checksum"],
  "reachability": "outer parser reached by safe seed; deep parser gated by state or field",
  "abi_notes": "buf,len arguments; context initialized by init_candidate",
  "sink": "input-derived length controls cursor, allocation, copy, index, or recursion",
  "fuzzer_mode": "shared_library_harness_then_rust_libafl",
  "seeds": ["safe baseline frame", "minimal structured frame"],
  "stop_conditions": ["timeout", "reset", "TRACEBACK", "core file"]
}
```

Do not start fuzzing from a decompiler suspicion alone. First produce at least one seed that reaches the parser or explain why the campaign is blocked. Feed recovered constants, field names, enum values, and magic bytes into [dictionary_strategy.md](dictionary_strategy.md), and record the reachability signal defined by [coverage_and_reachability.md](coverage_and_reachability.md).

## MCP Analysis Checklist

For each candidate selected from `ida_surface_candidates.jsonl`, collect:

- Decompiler text for the candidate function and one caller above it.
- Xrefs to protocol constants, route strings, command strings, or TLV tables.
- The input buffer variable and the length variable.
- Branches that reject malformed inputs before the sink.
- Any field fixups required for a seed to pass the shallow parser.
- Crash mapping fields: module base, function start, basic block address, and source line if symbols exist.
- For shared libraries, required constructors/init functions, dependency
  libraries, global state, allocator ownership, and whether coverage can observe
  library internals.

Use modern `ida_*`/`idautils` APIs for any IDAPython additions. Avoid legacy `idc` helpers.
