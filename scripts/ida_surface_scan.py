"""IDA Pro script: emit candidate fuzzing input surfaces as JSONL.

Run inside IDA, for example through ida-pro-mcp execute_script. Set
CISCO_FUZZ_IDA_OUT to choose the output path; otherwise the script writes
ida_surface_candidates.jsonl in IDA's current working directory.
"""

from __future__ import annotations

import json
import os
import re

import ida_auto
import ida_funcs
import ida_kernwin
import ida_nalt
import idautils


API_CATEGORIES = {
    "file_input": {
        "open",
        "fopen",
        "read",
        "fread",
        "mmap",
        "stat",
        "lstat",
    },
    "network_input": {
        "accept",
        "recv",
        "recvfrom",
        "recvmsg",
        "read",
        "SSL_read",
        "BIO_read",
    },
    "memory_sink": {
        "memcpy",
        "memmove",
        "strcpy",
        "strncpy",
        "strcat",
        "snprintf",
        "sprintf",
        "vsnprintf",
        "malloc",
        "calloc",
        "realloc",
        "free",
    },
    "process_or_shell": {
        "system",
        "popen",
        "execve",
        "execl",
        "fork",
    },
}

STRING_PATTERNS = [
    ("http_route", re.compile(r"^/[A-Za-z0-9_./{}-]{2,}$")),
    ("yang_or_restconf", re.compile(r"(restconf|netconf|tailf:|actionpoint|yang)", re.I)),
    ("protocol_name", re.compile(r"(snmp|xmcp|grpc|soap|xml|json|tlv|ber|asn\\.1)", re.I)),
    ("crash_error", re.compile(r"(invalid|overflow|underflow|too large|too small|bad length|parse|decode)", re.I)),
    ("file_extension", re.compile(r"\\.(cfg|xml|json|pem|crt|der|tar|zip|bin|dat)$", re.I)),
]


def func_name(ea):
    func = ida_funcs.get_func(ea)
    if not func:
        return None, None
    return func.start_ea, ida_funcs.get_func_name(func.start_ea)


def import_category(name):
    if not name:
        return None
    short = name.split("@", 1)[0]
    for category, names in API_CATEGORIES.items():
        if short in names:
            return category
    return None


def iter_imports():
    imports = []
    for idx in range(ida_nalt.get_import_module_qty()):
        module = ida_nalt.get_import_module_name(idx) or ""

        def cb(ea, name, ordinal):
            imports.append({"ea": ea, "name": name or f"ordinal_{ordinal}", "module": module})
            return True

        ida_nalt.enum_import_names(idx, cb)
    return imports


def emit_import_records():
    for imp in iter_imports():
        category = import_category(imp["name"])
        if not category:
            continue
        refs = list(idautils.XrefsTo(imp["ea"]))
        for ref in refs[:50]:
            start, name = func_name(ref.frm)
            yield {
                "kind": "import_xref",
                "category": category,
                "import": imp["name"],
                "module": imp["module"],
                "import_ea": hex(imp["ea"]),
                "xref_from": hex(ref.frm),
                "function": hex(start) if start is not None else None,
                "function_name": name,
            }


def emit_string_records():
    strings = idautils.Strings()
    strings.setup(strtypes=[0, 1], minlen=4)
    for s in strings:
        text = str(s)
        matches = [name for name, pattern in STRING_PATTERNS if pattern.search(text)]
        if not matches:
            continue
        refs = list(idautils.XrefsTo(s.ea))
        if not refs:
            yield {
                "kind": "string",
                "category": matches,
                "string_ea": hex(s.ea),
                "text": text[:200],
                "function": None,
                "function_name": None,
            }
            continue
        for ref in refs[:50]:
            start, name = func_name(ref.frm)
            yield {
                "kind": "string_xref",
                "category": matches,
                "string_ea": hex(s.ea),
                "text": text[:200],
                "xref_from": hex(ref.frm),
                "function": hex(start) if start is not None else None,
                "function_name": name,
            }


def main():
    ida_auto.auto_wait()
    out_path = os.environ.get("CISCO_FUZZ_IDA_OUT", "ida_surface_candidates.jsonl")
    count = 0
    with open(out_path, "w", encoding="utf-8") as f:
        for record in emit_import_records():
            f.write(json.dumps(record, sort_keys=True) + "\n")
            count += 1
        for record in emit_string_records():
            f.write(json.dumps(record, sort_keys=True) + "\n")
            count += 1
    ida_kernwin.msg(f"[cisco-fuzz] wrote {count} candidates to {out_path}\\n")


if __name__ == "__main__":
    main()
