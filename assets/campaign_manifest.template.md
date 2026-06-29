# Campaign Manifest

Use this file as the working context for the fuzzing campaign. It is not a
schema. Write concise, factual notes that help the model choose targets, tools,
access paths, and test actions. Do not invent values that the user did not
provide. When a detail is unknown, say so directly and continue with the best
available path.

## Device Settings

Describe the real target and every available management or observation path.
Include enough detail for the model to connect, collect evidence, and correlate
test cases with device behavior.

Useful details:

- Device IP or hostname, model, platform, software version, serial number, and
  test interfaces or reachable ports.
- Telnet management: host, port, username, password or password environment
  variable, enable password if applicable.
- WebUI management: scheme, host, port, base URL, username, password or
  password environment variable, and authentication type.
- Serial console: local device path, baud rate, login details, and any console
  capture notes.
- SSH or remote shell access if available.
- Firmware image path, extraction root, download URL, SHA-256, main binaries,
  shared libraries, configs, YANG files, route files, or other analysis inputs.

## Threat Model

Define the attacker before selecting binaries, protocols, or fuzz targets.
Describe the role as concretely as possible.

Capture:

- Attacker identity and privilege: unauthenticated network client,
  authenticated low-privilege WebUI user, Telnet/SSH user, CLI operator,
  adjacent LAN host, local shell user, firmware/update provider, or another
  campaign-specific role.
- Credentials and sessions available to that attacker.
- Interfaces, VRFs, ports, management surfaces, commands, APIs, uploads,
  imports, or config paths reachable by that role.
- Inputs controlled by the attacker and expected formats.
- Observability available after a test case: response, logs, console,
  crashinfo/core files, process state, timing, health checks, or reload
  evidence.

## Attack Surface Candidates

Enumerate only surfaces reachable under the threat model above. For each
candidate, note:

- Surface name and protocol/API/command/file format.
- Required privilege or precondition.
- Parser, binary, route, shared library, or function believed to handle it.
- Seed source and dictionary/token sources.
- Feedback or evidence expected from local, offline, or live execution.
- Why this candidate is worth reversing or fuzzing first.

## Resources

List the tools and environments the model can use. Prefer concrete paths,
versions, endpoints, and access notes over generic tool names.

Cover these areas when available:

- Reverse engineering and static analysis: IDA Pro MCP endpoint/database,
  Ghidra project, angr setup, strings/xrefs outputs, symbol files, base
  addresses, known parser candidates, and prior notes.
- Fuzzing toolchain: LibAFL checkout, Rust toolchain, dictionaries, seed
  sources, corpus locations, generated fuzzer path, and sanitizer availability
  such as ASAN, UBSAN, or QASAN.
- Emulation: QEMU user/system binaries, target architecture, library root,
  rootfs, kernel, machine type, loader scripts, and known emulation blockers.
- Debugging and observability: gdb, gdbserver, remote shell, core/crashinfo
  locations, log commands, process names, health checks, console access, and
  where evidence should be saved.

## Forbidden

Record only operations the user explicitly forbids. Be specific enough that a
model can avoid the action without blocking unrelated testing.

Examples:

- Do not change the administrator password.
- Do not modify named user accounts, authentication methods, or AAA settings.
- Do not touch protected services, interfaces, files, directories, VRFs, or
  unrelated protocols.
- Do not run a named command, upload to a named path, reboot outside a named
  window, or attach a debugger to a named process.

If the user forbids only administrator password changes, say that directly and
do not infer broader restrictions.

## Working Notes

Use this area for campaign-specific decisions that do not fit elsewhere:

- Current target hypothesis and input surface.
- Planned fuzzer, replay path, or evidence collection notes.
- Seed and case directories.
- Evidence directory.
- Open questions for the user.
- Commands already run and notable results.
