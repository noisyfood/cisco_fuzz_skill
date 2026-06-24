# Fuzzing Obstacles

Use this when a harness reaches only shallow validation or behaves
non-deterministically. Obstacles must be handled differently for source-built
local harnesses, binary-only offline targets, shared libraries, and live Cisco
devices.

## Common Obstacles

- Magic values, version fields, or command IDs.
- Length, count, checksum, hash, signature, or CRC fields.
- Authentication, configuration, license, feature flag, or platform checks.
- Time, PRNG, PID, hostname, interface, or filesystem-dependent behavior.
- Global state, caches, threads, stale descriptors, memory pools, or singleton
  contexts.
- Multi-message protocol setup before the parser state is reachable.
- ABI uncertainty in `.so` harnesses.

## Decision Rule

Prefer the least invasive fix that preserves production-relevant behavior:

1. Better valid seeds.
2. Focused dictionary tokens.
3. Field-aware mutator with length/count/checksum fixups.
4. Harness initialization or environment setup.
5. Fuzzing-only patch, only for source or controlled local harness builds.

Do not patch a live Cisco device or repack firmware to make fuzzing easier.
For extracted binary-only firmware, record any binary patch as a lab-only
reachability experiment and do not treat resulting crashes as confirmed
production vulnerabilities without unpatched replay evidence.

## Allowed Local Patches

For source-built local or training harnesses, fuzzing-only patches may:

- Make PRNG or time sources deterministic.
- Bypass non-security-critical checksums after recording false-positive risk.
- Replace blocking I/O with deterministic in-memory data.
- Provide safe defaults when skipping validation would otherwise create an
  impossible state.
- Disable noisy logging or unrelated plugins.

Every patch needs:

- File/function or binary location.
- Reason it blocks coverage or reachability.
- Why the patch does not create impossible target states, or what risk remains.
- Before/after coverage or reachability evidence.
- Whether findings require unpatched replay.

## Cisco Live Constraints

For live devices:

- Do not bypass authentication, config, reload/action RPCs, or safety checks.
- Do not change device configuration to reach a parser unless the user
  explicitly authorizes that class of change.
- Use safe setup traffic, valid protocol state, and low-rate field sweeps.
- Stop on health anomaly and collect evidence before continuing.

If a path requires destructive state, mark it `needs_permission` instead of
probing around the gate.

## Shared-Library Constraints

For `.so` harnesses:

- Fix ABI uncertainty before fuzzing. Do not mutate into unknown calling
  conventions.
- Initialize required context through documented init functions when possible.
- Recreate contexts per iteration if global state cannot be reset safely.
- Treat crashes from wrong ABI, missing dependencies, bad ownership, or skipped
  init as harness bugs.
- If a checksum or parser state can be repaired in the harness, record the
  fixup separately from fuzzed bytes.

## Field Fixups

When input format is known, implement fixups after mutation:

- Declared length equals serialized value length.
- Count equals number of child objects or TLVs.
- Checksum or CRC recomputed over the documented range.
- Alignment, padding, or terminator restored.
- Transaction IDs and session fields kept valid when required for reachability.

For minimization, remove whole protocol units first, then shrink fields, then
byte-minimize only after the parser state hypothesis is stable.

## Rejection Criteria

Reject or downgrade findings when:

- The crash occurs only because a fuzzing-only patch made production-impossible
  state reachable.
- The harness violated ABI or ownership contracts.
- The input cannot be replayed through the unpatched parser or equivalent live
  path.
- The only symptom is a single timeout with no health, replay, or trace evidence.

Mark such cases as `harness_bug`, `unconfirmed`, or `needs_permission` rather
than a vulnerability.
