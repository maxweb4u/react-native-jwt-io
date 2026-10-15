---
doc_kind: adr
doc_function: canonical
purpose: Record how the supported React Native range is defined — by the engine features the code needs, not by a peer dependency.
derived_from:
  - ADR-001-crypto-backend.md
status: active
decision_status: accepted
date: 2026-10-15
---

# ADR-005 — Host requirements instead of a React Native peer

## Context

The 2.0.0 core is pure JavaScript and never imports `react-native` ([ADR-001](ADR-001-crypto-backend.md)). What it needs from the host is a set of JavaScript engine features, used by the crypto packages at runtime — checked in their sources on 2026-10-15:

| Feature | Used by | Needed for |
|-|-|-|
| `BigInt`, including `0n` literals | `@noble/curves`, `@noble/hashes` (SHA-512), `micro-rsa-dsa-dh` | everything except HS256 — parsed at module load, so absence breaks the import itself |
| `Object.hasOwn` | `validateObject` in `@noble/hashes` and `@noble/curves`, called when curves are constructed | every ES* and EdDSA call; likely at module load |
| `crypto.getRandomValues` | `@noble/hashes` `randomBytes` | PS* signing only |
| `TextEncoder` | noble's `utf8ToBytes`, which the library does not call | nothing |
| `Uint8Array.fromHex` / `toHex` | noble, feature-detected with a fallback | nothing |

None of the imported files uses `export * as`, so the React Native Babel preset needs no extra plugin (unlike `matrix-js-sdk` 42 in `react-native-matrix`).

Hermes has had `BigInt` since React Native 0.70. When it gained `Object.hasOwn` is not documented anywhere found; React Native 0.77 removed its own uses of `Object.hasOwn` because they broke Animated **on JSC**, which suggests Hermes already had it, but that is inference, not a measurement.

## Decision

1. **No `react-native` peer dependency.** The package does not import it, and a peer range would only block installs.
2. **The supported floor is the lowest React Native version whose Hermes has every feature the code needs** — the minimum the library actually requires, not a chosen round number. It is measured in FT-001 stage 1a: run the self-test on the oldest candidate (0.70, the first Hermes with `BigInt`) and move up until every algorithm passes. The README states the measured floor.
3. **A runtime host check.** On first use the library checks the features above and throws `JwtHostRequirementError` naming the missing global and what supplies it, instead of letting `undefined is not a function` surface from inside noble. PS* signing checks `crypto.getRandomValues` separately and names `react-native-get-random-values`.
4. **Hermes only.** JSC is not tested or supported; it may work where it has the same features.

## Consequences

**Positive.** The range is as wide as the code allows and is backed by a measurement. Installs are never blocked by a peer warning. A host that is too old fails with a sentence, not a stack trace. Node ≥ 20.19 and browsers work as a side effect.

**Negative.** The floor is unknown until stage 1a runs, and measuring old React Native versions costs device time. If `Object.hasOwn` arrived late in Hermes, the floor rises with it — the library does not polyfill globals for the host.

**Rejected alternatives.**
- A fixed floor (0.76 was proposed) — arbitrary in both directions: it may exclude versions that work, and it was never measured.
- A `react-native` peer range — the library does not use React Native, so the range would express nothing true.
- Bundling polyfills for missing globals — patches the host's global scope from a library, which [react-native-matrix](https://github.com/maxweb4u/react-native-matrix) also refuses to do.
