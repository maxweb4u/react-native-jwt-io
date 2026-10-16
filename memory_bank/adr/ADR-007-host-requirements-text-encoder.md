---
doc_kind: adr
doc_function: canonical
purpose: Record how the supported React Native range is defined — ADR-005 restated, with TextEncoder added to the host requirements and the floor raised to 0.74 accordingly.
derived_from:
  - ADR-001-crypto-backend.md
status: active
decision_status: accepted
date: 2026-10-16
supersedes: ADR-005-host-requirements.md
---

# ADR-007 — Host requirements, with TextEncoder

Supersedes [ADR-005](ADR-005-host-requirements.md). Its decision — no `react-native` peer, a floor measured from the engine features the code needs, a runtime host check, Hermes only — stands. Its list of features was wrong in two places, and the floor moves with the correction.

## Context

ADR-005's table said noble's `utf8ToBytes`, the only user of `TextEncoder`, is never called by the library, so `TextEncoder` is not needed. The second review (2026-10-16) found that it is called **while the modules load**: `@noble/curves` builds its FROST helpers at the top level of `ed25519.js`, `nist.js` and `secp256k1.js`, and `createFROST` encodes its context strings with `utf8ToBytes`, which calls `new TextEncoder()`. The calls are marked `/* @__PURE__ */`, so bundlers that tree-shake (esbuild, Rollup) drop them; **Metro does not tree-shake**, so in an app they run. Without `TextEncoder` the curve modules fail to load with `ReferenceError: TextEncoder is not defined`. In Node, and under Metro without `inlineRequires`, that is the import of the library — every algorithm, HS256 included (measured with the global deleted). React Native's default Metro config turns `inlineRequires` on, which defers the curve modules to their first use: then HS256 and RS* work and every ES* and EdDSA import or call throws — some of it caught by the library's own `try` blocks and reported as an invalid key (measured on a Metro bundle of `example/`). Either way the host cannot run the library.

Hermes' sources at the React Native release tags (`lib/VM/JSLib/TextEncoder.cpp`, `PredefinedStrings.def`): absent at 0.71, 0.72 and 0.73; present from **0.74**.

The 0.71 floor ADR-005 led to was measured in the Hermes v0.12 CLI with a bundle built by esbuild — which dropped the FROST calls, so the measurement could not see this. The on-device runs were React Native 0.87, which has `TextEncoder`.

ADR-005 also said `0n` literals make a missing `BigInt` a parse error. The installed `@noble/*` and `micro-rsa-dsa-dh` contain no BigInt literals (they write `BigInt(0)`), so a missing `BigInt` is a runtime error that `hostCheck` can name.

| Feature | Used by | Needed for |
|-|-|-|
| `BigInt` (called, not as literals) | `@noble/curves`, `@noble/hashes` (SHA-512), `micro-rsa-dsa-dh` | everything except HS256; first use at module load |
| `Object.hasOwn` | `validateObject` in `@noble/hashes` and `@noble/curves`, at module load | the import itself |
| `TextEncoder` | noble's `utf8ToBytes`, from `createFROST` when `ed25519.js`, `nist.js`, `secp256k1.js` load | loading the curves: at import, or at first ES*/EdDSA use under `inlineRequires` |
| BigInt `**`, not rewritten by Babel | `@noble/curves/abstract/curve.js` (Ed25519 scalar multiplication) and `abstract/montgomery.js` (x25519, built while `ed25519.js` loads) | Ed25519, and loading `ed25519.js` |
| `crypto.getRandomValues` | `@noble/hashes` `randomBytes` | PS* signing; also probed once when a curve module loads, to enable blinding (absent: blinding off, signatures still correct) |
| `Uint8Array.fromHex` / `toHex` | noble, feature-detected with a fallback | nothing |

## Decision

1. **No `react-native` peer dependency**, as in ADR-005.
2. **The floor is React Native 0.74**, the first whose Hermes has `TextEncoder`; every other requirement is met from 0.71. An app on 0.71–0.73 that installs a `TextEncoder` polyfill (for example `fast-text-encoding`) before importing the library meets the requirements too, but that is not tested and the README presents it as a workaround, not as support.
3. **The runtime host check names `TextEncoder`** as it names `BigInt`, `Object.hasOwn` and a `**`-rewriting Babel setup: `JwtHostRequirementError` with `feature: 'TextEncoder'` and the advice to upgrade or polyfill. It runs at import, so the failure is immediate whatever the Metro config — never deferred to a first ES* call, or disguised as an invalid key.
4. **A host measurement goes through Metro, or through a bundler with tree-shaking off.** A tree-shaking bundler hides module-load side effects that an app will run.
5. **Hermes only**, as in ADR-005.

## Consequences

**Positive.** The README's floor is true for what an app actually bundles. A too-old app fails with a sentence naming `TextEncoder`, not with a `ReferenceError` from inside noble. `host.test.ts` also checks that noble still needs `TextEncoder` at load, so a noble release that stops needing it shows up as a failing test — the floor could then drop.

**Negative.** React Native 0.71–0.73 (released 2023) are no longer supported out of the box, three versions fewer than ADR-005 announced. Nothing was published with the 0.71 claim except in the unreleased `2.0.0-alpha.0` sources.

**Rejected alternatives.**
- Keeping 0.71 and requiring a polyfill — it makes the common case (a new app) carry advice it does not need, and the library would claim support for a combination no test runs.
- Installing a `TextEncoder` on `globalThis` from the library — patches the host's global scope, which ADR-005 already rejected.
- Patching noble or importing around `createFROST` — the FROST code is in the same modules as the curves the library uses; avoiding it means forking noble ([dependency-policy](../engineering/dependency-policy.md)).
