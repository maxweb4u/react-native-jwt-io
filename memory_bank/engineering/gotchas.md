---
doc_kind: engineering
doc_function: canonical
purpose: Traps in JWT handling, Hermes, and the toolchain that are easy to hit more than once.
derived_from:
  - architecture.md
status: active
canonical_for:
  - known_traps
---

# Gotchas

## JWT

- **`exp` is seconds.** `Date.now()` is milliseconds. A token signed with `exp: Date.now() + 3600` is valid for 55,000 years.
- **ECDSA in JWS is raw `r‖s`, not DER.** WebCrypto returns raw; Node's `crypto.sign` returns DER unless `dsaEncoding: 'ieee-p1363'` is passed. Interop tests must set it.
- **`jsrsasign` treats a hex-looking string as hex.** Measured on 1.0.3 with both 8.0.24 and 11.1.5: the secret `deadbeef` signs with bytes `de ad be ef`, not the UTF-8 text, so the token fails verification everywhere else. Any 1.0.x caller with such a secret has tokens 2.0.0 will reject unless they pass `hexToBytes(secret)` — the migration guide must say so.
- **`decode` in 1.0.x verified, and returned `jsrsasign`'s parse object** (`headerObj`, `payloadObj`, `sigHex`, …), not the payload the README implied. A 2.0.0 function named `decode` that did not verify would silently remove a security check from every upgraded caller.

## Hermes / React Native

- **No WebCrypto.** `globalThis.crypto.subtle` is undefined; `crypto.getRandomValues` too, unless the host installs `react-native-get-random-values`. Signing with HMAC, ECDSA, Ed25519, and RSA PKCS#1 v1.5 needs no randomness; RSA-PSS signing (random salt) and key generation do. noble 2.x ECDSA is deterministic only because `extraEntropy` defaults to `false` — passing `true` would make every ES* signature need the RNG.
- **`atob`/`btoa` exist only from React Native 0.74**, and work on Latin-1 strings. The library carries its own base64url over bytes.
- **`TextEncoder` exists in Hermes, `TextDecoder` only in recent versions.** Verify on the floor version chosen in stage 1 before relying on it.
- **What Hermes in React Native 0.87.1 has**, measured on 2026-10-15 in a Release build on an iOS 18.3 simulator: `BigInt`, `Object.hasOwn`, `TextEncoder`, `atob` — yes; `TextDecoder`, `crypto.getRandomValues` — no. Older versions are what FT-001 stage 1a measures.
- **`jsrsasign` is slow on Hermes**, measured in the same run with 1.0.4: RS256 sign 1405 ms, ES256 verify 1746 ms, RS256 verify 43 ms, HS256 4 ms — each one call, blocking the JS thread. This is the 1.0.x baseline the noble backend must beat in stage 1a, and a reason in itself to leave `jsrsasign`.
- **Which Hermes has what**, read from Hermes' sources at the React Native release tags: `Object.hasOwn` is present at the RN 0.69 tag already; `BigInt` arrives at the RN 0.70 tag.
- **React Native 0.70 is excluded by its Babel preset, not by Hermes.** `metro-react-native-babel-preset` 0.72 (the RN 0.70 template's) includes `@babel/plugin-transform-exponentiation-operator`, which rewrites `a ** b` into `Math.pow(a, b)`. Metro applies the app's preset to `node_modules` too, so `c.Fn.ORDER ** _4n` in `@noble/curves/abstract/curve.js` (reached by Ed25519 scalar multiplication) throws `Cannot convert a BigInt value to a number`: Ed25519 signing throws a raw TypeError and verification turns into a silent `false`. Preset 0.73 (RN 0.71) dropped the plugin. Measured in the Hermes v0.12.0 CLI with each preset; `hostCheck` evaluates `BigInt(2) ** BigInt(3)` at import, through the same Babel setup, and names the cause. Any `@babel/preset-env` targeting engines without `**` does the same.
- **BigInt is supported by Hermes** (React Native ≥ 0.70); all crypto except HS256 depends on it, and `0n` literals make a missing `BigInt` a parse error at import, not a runtime error.
- **noble calls `Object.hasOwn` while its modules load** — measured: with it deleted, importing `@noble/hashes/sha2.js`, any curve, or `micro-rsa-dsa-dh/rsa.js` throws `Object.hasOwn is not a function`. A check at the first `sign`/`verify` would be too late, so `src/host/hostCheck.ts` runs as the first import of `src/index.ts` ([ADR-005](../adr/ADR-005-host-requirements.md)). When Hermes gained it is undocumented; measure it, do not assume it.
- **noble 2.x rejects high-S ECDSA signatures by default** (`lowS: true` for every curve, not only secp256k1). OpenSSL — Node, and most servers — produces high-S signatures about half the time, so ES* tokens from a server would fail verification at random. `verifyBytes` passes `lowS: false`; the interop suite verifies twenty Node signatures per curve to keep it that way.

## Toolchain

- **`example/` runs the library from the folder above it, so Babel's helpers do not resolve.** Metro compiles `../src` and rewrites it to import `@babel/runtime/helpers/…`; resolution starts next to the library's files, finds the root's `node_modules` without `@babel/runtime`, and fails the bundle. `example/metro.config.js` maps `@babel/runtime` to the app's copy. A consumer installing from npm never hits this — the package sits inside the app's `node_modules`.

- **Objects from another realm are still plain objects.** Jest runs tests in a VM context, and Node's `KeyObject.export({ format: 'jwk' })` returns objects whose `Object.prototype` is not the test realm's. A plain-object check that compares with `Object.prototype` rejects them; `isPlainObject` checks that the prototype's prototype is null instead.

- **The React Native 0.87.1 template app crashes at launch on iOS 27 simulators** with `EXC_BREAKPOINT` in `_UIApplicationEvaluateRuntimeIssueForNoSceneLifecycleAdoption`: iOS 27 enforces the UIScene lifecycle the template does not declare. It dies before any JavaScript runs, so it says nothing about this library. Use an iOS 26 or older simulator, or adopt scenes in `example/`.
- **Release builds redact `console.log` in the unified log** (`<private>`), so a self-test screen is read from a screenshot, not from `log stream`.

- **No `files` field publishes the whole directory.** 1.0.3 had neither `files` nor `.npmignore`; with the memory bank added, `npm pack --dry-run` listed 52 files, 45 of them `memory_bank/`. 1.0.4 adds `files`. Run `npm pack --dry-run` before every publish.
- **`@noble/hashes`, `@noble/curves` 2.x and `micro-rsa-dsa-dh` are ESM-only** (`"type": "module"`, sub-paths end in `.js`). Metro handles that; Jest needs them in `transformIgnorePatterns` exceptions, and the CommonJS build `require()`s them — which works on Node ≥ 20.19 (`require(esm)`), the floor noble itself declares. `scripts/check-build.cjs` proves it on every `prepack`.
- **`micro-rsa-dsa-dh` accepts weak imported RSA keys.** Its own `keygen` enforces 2048 bits, imported keys get no check, by design. The 2048-bit floor is ours to enforce at import.
- **Metro does not tree-shake, but it bundles per file.** Importing `@noble/curves` from its root would bundle every curve; import the exact sub-path.
