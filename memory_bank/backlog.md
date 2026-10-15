---
doc_kind: project
doc_function: canonical
purpose: Open decisions waiting on the maintainer, and the known defects of the 1.0.x line.
derived_from:
  - product/roadmap.md
status: active
audience: humans_and_agents
canonical_for:
  - open_work_items
  - v1_defects
---

# Backlog

## Open decisions

Each blocks part of [FT-001](features/FT-001-typescript-rewrite/feature.md). The ADR holds the proposal and its alternatives.

Nothing is open.

## Open work for 2.0.0

What stands between the built code (stages 1–6, 2026-10-15) and the release.

| ID | Item |
|-|-|
| W-1 | ~~Android on Hermes~~ — done 2026-10-15 on a Realme RMX3363 (Android 13): 11/11, numbers in [engineering/performance.md](engineering/performance.md). |
| W-2 | ~~The React Native floor~~ — done 2026-10-15: **0.71**. Hermes' sources put `Object.hasOwn` at the RN 0.69 tag and `BigInt` at 0.70; running the self-test in the official Hermes v0.12.0 CLI (August 2022) then showed that RN 0.70 still fails — its Babel preset (`metro-react-native-babel-preset` 0.72) rewrites `**` into `Math.pow`, and `@noble/curves` raises a BigInt to a power on the Ed25519 path. With RN 0.71's preset (0.73.5) all 12 checks pass, from source and from bytecode. `hostCheck` now detects the rewrite at import. Details in [engineering/gotchas.md](engineering/gotchas.md). |
| W-3 | ~~Wycheproof vectors~~ — done 2026-10-15: 1717 vectors across HS256, RS256, PS256, ES256/384/512, ES256K and EdDSA, through `importPEM` and the crypto module; all pass. |
| W-4 | ~~`example/` app~~ — done 2026-10-15: React Native 0.87.1, library from source; Self-test 12/12 on an iOS 18.3 simulator and on the Realme RMX3363 (Release builds). |
| W-5 | ~~README, migration guide, CHANGELOG~~ — done 2026-10-15; the README's examples run as `src/__tests__/readme.test.ts`. What remains of stage 8 is the release itself. |
| W-6 | **Hot paths.** On a mid-range phone ES256 verification takes 60 ms, ES384/ES512 148/319 ms, RSA signing 0.8 s, all on the JS thread; try noble's per-key `Point.precompute` before anything native. Not a release blocker. |

## Review of 2026-10-15

An independent review of `src/` (a separate agent, adversarial, read-only) found no way to get a forged or unsigned token accepted, no algorithm confusion, and no key-binding bypass. It did find the defects below. Each fix has a regression test in `src/__tests__/review.test.ts`, numbered like this table.

| # | Finding | Severity | Outcome |
|-|-|-|-|
| 1 | `now: new Date('x')` made every time comparison false: an expired token verified, `isExpired` said false, `sign` wrote `"exp":null` | medium, fail-open | `now` must be a valid Date, else `JwtClaimError` |
| 2 | A string `clockTolerance` such as `'9…9s'` parsed to Infinity and disabled `exp` | low, fail-open | durations must be finite |
| 3 | `now` was floored to the second: a fractional `exp` lived up to a second too long; a fresh fractional `iat` read as "issued in the future" | low | compared exactly |
| 4 | With a JWKS, `options.algorithm` was ignored | low | it constrains key sets too |
| 5 | Two keys with the same `kid` and `alg`: the first was used | low | ambiguity is `JwtKeyNotFoundError` |
| 6 | Even RSA moduli, `d` out of range, and private keys mixed from two keys were accepted; a bad `d` made signing throw a plain `Error` | low | checked at import (primes when present); signing failures become `JwtKeyError` |
| 7 | `importPEM(…, { kid: 5 })` was accepted | low | `kid` must be a string |
| 8 | `null` options, `audience: null`, `hexToBytes('zz')` threw plain `TypeError`s | low | treated as no options / `JwtError`s |
| 9 | Registered claims and header fields were typed but not checked (`sub` could be an object) | low | enforced on read and write |
| 10 | A `toJSON` on the header or payload could change what was signed (even `alg`) | nit | validated as serialized |
| 11 | DER: trailing nodes, non-minimal lengths and integers, unchecked algorithm parameters, multi-byte first OID arc | nit | strict |
| 12 | JWK `key_ops` ignored | nit | honoured |
| 13 | A key with the RSASSA-PSS OID could be bound to RS256 | nit | PS* only |
| 14 | ECDSA signatures are malleable (high-S accepted on purpose) | nit | documented in [domain/algorithms.md](domain/algorithms.md) and the README |
| 15 | `header`/`payload` and the exported constants were not frozen | nit | frozen |
| 16 | `expiresIn: 1e300` produced `exp: 1e300` | nit | computed times are checked too |

Not changed: PEM text without its BEGIN/END lines, or a JWK passed as a JSON string, still reads as an HMAC secret — indistinguishable from a secret without guessing. A PEM inside a `Uint8Array` is now refused.

### Open: 1.x tombstones under `require` and Node ESM

Found while re-checking the packed tarball: the tombstones live on the default export only, so `require('react-native-jwt-io').encode` and a Node ESM default import get `undefined` and fail with `jwt.encode is not a function` instead of `JwtMigrationError`. Metro and bundlers are fine. Decide: add named `encode`/`decode` tombstones (ADR-004 forbids an unverified `decode`, not a throwing one), or accept the gap. Details: [_inbox/cjs-default-export-tombstones.md](_inbox/cjs-default-export-tombstones.md).

## Decided

| ID | Decision | Outcome | Record |
|-|-|-|-|
| OD-1 | Crypto backend | `@noble/hashes` + `@noble/curves` + `micro-rsa-dsa-dh`, pure JavaScript, no cryptography of our own, no native module. Accepted 2026-10-14, subject to the Hermes measurement in FT-001 stage 1a | [ADR-001](adr/ADR-001-crypto-backend.md) |
| OD-2 | Sync or async `sign` / `verify` | Synchronous core, no promises in 2.0.0; asynchrony only in separate functions that wait on the network or the user. Remote JWKS moved to 2.1. Accepted 2026-10-15 | [ADR-002](adr/ADR-002-synchronous-api.md) |
| OD-3 | How the algorithm is chosen | One key, one algorithm (RFC 8725): a bare secret is HS256 unless the `algorithm` option says otherwise; an imported key carries its own; no `algorithms` list; `none` never. Accepted 2026-10-15 | [ADR-003](adr/ADR-003-one-key-one-algorithm.md) |
| OD-4 | Relationship to 1.0.x | New names, no `decode`, no compatibility layer; tombstone default export until 3.0.0; short secrets refused unless `allowShortSecret`; hex secrets via `hexToBytes`; 1.0.x security fixes for three months after 2.0.0, then npm deprecate. Accepted 2026-10-15 | [ADR-004](adr/ADR-004-break-from-v1-api.md) |
| OD-5 | Minimum React Native version | No `react-native` peer; the floor is the lowest React Native whose Hermes has every feature the code needs (`BigInt`, `Object.hasOwn`), measured in FT-001 stage 1a starting from 0.70; runtime host check with `JwtHostRequirementError`; Hermes only. Accepted 2026-10-15 | [ADR-005](adr/ADR-005-host-requirements.md) |
| OD-6 | Ship 1.0.4 first | Yes: `jsrsasign` ^11.1.5, a `files` field so the memory bank is not published, `CHANGELOG.md`, a README note on 2.0.0 and the 1.0.x window. Accepted and published 2026-10-15 | [product/roadmap.md](product/roadmap.md) |

## Defects in the 1.0.x line

Measured on 2026-10-14 against `src/jwt.js` at 1.0.3, with `jsrsasign` 8.0.24 (what `^8.0.12` installs) and 11.1.5.

| ID | Defect | Evidence |
|-|-|-|
| V1-1 | Critical dependency advisories | `npm audit` on 8.0.24: critical — GHSA-h87q-g2wp-47pj, GHSA-3fvg-4v2m-98jf, GHSA-27fj-mc8w-j9wg, GHSA-8qwj-4jxw-m8jw (signature-verification bypasses) and more. 11.1.5: 0 vulnerabilities, identical behaviour |
| V1-2 | No claim validation | A token with `exp: 1` decodes and verifies as valid |
| V1-3 | `decode` returns `jsrsasign`'s parse object | `{ headerObj, payloadObj, headerPP, payloadPP, sigHex }`, not the payload |
| V1-4 | Hex-looking secrets are hex | Secret `deadbeef` produces a signature that standard HMAC over the UTF-8 text does not match |
| V1-5 | The token header chooses the algorithm | `JWS.verify(token, key)` without `acceptAlgs`; RS256→HS256 confusion fails only because PEM parsing throws first |
| V1-6 | Inconsistent failure reporting | `null` from `decode`, `false` from `verify`, raw exceptions for `alg: none` (`not supported`) and confusion attempts |
| V1-7 | No types, no tests, no `files` field | The tarball ships whatever is in the directory |
| V1-8 | README documents only `encode`, and encourages client-side HMAC | Shipping an HMAC secret in an app bundle publishes it |

V1-1 is closed: fixed by 1.0.4, published 2026-10-15. The rest are fixed by 2.0.0, each with a regression test (SC-7 for V1-4).
