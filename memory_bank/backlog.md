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
