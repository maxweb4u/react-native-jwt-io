---
doc_kind: engineering
doc_function: canonical
purpose: What must be tested, how the suites are split, and how to run them.
derived_from:
  - ../dna/governance.md
  - ../domain/validation.md
status: active
canonical_for:
  - test_suite_split
  - required_coverage
  - test_commands
---

# Testing Policy

## Stack

Jest. No device is needed for any automated suite; the device check lives in `example/` and the release checklist.

## Suites

| Suite | Proves | Location |
|-|-|-|
| interop | Every algorithm both ways against Node's `crypto`, keys from PEM and JWK; twenty Node ECDSA signatures per curve (high-S); RS256 and HS256 byte-identical to Node; RFC 7515 A.1 | `src/__tests__/interop.test.ts` |
| hostile input | Malformed segments, strict base64url, non-object payloads, invalid UTF-8, `alg: none`, algorithm confusion, `crit`, `b64`, oversized input, `__proto__`, DER signatures | `src/__tests__/hostile.test.ts` |
| keys | PEM formats, JWK binding, JWKS selection, weak RSA, and 2000 corrupted DER keys that must fail only with `JwtKeyError` | `src/__tests__/keys.test.ts` |
| claims | Signing options, every claim rule at its boundary, secrets, expiry helpers | `src/__tests__/claims.test.ts` |
| encoding | base64url, base64, UTF-8, durations against Node | `src/__tests__/encoding.test.ts` |
| host and API | Missing engine features at import, PS* without RNG, 1.x tombstones, the exact export list, no promises | `src/__tests__/host.test.ts`, `api.test.ts` |
| Wycheproof | 1717 C2SP vectors — malleable and out-of-range signatures, bad padding, edge-case points — through `importPEM` and the crypto module | `src/__tests__/wycheproof.test.ts`, fixtures in `src/__tests__/fixtures/wycheproof/` |
| README | Every example in the README, run as written | `src/__tests__/readme.test.ts` |
| review | One regression per finding of the independent review of 2026-10-15 (backlog) | `src/__tests__/review.test.ts` |

All suites run in one Jest project, in Node, with `now` injected where time matters. The device check — that every algorithm runs on Hermes — is the self-test screen of `example/` (12 checks), described in [performance.md](performance.md).

Node's `crypto` is the oracle because it is an independent implementation of every algorithm here. It is a dev dependency only; nothing in `src/` may import it.

## Required coverage

- Every row of [../domain/algorithms.md](../domain/algorithms.md) has an interop test in both directions.
- Every step of [../domain/validation.md](../domain/validation.md#order) has a test proving the right error class and `code`.
- Every 1.0.x defect in [../backlog.md](../backlog.md#defects-in-the-10x-line) gets a regression test naming it.
- `coverageThreshold` is a floor, set just under the measured value: 93.63% statements, 90.19% branches, 100% functions, 93.49% lines on 2026-10-15 with 263 tests (the floor itself is 93 / 90 / 100 / 93). The branch margin is thin: the review fixes added defensive branches for inputs no test can reach through the public API.

## Before handing work over

```sh
npm run verify     # typecheck + lint + all suites + memory bank check
```
