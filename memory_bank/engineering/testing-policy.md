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
| keys | PEM formats, JWK binding, JWKS selection and skipped keys, weak RSA, and 2000 fuzzed DER inputs (about two thirds corrupted, the rest intact) that must import or fail only with `JwtKeyError` | `src/__tests__/keys.test.ts` |
| claims | Signing options, every claim rule at its boundary, secrets, expiry helpers | `src/__tests__/claims.test.ts` |
| encoding | base64url, base64 and UTF-8 against Node; durations against fixed values | `src/__tests__/encoding.test.ts` |
| host and API | Missing engine features at import (and that noble still needs `TextEncoder` at load), PS* without RNG, 1.x tombstones, the exact export list, no promises | `src/__tests__/host.test.ts`, `api.test.ts` |
| Wycheproof | 1717 C2SP vectors — malleable and out-of-range signatures, bad padding, edge-case points — through `importPEM` and the crypto module | `src/__tests__/wycheproof.test.ts`, fixtures in `src/__tests__/fixtures/wycheproof/` |
| README | Every example in the README, run as written | `src/__tests__/readme.test.ts` |
| review | One regression per finding of the independent reviews (backlog): 2026-10-15, the rounds of 2026-10-16, and 2026-10-17 before the release candidate | `src/__tests__/review.test.ts`, `review2.test.ts`, `review3.test.ts`, `review4.test.ts` |
| mutation | One test per mutant that survived the suite ([Mutation testing](#mutation-testing)) | `src/__tests__/mutation.test.ts`, `mutation2.test.ts` |

All suites run in one Jest project, in Node, with `now` injected where time matters. The device check — that every key family and curve runs on Hermes — is the self-test screen of `example/`, 16 checks: the engine is Hermes; HS256, RS256, PS256, ES256, ES384, ES512, ES256K and EdDSA against Node's tokens (HS384/512, RS384/512 and PS384/512 share their code paths and are covered in Jest only); HS256/RS256/EdDSA byte-identical to Node; every tampered signature refused with `instanceof` and `name` intact; `decodeUnverified`/`isExpired`; `alg: none` refused; an option mistake a `JwtOptionError` with its name intact, even for a tampered token; a public key refused as a secret as PEM, as bytes after a preamble and as bare base64; PS256/384/512 signing with `react-native-get-random-values`, two signatures of the same input differing (the salt is random). Its timings are in [performance.md](performance.md). It is bundled by Metro, which matters: a tree-shaking bundler hides module-load side effects ([gotchas.md](gotchas.md)).

**Expo Go** is checked by hand, not from `example/` (a bare app with native folders): `npx create-expo-app --template blank-typescript` outside the repository, `npm install` the tarball from `npm pack` — what npm will serve — plus `npx expo install react-native-get-random-values`, imported first in `index.ts`; copy `example/App.tsx`, `src/selfTest.ts` and the generated `src/fixtures.ts`; `npx expo start --android` (or `--ios`). Expo CLI installs Expo Go on the device. On 2026-10-16, with Expo SDK 58 (React Native 0.88) and Expo Go 58.0.4: 16/16 on the Realme RMX3363 in development and in `--no-dev --minify` bundles, with `react-native-get-random-values` and with `crypto.getRandomValues` taken from `expo-crypto`; 16/16 on an iOS 27 simulator. Mind the bundle cache ([gotchas.md](gotchas.md)).

Node's `crypto` is the oracle because it is an independent implementation of every algorithm here. It is a dev dependency only; nothing in `src/` may import it.

## Required coverage

- Every row of [../domain/algorithms.md](../domain/algorithms.md) has an interop test in both directions.
- Every step of [../domain/validation.md](../domain/validation.md#order) has a test proving the right error class and `code`.
- Every 1.0.x defect in [../backlog.md](../backlog.md#defects-in-the-10x-line) gets a regression test naming it.
- `coverageThreshold` is a floor, set just under the measured value: 97.4% statements, 96.09% branches, 100% functions, 97.34% lines on 2026-10-17 with 608 tests (the floor itself is 97 / 95 / 100 / 97). The numbers move by about 0.1 between runs, because test keys are generated on each run and some branches depend on their bytes. The reviews' regressions ([../backlog.md](../backlog.md#review-of-2026-10-16)) raised it from 93 / 90 / 100 / 93. Most of what stays uncovered is defensive branches for inputs no test can reach through the public API.
- **A test must fail for the reason its name gives.** The second review found three that passed for another one — a PKCS#8 test whose hand-built DER broke on its length byte, an "oversized" token that was also not JSON, a duration overflow cut short by the length limit. Assert the message or the field that names the cause, not only the error class, and build DER with the `tlv` helper in `src/__tests__/helpers/node.ts`.

## Mutation testing

Line coverage says a check ran, not that a test would notice it gone. On 2026-10-16, 131 hand-written mutants of security-relevant code — each one removed or weakened check, applied to a copy of `src/` and run against the whole suite — left 45 alive: among them, `equalBytes` without its length check (an HMAC tag with bytes appended verified), base64url without the `length % 4 === 1` check, `audience` given but `aud` absent, the 2048-bit floor at 2047, and the RSA self-check skipped for PS*. Each now has a test in `mutation.test.ts`, named after its mutant. Five were equivalent and need none: the signature-length checks in `verifyBytes` (the crypto packages check lengths themselves; kept as defence in depth), `selectKey(opts.algorithm ?? alg)` after the pin check, and the RSASSA-PSS default salt length.

A second run the same day, over the code the reviews had just added (122 mutants: key-material detection, `isKeyDer`, error names, option checks, RSA size limits, JWKS skipped keys, `clockTolerance`), left 51 alive; each non-equivalent one has a test in `mutation2.test.ts` (`K2:<id>`). The five equivalent ones: removing `first !== null` before an `in` that throws inside the same `try`; the SEQUENCE gate in `isKeyDer` (`readSingle` rejects the same inputs, the gate only saves time); the unreachable `default` in `withEmbeddedPublic`; again the RSASSA-PSS default salt; and the `typeof text === 'string'` guard in `describeValue`, whose failure lands in the same fallback.

Repeat it before a release that touches `src/keys/`, `src/crypto/` or `src/jwt/`: mutate the checks that changed, and add a test for every survivor.

## Before handing work over

```sh
npm run verify     # typecheck + lint + all suites + memory bank check
```
