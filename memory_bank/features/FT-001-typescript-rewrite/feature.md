---
doc_kind: feature
doc_function: canonical
purpose: 'Rewrite the library in TypeScript as 2.0.0: safe verification, claim validation, all common algorithms on Hermes, and typed errors.'
derived_from:
  - ../../product/context.md
  - ../../domain/validation.md
status: active
delivery_status: in_progress
---

# FT-001 — TypeScript rewrite

## Problem

1.0.3 is one 50-line JavaScript file over `jsrsasign` 8. It installs a dependency `npm audit` rates critical, returns `jsrsasign`'s internal parse object from `decode`, checks no claims (an expired token decodes as valid), signs hex-looking secrets in a way no other library can verify, reports failure as `null`, `false`, or a raw exception depending on the path, and ships no types and no tests. The full list is in [../../backlog.md](../../backlog.md#defects-in-the-10x-line).

## Scope

In scope:
- TypeScript source, CJS + ESM + declarations, `react-native` export condition.
- `sign`, `verify`, `decodeUnverified`, `isExpired`, `getExpiration`.
- Algorithms in [../../domain/algorithms.md](../../domain/algorithms.md); keys in [../../domain/keys.md](../../domain/keys.md); validation in [../../domain/validation.md](../../domain/validation.md).
- Named error classes with stable codes.
- Unit, interop, and hostile-input suites; an `example/` app with a self-test screen.
- README with a migration guide from 1.0.x; `CHANGELOG.md`.

Out of scope:
- JWE, OAuth, storage — product non-goals.
- `useJwt` hook — after 2.0.0, so the core ships without a React dependency question.
- Remote JWKS (fetching keys over the network) — 2.1; 2.0.0 is synchronous and has no network code ([ADR-002](../../adr/ADR-002-synchronous-api.md)).
- The 1.0.4 patch — separate, tiny, ships first ([../../product/roadmap.md](../../product/roadmap.md)).

## Acceptance criteria

| ID | Criterion | Verified by |
|-|-|-|
| SC-1 | A token signed with each supported `alg` verifies in Node's `crypto`, and a Node-signed token verifies here | interop suite |
| SC-2 | A key is bound to exactly one algorithm: `importPEM` without one is a type error and throws at runtime; an RSA or `oct` JWK with no `alg` and no argument is rejected on import; a bare secret defaults to HS256 | unit + type test |
| SC-14 | No export of the core returns a promise | type test over the public barrel |
| SC-15 | The default export's `encode`, `decode`, and `verify` each throw `JwtMigrationError` naming the replacement | unit |
| SC-16 | An HMAC secret shorter than the hash output is rejected by `sign` and `verify`, and accepted with `allowShortSecret: true` | unit |
| SC-17 | With `BigInt` or `Object.hasOwn` removed from the global scope, the first call throws `JwtHostRequirementError` naming the missing feature | unit, deleting the global as `react-native-matrix`'s `hostSupport.test.ts` does |
| SC-18 | The README's React Native floor is the lowest version on which the `example/` self-test passes every algorithm | manual: stage 1a measurement |
| SC-3 | `alg: none`, and any `alg` other than the key's own (including another hash in the same family) each throw `JwtAlgorithmError` before signature work | hostile suite |
| SC-4 | An RS256→HS256 confusion token signed with the public key text fails | hostile suite |
| SC-5 | Expired, not-yet-valid, wrong `iss`/`aud`/`sub` tokens throw their named error; clock tolerance is honoured at the boundary | unit |
| SC-6 | Malformed tokens (segments, padding, non-object payload, unknown `crit`) throw `JwtMalformedError` before any crypto runs | hostile suite |
| SC-7 | A string secret is UTF-8: `deadbeef` signs the eight ASCII bytes; `hexToBytes('deadbeef')` reproduces the 1.0.x signature | regression test naming the 1.0.x defect |
| SC-8 | Non-ASCII payloads round-trip | unit |
| SC-9 | Every algorithm runs on Hermes on both platforms with no native crypto module installed | manual: `example/` self-test screen |
| SC-10 | A local JWKS selects the key by `kid` and rejects a token whose `kid` is absent with a named error. (Before 2026-10-15 this was the remote-JWKS cooldown criterion, which moved to 2.1) | unit |
| SC-11 | `npm pack` contains no tests, example, or memory bank | release checklist |
| SC-12 | An RSA key below 2048 bits is rejected on import, for PEM and JWK alike | hostile suite |
| SC-13 | ES256 verification on Hermes stays fast enough not to block the JS thread visibly; threshold set by the stage 1 measurement | manual: `example/` benchmark screen |

## Failure modes

| ID | Mode | Handling |
|-|-|-|
| FM-1 | PS* signing on a host without `crypto.getRandomValues` | Named error naming `react-native-get-random-values` as the fix |
| FM-2 | Token `kid` not in the JWKS the caller passed | `JwtKeyNotFoundError`, distinct from a bad signature, so the caller can reload keys and retry |
| FM-3 | `exp` passed in milliseconds to `sign` | Rejected with a message saying seconds are expected |

## Public API impact

Breaking, per [ADR-004](../../adr/ADR-004-break-from-v1-api.md): the 1.0.x default export becomes migration tombstones that throw; `decode` has no successor of the same name; short HMAC secrets are refused by default; string secrets are always UTF-8.

## Notes

Settled: crypto backend ([ADR-001](../../adr/ADR-001-crypto-backend.md)), synchronous API ([ADR-002](../../adr/ADR-002-synchronous-api.md)), one key one algorithm ([ADR-003](../../adr/ADR-003-one-key-one-algorithm.md)), the break from 1.0.x ([ADR-004](../../adr/ADR-004-break-from-v1-api.md)). Still open: [../../backlog.md](../../backlog.md#open-decisions).
