---
doc_kind: feature
doc_function: canonical
purpose: Ordered implementation steps for FT-001 and how each is verified.
derived_from:
  - feature.md
status: draft
---

# FT-001 — Implementation Plan

## Order

| # | Step | Touches | Verification |
|-|-|-|-|
| 0 | Memory bank | `memory_bank/`, `scripts/check-memory-bank.mjs` | `node scripts/check-memory-bank.mjs` |
| 1 | Scaffold: `package.json` (exports, `files`, `engines`), tsconfig, ESLint flat config, Jest, build scripts; prove the three ESM-only crypto packages load in Jest, in the CJS build, and in Metro | root config | `npm run verify` on an empty `src/index.ts` |
| 1a | Hermes measurement: HS256, ES256, EdDSA, RS256 sign and verify on an iOS simulator and an Android device, with no native crypto module installed; then the same self-test on older React Native, from 0.70 upward, until it passes — that version is the floor | throwaway screens in `example/` and in scratch apps | speed in [../../engineering/performance.md](../../engineering/performance.md), floor in the README; a blocking speed reopens ADR-001 |
| 2 | Core: base64url, UTF-8, safe JSON, NumericDate, duration parsing, `JwtError` hierarchy, token parsing, host check | `src/utils`, `src/errors`, `src/host`, `src/jwt/parse.ts` | unit + hostile suites for parsing |
| 3 | Crypto backend over noble and `micro-rsa-dsa-dh`: HMAC, ECDSA (raw `r‖s`), Ed25519, RSA PKCS#1 v1.5 and PSS, sign and verify | `src/crypto` | interop suite per algorithm both ways; Wycheproof vectors at our boundary |
| 4 | Keys: secret, PEM (SPKI, PKCS#8, PKCS#1), JWK, local JWKS | `src/keys` | unit; SC-10, SC-12 |
| 5 | `sign`, `verify`, claim validation, `decodeUnverified`, expiry helpers — all synchronous | `src/jwt` | SC-2 … SC-8, SC-14 |
| 6 | Interop and hostile suites completed; coverage floor set | `__tests__/` | SC-1, SC-3, SC-4, SC-6 |
| 7 | `example/` app with a self-test screen, run on iOS and Android | `example/` | SC-9 |
| 8 | README + migration guide (names, tombstones, `allowShortSecret`, `hexToBytes`, 1.0.x end date), `CHANGELOG.md`, docs to `active`, publish 2.0.0 | root docs, memory bank | [../../ops/release.md](../../ops/release.md) checklist |

## Dependencies

Step 1a gates step 3. Step 5 needs the open decisions in [../../backlog.md](../../backlog.md#open-decisions) settled. The 1.0.4 patch has no dependency on any step.

## Rollback

Before publish: revert. After publish: 1.0.x stays installable and receives security fixes for three months; a broken 2.0.x is fixed forward or deprecated on npm.
