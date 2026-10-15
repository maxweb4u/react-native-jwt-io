---
doc_kind: engineering
doc_function: canonical
purpose: Measured cost of every algorithm on Hermes, against the 1.0.x baseline. Read before promising speed, or when a change touches the crypto backend.
derived_from:
  - ../adr/ADR-001-crypto-backend.md
status: active
canonical_for:
  - hermes_performance
---

# Performance on Hermes

Every operation is synchronous and runs on the JS thread ([ADR-002](../adr/ADR-002-synchronous-api.md)), so its time is time the UI cannot use. These are the numbers that decide whether that is acceptable.

## 2.0 on Hermes — measured 2026-10-15

React Native 0.87.1, Release build (Hermes bytecode), iOS 18.3 simulator on an Apple Silicon Mac; the packed `2.0.0-alpha.0` tarball, tokens signed by Node. One call, after one warm-up; the first call was within 3% of these, so noble's precomputation costs nothing noticeable.

| Algorithm | verify | sign |
|-|-|-|
| HS256 | 0.5 ms | 0.4 ms |
| RS256 | 3.8 ms | 507 ms |
| PS256 | 4.9 ms | needs `getRandomValues` — host error by design |
| ES256 | 34 ms | 7.9 ms |
| ES384 | 85 ms | 17 ms |
| ES512 | 183 ms | 35 ms |
| ES256K | 18.5 ms | 6.9 ms |
| EdDSA | 17.6 ms | 5.3 ms |

## 2.0 on a physical Android phone — measured 2026-10-15

Realme RMX3363, Android 13, arm64-v8a, mid-range (2021); same app and tarball, Release APK. All eleven self-test checks passed, including the PS256 host error.

| Algorithm | verify | sign |
|-|-|-|
| HS256 | 0.9 ms | 0.8 ms |
| RS256 | 7.4 ms | 828 ms |
| PS256 | 7.5 ms | host error by design |
| ES256 | 60 ms | 13.5 ms |
| ES384 | 148 ms | 29 ms |
| ES512 | 319 ms | 59 ms |
| ES256K | 32 ms | 11.7 ms |
| EdDSA | 30 ms | 8.5 ms |

The phone is about 1.7× slower than the simulator across the board, so the simulator ratios against 1.0.4 below carry over.

## The oldest supported setup — measured 2026-10-15

Official Hermes v0.12.0 CLI (August 2022, the React Native 0.70/0.71 era) on the same Mac, with the self-test compiled through React Native 0.71's Babel preset and run as bytecode: all 12 checks pass, and the times match the 0.87 simulator within 10% (ES256 verify 37 ms, RS256 verify 5.7 ms, EdDSA verify 18 ms). An old app gains nothing and loses nothing by its Hermes version.

## Against 1.0.4 (`jsrsasign` 11), same simulator

| Operation | 1.0.4 | 2.0 | |
|-|-|-|-|
| ES256 verify | 1746 ms | 34 ms | 51× faster |
| RS256 verify | 43 ms | 3.8 ms | 11× faster |
| RS256 sign | 1405 ms | 507 ms | 2.8× faster |
| HS256 sign | 4 ms | 0.4 ms | 10× faster |

## Reading the numbers

- **Verification of the common case is cheap.** HS256, RS256 and PS256 — what servers issue — cost under 8 ms even on the phone.
- **ES256 is 34 ms on the simulator and 60 ms on a mid-range phone — two to four frames.** Acceptable for a call made on login or on a deep link; not for one per list row. This is the measurement ADR-001 waited on, and it does not reopen the decision: it is 51× better than the library it replaces.
- **ES384 and ES512 verification (148 and 319 ms on the phone) and RSA signing (0.8 s) visibly block the thread.** All three are rare on a device. If a caller needs them in a hot path, noble's per-key precomputation (`Point.precompute`) is the first thing to try; a native backend the second.
- **Hermes is about 20× slower than V8 on this BigInt-heavy code** (ES256 verify: 34 ms here, 1.8 ms in Node on the same machine).
