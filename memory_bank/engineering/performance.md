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

## After the reviews — measured 2026-10-16

The 14-check self-test of `example/`, Release builds, after both review rounds of 2026-10-16: **14/14** on the same Realme RMX3363 and on an iOS 18.3 simulator (iPhone 16 Pro). Times match the tables above within noise, except RS256 signing: 917 ms on the phone (507 → 492 ms on the simulator), because `sign` now verifies every RSA signature before returning it (about 1% of the cost — the rest is run-to-run variation). The release builds are minified, so the "name intact" part of the tampered-signature check proves the error-name fix where it matters.

With `react-native-get-random-values` added to `example/` (15 checks), RSA-PSS signs on the phone for the first time: PS256 828 ms, PS384 826 ms, PS512 832 ms (511 ms each on the iOS simulator) — the cost of RS256 signing, as expected (the private-key operation dominates; the salt is 32–64 random bytes).

## With RSA blinding — measured 2026-10-17

RSA signing is blinded when `crypto.getRandomValues` exists ([../domain/keys.md](../domain/keys.md#rsa-blinding)). One Release run each, before and after: on the Realme RMX3363 RS256 signing took 1010 ms (849 ms unblinded), PS256 846–882 ms (824–832 ms); on the iOS 18.3 simulator RS256 506 ms (483 ms), PS256 501–514 ms (488–512 ms). Blinding adds an inverse and a random draw to a private operation of about 0.8 s — a few to twenty percent in these single runs, within the run-to-run spread on the phone. Verification is unaffected.

## An older Hermes — measured 2026-10-15

Official Hermes v0.12.0 CLI (August 2022, the React Native 0.70/0.71 era) on the same Mac, with the self-test compiled through React Native 0.71's Babel preset and run as bytecode: all 12 checks of the time pass, and the times match the 0.87 simulator within 10% (ES256 verify 37 ms, RS256 verify 5.7 ms, EdDSA verify 18 ms). An old app gains nothing and loses nothing by its Hermes version.

The bundle was built with esbuild, which tree-shook noble's module-level `TextEncoder` calls, so this run could not show that Hermes before React Native 0.74 fails at import. The timings stand; the floor it suggested (0.71) does not — see [ADR-007](../adr/ADR-007-host-requirements-text-encoder.md).

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
