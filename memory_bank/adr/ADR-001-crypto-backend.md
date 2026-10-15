---
doc_kind: adr
doc_function: canonical
purpose: Record the choice of cryptographic backend for 2.0.0.
derived_from:
  - ../product/vision.md
  - ../domain/algorithms.md
status: active
decision_status: accepted
date: 2026-10-14
---

# ADR-001 — Crypto backend

## Context

1.0.x delegates everything to `jsrsasign`. The library's value is that it signs and verifies JWTs **entirely on the device, in JavaScript**: no server, no native module, nothing to link or rebuild. Hermes has no WebCrypto, so whatever does the cryptography must be pure JavaScript.

`jsrsasign` 11.1.5 has no open advisories, but it carries 14 in the GitHub Advisory Database, six of them published together on 2026-03-23, and about eight in code a JWT library calls: RSA-PSS and ECDSA encoding checks, malleable RSA signatures, JWS with special characters (GHSA-3fvg-4v2m-98jf), and a signature-verification bypass through a negative exponent (GHSA-8qwj-4jxw-m8jw). It is one 342 KB minified file (91 KB gzip) of PKI toolkit — X.509, CMS, ASN.1, DSA, RSA encryption — and Metro bundles all of it.

## Options

Measured on 2026-10-14; sizes are esbuild-minified bundles of exactly the modules a JWT library imports.

| Option | Algorithms | gzip | Audit | Advisories | Crypto we write | Native |
|-|-|-|-|-|-|-|
| `jsrsasign` 11 | all | 91 KB | none known | 14 | none | no |
| **`@noble/hashes` + `@noble/curves` + `micro-rsa-dsa-dh`** | all | **29 KB** | noble: Cure53 and others; RSA part: none | 0 | none | no |
| noble + in-house RSA verify | all but RSA signing | 22 KB | partial | 0 | ~150 lines | no |
| `node-forge` | no ECDSA | 1.6 MB unpacked | none | 16 (5 in 2026) | none | no |
| `react-native-quick-crypto` required | all | — | — | — | none | **yes** |
| Own Swift/Kotlin module | all but Ed25519 below Android 13 and ES256K | — | platform | — | glue on two platforms | **yes** |

## Decision

The crypto backend is **`@noble/hashes`, `@noble/curves`, and `micro-rsa-dsa-dh`**, pure JavaScript:

| Family | Package |
|-|-|
| HMAC-SHA2 (HS*) | `@noble/hashes` (`hmac`, `sha2`) |
| ECDSA P-256/384/521, secp256k1 (ES*) | `@noble/curves` (`nist`, `secp256k1`) |
| Ed25519 (EdDSA) | `@noble/curves` (`ed25519`) |
| RSA PKCS#1 v1.5 and PSS, sign and verify (RS*, PS*) | `micro-rsa-dsa-dh` (`rsa`) |

The library writes no cryptography of its own. It writes the parsing around it — base64url, PEM/DER key import, JWK — and the JWT logic.

Measured in Node against `node:crypto`: RS256 and PS256 tokens signed by Node verify, a token with one flipped byte does not, and an RS256 signature produced here verifies in Node. RSA-2048 verify 0.1 ms, sign 11.6 ms; ES256 verify 1.8 ms; Ed25519 verify 1.1 ms (V8).

## Consequences

**Positive.** Every algorithm, including RSA signing, works on Hermes and in Expo Go as installed, with no server and no native module. Three times smaller than `jsrsasign`. All three packages come from one author with one coding standard, and the elliptic-curve and hash parts are independently audited.

**Negative.**
- The RSA part (`micro-rsa-dsa-dh`) is not audited and is `0.x`; its version is pinned exactly and upgraded deliberately.
- It does not reject imported RSA keys below 2048 bits — its README says so — so the library enforces the minimum itself.
- RSA-PSS signing draws a random salt and needs `crypto.getRandomValues`, which Hermes does not provide without `react-native-get-random-values`. HMAC, ECDSA (RFC 6979, `extraEntropy: false` by default in noble 2.x), Ed25519, and RSA PKCS#1 v1.5 signing need no randomness.
- Pure-JS RSA signing is exposed to timing measurement by code on the same device. Accepted: signing happens on the user's own device; verification handles no secret.
- All three packages are ESM-only.
- **Performance on Hermes is not yet measured.** Hermes `BigInt` is slower than V8's; FT-001 stage 1 measures it on devices before code depends on it, and a result that makes ES256 verification visibly block the JS thread reopens this decision.

**Rejected alternatives.**
- `jsrsasign` 11 — four times the size and an advisory record that kept growing into 2026, in exactly the code JWT uses. It stays only as the dependency of the 1.0.x line.
- In-house RSA verification — `micro-rsa-dsa-dh` does the same with tests behind it, and adds signing.
- A required native module, ours or `react-native-quick-crypto` — removes the reason the library exists (install and it works), adds Swift and Kotlin to maintain across React Native majors, cannot be tested in Jest, and buys speed a once-per-token operation does not need.
- `node-forge`, `crypto-js`, `elliptic`, `tweetnacl` — incomplete algorithm coverage, unmaintained, or with their own advisory records.

**Follow-on.**
- [../engineering/dependency-policy.md](../engineering/dependency-policy.md) allows exactly these three packages.
- Hardware-backed keys (Secure Enclave, Android Keystore) need native code by definition; they are an idea for after 2.0, as a separate optional package, in [../product/roadmap.md](../product/roadmap.md#after-200).
