---
doc_kind: domain
doc_function: canonical
purpose: Supported signature algorithms, the key each requires, and what is refused.
derived_from:
  - token-model.md
status: active
canonical_for:
  - supported_algorithms
  - refused_algorithms
---

# Algorithms

Target set for 2.0.0. Every row signs and verifies in pure JavaScript; the packages are fixed by [ADR-001](../adr/ADR-001-crypto-backend.md).

| `alg` | Family | Key | Implemented by | Needs `getRandomValues` to sign |
|-|-|-|-|-|
| HS256 / HS384 / HS512 | HMAC-SHA2 | secret ≥ hash length | `@noble/hashes` | no |
| RS256 / RS384 / RS512 | RSASSA-PKCS1-v1_5 | RSA ≥ 2048 bits | `micro-rsa-dsa-dh` | no |
| PS256 / PS384 / PS512 | RSASSA-PSS, salt = hash length | RSA ≥ 2048 bits | `micro-rsa-dsa-dh` | **yes** |
| ES256 / ES384 / ES512 | ECDSA P-256 / P-384 / P-521 | EC | `@noble/curves` | no (RFC 6979) |
| ES256K | ECDSA secp256k1 (RFC 8812) | EC | `@noble/curves` | no (RFC 6979) |
| EdDSA (Ed25519) | RFC 8037 | OKP | `@noble/curves` | no |

Verification never needs randomness. Signing with PS* on a host without `crypto.getRandomValues` throws a named error naming `react-native-get-random-values`.

## Refused

- `none` — always, with no option to enable it.
- Any `alg` other than the key's own single algorithm, even if the key could verify it — RS256 for a key bound to PS256, HS512 for a secret used as HS256. See [keys.md](keys.md#binding).

## Encoding rules that break interop when wrong

- ECDSA signatures are raw `r‖s` of fixed length (64, 96, or 132 bytes), **not DER**. Libraries that emit DER produce tokens nobody else accepts.
- ECDSA signatures are malleable: `(r, s)` and `(r, n − s)` both verify, and both are accepted because OpenSSL emits either (high-S). Every ES* token therefore has a second valid string. Do not deduplicate, revoke, or cache ES* tokens by their string or hash; use `jti`.
- An HMAC secret given as a string is UTF-8 bytes, always. 1.0.x inherited `jsrsasign`'s rule that a string matching `/^[0-9a-f]+$/i` is hex, so a secret like `deadbeef` produced tokens no other library could verify — measured, see [../backlog.md](../backlog.md#defects-in-the-10x-line). Callers who need the old signatures pass the bytes as a `Uint8Array`.
- HMAC secrets shorter than the hash output (32, 48, 64 bytes for HS256/384/512) are rejected by `sign` and `verify` (RFC 7518 §3.2), unless the caller passes `allowShortSecret: true` — a legacy escape hatch for issuers whose secret the caller does not control ([ADR-006](../adr/ADR-006-named-1x-tombstones.md)).
- RSA keys below 2048 bits are rejected on import (RFC 7518 §3.3). `micro-rsa-dsa-dh` does not check this for imported keys, so the library does.
