---
doc_kind: engineering
doc_function: canonical
purpose: The rule for runtime dependencies and the process for adding one.
derived_from:
  - ../product/vision.md
  - ../adr/ADR-001-crypto-backend.md
status: active
canonical_for:
  - runtime_dependency_policy
  - peer_dependency_policy
  - dev_dependency_policy
---

# Dependency Policy

## The rule

Runtime dependencies are cryptographic primitives and nothing else. Everything else — base64url, PEM/DER and JWK import, JSON handling, claim logic, duration parsing, JWKS caching — is written in the library.

The library writes **no cryptography of its own**. Unlike `react-native-matrix` it is not zero-dependency, on purpose: hand-written HMAC, elliptic-curve, or RSA code is a worse risk than a dependency.

## Allowed runtime dependencies

Exactly these, chosen in [ADR-001](../adr/ADR-001-crypto-backend.md):

| Package | Range | Why |
|-|-|-|
| `@noble/hashes` | `^2` | HMAC, SHA-2; audited |
| `@noble/curves` | `^2` | ECDSA, Ed25519; audited |
| `micro-rsa-dsa-dh` | exact version | RSA PKCS#1 v1.5 and PSS; `0.x` and unaudited, so every upgrade is a deliberate change with the interop suite re-run |

`micro-rsa-dsa-dh` declares `@noble/ciphers` as a dependency. Its `rsa.js` does not import it, so it is installed but never bundled.

Import sub-paths (`@noble/curves/nist.js`), never a package root: Metro bundles at file granularity, so a root import would pull in curves the library does not use.

## Why the 1.0.x dependency is not kept

`jsrsasign` bundles a PKI toolkit JWT does not use, and its advisories have kept landing in the parts JWT does use. The evidence is in ADR-001.

## Peer dependencies

None for the core — not even `react-native`, which the library never imports; the supported range is defined by engine features instead ([ADR-007](../adr/ADR-007-host-requirements-text-encoder.md)). React becomes an optional peer only if the `useJwt` hook ships behind its own entry point.

## Adding a runtime dependency

All must hold: it implements cryptography, not convenience; its own dependencies stay inside the noble family; it is audited or is the de-facto standard; it runs on Hermes without native code; an ADR records it.

## Dev dependencies

Unconstrained; keep them current. `node:crypto` is the interop oracle in tests and must never be imported from `src/`.
