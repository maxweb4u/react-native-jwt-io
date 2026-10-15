---
doc_kind: engineering
doc_function: canonical
purpose: Module boundaries, the crypto backend seam, and the public API surface of 2.0.0.
derived_from:
  - ../product/vision.md
  - ../domain/validation.md
status: draft
canonical_for:
  - module_layering
  - public_api_surface
---

# Architecture

## Layers

```
src/types/      Public types: JwtHeader, JwtPayload, options, results. No logic.
src/utils/      base64url, UTF-8, JSON parsing, NumericDate, duration parsing ("15m"). Pure.
src/errors/     JwtError and its subclasses, each with a stable `code`.
src/host/       The runtime host check (ADR-005). Runs once, before the first crypto call.
src/crypto/     Backend interface and the per-algorithm adapters over noble and micro-rsa-dsa-dh.
src/keys/       Secret / PEM / JWK import and local JWKS lookup by kid.
src/jwt/        sign, verify, decodeUnverified, claim validation, expiry helpers.
src/index.ts    The barrel. Re-exports only.
```

Dependencies point downward only. Only `src/crypto/` imports a cryptography package; everything above it calls the backend interface.

## Crypto backend seam

One internal interface: `sign(alg, key, data)` and `verify(alg, key, data, signature)` over bytes. Behind it sit `@noble/hashes`, `@noble/curves`, and `micro-rsa-dsa-dh`, per [ADR-001](../adr/ADR-001-crypto-backend.md); no other file imports them. Keeping the seam internal means a backend can be swapped or added — a native one for hardware keys, say — in a minor release.

## Public API surface (sketch)

```ts
sign(payload, key, { algorithm?, allowShortSecret?, expiresIn?, notBefore?, issuer?, audience?, subject?, jwtId?, keyId?, header? }): string
verify<T>(token, key | jwks, { algorithm?, allowShortSecret?, issuer?, audience?, subject?, clockTolerance?, maxTokenAge?, requiredClaims?, typ?, now? }): { header, payload: T }
decodeUnverified<T>(token): { header, payload: T }
isExpired(token, { clockTolerance?, now? }): boolean
getExpiration(token): Date | null
importPEM(pem, algorithm), importJWK(jwk, algorithm?)
createJWKS(jwks)
hexToBytes(hex): Uint8Array

default export: { encode, decode, verify } — migration tombstones that throw JwtMigrationError; removed in 3.0.0
```

Every function above is synchronous and throws a named error on failure ([ADR-002](../adr/ADR-002-synchronous-api.md)); none returns a promise. `algorithm` applies only to a bare secret (default `HS256`); an imported key carries its own ([ADR-003](../adr/ADR-003-one-key-one-algorithm.md)). Names, the absence of `decode`, the tombstones, and `allowShortSecret` are [ADR-004](../adr/ADR-004-break-from-v1-api.md).

Everything exported from `src/index.ts` is a published contract. Adding to it is a minor release; changing or removing from it is a major one.
