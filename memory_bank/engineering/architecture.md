---
doc_kind: engineering
doc_function: canonical
purpose: Module boundaries, the crypto backend seam, and the public API surface of 2.0.0.
derived_from:
  - ../product/vision.md
  - ../domain/validation.md
status: active
canonical_for:
  - module_layering
  - public_api_surface
---

# Architecture

## Layers

```
src/host/       hostCheck: engine features (BigInt, Object.hasOwn, TextEncoder) and a `**`-rewriting Babel setup, checked before the crypto packages load (ADR-007).
                random: the getRandomValues check for PS* signing.
src/errors/     JwtError and its subclasses, each with a stable `code`.
src/types/      Public types: Algorithm, JwtHeader, JwtPayload, Jwk, options. No logic.
src/utils/      base64url, UTF-8, JSON without __proto__ (and deep freezing), bytes, NumericDate and durations, option checks, safe value descriptions for messages. Pure.
src/keys/       JwtKey (opaque, one algorithm), DER reader, importPEM, importJWK, createJWKS,
                resolveKey (bare secrets, binding, secret length), keyMaterial (public keys
                passed as secrets, in any encoding).
src/crypto/     curves (noble instances, point validation) and backend (sign/verify over bytes).
src/jwt/        parse, sign, verify, claims, decodeUnverified, expiry helpers, 1.x tombstones.
src/index.ts    The barrel. Its first import is host/hostCheck; the rest is re-exports.
```

Dependencies point downward only. Only `src/crypto/` imports a cryptography package; `src/keys/` reaches noble only through `crypto/curves` to validate points and derive public keys.

## Keys

A `JwtKey` is a frozen object with `algorithm`, `type` and optional `kid`; its material lives in a module-level `WeakMap`. A plain object posing as a key has no material and is refused, and logging a key never prints its secret parts. Public parts are always present, so a private key also verifies.

## Crypto backend seam

`signBytes(alg, material, data)` and `verifyBytes(alg, material, data, signature)` in `src/crypto/backend.ts`. Behind them sit `@noble/hashes`, `@noble/curves`, and `micro-rsa-dsa-dh` ([ADR-001](../adr/ADR-001-crypto-backend.md)). `verifyBytes` never throws for a bad signature: wrong lengths and malformed values are simply invalid. Keeping the seam internal means a backend can be swapped or added — a native one for hardware keys, say — in a minor release.

## Public API surface

```ts
sign(payload, key, { algorithm?, allowShortSecret?, expiresIn?, notBefore?, issuer?, audience?, subject?,
                     jwtId?, keyId?, header?, noTimestamp?, now? }): string
verify<T>(token, key | jwks, { algorithm?, allowShortSecret?, issuer?, audience?, subject?, typ?,
                               requiredClaims?, maxTokenAge?, clockTolerance?, ignoreExpiration?,
                               ignoreNotBefore?, now? }): { header, payload: T }
decodeUnverified<T>(token): { header, payload: T }
isExpired(token, { clockTolerance?, now? }): boolean
getExpiration(token): Date | null
importPEM(pem, algorithm, { kid? }): JwtKey
importJWK(jwk, algorithm?): JwtKey
createJWKS(jwks, { algorithm? }): JwtKeySet   — { keys, skipped }
hexToBytes(hex): Uint8Array
Algorithm, JwtErrorCode, JwtError and its ten subclasses

encode, decode, and the default export { encode, decode, verify } — 1.x tombstones that throw JwtMigrationError; removed in 3.0.0
```

Every function is synchronous and throws a named error on failure ([ADR-002](../adr/ADR-002-synchronous-api.md)); none returns a promise, which `src/__tests__/api.test.ts` asserts along with the exact export list. For a bare secret `algorithm` picks the HMAC (default `HS256`); for an imported key it must equal the key's own; in `verify` it also pins the token's `alg`, for a key set too ([ADR-003](../adr/ADR-003-one-key-one-algorithm.md)). Options are plain objects with known names only. Names, `decode` existing only as a tombstone, the tombstones and `allowShortSecret` are [ADR-006](../adr/ADR-006-named-1x-tombstones.md).

Everything exported from `src/index.ts` is a published contract. Adding to it is a minor release; changing or removing from it is a major one.

## Packaging

| Consumer | Resolves to | Through |
|-|-|-|
| Metro (React Native) | `src/index.ts` | the `react-native` export condition |
| Node, `require` or `import` | `lib/commonjs` | the `node` and `require` conditions; noble is loaded with `require(esm)`, Node ≥ 20.19 |
| Bundlers | `lib/module` | the `import` condition |
| TypeScript | `lib/typescript` | `types` |

`sideEffects` lists only `host/hostCheck`, so a tree-shaking bundler keeps the engine check.
