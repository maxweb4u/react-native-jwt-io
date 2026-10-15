---
doc_kind: domain
doc_function: canonical
purpose: Accepted key inputs and how a key is bound to an algorithm.
derived_from:
  - algorithms.md
status: active
canonical_for:
  - key_inputs
  - key_algorithm_binding
---

# Keys

## Inputs

| Input | Meaning |
|-|-|
| `string` | HMAC secret as UTF-8. Never parsed as hex, never parsed as PEM. Algorithm `HS256` unless the `algorithm` option names `HS384` or `HS512` |
| `Uint8Array` | Raw HMAC secret bytes, same algorithm rule. Also the migration path for 1.0.x secrets that were read as hex |
| PEM via `importPEM(pem, algorithm)` | SPKI public key or PKCS#8 private key; PKCS#1 `RSA PRIVATE KEY` accepted for migration from 1.0.x. `algorithm` is required |
| JWK object via `importJWK(jwk, algorithm?)` | Public or private; `use` is honoured; algorithm per [Binding](#binding) |
| JWKS object via `createJWKS()` | Key chosen by the token's `kid`, then filtered by `alg` |

A PEM is never accepted as a bare string. The bare-string path means "HMAC secret", and keeping the two apart is what closes algorithm confusion structurally rather than by a runtime check.

## Binding

Every key carries exactly one algorithm ([ADR-003](../adr/ADR-003-one-key-one-algorithm.md)):

- a bare secret: `HS256`, or the `algorithm` option;
- a PEM: the algorithm given to `importPEM`;
- a JWK: its `alg`; else the `algorithm` argument; else derived only when the key type allows exactly one — EC P-256/P-384/P-521/secp256k1 → ES256/ES384/ES512/ES256K, Ed25519 → EdDSA. An RSA or `oct` JWK with neither is rejected on import.

The binding is checked when the key is imported (an RSA key cannot be bound to ES256) and on every operation: `verify` refuses a token whose `alg` differs, before the signature is computed, and `sign` refuses an `algorithm` option that contradicts the key.

## Remote JWKS (deferred to 2.1)

Not in 2.0.0: it is the only feature that touches the network, and 2.0.0 is synchronous ([ADR-002](../adr/ADR-002-synchronous-api.md)). In 2.0.0 the caller loads a JWKS however it likes and passes the object to `createJWKS()`. The rules below are kept for when it is built:

- A separate asynchronous function that loads keys and then calls the synchronous `verify`.
- Fetched with the host's `fetch`; no HTTP library.
- Cached; refetched at most once per cooldown window when a `kid` is unknown, so a stream of forged `kid`s cannot turn into a request flood.
- Network failure is a named error, never "signature invalid".
