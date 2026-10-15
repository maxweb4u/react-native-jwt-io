---
doc_kind: adr
doc_function: canonical
purpose: Record how verify and sign decide which algorithm to use, so the token's header never chooses it.
derived_from:
  - ../domain/validation.md
  - ../domain/keys.md
status: active
decision_status: accepted
date: 2026-10-15
---

# ADR-003 — One key, one algorithm

## Context

The `alg` header is written by whoever produced the token, possibly an attacker. A library that verifies with the algorithm the header names is open to **algorithm confusion**: an application verifies RS256 tokens with a public key, an attacker sets `alg: HS256` and signs with the public key's text as the HMAC secret, and the library accepts the forgery.

1.0.x lets the header choose (`jsrsasign`'s `JWS.verify(token, key)` without `acceptAlgs`). It survives the classic RS256→HS256 form only because `jsrsasign` turns a PEM string into a key object and the HMAC path then throws — measured on 2026-10-14, an accident of key parsing.

RFC 8725 §3.1 requires that the caller *can* specify the algorithms and that no other is used, and that **each key is used with exactly one algorithm**, checked on every operation.

The earlier proposal made `algorithms` a required option on every `verify` call. With typed keys that is repetition: `verify(token, importPEM(pem, 'RS256'), { algorithms: ['RS256'] })`.

## Decision

Every key has exactly one algorithm, and the token's `alg` must equal it.

| Key given | Its algorithm |
|-|-|
| `string` or `Uint8Array` secret | `HS256`, or the `algorithm` option (`HS384`, `HS512`). A string is always an HMAC secret, never parsed as PEM |
| `importPEM(pem, algorithm)` | The algorithm passed at import; required |
| `importJWK(jwk, algorithm?)` | The JWK's `alg`; else the argument; else derived when the key type allows exactly one (EC curve → ES256/384/512/256K, Ed25519 → EdDSA). An RSA or `oct` JWK with neither is rejected on import with a named error |
| JWKS via `createJWKS()` | Per key, by the JWK rule above, after selecting by `kid` |

- `verify` with a token whose `alg` differs from the key's algorithm throws `JwtAlgorithmError` before any signature work.
- `sign` writes the key's algorithm into the header; a conflicting `algorithm` option is an error, not an override.
- `none` is never accepted or produced, with no option to enable it.
- There is no `algorithms` list option. A caller who accepts several algorithms passes a JWKS with one key per algorithm.

## Consequences

**Positive.** Algorithm confusion is closed by construction: a public key cannot be passed as a string, and no key verifies under a second algorithm. `verify(token, secret)` keeps the shape and the HS256 default of 1.0.x. No option repeats what the key already says.

**Negative.** The HS256 default for bare secrets is implicit; a caller whose issuer uses HS512 must say so, and gets `JwtAlgorithmError` until they do. The error message names the option.

**Rejected alternatives.**
- A required `algorithms` list on every call — same security, constant repetition, and every 1.0.x call site needs a new option.
- Inferring a *family* from the key type (any HS* for a secret, RS* or PS* for an RSA key) — not exploitable as such, but it breaks RFC 8725's one-key-one-algorithm rule and lets a token downgrade within the family.
