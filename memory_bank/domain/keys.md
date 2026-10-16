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
| `string` | HMAC secret as UTF-8. Never parsed as hex, never parsed as PEM or JWK. Algorithm `HS256` unless the `algorithm` option names `HS384` or `HS512` |
| `Uint8Array` | Raw HMAC secret bytes, same algorithm rule. Also the migration path for 1.0.x secrets that were read as hex |
| PEM via `importPEM(pem, algorithm, { kid? })` | `PUBLIC KEY` (SPKI), `PRIVATE KEY` (PKCS#8 v1 or v2), `RSA PUBLIC KEY` / `RSA PRIVATE KEY` (PKCS#1), `EC PRIVATE KEY` (SEC1). `algorithm` is required. A key whose OID is id-RSASSA-PSS binds to PS* only; if it carries RSASSA-PSS parameters (RFC 4055 §3.1), they must name one SHA-2 hash for the digest and MGF1 and a salt no longer than that hash, and the key binds to that PS* alone |
| JWK object via `importJWK(jwk, algorithm?)` | Public or private; `use`, if present, must be `sig`, and `key_ops`, if present, must include `sign` or `verify`; algorithm per [Binding](#binding) |
| JWKS object via `createJWKS()` | Key chosen by the token's `kid`, then filtered by `alg`. Keys not for signatures (`use: "enc"`) or of an unsupported type are left out silently; a supported key that cannot be imported is left out and listed in the set's `skipped` with the reason, so one bad key does not stop the others — and a token whose `kid` names it gets `JwtKeyError` with that reason, not "no such key" |

Checked at import: RSA moduli are odd and 2048 to 16384 bits (the upper limit is `micro-rsa-dsa-dh`'s, enforced at every operation — refusing at import says why, instead of every verification failing as "invalid signature"), public exponents odd, at least 3 and at most 33 bits (as BoringSSL allows; real keys use 65537, and a 256-bit exponent from a hostile JWKS makes every verification 45 times slower). Sizes are checked before any arithmetic: a 48 KB field must fail at once, not after half a second of BigInt conversion. Also `1 < d < n`, and when the primes are present (PKCS#1, PKCS#8, and JWKs that carry `p` and `q`) they must produce `n`, `e` and `d`. A private key whose parts were mixed from two keys is refused instead of signing tokens nobody can verify. EC and Ed25519 private keys are checked against their public parts the same way, and so is the public key a PKCS#8 v2 key or a SEC1 key carries — for RSA, EC and Ed25519 alike.

An RSA JWK may carry `d` without the primes, so nothing at import proves that `d` belongs to `n` and `e`. `sign` therefore verifies every RSA signature before returning it — about 1% of the signing time — and throws `JwtKeyError` if it does not verify.

DER is read with one encoding per value: definite minimal lengths, minimal positive integers, OIDs without `0x80` padding, no trailing data, and optional fields (`[0]`, `[1]` in PKCS#8 and SEC1; `[0]`–`[3]` in RSASSA-PSS parameters) at most once each and in order.

Key material is never accepted as a secret, in any form a public key is commonly shown in:

- PEM armor anywhere in the input (`openssl pkcs12` writes "Bag Attributes" lines before it), in any case and with any spacing;
- JWK or JWKS JSON, escaped or not;
- an OpenSSH public key (`ssh-rsa AAAA…`, `ssh-ed25519`, `ecdsa-sha2-…`);
- DER of a key (SPKI, PKCS#1, PKCS#8, SEC1) or of an X.509 certificate — as bytes, or as base64, base64url (Keycloak shows a realm's `public_key` this way), hex or Latin-1 text.

The secret path means "HMAC secret", and keeping the two apart is what closes algorithm confusion structurally rather than by a runtime check. One form cannot be told apart from a secret: a bare RSA modulus (a JWK's `n` alone) is indistinguishable from random bytes. The DER check costs little on real secrets: it parses only input that begins with a SEQUENCE spanning all of it, about one random secret in 65,000.

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
