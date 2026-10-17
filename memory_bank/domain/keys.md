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
| PEM via `importPEM(pem, algorithm, { kid? })` | `PUBLIC KEY` (SPKI), `PRIVATE KEY` (PKCS#8 v1 or v2), `RSA PUBLIC KEY` / `RSA PRIVATE KEY` (PKCS#1), `EC PRIVATE KEY` (SEC1). `algorithm` is required. Read as OpenSSL and Node read it: text around the block (Bag Attributes, comments) and an `EC PARAMETERS` block are ignored; two key blocks, mismatched BEGIN/END labels, or more than 64 KB are refused, and literal `\n` sequences in place of line breaks are named as such. A key whose OID is id-RSASSA-PSS binds to PS* only; if it carries RSASSA-PSS parameters (RFC 4055 §3.1), they must name one SHA-2 hash for the digest and MGF1 and a salt no longer than that hash, and the key binds to that PS* alone |
| JWK object via `importJWK(jwk, algorithm?)` | Public or private; `use`, if present, must be `sig`, and `key_ops`, if present, must include `sign` or `verify`, agree with `use: "sig"`, and give a public key `verify`; the key then does only what `key_ops` lists — signing with `["verify"]` or verifying with `["sign"]` is a `JwtKeyError`, and `createJWKS` skips a key without `verify` (OD-9); algorithm per [Binding](#binding) |
| JWKS object via `createJWKS()` | Key chosen by the token's `kid`, then filtered by `alg`. Keys not for signatures (`use: "enc"`, or a JWE `alg` such as `RSA-OAEP` or `ECDH-ES`) or of an unsupported type are left out silently; a supported key that cannot be imported is left out and listed in the set's `skipped` with the reason, so one bad key does not stop the others — and a token whose `kid` names it gets `JwtKeyError` with that reason, not "no such key" |

Checked at import: RSA moduli are odd and 2048 to 16384 bits (the upper limit is `micro-rsa-dsa-dh`'s, enforced at every operation — refusing at import says why, instead of every verification failing as "invalid signature"), public exponents odd, at least 3 and at most 33 bits (as BoringSSL allows; real keys use 65537, and a 256-bit exponent from a hostile JWKS makes every verification 45 times slower). Sizes are checked before any arithmetic: a 48 KB field must fail at once, not after half a second of BigInt conversion. Also `1 < d < n`, and when the primes are present (PKCS#1, PKCS#8, and JWKs that carry `p` and `q`) they must produce `n`, `e` and `d`. A private key whose parts were mixed from two keys is refused instead of signing tokens nobody can verify. EC and Ed25519 private keys are checked against their public parts the same way, and so is the public key a PKCS#8 v2 key or a SEC1 key carries — for RSA, EC and Ed25519 alike.

An RSA JWK may carry `d` without the primes, so nothing at import proves that `d` belongs to `n` and `e`. `sign` therefore verifies every RSA signature before returning it — about 1% of the signing time — and throws `JwtKeyError` if it does not verify.

DER is read with one encoding per value: definite minimal lengths, minimal positive integers, OIDs without `0x80` padding, no trailing data, and optional fields (`[0]`, `[1]` in PKCS#8 and SEC1; `[0]`–`[3]` in RSASSA-PSS parameters) at most once each and in order.

Key material is never accepted as a secret, in any form a public key is commonly stored or pasted in (`src/keys/keyMaterial.ts`):

- PEM armor anywhere in the input (`openssl pkcs12` writes "Bag Attributes" lines before it), in any case, with any spacing, typographic dashes, or only its END line;
- JWK or JWKS JSON, escaped or not, a JS literal, `n`/`e` or `crv`/`x` without `kty`, and JSON documents that carry a key (a Keycloak realm with its `public_key`);
- OpenSSH public keys, authorized_keys lines with options, SSH certificates, and the SSH wire blob without its type;
- DER of a key (SPKI, PKCS#1, PKCS#8, SEC1), an X.509 certificate or PKCS#7, and an uncompressed EC point (`04‖x‖y`, WebCrypto's raw export) on a supported curve;
- each of these as bytes or text: base64, base64url (Keycloak's `public_key`), hex (also `0x`-prefixed or colon-separated, as `openssl … -text` prints), Latin-1, UTF-8 with a BOM, UTF-16LE; with literal `\n` escapes (`.env` files), JSON quotes, URL encoding, trailing whitespace — and base64 of any of it (Kubernetes secrets), up to three levels.

The secret path means "HMAC secret", and keeping the two apart is what closes algorithm confusion structurally rather than by a runtime check. Measured on 2026-10-16 against 425 forms of six key types (RSA, P-256, P-384, P-521, secp256k1, Ed25519): 52 still pass, all of them either indistinguishable from random bytes — a bare RSA modulus, a bare EC or Ed25519 coordinate (half of all random 32-byte strings are valid Ed25519 points), a compressed EC point — or forms no tool writes (BER lengths, DER decoded lossily as UTF-8), or private-key containers whose public part an attacker does not have. The review of 2026-10-17 found that some passing forms are written by tools after all — .NET `RSA.ToXmlString`, a JWK as YAML or TOML (with or without `kty`), `openssl … -text` output, DER as a JSON array or comma list of decimal bytes — and they are refused now. The second round the same day closed their variants: XML with namespace prefixes and attributes (XMLDSig, .NET `ECDSAKeyValue xmlns=…`), a SAML `X509Certificate`, a TOML inline table, a PyYAML list item, partial `openssl -text` (`Modulus:` or `pub:` then hex, `ASN1 OID:`, `Modulus=`), and DER as numbers in every shape tools print — Java's signed bytes, Go's spaces, one per line, C braces with hex, a trailing comma, `JSON.stringify` of a `Buffer` or a `Uint8Array`. The line patterns check their values (`e` short, `crv` a curve name, `n` at least 1024 bits, `x` at least 32 bytes), so a config line that only shares a name is a secret. The third round added the declarations around such lists (`xxd -i`, Go `%#v`'s `[]byte{…}`, Java `new byte[]{…}`, PowerShell `[byte[]](…)` and `@(…)`, Python `bytes([…])`, Rust's `48u8`), a Python `b'…'` literal, `hexdump -C` and `xxd` dumps, a JWK as INI in capitals, and UTF-16BE; Node's `util.inspect` of a buffer shows only its first bytes, so it cannot be recognised. Still passing: forms nested deeper than three encodings, base64 of UTF-16 text, PEM with non-breaking spaces or full-width dashes, HTML entities, base32, compressed data. Against 520,000 generated secrets of 26 kinds — random bytes, base64, hex, UUIDs, passphrases, framework secret formats, JSON that is not a JWK — none was refused. Refused on purpose: text that contains a PEM armor line or starts like an OpenSSH key, and an `oct` JWK (use `importJWK`). Every pattern is linear: an earlier `-{3,}BEGIN` took 7 seconds on 64 KB of dashes, and in the second round's number lists a trailing-bracket regex did the same on 64 KB of spaces; lists are tokenized by hand.

## RSA blinding

`micro-rsa-dsa-dh` blinds the private RSA operation — multiplies the input by a random `r^e` first, so its time does not depend on `d` — only when the private key it is given includes `e`, and checks the result against `e` as it goes. The backend passes `e` whenever the host has `crypto.getRandomValues`, and omits it otherwise: on Hermes without `react-native-get-random-values`, RS* signing stays unblinded instead of failing, and PS* has already required a random source. PKCS#1 v1.5 signatures are the same either way. A private key whose `d` does not belong to its `n` and `e` is reported as such on both paths. "Has `crypto.getRandomValues`" means one that works, asked before each signature: reading it must not throw, and it must return (noble uses what it returns, not the array it passed) a Uint8Array of the length asked for, not all zero and different from the one before, and — for a blinded RSA signature — yield a number in (1, n) the way `micro-rsa-dsa-dh` draws its blinding factor, within 32 modulus-sized draws and never on the first. That draw is a loop without a bound: a source whose numbers never fall below the modulus, or that fills a single array, hung it (third review of 2026-10-17). A source that behaves for the probe and fails after it can still hang it; no test mock seen does. A test mock that returns its argument made blinding loop forever looking for a usable random number, and react-native-get-random-values without its native module made RS* signing fail with an error blaming the key (second review of 2026-10-17); such a host now signs RS* unblinded, and PS* throws `JwtHostRequirementError`. Decided after the review of 2026-10-17; a timing attack on signing inside an app is unlikely, so the hardening must not cost a new requirement.

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
