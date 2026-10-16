# Wycheproof test vectors

Trimmed copies of test vectors from [C2SP/wycheproof](https://github.com/C2SP/wycheproof),
`testvectors_v1/`, downloaded on 2026-10-15. Licensed under the Apache License 2.0 by
their authors; see the upstream repository.

| File | Upstream | Vectors |
|-|-|-|
| `HS256.json` | `hmac_sha256_test.json` (256-bit tags only) | 87 |
| `RS256.json` | `rsa_signature_2048_sha256_test.json` | 259 |
| `PS256.json` | `rsa_pss_2048_sha256_mgf1_32_test.json` | 108 |
| `ES256.json` | `ecdsa_secp256r1_sha256_p1363_test.json` | 262 |
| `ES384.json` | `ecdsa_secp384r1_sha384_p1363_test.json` | 280 |
| `ES512.json` | `ecdsa_secp521r1_sha512_p1363_test.json` | 318 |
| `ES256K.json` | `ecdsa_secp256k1_sha256_p1363_test.json` | 252 |
| `EdDSA.json` | `ed25519_test.json` | 151 |

Only the fields the test reads are kept: the group's `publicKeyPem` (or the HMAC
`key`), and per vector `tcId`, `msg`, `sig`/`tag`, `result`, `comment`. The P1363
ECDSA files are used because P1363 (raw `r‖s`) is the JWS signature format.

Used by `../../wycheproof.test.ts`. Excluded from the npm package with the rest of
`__tests__/`.
