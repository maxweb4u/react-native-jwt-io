---
doc_kind: domain
doc_function: canonical
purpose: JWT vocabulary as this library uses it.
derived_from:
  - ../dna/glossary.md
status: active
canonical_for:
  - domain_terms
---

# Glossary

| Term | Definition |
|-|-|
| JWT | A set of claims carried as a signed JWS in compact form (RFC 7519) |
| JWS | A signed payload: `header.payload.signature`, each part base64url (RFC 7515) |
| JWE | An encrypted token. Not supported — see [../product/context.md](../product/context.md#non-goals) |
| JWK / JWKS | A key as JSON (RFC 7517); a JWKS is `{ "keys": [ … ] }`, usually served by an issuer |
| `alg` | Header parameter naming the signature algorithm (RFC 7518) |
| `kid` | Header parameter selecting a key from a JWKS |
| Registered claims | `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti` (RFC 7519 §4.1) |
| NumericDate | Seconds since the epoch, not milliseconds. The single most common caller mistake |
| Clock tolerance | Seconds of skew allowed when comparing time claims; device clocks drift |
| Unverified decode | Reading header and payload without checking the signature. Safe for display, never for authorisation |
| Algorithm confusion | Verifying a token with the algorithm its own header names, letting an attacker switch RS256 to HS256 with the public key as the secret |
