---
doc_kind: domain
doc_function: canonical
purpose: Rules for the compact JWS serialization this library produces and accepts.
derived_from:
  - glossary.md
status: active
canonical_for:
  - token_format
  - base64url_rules
---

# Token Model

## Shape

Exactly three dot-separated segments. A token with two segments, four, or five (JWE) is rejected as malformed before anything is decoded.

At most 65,536 characters (`MAX_TOKEN_LENGTH` in `src/jwt/parse.ts`); a longer string is malformed before it is split. HTTP headers rarely allow more than 16 KiB, so the limit costs no real token anything and bounds the work hostile input can cause.

## base64url

- Alphabet `A–Z a–z 0–9 - _`, no padding on output.
- On input, padding and characters outside the alphabet are rejected. Lenient decoding of this kind is what [GHSA-3fvg-4v2m-98jf](https://github.com/advisories/GHSA-3fvg-4v2m-98jf) exploited in `jsrsasign`.
- Implemented in the library without `atob`/`btoa`: Hermes has had them only since React Native 0.74, and they operate on Latin-1, not bytes.

## Header

- `alg` is required. `typ` defaults to `JWT` on output.
- `crit` is rejected unless every listed extension is understood — none are, so any `crit` fails verification (RFC 7515 §4.1.11).
- `b64: false` (RFC 7797) is not supported.
- `typ`, `cty` and `kid` must be strings when present.
- The header is parsed for routing (`alg`, `kid`) but its claims are not trusted until the signature verifies.

## Payload

- Must be a JSON object. Arrays, strings, and numbers are malformed for a JWT even though JWS allows them.
- Registered claims have their RFC 7519 types, checked on every read and every write: `iss`, `sub`, `jti` strings; `aud` a string or array of strings; `exp`, `nbf`, `iat` finite numbers. The `JwtPayload` type promises exactly this, so it is enforced rather than assumed.
- `sign` validates the payload and header **as serialized**: a `toJSON` method or getter that rewrites `alg` or a claim is refused.
- Text is UTF-8 both ways. 1.0.x round-tripped non-ASCII correctly through `jsrsasign`; the rewrite must keep that, and a test pins it.
- Parsed with `JSON.parse`; `__proto__` keys are dropped so a hostile payload cannot reach a prototype.
