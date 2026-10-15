---
doc_kind: domain
doc_function: canonical
purpose: The order of checks in verify and the rules for each claim.
derived_from:
  - token-model.md
  - algorithms.md
  - keys.md
status: active
canonical_for:
  - verification_order
  - claim_rules
---

# Validation

## Order

`verify` stops at the first failure and throws the named error for that step.

1. **Shape** — three segments, at most 65,536 characters, strict base64url, JSON object header and payload, header `typ`/`cty`/`kid` strings → `JwtMalformedError`; registered claims of the right type (`iss`, `sub`, `jti` strings, `aud` a string or array of strings, `exp`/`nbf`/`iat` finite numbers) → `JwtClaimError`. Types only, no values: this reveals nothing an attacker could not see in the token.
2. **Algorithm** — `alg` present, not `none`, and equal to the key's single algorithm → `JwtAlgorithmError`. With a JWKS, the key is first selected by `kid`: no key with that `kid`, or several for the token's `alg` → `JwtKeyNotFoundError`; a key with that `kid` but for another algorithm → `JwtAlgorithmError`. The `algorithm` option, when given, must also match — for a key set as for a bare secret.
3. **Header** — no unknown `crit` → `JwtMalformedError`.
4. **Signature** — constant-time comparison for HMAC → `JwtSignatureError`.
5. **Claims** — values, only after the signature holds, so an attacker cannot probe claim logic with unsigned input → `JwtExpiredError`, `JwtNotBeforeError`, `JwtClaimError`.

## Algorithm

The token's header never chooses the algorithm; the key does. Every key has exactly one algorithm (RFC 8725 §3.1), bound at import, or `HS256` for a bare secret unless the `algorithm` option says otherwise. The rules for binding are in [keys.md](keys.md#binding); the decision is [ADR-003](../adr/ADR-003-one-key-one-algorithm.md).

## Time claims

- NumericDate in seconds. A value above `1e11` is almost certainly milliseconds; signing rejects it rather than producing a token that expires in the year 5000.
- `exp`: invalid when `now - tolerance >= exp`.
- `nbf`: invalid when `now + tolerance < nbf`.
- `iat`: in the future beyond tolerance is invalid; `maxTokenAge` additionally bounds `now - iat`.
- `exp` is checked by default. Skipping it is an explicit option, not an omission.
- Default tolerance: 0 seconds, configurable; a tolerance that is not a finite duration is a `JwtClaimError`, never infinity.
- `now` is injectable, and must be a valid `Date`. An Invalid Date would make every comparison false and switch every time check off, so it is a `JwtClaimError`.
- Times are compared exactly, not rounded to the second: a fractional `exp` (some issuers emit them) expires at its fraction.

## Other claims

| Option | Rule |
|-|-|
| `issuer` | `iss` equals one of the given values |
| `audience` | `aud` (string or array) intersects the given values |
| `subject` | `sub` equals the given value |
| `typ` | header `typ` equals the given value, case-insensitive per RFC 7515 |
| `requiredClaims` | each named claim is present |

Claim checks run only when the option is given — except `exp`, `nbf`, and "`iat` is not in the future", which run whenever the claim is present.
