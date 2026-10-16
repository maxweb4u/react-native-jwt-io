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
  - option_rules
---

# Validation

## Order

`verify` stops at the first failure and throws the named error for that step.

0. **Options** — no unknown option names ([Options](#options)) → `JwtClaimError`. The caller's mistake, reported before anything in the token is read.
1. **Shape** — three segments, at most 65,536 characters, strict base64url, JSON object header and payload, a non-empty string `alg`, header `typ`/`cty`/`kid` strings → `JwtMalformedError`; registered claims of the right type (`iss`, `sub`, `jti` strings, `aud` a string or array of strings, `exp`/`nbf`/`iat` finite numbers within ±8.64e12, the range of a `Date`) → `JwtClaimError`. Types only, no values: this reveals nothing an attacker could not see in the token.
2. **Algorithm** — `alg` not `none` and supported → `JwtAlgorithmError`.
3. **Header extensions** — no `crit`, no `b64` → `JwtMalformedError`.
4. **Key** — the `algorithm` option, when given, must equal `alg` — for a key set as for a single key, and before the set is searched → `JwtAlgorithmError`. With a JWKS, the key is then selected by `kid`: no key with that `kid`, several for the token's `alg`, or — without a `kid` — not exactly one for `alg` → `JwtKeyNotFoundError`; a key with that `kid` but for another algorithm → `JwtAlgorithmError`; a `kid` that names a key the set could not import → `JwtKeyError` with the reason. Key material passed as a secret, or an object that is not a key → `JwtKeyError`. The key's single algorithm must equal `alg` → `JwtAlgorithmError`; then an HMAC secret shorter than its hash → `JwtKeyError`.
5. **Signature** — constant-time comparison for HMAC → `JwtSignatureError`.
6. **Claims** — values, only after the signature holds, so an attacker cannot probe claim logic with unsigned input → `JwtExpiredError`, `JwtNotBeforeError`, `JwtClaimError`. The values of the claim options (`clockTolerance`, `maxTokenAge`, `now`, the types of `issuer`, `audience`, `subject`, `typ`, `requiredClaims`) are checked here too, so a token with a bad signature reports the signature even when an option is also wrong.

## Algorithm

The token's header never chooses the algorithm; the key does. Every key has exactly one algorithm (RFC 8725 §3.1), bound at import, or `HS256` for a bare secret unless the `algorithm` option says otherwise. The rules for binding are in [keys.md](keys.md#binding); the decision is [ADR-003](../adr/ADR-003-one-key-one-algorithm.md).

## Time claims

- NumericDate in seconds. A value above `1e11` is almost certainly milliseconds; signing rejects it rather than producing a token that expires in the year 5000. Beyond ±8.64e12 no `Date` can represent it, so reading one is a `JwtClaimError` too — never a `RangeError` from formatting the message, never an Invalid Date from `getExpiration`.
- `exp`: invalid when `now - tolerance >= exp`.
- `nbf`: invalid when `now + tolerance < nbf`.
- `iat`: in the future beyond tolerance is invalid; `maxTokenAge` additionally bounds it: invalid when `now - tolerance >= iat + maxTokenAge` — the same exclusive bound as `exp`.
- `exp` is checked by default. Skipping it is an explicit option, not an omission.
- Default tolerance: 0 seconds, configurable up to **one day** (86,400 seconds); anything else is a `JwtClaimError`. Clock skew is seconds to minutes; a larger tolerance is `exp` switched off, which has its own explicit option (`ignoreExpiration`).
- Durations (`clockTolerance`, `maxTokenAge`, `expiresIn`, `notBefore`) are whole seconds, rounded down, computed in integers: `'2.05m'` is 123 seconds, not the 122 that `2.05 * 60` gives in floating point. The longest is `1e11` seconds.
- `now` is injectable, and must be a valid `Date`. An Invalid Date would make every comparison false and switch every time check off, so it is a `JwtClaimError`.
- Times are compared exactly, not rounded to the second: a fractional `exp` (some issuers emit them) expires at its fraction.

## Other claims

| Option | Rule |
|-|-|
| `issuer` | `iss` equals one of the given values |
| `audience` | `aud` (string or array) intersects the given values |
| `subject` | `sub` equals the given value |
| `typ` | header `typ` equals the given value after RFC 7515 §4.1.9 normalization: a value without `/` means `application/<value>`; compared case-insensitively. `JWT` matches `application/jwt`; `a/b` does not match `application/a/b` |
| `requiredClaims` | each named claim is present |

Claim checks run only when the option is given — except `exp`, `nbf`, and "`iat` is not in the future", which run whenever the claim is present. In particular a token's `aud` is ignored without `audience`; RFC 7519 §4.1.3 asks a recipient to reject an `aud` it is not in, and only the caller knows which audience it is, so the README tells callers to pass it.

An option of the wrong type (`issuer: 5`, `subject: ['u']`) is a `JwtClaimError` naming the option, not a mismatch.

## Options

Options must be a **plain object** (`{…}`, or one with a null prototype): a function — a jsonwebtoken-style callback —, a string, a `Map` or a class instance would otherwise read as "no options", and options inherited through a prototype would apply without being checked. Every function that takes an options object refuses a name it does not know: `JwtClaimError` (with the name as `claim`) from `sign`, `verify` and `isExpired`, `JwtKeyError` from `importPEM` and `createJWKS`. An ignored option fails open — a misspelled `expiresin` issues a token without `exp`, and jsonwebtoken's `maxAge` would skip the age check it was meant to add — so the message names the right option for the names other libraries use (`maxAge`, `algorithms`, `clockTimestamp`, `complete`).

`null` in place of options means none, as `undefined` does.

`verify` and `decodeUnverified` return the header and payload **deeply** frozen, so a verified `aud` array cannot be edited after the check.
