---
doc_kind: adr
doc_function: canonical
purpose: Record why a mistake in a call's options is its own error class, checked before the token is read, and why a payload generic adds to the registered claims — the last API changes before 2.0.0.
derived_from:
  - ADR-002-synchronous-api.md
  - ../domain/validation.md
status: active
decision_status: accepted
date: 2026-10-16
---

# ADR-008 — Option errors are their own class

## Context

The last pass over the public API before 2.0.0 (2026-10-16, after `2.0.0-alpha.0`) looked for what could not change later without a major release. Two things qualified.

**Option errors looked like token errors.** An unknown option, `now: new Date('x')`, a `clockTolerance` over a day or `issuer: 5` threw `JwtClaimError` from `sign`, `verify` and `isExpired` — with the option's name in `claim` — and `JwtKeyError` from `importPEM` and `createJWKS`. An app that treats every `JwtError` from `verify` as "sign the user out" then signs everyone out on every launch because of a typo in its own code, and nothing points at the code. After 2.0.0, moving these to another class would break callers who branch on `code`.

The values of the claim options were also checked only once a token had passed the signature check — on purpose, so that a forged token reported its signature even when an option was also wrong (validation.md said so). With option errors in a class of their own, that ordering hides the bug: a call with `issuer: 5` works as "invalid token" until a valid token arrives.

Two smaller faults turned up on the way. `createJWKS(set, { algorithm: 'RS999' })` skipped every key the option applied to and listed them in `skipped`, instead of refusing the option. And the switches (`ignoreExpiration`, `ignoreNotBefore`, `allowShortSecret`, `noTimestamp`) were compared with `=== true`, so `ignoreExpiration: 'true'` was quietly read as false.

**A payload generic replaced the registered claims.** `verify<{ roles: string[] }>()` returned `payload: { roles: string[] }`, so `payload.exp` and `payload.sub` no longer type-checked — the README's own `decodeUnverified<{ sub; roles }>` example lost `exp`. Changing the type later would break someone's types.

## Decision

1. **`JwtOptionError`**, code `ERR_JWT_OPTION_INVALID`, with `option` — the option's name (`clockTolerance`, `header.kid`; `options` for the object itself). A subclass of `JwtError`: every deliberate failure is still a `JwtError`.
2. **It covers mistakes in the call**, in every function that takes options: options that are not a plain object, unknown names, values of the wrong type or out of range, an `algorithm` that names no supported algorithm, a claim set both in the payload and through an option, reserved or non-string headers in `options.header`, a non-string `kid` for `importPEM`. The switches must be booleans.
3. **What the token says keeps its class.** A wrong or missing claim is `JwtClaimError`; a payload that is not a JSON object is `JwtClaimError`; a real algorithm that does not fit the key or the token is `JwtAlgorithmError`; a key problem is `JwtKeyError`.
4. **Options are checked before the token is read**, in `verify` and `isExpired`, whatever the token is. This replaces the earlier rule that claim-option values were checked after the signature.
5. **`DecodedJwt<T>` has `payload: JwtPayload & T`.** The generic adds the caller's claims to the registered ones, and can narrow one (`verify<{ sub: string }>` makes `sub` a `string`). As before, only the registered claims are checked at run time; the rest is the caller's assertion.

## Consequences

**Positive.** An app can tell a bug in its call from a bad token by class or by `code`, and the bug shows on the first call, not on the first valid token. A misspelt switch is an error rather than a silent default. Registered claims stay typed whatever generic the caller passes.

**Negative.** A breaking change after `2.0.0-alpha.0`: code that caught `JwtClaimError` or matched `ERR_JWT_CLAIM_INVALID` for option mistakes must catch `JwtOptionError`. Only alpha users are affected, and that is what the alpha is for. A forged token passed together with a wrong option now reports the option, not the signature — the caller's mistake has to be fixed either way.

**Rejected alternatives.**
- Throwing `TypeError` for option mistakes — it would break the rule that every deliberate failure is a `JwtError` with a `code`, and a `catch` that checks for `JwtError` would let it escape as a crash in production as well as in development.
- Keeping `JwtClaimError` and adding a flag — callers would have to know to check it; a separate class is what `instanceof` and `code` already handle.
- Leaving `payload: T` — a caller would have to write `JwtPayload & MyClaims` by hand every time, and most would not.
