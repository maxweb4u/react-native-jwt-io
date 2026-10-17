---
doc_kind: adr
doc_function: canonical
purpose: Record why verify checks a future iat only when maxTokenAge is given, as jose does, instead of on every token.
derived_from:
  - ../domain/validation.md
status: active
decision_status: accepted
date: 2026-10-17
---

# ADR-009 — A future `iat` is checked only with `maxTokenAge`

## Context

Until the review of 2026-10-17, `verify` refused any token whose `iat` was later than `now + clockTolerance`, whether or not the caller asked about the token's age. `clockTolerance` defaults to 0. A phone's clock that is two seconds behind the issuer's therefore refused every token for its first two seconds — the moment an app receives a fresh token and verifies it. Phone clocks drift and are set by hand; the server's are not the device's.

`jose` checks a future `iat` only as part of `maxTokenAge`; `jsonwebtoken` does not check it at all. RFC 7519 §4.1.6 defines `iat` as information — the age of the token — and asks for no check of its own. Validity is bounded by `exp` and `nbf`, which `verify` checks by default.

## Decision

1. Without `maxTokenAge`, `iat` is only type-checked (a finite number within the range of a `Date`), never compared with the clock.
2. With `maxTokenAge`, `iat` is required, must not be in the future beyond `clockTolerance`, and the token must be younger than `maxTokenAge` — as before.
3. `maxTokenAge` must be at least one second: 0 would refuse every token ([ADR-008](ADR-008-option-errors.md)).
4. The README advises a `clockTolerance` of some seconds when verifying on a device.

## Consequences

**Positive.** A fresh token verifies on a device whose clock is a little behind. The behaviour matches `jose`, which callers moving from it expect.

**Negative.** A token stamped in the future is accepted when nothing asks for its age. Such a token is still bounded by its `exp`, and an issuer that wants an age limit enforced says so through `maxTokenAge`. A breaking change against `2.0.0-alpha.0`, where the check was unconditional.

**Rejected alternatives.**
- A default `clockTolerance` above 0 — it would also loosen `exp` and `nbf` for everyone, silently.
- Keeping the check and documenting it — every app verifying on a device would have to discover the same failure and the same fix.
