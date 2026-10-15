---
doc_kind: adr
doc_function: canonical
purpose: Record that sign and verify are synchronous, and where asynchrony is allowed.
derived_from:
  - ADR-001-crypto-backend.md
status: active
decision_status: accepted
date: 2026-10-15
---

# ADR-002 — Synchronous sign and verify

## Context

1.0.x is synchronous. The proposal before this decision made `sign` and `verify` return promises, for two reasons: a WebCrypto backend would be asynchronous, and asynchronous functions can later serve any backend while synchronous ones cannot.

[ADR-001](ADR-001-crypto-backend.md) removed the first reason: every algorithm runs in synchronous pure JavaScript, and no WebCrypto backend is planned. That also emptied the second, because the only asynchronous things left are asynchronous by nature and have their own entry points anyway:

- fetching a JWKS over the network — moved out of 2.0.0, see [../product/roadmap.md](../product/roadmap.md#after-200);
- hardware-backed keys, which wait on a biometric prompt — a separate native package, if ever built.

## Decision

The core API is synchronous: `sign`, `verify`, `decodeUnverified`, `isExpired`, `getExpiration`, and key import return values and throw named errors. Nothing in the 2.0.0 core returns a promise.

Asynchrony is allowed only where the operation itself waits on something outside the JS thread — the network or the user — and then in a separate function that ends by calling the synchronous core (for example a future `verifyWithRemoteJWKS` that loads keys, then calls `verify`).

## Consequences

**Positive.**
- A 1.0.x call keeps its shape: call, get the result. Migration changes names and options, not control flow.
- Usable anywhere: render, selectors, reducers, synchronous interceptors, `useMemo`.
- Failures are a plain `try/catch`; there is no unhandled rejection to forget.
- A clear difference from `jose`, which is asynchronous throughout.

**Negative.**
- If a future backend had to be asynchronous for the core functions themselves, it would need `signAsync`/`verifyAsync` twins. No such backend is planned.
- Callers coming from `jose` will write `await`; it is harmless on a plain value, but it is noise.

**Not a factor.** Hermes speed. Pure JavaScript inside a promise still runs on the JS thread and blocks it just the same; only moving work to another thread would help, and that is out of scope. The FT-001 stage 1a measurement therefore cannot reopen this decision, only ADR-001.

**Rejected alternative.** Asynchronous `sign`/`verify` with synchronous decoding helpers — the earlier proposal, which paid an `await` on every call for backends that no longer exist in the plan.
