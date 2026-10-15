---
doc_kind: adr
doc_function: canonical
purpose: Record how 2.0.0 relates to the 1.0.x API, its existing callers, and how long 1.0.x is supported.
derived_from:
  - ../product/context.md
  - ADR-002-synchronous-api.md
  - ADR-003-one-key-one-algorithm.md
status: archived
decision_status: superseded
superseded_by: ADR-006-named-1x-tombstones.md
date: 2026-10-15
---

# ADR-004 — Break from the 1.0.x API

> **Superseded by [ADR-006](ADR-006-named-1x-tombstones.md)** on 2026-10-15: the 1.x tombstones are also exported by name, so `require()` and Node ESM default imports see them. Everything else here stands and is restated there.

## Context

1.0.x exports a default object with `encode(payload, key, alg)`, `decode(token, key)` (verifies, returns a `jsrsasign` parse object or `null`), and `verify(token, key)` (returns a boolean). About 12.5k downloads a month still resolve to it. Two 1.0.x behaviours cannot survive a secure 2.0.0: secrets that look like hex are used as hex (V1-4 in [../backlog.md](../backlog.md#defects-in-the-10x-line)), and secrets of any length are accepted, including the 15-byte `'your_secret_key'` of the 1.0.x README.

## Decision

**API.**
- 2.0.0 exports `sign`, `verify`, `decodeUnverified`, and the helpers as named exports.
- **No `decode` export.** Reusing the name for an unverified read would silently drop verification from every upgraded `decode(token, key)` call — the worst migration failure, because nothing breaks.
- **No compatibility layer.** It would have to keep hex secrets and skip `exp` to be compatible, i.e. keep the defects on purpose.

**Migration tombstones.** Until 3.0.0 the default export remains, as an object whose `encode`, `decode`, and `verify` throw `JwtMigrationError` naming the replacement and the README section, instead of the bare `Cannot read property 'encode' of undefined` a removed export would produce. 3.0.0 removes it.

**Short HMAC secrets.** Rejected by default in `sign` and `verify`, per RFC 7518 §3.2 (secret at least as long as the hash output: 32 bytes for HS256). `allowShortSecret: true` accepts them, documented as legacy-only — for verifying tokens from an issuer whose secret the caller does not control.

**Hex secrets.** A string is UTF-8, always. A caller whose 1.0.x secret looked like hex keeps the old signatures by passing the bytes: `verify(token, hexToBytes('deadbeef'))`. The migration guide states this.

**1.0.x support.** 1.0.4 ships first (`jsrsasign` ^11.1.5). After 2.0.0 is published, 1.0.x receives security fixes for **three months**; then every 1.x version is marked deprecated on npm with a message pointing to 2.0.0, and the line is closed. The README states the end date at the 2.0.0 release.

## Consequences

**Positive.** Every upgraded call site fails loudly — at compile time, or on first call with a message saying what to write instead — never quietly. The two incompatible behaviours each have an explicit, opt-in way to keep working.

**Negative.** Upgrading is real work, and three months is a short window for callers who pin versions. The deprecation message on npm is the backstop: installs keep working, but every install prints where to go.

**Rejected alternatives.**
- A `react-native-jwt-io/legacy` entry re-implementing 1.0.x on the new core — preserves the defects.
- Removing the default export outright — an unreadable `TypeError` in place of a migration hint.
- Twelve months of 1.0.x support — two lines to maintain for a year for a package with one maintainer.
