---
doc_kind: adr
doc_function: canonical
purpose: Record how 2.0.0 relates to the 1.0.x API and its callers — ADR-004 restated, with the 1.x tombstones exported by name as well as on the default export.
derived_from:
  - ../product/context.md
  - ADR-002-synchronous-api.md
  - ADR-003-one-key-one-algorithm.md
status: active
decision_status: accepted
date: 2026-10-15
supersedes: ADR-004-break-from-v1-api.md
---

# ADR-006 — Break from the 1.0.x API, with named tombstones

Supersedes [ADR-004](ADR-004-break-from-v1-api.md). Everything ADR-004 decided stands; one point changes, and is marked **Changed** below.

## Context

ADR-004 kept the 1.x functions alive until 3.0 as **tombstones on the default export** — `encode`, `decode` and `verify` that throw `JwtMigrationError` with the replacement — and ruled out a named `decode` export.

Re-checking the packed `2.0.0-alpha.0` tarball in a clean project on 2026-10-15 showed where that is not enough. A default export is honoured by Metro (which compiles `src/`) and by bundlers (`lib/module`). It is not seen by:

- **CommonJS** — `const jwt = require('react-native-jwt-io')` returns the whole `exports` object; the tombstones sit under `jwt.default`.
- **A Node ESM default import** — the `node` condition resolves to `lib/commonjs`, and Node's default import of a CommonJS module is `module.exports`, not `exports.default`.

In both, 1.x code written as `jwt.encode(...)` failed with `jwt.encode is not a function`: exactly the unreadable error the tombstones exist to replace.

ADR-004's reason for "no `decode` export" was that a `decode` which **reads without verifying** would silently drop verification from every upgraded `decode(token, key)` call. A `decode` that **throws** cannot do that.

## Decision

**API.**
- 2.0.0 exports `sign`, `verify`, `decodeUnverified`, and the helpers as named exports.
- **No `decode` that decodes.** Reading without verifying is `decodeUnverified`, a name that says so.
- **No compatibility layer.** It would have to keep hex secrets and skip `exp` to be compatible, i.e. keep the defects on purpose.

**Migration tombstones — Changed.** Until 3.0.0, `encode` and `decode` are exported **by name** and also on the default export, and the default export's `verify` is a tombstone too. All of them throw `JwtMigrationError` naming the replacement and the README section. The named `verify` is the real 2.x `verify`, so 1.x `jwt.verify(token, key)` reached through `require` gets an object or a thrown error — never a silent pass. 3.0.0 removes every tombstone.

**Short HMAC secrets.** Rejected by default in `sign` and `verify`, per RFC 7518 §3.2 (32 bytes for HS256). `allowShortSecret: true` accepts them, legacy-only.

**Hex secrets.** A string is UTF-8, always. A caller whose 1.0.x secret looked like hex keeps the old signatures by passing the bytes: `verify(token, hexToBytes('deadbeef'))`.

**1.0.x support.** 1.0.4 shipped first (`jsrsasign` ^11.1.5). After 2.0.0 is published, 1.0.x receives security fixes for **three months**; then every 1.x version is deprecated on npm, pointing to 2.0.0, and the line is closed. The README states the end date at the 2.0.0 release.

## Consequences

**Positive.** Every upgraded call site fails loudly — at compile time, or on first call with a sentence — however the package is loaded. `scripts/check-build.cjs` proves it for `require` and for a Node ESM default import on every `prepack`.

**Negative.** Two deprecated names, `encode` and `decode`, appear in autocompletion until 3.0. Both are marked `@deprecated` with the replacement in their documentation.

**Rejected alternatives.**
- Keeping tombstones on the default export only (ADR-004) — leaves CommonJS and Node ESM callers with a `TypeError`.
- Pointing the `node` condition at a true ES module build — the ESM output uses extensionless imports, which Node cannot load; rewriting them is more change than the problem warrants.
- A `react-native-jwt-io/legacy` entry re-implementing 1.0.x — preserves the defects.
- Twelve months of 1.0.x support — two lines to maintain for a year for a package with one maintainer.
