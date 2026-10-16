---
title: The 1.x tombstones are invisible to require() and Node ESM default imports
doc_kind: engineering
doc_function: canonical
purpose: 'Read before changing the default export or the package exports map, or when a 1.x user reports "jwt.encode is not a function".'
derived_from:
  - ../adr/ADR-006-named-1x-tombstones.md
status: archived
---

> **Resolved** on 2026-10-15 by [ADR-006](../adr/ADR-006-named-1x-tombstones.md): `encode` and `decode` are exported by name too. Kept as the measurement behind that decision; the present tense below describes `2.0.0-alpha.0` before the fix.
# The 1.x tombstones are invisible to require() and Node ESM default imports

Measured on 2026-10-15 against the packed `2.0.0-alpha.0` tarball in a clean consumer project.

The 1.x tombstones (`encode`, `decode`, `verify` that throw `JwtMigrationError`) live on the **default export** only. That works where an ES-module default is honoured:

- Metro (`import jwt from 'react-native-jwt-io'`, compiled from `src/`) — `jwt.encode()` throws `JwtMigrationError`;
- bundlers resolving the `import` condition to `lib/module`.

It does not work in two other places:

- **CommonJS** — `const jwt = require('react-native-jwt-io')` returns the whole `exports` object; the tombstones are under `jwt.default`, so `jwt.encode` is `undefined` and 1.x code fails with `jwt.encode is not a function`.
- **Node ESM default import** — the `node` condition points at `lib/commonjs`, and Node's default import of a CommonJS module is `module.exports`, not `exports.default`. Same `undefined`.

`jwt.verify(token, key)` from 1.x code in those two places reaches the real 2.x named `verify`, which returns an object or throws — loud, not silent.

Decided the same day: named `encode` and `decode` tombstones were added — [ADR-006](../adr/ADR-006-named-1x-tombstones.md), superseding ADR-004.
