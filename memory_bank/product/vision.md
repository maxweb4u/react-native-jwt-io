---
doc_kind: product
doc_function: canonical
purpose: The intended shape of the library and the trade-offs it accepts.
derived_from:
  - context.md
status: active
canonical_for:
  - product_principles
---

# Vision

The JWT library a React Native developer installs without thinking about Hermes, native modules, or which options make verification safe.

## Principles

1. **Safe defaults, no footguns.** The algorithm comes from the key, never from the token; `exp` and `nbf` are checked by default; `alg: none` is never accepted; short HMAC secrets are refused unless the caller opts in. Reading a token without verifying it has a name that says so.
2. **Runs on Hermes as installed.** No native module and no polyfill is required for the common algorithms. A faster native backend is an option, never a prerequisite.
3. **Typed contracts.** Payload types flow through generics; every error is a named class with a stable `code`.
4. **Interoperable.** Tokens produced here verify in `jose`, `jsonwebtoken`, and jwt.io, and the other way round. The test suite proves it against Node's `crypto`.
5. **Small.** The whole crypto set is about 29 KB gzip — a third of `jsrsasign` — with no X.509, CMS, or general ASN.1 toolkit riding along.

## Accepted trade-offs

- Three runtime dependencies instead of zero, because hand-written cryptography would be worse than a dependency. One of them, the RSA part, is unaudited and `0.x`. See [../adr/ADR-001-crypto-backend.md](../adr/ADR-001-crypto-backend.md).
- Pure JavaScript is slower than native code. A JWT costs one signature, so this is accepted — provided the Hermes measurement in FT-001 stage 1 confirms it.
- The 2.0.0 API breaks 1.0.x. A migration guide, tombstone exports that say what to write instead, and three months of 1.0.x security fixes make that cost explicit rather than hidden.
