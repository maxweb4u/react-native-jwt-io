---
doc_kind: product
doc_function: canonical
purpose: Who the library serves, the problem it solves, and its explicit non-goals.
derived_from:
  - ../dna/principles.md
status: active
canonical_for:
  - target_audience
  - product_scope
  - product_non_goals
---

# Product Context

## Who this is for

React Native applications that handle JWTs on the device. The package has been on npm since 2017 and still sees about 12.5k downloads a month (npm, 2026-09-13 → 2026-10-12), so existing callers of the 1.0.x API are part of the audience, not only new ones.

## Use cases, in order of how common they are

1. **Read an access token the server issued** — user id, roles, `exp` — to decide when to refresh. No verification is possible or needed: the device does not hold the server's secret.
2. **Verify a token signed by someone else** with a public key or a JWKS — deep links, QR codes, offline licences, tokens relayed between devices.
3. **Sign a token with an asymmetric key the device owns** — device attestation, request signing, App Store Connect / MusicKit style ES256 tokens.
4. **Sign or verify with a shared HMAC secret** — tests, local tooling, and legacy callers. The library supports it and the README warns that a secret shipped inside an app bundle is not a secret.

## Problem

Node JWT libraries (`jsonwebtoken`) depend on Node's `crypto` and do not run on Hermes. `jose` needs WebCrypto, which Hermes does not ship, so it requires a native module. `jwt-decode` only decodes. The 1.0.x line of this package works on Hermes but pulls in `jsrsasign` 8, which `npm audit` rates critical, returns an internal parser object instead of the payload, and checks no claims at all — see [../backlog.md](../backlog.md#defects-in-the-10x-line).

## What the library provides

1. `sign`, `verify`, and an explicitly unverified decode, typed end to end.
2. Claim validation (`exp`, `nbf`, `iat`, `iss`, `aud`, `sub`, `typ`, max age) with clock tolerance.
3. HS, RS, PS, ES, and EdDSA algorithms, working on Hermes with no native module.
4. Key import from a string secret, bytes, PEM, and JWK; JWKS lookup by `kid`.
5. Small expiry helpers for refresh logic.

## Non-goals

- **No JWE.** Encrypted tokens are a different threat model and a much larger surface. Revisit only on demand.
- **No auth flows.** OAuth, PKCE, refresh orchestration, and token storage stay with the host or with dedicated libraries.
- **No secure storage.** Keychain / Keystore belongs to native modules the host already uses.
- **Not a general crypto toolkit.** No X.509, CSR, or certificate chains — the reason `jsrsasign` is 340 KB minified.
