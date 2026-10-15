---
doc_kind: product
doc_function: canonical
purpose: Ordered delivery plan for the security patch, the rewrite, and the work that follows it.
derived_from:
  - vision.md
status: active
canonical_for:
  - delivery_order
---

# Roadmap

## 1.0.4 — security patch of the existing line

**Published to npm on 2026-10-15** as `latest`, from `master` at `6bfc593`. Checked from the registry the same day: a clean install resolves `jsrsasign` 11.1.5, `npm audit` reports 0 vulnerabilities, the tarball holds the five expected files, and an HS256 token matches Node's byte for byte.

Independent of the rewrite and shippable first. `jsrsasign` `^8.0.12` resolves to 8.0.24, which `npm audit` rates critical (signature-verification bypasses among them). 11.1.5 runs the 1.0.x code unchanged — measured: encode, decode, verify, RS256, and the attack probes behave identically and `npm audit` reports 0 vulnerabilities. Raising the range protects existing callers who will not move to 2.0.0 soon. Verified before publishing on 2026-10-15: the packed 1.0.4 tarball, installed into a React Native 0.87.1 app and run as a Hermes Release build on an iOS 18.3 simulator, passed 10 of 10 checks — HS256 and RS256 tokens byte-identical to Node's, Node-signed RS256 and ES256 tokens verified, `alg: none` rejected, Unicode round-trip. Android was not run. The release also adds a `files` field — without it the memory bank would be published — a `CHANGELOG.md`, and a README note announcing 2.0.0 and the support window.

The 1.0.x line is supported with security fixes for **three months after 2.0.0 is published**, then every 1.x version is deprecated on npm and the line is closed ([ADR-004](../adr/ADR-004-break-from-v1-api.md)).

## 2.0.0 — TypeScript rewrite

Tracked as [FT-001](../features/FT-001-typescript-rewrite/feature.md); the ordered steps are in its implementation plan.

| Stage | Content | State |
|-|-|-|
| 0 | Memory bank | done |
| 1 | Package scaffold: TypeScript, ESLint, Jest, build | done |
| 1a | Crypto speed on Hermes, and the React Native floor, measured on devices ([ADR-001](../adr/ADR-001-crypto-backend.md), [ADR-005](../adr/ADR-005-host-requirements.md)) | in_progress |
| 2 | Core: base64url, JSON, token parsing, errors | done |
| 3 | Crypto backend over noble and `micro-rsa-dsa-dh` | done |
| 4 | Key import: secret, PEM, JWK; local JWKS | done |
| 5 | Synchronous `sign` / `verify` / claim validation / helpers | done |
| 6 | Interop and hostile-input test suites | done |
| 7 | `example/` app on a device, both platforms | planned |
| 8 | README, migration guide, changelog, npm release | planned |

Stages 1–6 were built on 2026-10-15 on the `release/v2.0.0` branch: `npm run verify` passes with 210 tests. Stage 1a has its numbers for an iOS simulator and a physical Android phone ([../engineering/performance.md](../engineering/performance.md)); the React Native floor is open, as are stages 7 and 8 — the remaining work is listed in [../backlog.md](../backlog.md#open-work-for-200).

## After 2.0.0

- **2.1 — remote JWKS.** Fetching an issuer's keys over the network, with caching and a refetch cooldown. Moved out of 2.0.0 on 2026-10-15: it is the only network code in the core, and keeping it out lets 2.0.0 be entirely synchronous ([ADR-002](../adr/ADR-002-synchronous-api.md)). Rules in [../domain/keys.md](../domain/keys.md#remote-jwks-deferred-to-21).
- Optional `useJwt` hook (decoded payload plus a re-render at expiry), behind a sub-path entry so React stays out of the core.
- **Hardware-backed keys — an idea, on demand only.** A private key created in the Secure Enclave or Android Keystore can sign but can never be read or copied, which is what banking-grade device binding (DPoP, RFC 9449) and biometric confirmation need. It requires native code by definition, so it would be a separate optional package plugged into the crypto backend seam, ES256 only (the one algorithm both platforms' hardware supports). Not built until a real user asks for it.

## 3.0.0

Removes the migration tombstones — the default export whose `encode`, `decode`, and `verify` throw `JwtMigrationError`. No other change is planned for it; it ships when the tombstones have done their job, not on a date.

## Not planned

JWE, OAuth flows, and secure storage — non-goals in [context.md](context.md).
