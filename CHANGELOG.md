# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org).

## [2.0.0-alpha.0] — unreleased

A rewrite in TypeScript with a new, synchronous API. Breaking: see
**Migrating from 1.x** in the README.

### Added

- `sign`, `verify`, `decodeUnverified`, `isExpired`, `getExpiration` — all
  synchronous; failures throw named `JwtError` subclasses with a stable `code`.
- Algorithms HS384/512, RS384/512, PS256/384/512, ES256/384/512, ES256K and
  EdDSA, besides HS256 and RS256 — in pure JavaScript on `@noble/hashes`,
  `@noble/curves` and `micro-rsa-dsa-dh`, with no native module.
- Key import: `importPEM` (SPKI, PKCS#8, PKCS#1, SEC1), `importJWK`, and
  `createJWKS` with key selection by `kid`.
- Claim validation: `exp` and `nbf` always; `iss`, `aud`, `sub`, `typ`,
  `requiredClaims`, `maxTokenAge` on request; `clockTolerance`.
- Signing options: `expiresIn`, `notBefore`, `issuer`, `audience`, `subject`,
  `jwtId`, `keyId`, extra header parameters; `iat` by default.
- `hexToBytes`, to keep verifying 1.x tokens whose secret looked like hex.
- TypeScript types, CommonJS and ESM builds; Metro reads the TypeScript
  sources through the `react-native` export condition.
- Requires React Native 0.71 or later with Hermes. Importing the library on an
  unsuitable engine or build throws `JwtHostRequirementError` naming the cause:
  a missing `BigInt` or `Object.hasOwn`, or a Babel setup that rewrites `**`
  into `Math.pow` (React Native 0.70's preset).

### Changed

- Every key is bound to exactly one algorithm (RFC 8725). The token's `alg`
  must equal it; a bare secret is HS256 unless `algorithm` says otherwise.
- String secrets are always UTF-8. 1.x treated hex-looking strings as hex.
- HMAC secrets shorter than the hash output are refused unless
  `allowShortSecret: true`.
- `iat` is added to signed tokens unless `noTimestamp: true`.

### Removed

- The 1.x default export. Its `encode`, `decode` and `verify` now throw
  `JwtMigrationError` naming the replacement; they are removed in 3.0.
- `jsrsasign`.

### Security

- `alg: none` is never accepted; a PEM passed as a string is refused, closing
  RS256-to-HS256 algorithm confusion by construction.
- Base64url is decoded strictly (no padding, no foreign characters, zero
  trailing bits); `__proto__` keys are dropped from decoded JSON; unknown
  `crit` extensions are refused; RSA keys below 2048 bits are refused.
- Tested against Node's `crypto` for every algorithm in both directions, the
  Wycheproof vectors (1717 cases), and 2000 corrupted DER keys.

## [1.0.4] — 2026-10-15

Security update of the 1.0.x line. The API and its behaviour are unchanged.

### Security

- `jsrsasign` raised from `^8.0.12` to `^11.1.5`. The 8.x line that `^8.0.12`
  installs carries advisories rated critical by `npm audit`, including
  signature-verification bypasses (GHSA-27fj-mc8w-j9wg, GHSA-h87q-g2wp-47pj,
  GHSA-3fvg-4v2m-98jf, GHSA-8qwj-4jxw-m8jw). 11.1.5 has none open, and
  `encode`, `decode`, and `verify` return the same results on it.

### Changed

- The published package contains only `index.js` and `src/`. Earlier versions
  had no `files` field and published everything in the repository directory.

### Notice

- 2.0.0, a TypeScript rewrite with a new API, is in development. Once it is
  published, 1.0.x receives security fixes for three months and is then
  deprecated.
