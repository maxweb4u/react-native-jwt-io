# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org).

## [2.0.0-rc.0] — 2026-10-17

The release candidate. From the last pass over the public API before 2.0.0;
breaking against `2.0.0-alpha.0`.

### Added

- `JwtOptionError` (`ERR_JWT_OPTION_INVALID`, with `option`): a mistake in
  the call — an unknown option, or one of the wrong type or out of range — in
  every function that takes options. An app can now tell a bug in its own
  code from a bad token.

### Changed

- Option mistakes that were `JwtClaimError` (from `sign`, `verify`,
  `isExpired`) or `JwtKeyError` (from `importPEM`, `createJWKS`) are
  `JwtOptionError`. Problems in the token or the payload stay `JwtClaimError`.
- `verify` and `isExpired` check all their options before reading the token,
  so a bad token no longer hides a mistake in them.
- The switches `ignoreExpiration`, `ignoreNotBefore`, `allowShortSecret` and
  `noTimestamp` must be booleans; `'true'` was read as false.
- `verify<T>` and `decodeUnverified<T>` return `payload: JwtPayload & T`:
  `exp`, `sub` and the other registered claims stay typed whatever `T` is.

### Documented

- Works in Expo Go and in Expo development builds, with no config plugin:
  checked with Expo SDK 58 on Android and iOS.
- A README section on when you do not need this library: `jwt-decode` for
  reading your own tokens, server-side verification, and `jose` with
  `react-native-quick-crypto` when a native module is acceptable.

### Fixed

- `createJWKS(set, { algorithm: 'RS999' })` skipped every key the option
  applied to; an unknown algorithm name is now refused.

## [2.0.0-alpha.0] — 2026-10-16

A rewrite in TypeScript with a new, synchronous API. Breaking: see
**Migrating from 1.x** in the README.

### Added

- `sign`, `verify`, `decodeUnverified`, `isExpired`, `getExpiration` — all
  synchronous; failures throw named `JwtError` subclasses with a stable `code`.
- Algorithms HS384/512, RS384/512, PS256/384/512, ES256/384/512, ES256K and
  EdDSA, besides HS256 and RS256 — in pure JavaScript on `@noble/hashes`,
  `@noble/curves` and `micro-rsa-dsa-dh`, with no native module.
- Key import: `importPEM` (SPKI, PKCS#8, PKCS#1, SEC1), `importJWK`, and
  `createJWKS` with key selection by `kid`; keys a set cannot import are
  listed in its `skipped`, and the rest still work.
- Claim validation: `exp` and `nbf` by default (`ignoreExpiration`,
  `ignoreNotBefore` skip them); `iss`, `aud`, `sub`, `typ`, `requiredClaims`,
  `maxTokenAge` on request; `clockTolerance`.
- Signing options: `expiresIn`, `notBefore`, `issuer`, `audience`, `subject`,
  `jwtId`, `keyId`, extra header parameters; `iat` by default.
- `hexToBytes`, to keep verifying 1.x tokens whose secret looked like hex.
- TypeScript types, CommonJS and ESM builds; Metro reads the TypeScript
  sources through the `react-native` export condition.
- Requires React Native 0.74 or later with Hermes, and Node 20.19+ or 22.12+
  outside React Native. Importing the library on an unsuitable engine or build
  throws `JwtHostRequirementError` naming the cause: a missing `BigInt`,
  `Object.hasOwn`, or `TextEncoder` (missing in Hermes before React Native 0.74), or a Babel
  setup that rewrites `**` into `Math.pow` (React Native 0.70's preset).

### Changed

- Every key is bound to exactly one algorithm (RFC 8725). The token's `alg`
  must equal it; a bare secret is HS256 unless `algorithm` says otherwise.
- String secrets are always UTF-8. 1.x treated hex-looking strings as hex.
- HMAC secrets shorter than the hash output are refused unless
  `allowShortSecret: true`.
- `iat` is added to signed tokens unless `noTimestamp: true`.
- Options must be a plain object, and an unknown option name is an error, in
  every function that takes options.
- Error names are string literals, so `error.name` survives minification.
- `verify`'s `algorithm` pins the token's `alg` for a key set too, and takes
  any algorithm, not only an HMAC.

### Removed

- The 1.x API. `encode` and `decode` (exported by name and on the default
  export) throw `JwtMigrationError` naming the replacement, however the package
  is loaded — `import`, `require()`, or a Node ESM default import. So does the
  default export's `verify`; through `require()` or a Node ESM default import
  `jwt.verify` is the 2.x `verify`. The tombstones are removed in 3.0.
- `jsrsasign`.

### Security

- `alg: none` is never accepted, and key material passed as a secret is
  refused — PEM, JWK and JWKS JSON, OpenSSH keys, certificates, PKCS#7, raw EC
  points and DER, as bytes or base64, base64url, hex or Latin-1 text, also
  behind `.env` escapes, JSON quotes, URL encoding, UTF-16 or base64 —
  closing RS256-to-HS256 algorithm confusion by construction.
- Base64url is decoded strictly (no padding, no foreign characters, zero
  trailing bits); `__proto__` keys are dropped from decoded JSON; unknown
  `crit` extensions are refused; RSA keys below 2048 bits are refused.
- Registered claims (`iss`, `sub`, `jti`, `aud`, `exp`, `nbf`, `iat`) and the
  header's `typ`, `cty`, `kid` are type-checked on read and write; `sign`
  checks the header and payload as serialized, so `toJSON` cannot rewrite them.
- An invalid `now`, a `clockTolerance` above a day, or a time
  claim outside the range of dates is an error, never a silently disabled
  check; time claims are compared exactly, durations computed exactly.
- `verify` and `decodeUnverified` results are deeply frozen.
- RSA keys are checked at import (2048–16384 bits, odd modulus, exponent of at
  most 33 bits, `d` in range, primes consistent when present; sizes before any
  arithmetic, so a hostile JWKS cannot make the import slow), and an RSA
  signature is verified before `sign` returns it; DER is parsed strictly (one
  encoding per OID, ordered optional fields, a PKCS#8 v2 public key that must
  be the private key's own); JWK `key_ops`, the RSASSA-PSS key OID and its
  hash parameters are honoured.
- Tested against Node's `crypto` for every algorithm in both directions, the
  Wycheproof vectors (1717 cases), 2000 fuzzed DER inputs, one regression per
  finding of three independent reviews, and a test for each mutant that once
  survived the suite.

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
