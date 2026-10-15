# react-native-jwt-io

Sign, verify and decode JSON Web Tokens in React Native — on the device, in
pure TypeScript. No native module, no server, no polyfills for the common
algorithms.

```ts
import { verify } from 'react-native-jwt-io';

const { payload } = verify(token, publicKey); // throws if the signature, exp or nbf is wrong
```

- **Synchronous.** Every call returns its result or throws; nothing returns a promise.
- **Safe by default.** The algorithm comes from your key, never from the token;
  `alg: none` is never accepted; `exp` and `nbf` are always checked.
- **14 algorithms** — HS256/384/512, RS256/384/512, PS256/384/512,
  ES256/384/512, ES256K, EdDSA — on Hermes, tested against Node's `crypto` and
  the [Wycheproof](https://github.com/C2SP/wycheproof) vectors.
- **Typed.** Payload generics, and named errors with a stable `code`.

> **2.0 is a rewrite with a new API.** Coming from 1.x? See
> [Migrating from 1.x](#migrating-from-1x). The 1.x line receives security
> fixes for three months after 2.0.0 is published, then it is deprecated.

## Installation

```sh
npm install react-native-jwt-io
```

Requirements:

- **React Native 0.71 or later, with Hermes.** Run on devices with 0.87.1 (iOS
  and Android); 0.71 is confirmed by running the self-test in Hermes v0.12 with
  React Native 0.71's Babel preset. React Native 0.70 does not work: its Babel
  preset rewrites `**` into `Math.pow`, which breaks BigInt arithmetic in Ed25519.
  If the engine or the build is unsuitable, importing the library throws
  `JwtHostRequirementError` saying why — including for a custom Babel setup that
  rewrites `**` (an old `@babel/preset-env` target does).
- Signing with **PS256/384/512** needs `crypto.getRandomValues`, which Hermes
  lacks. Install [`react-native-get-random-values`](https://github.com/LinusU/react-native-get-random-values)
  and import it once, before this library. Nothing else needs it.
- Node ≥ 20.19 works too (CommonJS and ESM).

## Usage

### Read a token from your server

The device usually cannot verify the server's tokens — it does not hold the key —
but it can read them, for example to refresh before expiry:

```ts
import { decodeUnverified, isExpired, getExpiration } from 'react-native-jwt-io';

const { payload } = decodeUnverified<{ sub: string; roles: string[] }>(accessToken);
if (isExpired(accessToken, { clockTolerance: '30s' })) {
  await refresh();
}
const expiresAt = getExpiration(accessToken); // Date | null
```

None of these check the signature. Use them for display and scheduling, never to
decide who the user is.

### Verify with a public key

```ts
import { importPEM, verify } from 'react-native-jwt-io';

const key = importPEM(PUBLIC_KEY_PEM, 'RS256'); // a key is bound to exactly one algorithm

const { header, payload } = verify<{ sub: string }>(token, key, {
  issuer: 'https://auth.example.com',
  audience: 'my-app',
  clockTolerance: 30, // seconds, or '30s'
});
```

### Verify with a JWKS

Load the issuer's key set however you like, then:

```ts
import { createJWKS, verify } from 'react-native-jwt-io';

const jwks = createJWKS(await (await fetch(JWKS_URL)).json());
const { payload } = verify(token, jwks); // the key is chosen by the token's kid
```

Keys published without `alg` (some issuers do this for RSA) need it said once:
`createJWKS(json, { algorithm: 'RS256' })`. Encryption keys and unsupported key
types in the set are skipped.

### Sign on the device

With a key the device owns — for example an ES256 key in JWK form:

```ts
import { importJWK, sign } from 'react-native-jwt-io';

const key = importJWK(devicePrivateJwk); // ES256 is implied by the P-256 curve
const token = sign({ sub: deviceId }, key, { expiresIn: '5m', audience: 'api' });
```

`iat` is set automatically (`noTimestamp: true` turns that off). Times are
seconds; a value that looks like milliseconds is refused.

### HMAC secrets

A string or `Uint8Array` key is an HMAC secret, `HS256` unless you pass
`algorithm`. It must be at least as long as the hash (32 bytes for HS256,
RFC 7518 §3.2).

```ts
const token = sign({ sub: 'u1' }, SECRET, { expiresIn: '1h' });
const { payload } = verify(token, SECRET);
const strong = sign({ sub: 'u1' }, SECRET_64_BYTES, { algorithm: 'HS512' });
```

> A secret shipped inside an app bundle is not a secret: anyone can unpack the app
> and read it. Use HMAC for tests and tooling, or with a secret the device received
> at runtime — not to mint tokens your server trusts.

## API

| Function | Returns |
|-|-|
| `sign(payload, key, options?)` | `string` |
| `verify<T>(token, key \| jwks, options?)` | `{ header, payload: T }` — or throws |
| `decodeUnverified<T>(token)` | `{ header, payload: T }`, signature **not** checked |
| `isExpired(token, { clockTolerance?, now? }?)` | `boolean`; no `exp` means never |
| `getExpiration(token)` | `Date \| null` |
| `importPEM(pem, algorithm, { kid? }?)` | `JwtKey` — SPKI, PKCS#8, PKCS#1 (`RSA … KEY`), SEC1 (`EC PRIVATE KEY`) |
| `importJWK(jwk, algorithm?)` | `JwtKey` — `RSA`, `EC`, `OKP` (Ed25519), `oct` |
| `createJWKS({ keys }, { algorithm? }?)` | `JwtKeySet` |
| `hexToBytes(hex)` | `Uint8Array` |

**`sign` options:** `algorithm` (bare secrets only), `expiresIn`, `notBefore`,
`issuer`, `audience`, `subject`, `jwtId`, `keyId` (header `kid`; defaults to the
key's), `header` (extra parameters; not `alg`, `crit`, `b64`), `noTimestamp`,
`now`, `allowShortSecret`.

**`verify` options:** `algorithm` (bare secrets only), `issuer` (one or a list),
`audience` (one or a list; any match), `subject`, `typ`, `requiredClaims`,
`maxTokenAge` (requires `iat`), `clockTolerance`, `ignoreExpiration`,
`ignoreNotBefore`, `now`, `allowShortSecret`.

Durations are seconds or strings: `'30s'`, `'15m'`, `'2h'`, `'7d'`, `'1 week'`.

### Errors

Every failure is a `JwtError` subclass. Branch on `code` — it survives two copies
of the library in one bundle, where `instanceof` does not.

| Class | `code` | When |
|-|-|-|
| `JwtMalformedError` | `ERR_JWT_MALFORMED` | Not three base64url segments of JSON objects; `crit`; JWE |
| `JwtAlgorithmError` | `ERR_JWT_ALGORITHM` | `alg` is `none`, unsupported, or not the key's algorithm |
| `JwtSignatureError` | `ERR_JWT_SIGNATURE_INVALID` | The signature does not verify |
| `JwtExpiredError` | `ERR_JWT_EXPIRED` | `exp` passed, or older than `maxTokenAge`; has `expiredAt` |
| `JwtNotBeforeError` | `ERR_JWT_NOT_BEFORE` | `nbf` in the future; has `notBefore` |
| `JwtClaimError` | `ERR_JWT_CLAIM_INVALID` | A claim is wrong or missing; has `claim` |
| `JwtKeyError` | `ERR_JWT_KEY_INVALID` | A key cannot be imported or used — including a PEM passed as a string |
| `JwtKeyNotFoundError` | `ERR_JWT_KEY_NOT_FOUND` | No key in the JWKS for the token's `kid`; has `kid` |
| `JwtHostRequirementError` | `ERR_JWT_HOST_REQUIREMENT` | The engine lacks a feature; has `feature` |
| `JwtMigrationError` | `ERR_JWT_MIGRATION` | A 1.x function was called |

Checks run in this order and stop at the first failure: shape, algorithm,
signature, then claims — so claims are never evaluated for an unsigned token.

## Performance

Measured on a mid-range Android phone (Realme RMX3363, 2021), Release build:

| | verify | sign |
|-|-|-|
| HS256 | 0.9 ms | 0.8 ms |
| RS256 / PS256 | 7.5 ms | 0.8 s (RS) |
| ES256 | 60 ms | 14 ms |
| EdDSA | 30 ms | 9 ms |

ES384/ES512 verification takes 150–320 ms on the same phone. Every call runs on
the JS thread; keep the slow ones out of render paths. ES256 verification is about
50× faster than 1.x.

## Migrating from 1.x

| 1.x | 2.x |
|-|-|
| `import jwt from 'react-native-jwt-io'` | `import { sign, verify, decodeUnverified } from 'react-native-jwt-io'` |
| `jwt.encode(payload, secret)` | `sign(payload, secret)` |
| `jwt.encode(payload, privatePem, 'RS256')` | `sign(payload, importPEM(privatePem, 'RS256'))` |
| `jwt.verify(token, key)` → `true`/`false` | `verify(token, key)` → `{ header, payload }`, or throws |
| `jwt.decode(token, key)` → `{ payloadObj, … }` or `null` | `verify(token, key).payload` |
| reading claims without a key | `decodeUnverified(token).payload` |
| `jwt.verify(token, publicPem)` | `verify(token, importPEM(publicPem, 'RS256'))` |

What else changes:

- **The default export throws.** `jwt.encode`, `jwt.decode` and `jwt.verify` throw
  `JwtMigrationError` with the replacement in the message, until 3.0.
- **There is no `decode`.** In 1.x it verified; a 2.x `decode` that did not would
  silently drop a security check from your code.
- **`exp` and `nbf` are now enforced.** 1.x accepted expired tokens.
- **Short secrets are refused.** HS256 needs 32 bytes. If you cannot change the
  issuer's secret, pass `allowShortSecret: true` to `sign` and `verify`.
- **Secrets that look like hex.** 1.x (through `jsrsasign`) treated a string
  secret such as `'deadbeef'` as hex bytes, so its tokens matched no other
  library. 2.x reads every string as UTF-8. To keep verifying old tokens, pass the
  bytes: `verify(token, hexToBytes('deadbeef'), { allowShortSecret: true })`.
- **Public keys must be imported.** A PEM passed as a string is refused, because a
  string is an HMAC secret — the precondition of the RS256→HS256 forgery.
- **`iat` is added** to signed tokens unless `noTimestamp: true`.

## License

MIT
