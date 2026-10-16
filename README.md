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
  `alg: none` is never accepted; `exp` and `nbf` are checked by default.
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

- **React Native 0.74 or later, with Hermes.** Run with 0.87.1 on an Android
  phone and an iOS simulator, Release builds. The crypto dependencies call `TextEncoder` while they load, and
  Hermes has it from React Native 0.74. On 0.71–0.73, a `TextEncoder` polyfill
  imported before this library (such as `fast-text-encoding`) is a workaround,
  not a tested setup. If the engine or the build is unsuitable, importing the
  library throws `JwtHostRequirementError` saying why — including for a Babel
  setup that rewrites `**` into `Math.pow`, which breaks BigInt arithmetic in
  Ed25519 (React Native 0.70's preset did; so does an old `@babel/preset-env` target).
- Signing with **PS256/384/512** needs `crypto.getRandomValues`, which Hermes
  lacks. Install [`react-native-get-random-values`](https://github.com/LinusU/react-native-get-random-values)
  (2.x needs React Native 0.81 or later; use 1.11 below that) and import it
  once, first in your entry file — before this library, which checks for it
  when it loads. Nothing else needs it; without it, PS* signing throws
  `JwtHostRequirementError` naming the package.
- Node 20.19+ or 22.12+ works too (CommonJS and ESM): the CommonJS build loads
  the ES-module-only crypto packages with `require()`.
- **Jest in your app:** the crypto packages are ES modules only, so let Jest
  transform them —
  `transformIgnorePatterns: ['node_modules/(?!(react-native|@react-native|@noble|micro-rsa-dsa-dh|react-native-jwt-io)/)']`.

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
types in the set are skipped. A key that cannot be imported (too short,
malformed) is skipped too and listed in `jwks.skipped` with the reason, so one
bad key does not stop the others; a token whose `kid` names it fails with that
reason.

### Sign on the device

With a key the device owns — for example an ES256 key in JWK form:

```ts
import { importJWK, sign } from 'react-native-jwt-io';

const key = importJWK(devicePrivateJwk); // ES256 is implied by the P-256 curve
const token = sign({ sub: deviceId }, key, { expiresIn: '5m', audience: 'api' });
```

`iat` is set automatically (`noTimestamp: true` turns that off; an `iat` you put
in the payload is kept either way). Times are seconds; a value that looks like
milliseconds is refused.

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

**`sign` options:** `algorithm` (which HMAC, for a bare secret; an imported key
already has one, and a different value is an error), `expiresIn`, `notBefore`,
`issuer`, `audience`, `subject`, `jwtId`, `keyId` (header `kid`; defaults to the
key's), `header` (extra parameters; not `alg`, `crit`, `b64`), `noTimestamp`,
`now`, `allowShortSecret`.

**`verify` options:** `algorithm` (the token's `alg` must be this — for a key set
too; for a bare secret it also picks the HMAC), `issuer` (one or a list),
`audience` (one or a list; any match), `subject`, `typ`, `requiredClaims`,
`maxTokenAge` (requires `iat`), `clockTolerance`, `ignoreExpiration`,
`ignoreNotBefore`, `now`, `allowShortSecret`.

Options are a plain object. An unknown option name is an error, not ignored: a
misspelled `expiresin`, or jsonwebtoken's `maxAge`, would otherwise switch
nothing on. So is a callback in place of options — nothing here takes one.

A token's `aud` is checked only when you pass `audience`. If your app accepts
tokens from an issuer that serves several audiences, pass it.

Durations are seconds or strings: `'30s'`, `'15m'`, `'2.5h'`, `'7d'`, `'1 week'`,
in whole seconds, rounded down. `clockTolerance` is at most a day: it is for
clock skew; to accept expired tokens, say so with `ignoreExpiration`.

`verify` and `decodeUnverified` return deeply frozen objects.

### Errors

Every failure is a `JwtError` subclass. Branch on `code` — it survives two copies
of the library in one bundle, where `instanceof` does not.

| Class | `code` | When |
|-|-|-|
| `JwtMalformedError` | `ERR_JWT_MALFORMED` | Not three base64url segments of JSON objects; no `alg`; longer than 65,536 characters; `crit`; JWE |
| `JwtAlgorithmError` | `ERR_JWT_ALGORITHM` | `alg` is `none`, unsupported, not the key's algorithm, or not `options.algorithm` |
| `JwtSignatureError` | `ERR_JWT_SIGNATURE_INVALID` | The signature does not verify |
| `JwtExpiredError` | `ERR_JWT_EXPIRED` | `exp` passed, or older than `maxTokenAge`; has `expiredAt` |
| `JwtNotBeforeError` | `ERR_JWT_NOT_BEFORE` | `nbf` in the future; has `notBefore` |
| `JwtClaimError` | `ERR_JWT_CLAIM_INVALID` | A claim is wrong, missing, or of the wrong type, or a `sign`/`verify` option is malformed or unknown; has `claim` |
| `JwtKeyError` | `ERR_JWT_KEY_INVALID` | A key cannot be imported or used — including a public key passed as a secret, or a token whose `kid` names a key the JWKS could not import |
| `JwtKeyNotFoundError` | `ERR_JWT_KEY_NOT_FOUND` | No key in the JWKS for the token's `kid` — or, without a `kid`, not exactly one for its `alg`; has `kid` |
| `JwtHostRequirementError` | `ERR_JWT_HOST_REQUIREMENT` | The engine lacks a feature; has `feature` |
| `JwtMigrationError` | `ERR_JWT_MIGRATION` | A 1.x function was called |

Checks run in this order and stop at the first failure: option names, shape
(including the types of the registered claims), algorithm and header extensions,
key, signature, then claim values and the claim options' values (`clockTolerance`,
`issuer`, …) — so claim values are never evaluated for an unsigned token.

Error names are set as strings, so `error.name` reads `JwtExpiredError` in a
minified release build too.

ECDSA signatures are malleable: every ES* token has a second valid encoding of
its signature, and both verify. Do not deduplicate or revoke ES* tokens by their
string or hash; use a `jti`.

## Performance

Measured on a mid-range Android phone (Realme RMX3363, 2021), Release build:

| | verify | sign |
|-|-|-|
| HS256 | 0.9 ms | 0.8 ms |
| RS256 / PS256 | 7.5 ms | 0.9 s (RS) |
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

- **The 1.x functions throw.** `jwt.encode` and `jwt.decode` throw
  `JwtMigrationError` with the replacement in the message, until 3.0 — whether
  you `import jwt from`, `require()`, or import from Node ESM. So does
  `jwt.verify` where `jwt` is the default export (`import jwt from` under Metro or
  a bundler). Through `require()` or a Node ESM default import, `jwt.verify` is
  the 2.x `verify`: it returns `{ header, payload }` or throws — never `true`.
- **`decode` does not decode.** In 1.x it verified; a 2.x `decode` that did not
  would silently drop a security check from your code, so it only throws. Use
  `verify`, or `decodeUnverified` to read without checking.
- **`exp` and `nbf` are now enforced.** 1.x accepted expired tokens.
- **Short secrets are refused.** HS256 needs 32 bytes. If you cannot change the
  issuer's secret, pass `allowShortSecret: true` to `sign` and `verify`.
- **Secrets that look like hex.** 1.x (through `jsrsasign`) treated a string
  secret such as `'deadbeef'` as hex bytes, so its tokens matched no other
  library. 2.x reads every string as UTF-8. To keep verifying old tokens, pass the
  bytes: `verify(token, hexToBytes('deadbeef'), { allowShortSecret: true })`.
- **Public keys must be imported.** A key passed as a string or bytes is
  refused, because a string is an HMAC secret — the precondition of the
  RS256→HS256 forgery. That covers a PEM (any case, any preamble), a JWK or JWKS
  as JSON, an OpenSSH public key, a certificate, a raw EC point, and DER — as
  bytes or as base64, base64url or hex text, the way servers show their public
  key (Keycloak's `public_key`) — also inside `.env` escapes, JSON quotes or
  another layer of base64 (Kubernetes secrets). A bare RSA modulus or EC
  coordinate cannot be told from a secret; do not configure one as one.
- **`iat` is added** to signed tokens unless `noTimestamp: true`.

## License

MIT
