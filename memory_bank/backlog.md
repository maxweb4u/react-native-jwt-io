---
doc_kind: project
doc_function: canonical
purpose: Open decisions waiting on the maintainer, and the known defects of the 1.0.x line.
derived_from:
  - product/roadmap.md
status: active
audience: humans_and_agents
canonical_for:
  - open_work_items
  - v1_defects
---

# Backlog

## Open decisions

Each blocks part of [FT-001](features/FT-001-typescript-rewrite/feature.md). The ADR holds the proposal and its alternatives.

Nothing is open.

## Open work for 2.0.0

What stands between the built code (stages 1–6, 2026-10-15) and the release.

| ID | Item |
|-|-|
| W-1 | ~~Android on Hermes~~ — done 2026-10-15 on a Realme RMX3363 (Android 13): 11/11 in a scratch app, before `example/` existed; numbers in [engineering/performance.md](engineering/performance.md). |
| W-2 | ~~The React Native floor~~ — done 2026-10-15, corrected 2026-10-16: **0.74**, because noble calls `TextEncoder` at load and Hermes has it from 0.74 ([ADR-007](adr/ADR-007-host-requirements-text-encoder.md)). The first measurement said 0.71: Hermes' sources put `Object.hasOwn` at the RN 0.69 tag and `BigInt` at 0.70; running the self-test in the official Hermes v0.12.0 CLI (August 2022) then showed that RN 0.70 still fails — its Babel preset (`metro-react-native-babel-preset` 0.72) rewrites `**` into `Math.pow`, and `@noble/curves` raises a BigInt to a power on the Ed25519 path. With RN 0.71's preset (0.73.5) all 12 checks passed, from source and from bytecode — but from an esbuild bundle, which had tree-shaken the `TextEncoder` calls away. `hostCheck` detects the `**` rewrite and a missing `TextEncoder` at import. Details in [engineering/gotchas.md](engineering/gotchas.md). |
| W-3 | ~~Wycheproof vectors~~ — done 2026-10-15: 1717 vectors across HS256, RS256, PS256, ES256/384/512, ES256K and EdDSA, through `importPEM` and the crypto module; all pass. |
| W-4 | ~~`example/` app~~ — done 2026-10-15: React Native 0.87.1, library from source; Self-test 12/12 on an iOS 18.3 simulator and on the Realme RMX3363 (Release builds). After the reviews of 2026-10-16 the self-test has 14 checks: 14/14 on the Realme RMX3363 and the iOS 18.3 simulator, Release builds, after each round. With `react-native-get-random-values` added (15 checks, PS256/384/512 signing on the device for the first time): 15/15 on both. |
| W-5 | ~~README, migration guide, CHANGELOG~~ — done 2026-10-15; the README's examples run as `src/__tests__/readme.test.ts`. What remains of stage 8 is the release itself. |
| W-6 | **Hot paths.** On a mid-range phone ES256 verification takes 60 ms, ES384/ES512 148/319 ms, RSA signing 0.8 s, all on the JS thread; try noble's per-key `Point.precompute` before anything native. Not a release blocker. |
| W-7 | ~~Expo Go~~ — done 2026-10-16: the packed library runs in Expo Go unchanged — 16/16 with Expo SDK 58 (React Native 0.88) on the Realme RMX3363 (development and minified bundles; random values from `react-native-get-random-values`, which Expo Go includes, or from `expo-crypto`) and on an iOS 27 simulator. No code change was needed; the README says so under Installation. How to repeat it: [engineering/testing-policy.md](engineering/testing-policy.md). It answers "why not `jose` with `react-native-quick-crypto`?" — that pair is faster, but it is a native module, which Expo Go cannot load. |
| W-8 | ~~"When you do not need this library"~~ — done 2026-10-17: a README section after Performance — `jwt-decode` for reading your own tokens, no device-side verification of a token your own server checks, `jose` with `react-native-quick-crypto` when a native module is acceptable and speed matters; then what this library is for. |
| W-9 | **Remote JWKS** — the 2.1 feature ([product/roadmap.md](product/roadmap.md#after-200)), raised again on 2026-10-16 as the most common on-device need: verifying tokens from a provider (Auth0, Keycloak, Firebase) against its JWKS. Today the caller fetches the key set and passes it to `createJWKS`. Not a 2.0.0 blocker. |
| W-10 | **`alg: "Ed25519"` (RFC 9864)** — accept the fully-specified name besides `EdDSA`, in tokens and JWKs, and decide how a key bound to one relates to the other ([ADR-003](adr/ADR-003-one-key-one-algorithm.md)). Until then such a JWK is listed in `skipped` with the reason. Found by the review of 2026-10-17; for 2.1, additive. |

## Review of 2026-10-15

An independent review of `src/` (a separate agent, adversarial, read-only) found no way to get a forged or unsigned token accepted, no algorithm confusion, and no key-binding bypass. It did find the defects below. Each fix has a regression test in `src/__tests__/review.test.ts`, numbered like this table.

| # | Finding | Severity | Outcome |
|-|-|-|-|
| 1 | `now: new Date('x')` made every time comparison false: an expired token verified, `isExpired` said false, `sign` wrote `"exp":null` | medium, fail-open | `now` must be a valid Date, else `JwtClaimError` |
| 2 | A string `clockTolerance` such as `'9…9s'` parsed to Infinity and disabled `exp` | low, fail-open | durations must be finite |
| 3 | `now` was floored to the second: a fractional `exp` lived up to a second too long; a fresh fractional `iat` read as "issued in the future" | low | compared exactly |
| 4 | With a JWKS, `options.algorithm` was ignored | low | it constrains key sets too |
| 5 | Two keys with the same `kid` and `alg`: the first was used | low | ambiguity is `JwtKeyNotFoundError` |
| 6 | Even RSA moduli, `d` out of range, and private keys mixed from two keys were accepted; a bad `d` made signing throw a plain `Error` | low | checked at import (primes when present); signing failures become `JwtKeyError` |
| 7 | `importPEM(…, { kid: 5 })` was accepted | low | `kid` must be a string |
| 8 | `null` options, `audience: null`, `hexToBytes('zz')` threw plain `TypeError`s | low | treated as no options / `JwtError`s |
| 9 | Registered claims and header fields were typed but not checked (`sub` could be an object) | low | enforced on read and write |
| 10 | A `toJSON` on the header or payload could change what was signed (even `alg`) | nit | validated as serialized |
| 11 | DER: trailing nodes, non-minimal lengths and integers, unchecked algorithm parameters, multi-byte first OID arc | nit | strict |
| 12 | JWK `key_ops` ignored | nit | honoured |
| 13 | A key with the RSASSA-PSS OID could be bound to RS256 | nit | PS* only |
| 14 | ECDSA signatures are malleable (high-S accepted on purpose) | nit | documented in [domain/algorithms.md](domain/algorithms.md) and the README |
| 15 | `header`/`payload` and the exported constants were not frozen | nit | frozen |
| 16 | `expiresIn: 1e300` produced `exp: 1e300` | nit | computed times are checked too |

Not changed: PEM text without its BEGIN/END lines still reads as an HMAC secret — indistinguishable from a secret without guessing. A PEM inside a `Uint8Array` is now refused (anywhere in it since the second review, #2 below), and so is a JWK as JSON text.

### Resolved: 1.x tombstones under `require` and Node ESM

Found while re-checking the packed tarball: the tombstones lived on the default export only, so `require('react-native-jwt-io').encode` and a Node ESM default import got `undefined` and failed with `jwt.encode is not a function` instead of `JwtMigrationError`. Decided on 2026-10-15: `encode` and `decode` are also exported by name, as throwing tombstones — [ADR-006](adr/ADR-006-named-1x-tombstones.md), superseding ADR-004. `scripts/check-build.cjs` checks both loading paths on every `prepack`. The measurement is in ADR-006's context.

## Review of 2026-10-16

Five independent passes over the code (separate agents, read-only, each with its own area: signatures, untrusted-input parsing, claims and time, API and packaging, tests and Hermes), every finding reproduced before it was reported and again before it was fixed. One forgery path (#2) and one false support claim (#1). Each fix has a regression test, in `src/__tests__/review2.test.ts` (numbered like this table) unless it says otherwise.

| # | Finding | Severity | Outcome |
|-|-|-|-|
| 1 | noble calls `new TextEncoder()` while it loads; Hermes has it from React Native 0.74, so on 0.71–0.73 the import failed with a `ReferenceError`. The 0.71 floor came from an esbuild bundle that tree-shook the calls | high, false support claim | floor 0.74, `hostCheck` names `TextEncoder` ([ADR-007](adr/ADR-007-host-requirements-text-encoder.md)); `host.test.ts` |
| 2 | A PEM in a `Uint8Array` was looked for in the first 64 bytes only: after an `openssl pkcs12` "Bag Attributes" preamble a public key became an HMAC secret, and a forged HS256 token verified | high, forgery | the whole input is checked; a JWK as JSON text is refused too |
| 3 | `exp`/`nbf` beyond the `Date` range made `verify` throw a `RangeError`, `getExpiration` return an Invalid Date | medium | `JwtClaimError` beyond ±8.64e12 |
| 4 | A huge but finite `clockTolerance` (`1e300`, `'9…9w'`) switched `exp` off; review #1's #2 test passed only because of the length limit | medium, fail-open (caller) | durations at most `1e11` s; test rewritten in `review.test.ts` |
| 5 | Fractional durations lost a second to floating point (`'2.05m'` → 122) | low | integer arithmetic |
| 6 | `createJWKS(jwks, null)` threw a `TypeError` | low | `null` is no options |
| 7 | `options.header` could set a non-string `kid`/`typ`/`cty`: `sign` issued a token its own `verify` refused | low | refused at signing |
| 8 | RSA keys above 16384 bits or with an exponent above 256 bits imported, then every verification failed as "invalid signature" | low | refused at import, with the reason |
| 9 | An RSA JWK with a foreign odd `d` and no primes signed tokens nobody could verify | low | `sign` verifies its RSA signature |
| 10 | PKCS#8 v2: the embedded public key was not compared for EC and RSA, and for Ed25519 the comparison was skipped when it had unused bits or was empty | low | strict, compared for every key type |
| 11 | RSASSA-PSS parameters were not read: garbage was accepted, and a key restricted to SHA-512 imported as PS256 | low | parsed; hash, MGF1, salt and trailer enforced |
| 12 | OIDs with `0x80`-padded subidentifiers decoded like minimal ones | nit | refused |
| 13 | SEC1 `[1]` before `[0]`, or either twice, was accepted | nit | ordered, at most once |
| 14 | A JWK `crv` array passed the curve filter and then failed with a meaningless message | nit | `crv` must be a string |
| 15 | Two PEM blocks were reported as "not valid base64" | nit | "not a single PEM block" |
| 16 | `verify`'s `algorithm` was typed HMAC-only, though documented to pin key sets; with a set, a mismatch was reported as `JwtKeyNotFoundError` | inaccuracy | typed `Algorithm`, checked before the set is searched |
| 17 | `sign` refused interface-typed payloads at compile time | improvement | `payload: object` |
| 18 | Unknown options were ignored: `expiresin` issued a token without `exp`, jsonwebtoken's `maxAge` skipped the age check | improvement, fail-open (caller) | unknown names are errors, with hints |
| 19 | Results were frozen one level deep: a verified `aud` array could be edited | improvement | deeply frozen |
| 20 | `subject: 5` was reported as a mismatch, not a caller error | nit | type-checked |
| 21 | `typ` normalization stripped `application/` instead of adding it to values without `/` (RFC 7515 §4.1.9) | nit | per the RFC |
| 22 | `noTimestamp` was documented as "omit `iat`" but keeps a payload `iat` | inaccuracy | documented |
| 23 | Checks that could be deleted with every test green: seven at import (Ed25519 strict decoding, Ed25519 `d`≠`x`, SEC1 public-key mismatch, scalar range, short-scalar padding, RSA exponent, negative INTEGER), and two elsewhere (bare secret with RS256, low-S signing) | test gap | tests added |
| 24 | Three tests passed for another reason than their name: the PKCS#8 trailing-data test (its hand-built DER broke on the length), the "oversized" token (it was not JSON either), and #2 above | test gap | rewritten; DER built with the `tlv` helper |
| 25 | The `example/` self-test passed on any engine, and a verifier that always said "valid" would have passed it | test gap | Engine must be Hermes; Node-identical tokens for HS256/RS256/EdDSA; every tampered signature refused, `instanceof` intact |
| 26 | `maxTokenAge` accepted a token at exactly `iat + maxTokenAge`, while `exp` rejects at equality | nit | the same exclusive bound; `claims.test.ts` |
| 27 | No `LICENSE` file, though the package says MIT; the release checklist would have published `2.0.0-alpha.0` as `latest` | release blocker | `LICENSE` added; prereleases go out with `--tag next` ([ops/release.md](ops/release.md)); no test — `npm pack --dry-run` in the checklist shows it |
| 28 | `engines` admitted Node 21 and 22.0–22.11, where `require(esm)` is behind a flag; `exports` had no `default`; `check-build` never looked at `lib/module` or `lib/typescript` | low | `^20.19.0 \|\| >=22.12.0`; `default` added; both checked by `scripts/check-build.cjs` |
| 29 | Docs that did not match the code: README/CHANGELOG said the default export's `verify` throws however loaded; "`exp` and `nbf` always checked"; a missing `alg` documented as `JwtAlgorithmError`; the order of checks in validation.md; "`0n` literals" in gotchas; the 3.0 roadmap entry; the `JwtKeyNotFoundError` row; no word on Jest's `transformIgnorePatterns` | inaccuracy | corrected. ADR-006's hex-secret example also lacks `{ allowShortSecret: true }` — the README form is the correct one; ADRs are not edited |

## Review of 2026-10-16, second round

Five more passes the same day, over the code as fixed by the first round: regressions in the fixes, black-box attacks through the public API, what runs at load under Metro and Hermes 0.74 (with a real Metro bundle of `example/`), documentation against code, and mutation testing (131 mutants). No forged signature got through in more than sixty attempts; key material in a form other than canonical PEM did (#1). Regressions in `src/__tests__/review3.test.ts`, numbered like this table; mutation survivors in `mutation.test.ts`.

| # | Finding | Severity | Outcome |
|-|-|-|-|
| 1 | A public key not in canonical PEM was an HMAC secret, and a forged HS256 token verified: bare base64 SPKI (Keycloak's `public_key`), base64url, hex, DER bytes, `ssh-rsa`/`ssh-ed25519`, armor in lower case or with spaces, a certificate, JWK JSON with an escaped `"kty"` | high, forgery | all refused ([domain/keys.md](domain/keys.md#inputs)); a bare RSA modulus cannot be told from a secret and is documented as such |
| 2 | In a release build every error's `name` was `"u"`: Metro's minifier renames classes and `name` came from `new.target.name` | medium | names are string literals on the prototypes; the device self-test checks `name` |
| 3 | `clockTolerance` up to `1e11` seconds (3,170 years) still switched `exp` off | medium, fail-open (caller) | at most a day |
| 4 | Bytes to BigInt was quadratic, and RSA sizes were checked after the conversion: a 48 KB JWK field cost half a second | medium, DoS from a hostile JWKS | linear conversion; sizes checked first (JWK fields, DER INTEGERs) |
| 5 | An RSA exponent up to 2^256 made every verification 45 times slower | low, DoS | at most 33 bits |
| 6 | One unusable key failed the whole `createJWKS`, so the issuer's good keys stopped working too | low, availability | left out and listed in `skipped`; a token whose `kid` names one gets `JwtKeyError` with the reason |
| 7 | A function, string, `Map` or class instance as options read as "no options"; options inherited through a prototype applied unchecked | low, fail-open (caller) | options must be a plain object with own, known names |
| 8 | `crv: 1n`, a circular `crv`, or `algorithm: Object.create(null)` made the error message itself throw a `TypeError` | nit | `describeValue` never throws |
| 9 | Forty mutants of security checks survived the suite (among them `equalBytes` without its length check, base64url without `length % 4 === 1`, `audience` with no `aud` in the token, the 2048-bit floor, the PS* self-check) | test gap | a test each, in `mutation.test.ts`; method in [engineering/testing-policy.md](engineering/testing-policy.md#mutation-testing) |
| 10 | Documentation: the order of checks (option values are checked with the claims, after the signature), step 4 missing `JwtKeyError`, "every algorithm" for a self-test that covers each key family and curve, "2000 corrupted" DER keys (two thirds are), `use` "must be" `sig`, SC-17 wording, "run on devices" for an iOS simulator, coverage numbers that move by 0.1 between runs; ADR-007 did not mention `inlineRequires` (curves load lazily under Metro's default config) or the x25519 `**` at load | inaccuracy | corrected; ADR-007 was not yet committed, so it was corrected in place |

## Review of 2026-10-16, third pass

Two targeted passes over the second round's code, and the device gap it left. Regressions in `src/__tests__/review3.test.ts` (#1b) and `mutation2.test.ts`.

| # | Finding | Severity | Outcome |
|-|-|-|-|
| 1 | Key material behind one more wrapper was still an HMAC secret, in 250 of 425 forms tried across six key types: base64 of the PEM text (Kubernetes secrets, CI variables), a raw EC point (WebCrypto `raw`, VAPID), `.env`-style literal `\n`, JSON quotes, hex with `0x` or colons, SSH blobs and authorized_keys options, PKCS#7, BOMs and UTF-16, URL encoding | high, forgery | `src/keys/keyMaterial.ts` unwraps them; 52 forms remain, all indistinguishable from random bytes, written by no tool, or private-key containers ([domain/keys.md](domain/keys.md#inputs)); 0 false refusals in 520,000 generated secrets |
| 2 | `-{3,}[ \t]*BEGIN` was quadratic: 64 KB of dashes took 7 seconds, on every `sign`/`verify` with that secret | low, DoS (caller) | `-{3}`, linear; a test times it |
| 3 | `{"keys": [...]}` anywhere in a secret made it "a JWK" — a JSON list of rotating secrets was refused; `[[…]]` too, through the inherited `Array.prototype.keys` | low, false refusal | JSON counts only when it carries key members (`kty`, `n`+`e`, `crv`+`x`) |
| 4 | 46 mutants of the second round's code survived (among them OpenSSH variants, upper-case hex DER, PKCS#1 and SEC1 private DER, the 4096-byte chunk boundary, the error-name descriptor, JWKS `skipped` details) | test gap | a test each in `mutation2.test.ts`; 5 equivalent, described in [engineering/testing-policy.md](engineering/testing-policy.md#mutation-testing) |
| 5 | PS256/384/512 signing had never run on a device: `example/` had no random source | test gap | `react-native-get-random-values` in `example/`, imported first; a "PS* signing" check (15 checks); 15/15 on the Realme RMX3363 and the iOS simulator |
| 6 | The README did not say that `react-native-get-random-values` 2.x needs React Native 0.81 | inaccuracy | 1.11 below that, said in the README |

## API review before 2.0.0

The last pass over the public surface (`src/index.ts`, the option types, the error classes, `package.json` `exports`) on 2026-10-16, after `2.0.0-alpha.0`, looking for what cannot change after 2.0.0 without a major release. Regressions in `src/__tests__/apiFreeze.test.ts`; the decision is [ADR-008](adr/ADR-008-option-errors.md). The `example/` self-test gained a check that an option mistake is a `JwtOptionError` with its name intact, for a tampered token too: 16/16 on the Realme RMX3363 (Android 13) and the iOS 18.3 simulator, Release builds.

| # | Finding | Outcome |
|-|-|-|
| 1 | A mistake in the options was a `JwtClaimError` (or a `JwtKeyError` from `importPEM` and `createJWKS`): an app that signs the user out on any `JwtError` from `verify` would do so on every launch for a typo in its own code | `JwtOptionError`, `ERR_JWT_OPTION_INVALID`, with `option` |
| 2 | The claim options' values were checked only after the signature, so an expired or forged token hid a mistake in them; `isExpired` did not check `now` or `clockTolerance` for a token without `exp` | options are checked before the token is read |
| 3 | `createJWKS(set, { algorithm: 'RS999' })` skipped every key the option applied to | an unknown algorithm name is a `JwtOptionError`, in `sign` and `verify` too |
| 4 | Switches were compared with `=== true`: `ignoreExpiration: 'true'` was quietly false | they must be booleans |
| 5 | `verify<T>` returned `payload: T`, losing the registered claims' types — the README's `decodeUnverified<{ sub; roles }>` lost `exp` | `payload: JwtPayload & T` |

Kept as they are, each extensible in a minor release: the function names and option names (aligned with `jose` and `jsonwebtoken`), `hexToBytes` (1.x migration), `importJWK(jwk, algorithm?)` without an options argument, `now` as a `Date` only, `audience` as strings only, PEM without X.509 certificates, no key export or generation. Remote JWKS (2.1) fits the synchronous `verify`: fetching returns an ordinary `JwtKeySet`. The `types` condition comes first in `exports`, so TypeScript with `customConditions: ["react-native"]` reads the declarations, not the `.ts` sources.

## Review of 2026-10-17

Two independent passes (separate agents, adversarial, read-only) before `2.0.0-rc.0`: one over everything changed since `2.0.0-alpha.0`, one over the whole library. No accepted forgery with a correctly imported key; interop with Node's `crypto` 660/660 tokens both ways (RSA moduli of odd lengths included); 25,000 fuzzed JWKs and headers raised nothing but `JwtError`s. Regressions in `src/__tests__/review4.test.ts`, numbered like this table. After the fixes, `example/` read 16/16 on the Realme RMX3363 and the iOS 18.3 simulator, Release builds; blinding's cost is in [engineering/performance.md](engineering/performance.md).

| # | Finding | Severity | Outcome |
|-|-|-|-|
| 1 | `sign` reported an option out of range (`expiresIn: 1e11 - 1000`, `now: new Date(2e14)`) as a millisecond `exp`/`iat` claim | wrong error class | `JwtOptionError` naming the option; a millisecond `iat` in the payload is named before the `exp` computed from it |
| 2 | `requiredClaims: null` switched the check off; no test pinned `requiredClaims: 5` | fail-open (caller), test gap | an error; the string form is pinned |
| 3 | `issuer: []`, `audience: []`, `maxTokenAge: 0` refused every token as the token's fault; `sign` issued `aud: []` | wrong error class | `JwtOptionError` |
| 4 | `sign` checked the payload and the key before its options, hiding mistakes in them | wrong error class | options first |
| 5 | `sign({ aud: null }, key, { audience })` blamed the option | misattribution | the payload's registered claims are checked first |
| 6 | An unknown `algorithm` argument to `importPEM`/`importJWK` was a `JwtKeyError`, elsewhere a `JwtOptionError` | inconsistency | `JwtOptionError`, before the key is read |
| 7 | `JwtPayload & T` let `T` contradict a registered claim (`exp: Date` compiled and failed at run time) and lost `readonly` | type | `T extends PayloadShape<T>`, `Readonly<T>`; `PayloadShape` exported |
| 8 | Public-key dumps that tools write were accepted as HMAC secrets: .NET XML, JWK as YAML/TOML, `openssl -text`, DER as decimal bytes | medium, forgery (caller misconfiguration) | refused ([domain/keys.md](domain/keys.md#inputs)) |
| 9 | RSA signing ran unblinded: `micro-rsa-dsa-dh` blinds only when given `e` | low, timing side channel | blinded when `getRandomValues` exists, unblinded otherwise ([domain/keys.md](domain/keys.md#rsa-blinding)) |
| 10 | An unverified token's `alg` and `kid` reached error messages raw: a newline or ANSI escape could forge a log line | low, log injection | escaped with `describeValue` |
| 11 | A JWK with `alg: "Ed25519"` (RFC 9864) dropped out of a key set silently | interop | listed in `skipped` with the reason; support is W-10 |
| 12 | A future `iat` was refused with `clockTolerance` 0: a device clock two seconds behind refused every fresh token | interop | checked only with `maxTokenAge`, as in `jose` ([ADR-009](adr/ADR-009-future-iat.md)); README advises `clockTolerance` on devices |
| 13 | The README said the library checks for `getRandomValues` when it loads; it checks at PS* signing | docs | corrected |
| 14 | Mutants surviving in the new option code: options moved after `parseToken`, a non-list `requiredClaims` read as none, a header serialization error's class, the option named by a claim set twice, an inherited option's name | test gap | a test each in `review4.test.ts` (#13) and `apiFreeze.test.ts` |

## Review of 2026-10-17, second round

Two more passes the same day: one over the first round's fixes (with mutation testing and a false-refusal hunt: 150,000 realistic secrets, none refused), one from a consumer's side (the packed tarball in fresh projects: Node CJS and ESM, TypeScript 4.9–7.0 in every module resolution, webpack, Rollup, esbuild, Jest with two presets; 150 interop checks with `jose` 6.2 and `jsonwebtoken` 9.0; ten provider JWKS shapes). Regressions in `src/__tests__/review5.test.ts`, numbered like this table where they have one. After the fixes: `npm run verify` with 664 tests; `example/` 16/16 on the iOS 18.3 simulator, Release build; Android not yet re-run.

| # | Finding | Severity | Outcome |
|-|-|-|-|
| 1 | The first round's RSA blinding hung forever on a `getRandomValues` that returns its argument (a common Jest mock), and with one that throws blamed the key | DoS, regression | the source is probed before each use; RS* signs unblinded when it does not work, PS* throws `JwtHostRequirementError` |
| 2 | `options.header` (`typ`/`cty`/`kid` types, `toJSON`, BigInt) was checked after the payload and the key | wrong error class | checked with the other options |
| 3 | `expiresIn` under a second issued a token `verify` refuses at once | inconsistency | `JwtOptionError` |
| 4 | Variants of the dumps refused in the first round still passed: XML with prefixes or attributes, `X509Certificate`, TOML inline tables, PyYAML lists, partial `openssl -text`, DER as numbers in Java/Go/C/Node shapes | forgery (caller misconfiguration) | refused ([domain/keys.md](domain/keys.md#inputs)) |
| 4b | The new line patterns refused config lines that only shared a name (`n:` + any `e:`) | false refusal | values checked: short `e`, a curve name, an `n` of 1024 bits or more, an `x` of 32 bytes or more |
| 5 | `JSON.stringify` leaves U+2028, U+2029 and C1 controls raw in messages | log injection | escaped |
| 6 | `isExpired`/`getExpiration` refused tokens whose `sub` is a number, which `jose`, `jsonwebtoken` and jwt-decode read | interop | they check `exp` alone; `decodeUnverified` and `verify` stay strict ([domain/token-model.md](domain/token-model.md)) |
| 7 | `importPEM` refused what OpenSSL and Node read: `openssl ecparam -genkey` output (EC PARAMETERS first), a Bag Attributes preamble, text after END | interop | read as Node does; two key blocks still refused; literal `\n` named |
| 8 | A JWE key without `use` (`alg: "RSA-OAEP"`) was reported in `skipped`; an Entra key without `alg` was told to use `importJWK` | UX | encryption keys left out silently; the remedy names `createJWKS(jwks, { algorithm })` |
| 9 | `verify<{ sub: string \| undefined }>` did not compile; `Jwk`'s index signature refused WebCrypto's `JsonWebKey`; options refused explicit `undefined` under `exactOptionalPropertyTypes` | types | all three accepted |
| 10 | webpack 5 and Rollup dropped the host check with the barrel module | packaging | entry points in `sideEffects`; both bundles keep it (measured) ([engineering/gotchas.md](engineering/gotchas.md)) |
| 11 | The README's refresh example used `clockTolerance`, which makes a token live longer — it refreshed 30 seconds *after* expiry | docs (behaviour) | a later `now`; the README test pins both directions |
| 12 | The README's Jest pattern replaced `jest-expo`'s and broke every test in such a project | broken for some users | a line per preset, "add to it, do not replace it" |
| 13 | "Expo Go includes react-native-get-random-values" was wrong: it is not bundled; it works through `expo-crypto` | docs | corrected; measured that Expo provides no `getRandomValues` itself |
| 14 | An explicit `options.header.kid` was overwritten by the key's `kid` | surprise | it wins; a different `keyId` with it is an error |
| 15 | CHANGELOG missed `options.algorithm`'s move from `JwtAlgorithmError`; the `JwtAlgorithmError` JSDoc said "alg is missing"; the migration guide did not say certificates are refused | docs | corrected |
| 16 | 22 surviving mutants: line patterns' value checks and flags, XML case and DSA/ECDSA forms, the dump message, a non-function `getRandomValues`, the 1e11 boundaries, the order of the plausibility check, three kid messages | test gap | a test each in `review5.test.ts` (#4, #1, #10, #5) |

## Review of 2026-10-17, third round

Three passes the same day: one over the second round's fixes with 78 mutants; one for RFC 7515/7517/7518/7519/8037 conformance (70 probes) and Hermes 0.74 (the whole suite through `@react-native/babel-preset` 0.74.89 in both profiles, 663/664 — the one is a test that compiles a file by its repo path — and a bundle in the Hermes CLI for RN 0.74.1, output identical to Node's line for line); one with hostile input (ReDoS on 30 patterns at 256 KB, 150,000 fuzzed DER, JWK and token mutations: no exception outside the library's classes) and the public API from a consumer's side. Regressions in `src/__tests__/review6.test.ts`, numbered like this table. After the fixes: `npm run verify` with 750 tests; `example/` 16/16 on the iOS 18.3 simulator, Release build (RS256 sign 504 ms with blinding); Android not yet re-run.

| # | Finding | Severity | Outcome |
|-|-|-|-|
| 1 | `sign` threw a raw `RangeError` for a payload or `options.header` nested 2,700–6,000 deep: `parseJson`'s reviver recursed past the stack `JSON.stringify` had room for. `verify` called a too-deep payload "not valid JSON" | wrong error class | `parseJson` walks the result iteratively; the echo is wrapped; "nested too deeply" |
| 2 | A `toJSON` throwing `null` made `sign` throw a `TypeError` reading `.message` | wrong error class | described with `describeValue` |
| 3 | `verify`, `isExpired`, `getExpiration` read a millisecond `exp` as seconds: a token that expired an hour ago never expired, though `sign` refuses such a time | security (issuer bug) | refused above 1e11 in reading too (OD-9, [domain/validation.md](domain/validation.md)) |
| 4 | Claim-mismatch messages (`iss`, `aud`, `sub`, `typ`) printed token values raw and whole (20,000 characters, U+2028) | log injection | `describeValue`: escaped, 64 characters |
| 5 | A public PEM in UTF-16BE (PowerShell `-Encoding BigEndianUnicode`) was not recognised as a key passed for a secret | forgery (caller misconfiguration) | both byte orders |
| 6 | `JwtHeader.crit` was typed `string[]`, but `decodeUnverified` returned `crit: 5` | types | checked in `parseToken` |
| 7 | `createJWKS` checked the set before its options, unlike ADR-008 | consistency | options first |
| 8 | `verify` read `options.algorithm` four times, `issuer` and the others twice | robustness | each read once |
| 9 | `{ ...payload }` in `sign` is `Object.assign` under the RN preset's loose object spread: an own `__proto__` key became the copy's prototype, and `iat`/`iss` were inherited from it | host difference | own keys copied one by one, `__proto__` dropped ([engineering/gotchas.md](engineering/gotchas.md)) |
| 10 | `key_ops` only filtered encryption keys: a JWK with `["verify"]` signed, `use: "sig"` with `encrypt` was accepted | RFC 7517 §4.3 | per operation (OD-9, [domain/keys.md](domain/keys.md)) |
| 11 | `numericBytes`' trailing-bracket regex was quadratic on a run of whitespace: a 64 KB secret took 7 s per `sign` | DoS | tokenized by hand; every new pattern timed |
| 12 | The random-source probe used the array it passed, not the one returned: a polyfill that returns nothing made RS256 fail blaming the key. A source whose numbers never fall below the modulus, or that fills only one array, still hung blinding. Throwing getters escaped as raw errors | DoS, wrong error class | the probe draws modulus-sized numbers as `micro-rsa-dsa-dh` does, at least twice, from the returned arrays; getters inside the try ([domain/keys.md](domain/keys.md#rsa-blinding)) |
| 13 | Without the index signature, a JWK literal with `x5c`, `x5t`, `ext` or `oth` did not compile | types, regression | the registered members typed |
| 14 | Bidirectional and invisible format characters (U+202E, U+2066…) were left raw in messages | log spoofing | escaped |
| 15 | `importPEM`: a broken first block was skipped and the next one imported; spaces after BEGIN refused; an EC PARAMETERS-only file called "not a PEM block"; the literal `\n` hint lost to a trailing newline | interop | as OpenSSL |
| 16 | Dumps still passing as secrets: `xxd -i`, Go `%#v`, Java `new byte[]`, Python `b'…'` and `bytes([…])`, PowerShell, Rust `u8`, `hexdump -C`, `xxd`, INI in capitals | forgery (caller misconfiguration) | refused ([domain/keys.md](domain/keys.md#inputs)) |
| 17 | Surviving mutants: JWE algorithm variants, the HS256 hint for an `oct` key, DEL/C1 boundaries, the probe's returned value, false-positive line values | test gap | a test each in `review6.test.ts` (#17, #14, #12, #16) |
| 18 | Hermes 0.74 cannot parse `class`; the library runs because the RN preset always lowers classes | docs | [engineering/gotchas.md](engineering/gotchas.md) |

Not changed: Node `util.inspect` of a `Buffer` or `Uint8Array` shows the first 50 or 100 bytes only, so a key printed so cannot be told from a list of numbers; YAML tags and folded scalars, `<PublicKey>` XML and XML entities stay undetected; a certificate and a key in one PEM stays an error (which one was meant would be a guess); a random source that works for the probe and fails after it is beyond the probe.

## Decided

| ID | Decision | Outcome | Record |
|-|-|-|-|
| OD-1 | Crypto backend | `@noble/hashes` + `@noble/curves` + `micro-rsa-dsa-dh`, pure JavaScript, no cryptography of our own, no native module. Accepted 2026-10-14, subject to the Hermes measurement in FT-001 stage 1a | [ADR-001](adr/ADR-001-crypto-backend.md) |
| OD-2 | Sync or async `sign` / `verify` | Synchronous core, no promises in 2.0.0; asynchrony only in separate functions that wait on the network or the user. Remote JWKS moved to 2.1. Accepted 2026-10-15 | [ADR-002](adr/ADR-002-synchronous-api.md) |
| OD-3 | How the algorithm is chosen | One key, one algorithm (RFC 8725): a bare secret is HS256 unless the `algorithm` option says otherwise; an imported key carries its own; no `algorithms` list; `none` never. Accepted 2026-10-15 | [ADR-003](adr/ADR-003-one-key-one-algorithm.md) |
| OD-4 | Relationship to 1.0.x | New names, no `decode` that decodes, no compatibility layer; tombstones (default export, and named `encode`/`decode` since ADR-006) until 3.0.0; short secrets refused unless `allowShortSecret`; hex secrets via `hexToBytes`; 1.0.x security fixes for three months after 2.0.0, then npm deprecate. Accepted 2026-10-15 | [ADR-006](adr/ADR-006-named-1x-tombstones.md), superseding ADR-004 |
| OD-5 | Minimum React Native version | No `react-native` peer; the floor is the lowest React Native whose Hermes has every feature the code needs (`BigInt`, `Object.hasOwn`, `TextEncoder`), measured — 0.74; runtime host check with `JwtHostRequirementError`; Hermes only. Accepted 2026-10-15, floor corrected 2026-10-16 | [ADR-007](adr/ADR-007-host-requirements-text-encoder.md), superseding ADR-005 |
| OD-6 | Ship 1.0.4 first | Yes: `jsrsasign` ^11.1.5, a `files` field so the memory bank is not published, `CHANGELOG.md`, a README note on 2.0.0 and the 1.0.x window. Accepted and published 2026-10-15 | [product/roadmap.md](product/roadmap.md) |
| OD-7 | Option errors and payload generics | A mistake in the call is `JwtOptionError`, checked before the token is read; switches must be booleans; `payload: JwtPayload & T`. Accepted 2026-10-16, after `2.0.0-alpha.0` | [ADR-008](adr/ADR-008-option-errors.md) |
| OD-8 | Future `iat`, RSA blinding, `alg: "Ed25519"`, payload type constraint | Future `iat` only with `maxTokenAge`; RSA blinding when a random source exists; `Ed25519` reported in `skipped`, supported in 2.1; `T extends PayloadShape<T>`. Accepted 2026-10-17 | [ADR-009](adr/ADR-009-future-iat.md), [domain/keys.md](domain/keys.md#rsa-blinding) |
| OD-9 | Millisecond times in tokens, `key_ops` | A time claim above 1e11 is refused wherever a token is read, as in signing — stricter than `jose`; `key_ops` allows only the operations it lists, like WebCrypto's usages. Accepted 2026-10-17, third review round | [domain/validation.md](domain/validation.md), [domain/keys.md](domain/keys.md) |

## Defects in the 1.0.x line

Measured on 2026-10-14 against `src/jwt.js` at 1.0.3, with `jsrsasign` 8.0.24 (what `^8.0.12` installs) and 11.1.5.

| ID | Defect | Evidence |
|-|-|-|
| V1-1 | Critical dependency advisories | `npm audit` on 8.0.24: critical — GHSA-h87q-g2wp-47pj, GHSA-3fvg-4v2m-98jf, GHSA-27fj-mc8w-j9wg, GHSA-8qwj-4jxw-m8jw (signature-verification bypasses) and more. 11.1.5: 0 vulnerabilities, identical behaviour |
| V1-2 | No claim validation | A token with `exp: 1` decodes and verifies as valid |
| V1-3 | `decode` returns `jsrsasign`'s parse object | `{ headerObj, payloadObj, headerPP, payloadPP, sigHex }`, not the payload |
| V1-4 | Hex-looking secrets are hex | Secret `deadbeef` produces a signature that standard HMAC over the UTF-8 text does not match |
| V1-5 | The token header chooses the algorithm | `JWS.verify(token, key)` without `acceptAlgs`; RS256→HS256 confusion fails only because PEM parsing throws first |
| V1-6 | Inconsistent failure reporting | `null` from `decode`, `false` from `verify`, raw exceptions for `alg: none` (`not supported`) and confusion attempts |
| V1-7 | No types, no tests, no `files` field | The tarball ships whatever is in the directory |
| V1-8 | README documents only `encode`, and encourages client-side HMAC | Shipping an HMAC secret in an app bundle publishes it |

V1-1 is closed: fixed by 1.0.4, published 2026-10-15. The rest are fixed by 2.0.0, each with a regression test (SC-7 for V1-4).
