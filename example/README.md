# react-native-jwt-io example

A React Native 0.87 app that runs the library **from source** on a device and
shows a self-test: each key family and curve (HS256, RS256, PS256,
ES256/384/512, ES256K, EdDSA) verifies a token signed by Node's `crypto`, signs
one of its own, and reports the time each took; PS256/384/512 sign with a
random salt from `react-native-get-random-values`; deterministic signatures must
equal Node's byte for byte, tampered ones must fail, and error names must
survive the release build's minifier. It is the manual check
behind SC-9 and SC-13 in `memory_bank/features/FT-001-typescript-rewrite/` and
the numbers in `memory_bank/engineering/performance.md`.

## Run

```sh
cd example
npm install        # also generates src/fixtures.ts: throwaway keys and Node-signed tokens
npm run android    # or: npm run ios
```

For timing numbers use a Release build — Debug runs the JavaScript through the
dev server and is several times slower:

```sh
cd ios && pod install && cd ..
npx react-native run-ios --mode Release
npx react-native run-android --mode release
```

After a change to the library alone (`../src`), Gradle does not notice and
reuses the old JavaScript bundle. Remove it first:

```sh
rm -rf android/app/build/generated/assets/react
```

The screen should read **Self-test 15/15 passed**. The first line must say
Hermes: the self-test fails on any other engine, since Hermes is the only one
supported. The app installs `react-native-get-random-values` and imports it
first in `index.js`, as the library's README asks, so PS256/384/512 sign on
the device; the "PS* signing" check fails if the import is removed. Signing
without it is the host error tested in Jest (`host.test.ts`).

## How it is wired

There is no `react-native-jwt-io` entry in `package.json`. `metro.config.js`
watches the repository root and maps the package name to it; the package's
`react-native` export condition then points Metro at `../src/index.ts`, so a
change to the library shows up on reload. `tsconfig.json` mirrors the mapping
for type checking.

`src/fixtures.ts` is generated on install by `scripts/make-fixtures.mjs` and is
git-ignored: it contains private keys, throwaway ones, which do not belong in
the repository.

## Known issue

The React Native 0.87.1 template crashes at launch on **iOS 27** simulators
(UIScene lifecycle; see `memory_bank/engineering/gotchas.md`). Use an iOS 26 or
older simulator.
