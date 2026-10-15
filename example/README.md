# react-native-jwt-io example

A React Native 0.87 app that runs the library **from source** on a device and
shows a self-test: every algorithm verifies a token signed by Node's `crypto`,
signs one of its own, and reports the time each took. It is the manual check
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

The screen should read **Self-test 12/12 passed**. PS256 reports that signing
needs `getRandomValues`: that is the designed behaviour without
`react-native-get-random-values`, not a failure.

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
