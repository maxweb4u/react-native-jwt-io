---
doc_kind: ops
doc_function: canonical
purpose: Local setup and everyday commands.
derived_from:
  - ../engineering/testing-policy.md
status: active
canonical_for:
  - local_setup
  - everyday_commands
---

# Development

## Requirements

Node 22.13 or later (matching `react-native-matrix`).

## Commands

| Command | Purpose |
|-|-|
| `npm run verify` | Typecheck, lint, all test suites, memory bank check. Run before handing work over |
| `npm test` | All Jest suites (Node only, no device) |
| `npm run typecheck` | `tsc --noEmit` |
| `npm run lint` / `lint:fix` | ESLint |
| `npm run build` | CommonJS, ESM, and declarations into `lib/` |
| `npm run check:docs` | `node scripts/check-memory-bank.mjs` — frontmatter, links, orphans |
| `npm run check:build` | Loads the built `lib/commonjs` through the package's own `exports` and round-trips a token; part of `prepack` |
| `npm run test:coverage` | Coverage, enforced by the floor in `jest.config.js` |

## Example application

`example/` is a React Native 0.87.1 app consuming the package from source through Metro. It exists to prove what Jest cannot: that every algorithm runs under Hermes on a device, with no native crypto module installed. Setup, Release-mode commands and the wiring are in `example/README.md`; `npm install` there generates the throwaway key fixtures, which are git-ignored.

**CocoaPods needs a UTF-8 locale.** `pod install` (CocoaPods 1.15.2 under rbenv Ruby 2.7.5) aborts with `Unicode Normalization not appropriate for ASCII-8BIT (Encoding::CompatibilityError)` in a shell without one — any non-interactive shell, an agent's included. Run `LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 pod install`, and keep the variables for the `xcodebuild` that follows. Seen on 2026-10-15 with a React Native 0.87.1 app.
