---
doc_kind: ops
doc_function: canonical
purpose: Local setup and everyday commands.
derived_from:
  - ../engineering/testing-policy.md
status: draft
canonical_for:
  - local_setup
  - everyday_commands
---

# Development

Draft: the commands below arrive with FT-001 stage 1. Today the repository has no build, lint, or tests; only `npm run check:docs` is meaningful once `package.json` declares it.

## Requirements

Node 22.13 or later (matching `react-native-matrix`).

## Commands

| Command | Purpose |
|-|-|
| `npm run verify` | Typecheck, lint, all test suites, memory bank check. Run before handing work over |
| `npm test` | All Jest suites |
| `npm run typecheck` | `tsc --noEmit` |
| `npm run lint` / `lint:fix` | ESLint |
| `npm run build` | CommonJS, ESM, and declarations into `lib/` |
| `npm run check:docs` | `node scripts/check-memory-bank.mjs` — frontmatter, links, orphans |

## Example application

`example/` is a React Native app consuming the package from source through Metro. It exists to prove what Jest cannot: that every algorithm runs under Hermes on a device, with no native crypto module installed.
