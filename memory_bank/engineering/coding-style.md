---
doc_kind: engineering
doc_function: canonical
purpose: Naming, comments, file layout, and lint conventions.
derived_from:
  - typescript.md
status: active
canonical_for:
  - naming_conventions
  - comment_policy
  - file_layout
---

# Coding Style

## Files

One primary export per file, named after it. Tests in a sibling `__tests__/` directory. Barrels re-export and contain no logic.

## Naming

| Kind | Convention |
|-|-|
| Types, classes | `PascalCase` |
| Functions, variables | `camelCase` |
| Constant value objects | `PascalCase` (`Algorithm`) |
| Booleans | `is` / `has` prefix |
| Options mirroring the RFC | The `jose` / `jsonwebtoken` name when one exists (`clockTolerance`, `expiresIn`), so callers migrating need no lookup |

## Comments

Comments explain why. A check that exists because of an RFC clause or an advisory cites it (`RFC 7518 §3.2`, `GHSA-…`). Pointers to canonical documents follow [../dna/cross-references.md](../dna/cross-references.md). Commented-out code is deleted.

## Lint

ESLint flat config. `no-console` is an error. Any comparison of secret-derived bytes goes through the constant-time helper, never `===`.
