---
doc_kind: engineering
doc_function: index
purpose: Navigation for repository engineering rules.
derived_from:
  - ../dna/governance.md
status: active
audience: humans_and_agents
---

# Engineering Index

Documents marked `draft` describe the 2.0.0 target and become `active` as [FT-001](../features/FT-001-typescript-rewrite/feature.md) builds them.

- [Architecture](architecture.md) — `draft`. Module layering, the crypto backend seam, and the public API surface.
- [Dependency Policy](dependency-policy.md) — the three allowed runtime dependencies and why this library is not zero-dependency. Read before adding any package.
- [TypeScript Conventions](typescript.md) — strictness settings, public type rules, and error classes.
- [Coding Style](coding-style.md) — naming, comments, file layout, and lint rules.
- [Testing Policy](testing-policy.md) — `draft`. Unit, interop, and hostile-input suites, and what each must prove.
- [Git Workflow](git-workflow.md) — branches, commits, and release tags.
- [Gotchas](gotchas.md) — traps in JWT handling, Hermes, and the toolchain that are easy to hit twice.
