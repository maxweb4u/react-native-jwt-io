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

- [Architecture](architecture.md) — module layering, the crypto backend seam, packaging, and the public API surface.
- [Dependency Policy](dependency-policy.md) — the three allowed runtime dependencies and why this library is not zero-dependency. Read before adding any package.
- [TypeScript Conventions](typescript.md) — strictness settings, public type rules, and error classes.
- [Coding Style](coding-style.md) — naming, comments, file layout, and lint rules.
- [Testing Policy](testing-policy.md) — the suites, what each must prove, and the coverage floor.
- [Performance](performance.md) — every algorithm measured on Hermes, against the 1.0.x baseline. Read before promising speed.
- [Git Workflow](git-workflow.md) — branches, commits, and release tags.
- [Gotchas](gotchas.md) — traps in JWT handling, Hermes, and the toolchain that are easy to hit twice.
