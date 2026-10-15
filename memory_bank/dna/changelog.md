---
doc_kind: governance
doc_function: canonical
purpose: Versioned changes to the memory bank structure itself.
derived_from:
  - governance.md
status: active
---

# Memory Bank Changelog

## v1 — 2026-10-14

Initial memory bank, created before the TypeScript rewrite of the 1.0.x line.

- DNA, flows, and templates copied from the `react-native-matrix` memory bank, which is the reference layout for the maintainer's modules; principle 12 (secure by default) added for this library.
- Product, domain, engineering, ops, adr, and features sections written for JWT. No `prd/`, `epics/`, `use-cases/`, or `processes/` sections until a real need appears (see [principles.md](principles.md), rule 10).
- Engineering and ops documents describing the target toolchain are `draft` until FT-001 stage 1 lands; ADRs are `proposed` until the maintainer accepts them.
