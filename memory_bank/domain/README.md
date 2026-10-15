---
doc_kind: domain
doc_function: index
purpose: Navigation for JWT domain documentation.
derived_from:
  - ../dna/governance.md
status: active
---

# Domain Index

- [Glossary](glossary.md) — JWT, JWS, JWK, JWKS, and claim vocabulary as this library uses it.
- [Token Model](token-model.md) — compact serialization, base64url, header and payload rules.
- [Algorithms](algorithms.md) — the supported `alg` values, which key each needs, and what is refused.
- [Keys](keys.md) — accepted key inputs (secret, PEM, JWK, JWKS) and how they are bound to an algorithm.
- [Validation](validation.md) — the order of checks in `verify` and the claim rules. The densest rules in the project.
