---
title: Documentation Index
doc_kind: project
doc_function: index
purpose: Root navigation for the memory bank. Read this first to understand the structure of the project.
derived_from:
  - dna/governance.md
status: active
audience: humans_and_agents
---

# Documentation Index

`react-native-jwt-io` is a JSON Web Token library for React Native: create, decode, and verify JWTs on Hermes without a native module. This memory bank owns the intent, contracts, and decisions behind it; the code owns the implementation.

The 1.0.x line (2017, plain JavaScript over `jsrsasign` 8) is being rewritten in TypeScript as [FT-001](features/FT-001-typescript-rewrite/feature.md). Until that ships, engineering and ops documents describe the **target** and are `draft`.

## Annotated Index

- [`product/README.md`](product/README.md)
  Read when you need who the library is for, what it does and deliberately does not do, and the release order.

- [`domain/README.md`](domain/README.md)
  Read when you need JWT/JWS/JWK language, the supported algorithms, key formats, and the validation rules a token must pass.

- [`engineering/README.md`](engineering/README.md)
  Read when you need module layout, the crypto backend contract, dependency policy, TypeScript conventions, or the testing policy.

- [`ops/README.md`](ops/README.md)
  Read when you need local development commands or the release process.

- [`adr/README.md`](adr/README.md)
  Read when you need the reasoning behind an architecture decision, or need to record a new one.

- [`features/README.md`](features/README.md)
  Read when you need the delivery packages that track substantial changes.

- [`backlog.md`](backlog.md)
  Read when you need what is still open: decisions waiting on the maintainer and known defects of the 1.0.x line.

- [`flows/README.md`](flows/README.md)
  Read when you need to create a feature package or an ADR, or need the templates.

- [`dna/README.md`](dna/README.md)
  Read when you need the documentation rules themselves: SSoT, the frontmatter contract, and the lifecycle.
