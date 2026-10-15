---
doc_kind: adr
doc_function: index
purpose: Index of Architecture Decision Records.
derived_from:
  - ../dna/governance.md
status: active
---

# Architecture Decision Records

One decision per record: context, decision, consequences. A record is never edited after acceptance except to mark it superseded. Records still `proposed` wait on the maintainer — see [../backlog.md](../backlog.md#open-decisions).

- [ADR-001 — Crypto backend](ADR-001-crypto-backend.md) — `accepted`. `@noble/hashes`, `@noble/curves`, and `micro-rsa-dsa-dh` replace `jsrsasign`: pure JavaScript, no cryptography of our own, no native module.
- [ADR-002 — Synchronous sign and verify](ADR-002-synchronous-api.md) — `accepted`. The whole 2.0.0 core is synchronous; asynchrony lives only in separate functions that wait on the network or the user.
- [ADR-003 — One key, one algorithm](ADR-003-one-key-one-algorithm.md) — `accepted`. The key decides the algorithm, never the token; a bare secret defaults to HS256.
- [ADR-004 — Break from the 1.0.x API](ADR-004-break-from-v1-api.md) — `accepted`. New names, no `decode`, migration tombstones until 3.0.0, short-secret and hex-secret paths, three months of 1.0.x fixes.
- [ADR-005 — Host requirements instead of a React Native peer](ADR-005-host-requirements.md) — `accepted`. The floor is the lowest React Native whose Hermes has the features the code needs, measured, plus a runtime host check.

Use the template at [../flows/templates/adr/adr.md](../flows/templates/adr/adr.md).
