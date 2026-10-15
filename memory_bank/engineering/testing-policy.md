---
doc_kind: engineering
doc_function: canonical
purpose: What must be tested, how the suites are split, and how to run them.
derived_from:
  - ../dna/governance.md
  - ../domain/validation.md
status: draft
canonical_for:
  - test_suite_split
  - required_coverage
  - test_commands
---

# Testing Policy

## Stack

Jest. No device is needed for any automated suite; the device check lives in `example/` and the release checklist.

## Suites

| Suite | Proves | Location |
|-|-|-|
| unit | Each module in isolation; fake `now` | `src/**/__tests__/` |
| interop | Every algorithm both ways against Node's `crypto`: tokens signed here verify there, and the reverse, including RFC 7515/7520 published examples | `src/**/__tests__/interop/` |
| hostile input | Malformed segments, padding, non-object payloads, `alg: none`, algorithm confusion, `crit`, oversized input, `__proto__`, wrong key type | `src/**/__tests__/hostile/` |

Node's `crypto` is the oracle because it is an independent implementation of every algorithm here. It is a dev dependency only; nothing in `src/` may import it.

## Required coverage

- Every row of [../domain/algorithms.md](../domain/algorithms.md) has an interop test in both directions.
- Every step of [../domain/validation.md](../domain/validation.md#order) has a test proving the right error class and `code`.
- Every 1.0.x defect in [../backlog.md](../backlog.md#defects-in-the-10x-line) gets a regression test naming it.
- `coverageThreshold` is a floor, set just under the measured value.

## Before handing work over

```sh
npm run verify     # typecheck + lint + all suites + memory bank check
```
