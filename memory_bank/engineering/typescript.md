---
doc_kind: engineering
doc_function: canonical
purpose: TypeScript strictness settings, public type rules, and error conventions.
derived_from:
  - architecture.md
status: active
canonical_for:
  - typescript_strictness
  - public_type_rules
  - error_class_rules
---

# TypeScript Conventions

## Strictness

`strict` plus `noUncheckedIndexedAccess`, `noImplicitOverride`, `noUnusedLocals`, `noUnusedParameters`, `noFallthroughCasesInSwitch`. `@typescript-eslint/no-explicit-any` is an error. Same baseline as `react-native-matrix`.

## Public types

- Payload types flow through generics (`verify<MyClaims>()`), defaulting to `JwtPayload` with the registered claims typed and the rest `unknown` — never `any`.
- Results are `readonly`.
- Algorithm names are a string-literal union exported as a `const` object plus a type under one name.
- Byte data is `Uint8Array`. No `Buffer` in the public surface: Hermes has none.

## Errors

Every deliberate throw is a subclass of `JwtError` with a stable string `code` (`ERR_JWT_EXPIRED`, …) so callers can branch without `instanceof` across bundle copies. A message says what failed and what to do. A bare `throw new Error()` in library code is a defect; so is returning `null` or `false` for a failure, which is what 1.0.x did.
