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

- Payload types flow through generics (`verify<MyClaims>()`) and are added to `JwtPayload` (`JwtPayload & Readonly<MyClaims>`), so the registered claims stay typed whatever the caller passes; `T extends PayloadShape<T>` lets `T` narrow a registered claim but not change its type; the rest is `unknown` — never `any` ([ADR-008](../adr/ADR-008-option-errors.md)).
- Results are `readonly`.
- Algorithm names are a string-literal union exported as a `const` object plus a type under one name.
- Byte data is `Uint8Array`. No `Buffer` in the public surface: Hermes has none.

## Errors

Every deliberate throw is a subclass of `JwtError` with a stable string `code` (`ERR_JWT_EXPIRED`, …) so callers can branch without `instanceof` across bundle copies. A mistake in the call is a `JwtOptionError`, never the class of a token failure, so an app can tell a bug from a bad token ([ADR-008](../adr/ADR-008-option-errors.md)). A message says what failed and what to do. A bare `throw new Error()` in library code is a defect; so is returning `null` or `false` for a failure, which is what 1.0.x did.
