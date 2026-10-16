---
doc_kind: ops
doc_function: canonical
purpose: Versioning rules, publish checklist, and package contents.
derived_from:
  - ../engineering/git-workflow.md
status: active
canonical_for:
  - versioning_rules
  - publish_checklist
  - package_contents
---

# Release

## Versioning

Semantic versioning against [../engineering/architecture.md](../engineering/architecture.md).

- **Major** — an export is removed or changes shape; a default becomes stricter; an algorithm is dropped.
- **Minor** — new exports, algorithms, or options.
- **Patch** — fixes keeping every signature, and dependency bumps that keep behaviour.

The package is already at 1.0.3, so the rewrite is **2.0.0** — no `0.x` grace period. A stricter default is major on purpose: it turns tokens that used to pass into failures.

## The 1.0.x line

Security fixes only, cut from the last 1.0.x tag, for three months after 2.0.0 is published. When the window closes:

```sh
npm deprecate react-native-jwt-io@"<2.0.0" "1.x is no longer supported. Upgrade to 2.x: see the migration guide in the README."
```

The end date is written into the README with the 2.0.0 release. Decided in [ADR-006](../adr/ADR-006-named-1x-tombstones.md).

## Checklist

1. `npm run verify` passes.
2. `example/` runs in a Release build on a physical device or simulator on both platforms, and its self-test screen reads 14/14.
3. `npm pack --dry-run` lists only `lib/`, `src/`, `README.md`, `LICENSE`, `CHANGELOG.md`, `package.json`.
4. `CHANGELOG.md` has an entry; for 2.0.0 the README carries the migration guide and the 1.0.x end-of-support date.
5. The memory bank matches the change ([../dna/lifecycle.md](../dna/lifecycle.md)).
6. Publish — `prepack` rebuilds `lib/`:
   - a release: `npm publish`;
   - a prerelease (`2.0.0-alpha.0`, `-beta.N`, `-rc.N`): `npm publish --tag next`. Without `--tag`, npm moves `latest` to it, and every `npm install react-native-jwt-io` — 1.x users included — gets the breaking prerelease. Check with `npm dist-tag ls react-native-jwt-io` afterwards: `latest` must still be the last release.
7. Tag `v<version>` and push.

## Package contents

Through the `files` field: `lib/` and `src/` (Metro reads TypeScript through the `react-native` export condition). Tests, `example/`, `memory_bank/`, and scripts are excluded. Up to 1.0.3 there was no `files` field, so everything in the directory was published; 1.0.4 added one (`index.js`, `src`, `CHANGELOG.md`).
