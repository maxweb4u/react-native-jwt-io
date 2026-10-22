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

Security fixes only, on the `1.x` branch (cut from `v1.0.4`; [../engineering/git-workflow.md](../engineering/git-workflow.md#releases)), for three months after 2.0.0 is published. When the window closes:

```sh
npm deprecate react-native-jwt-io@"<2.0.0" "1.x is no longer supported. Upgrade to 2.x: see the migration guide in the README."
```

The end date is written into the README with the 2.0.0 release. Decided in [ADR-006](../adr/ADR-006-named-1x-tombstones.md).

## Checklist

1. `npm run verify` passes, and `npm audit --omit=dev` reports 0 vulnerabilities: that is what an app installs. Advisories in the development tools are tracked in the backlog, not blockers.
2. `example/` runs in a Release build on a physical device or simulator on both platforms, and its self-test screen reads 16/16.
3. `npm pack --dry-run` lists only `lib/`, `src/`, `README.md`, `LICENSE`, `CHANGELOG.md`, `package.json`.
4. `CHANGELOG.md` has an entry; for 2.0.0 the README carries the migration guide and the 1.0.x end-of-support date. While a prerelease is out, the README installs `react-native-jwt-io@next`, because `latest` is still 1.x; the release that moves `latest` to 2.x drops the `@next` and the note under it.
5. The memory bank matches the change ([../dna/lifecycle.md](../dna/lifecycle.md)).
6. Squash-merge the release branch into `master` through a pull request, then `git checkout master && git pull`: the package is published from `master`.
7. Publish — `prepack` rebuilds `lib/`:
   - a release: `npm publish`;
   - a prerelease (`2.0.0-alpha.0`, `-beta.N`, `-rc.N`): `npm publish --tag next`. Without `--tag`, npm moves `latest` to it, and every `npm install react-native-jwt-io` — 1.x users included — gets the breaking prerelease. Check with `npm dist-tag ls react-native-jwt-io` afterwards: `latest` must still be the last release.
8. Tag `v<version>` on that `master` commit and push the tag.

## Publishing account

The package has two npm owners, both on maxweb4u@gmail.com: `maxweb4u` and `maximgor`; either can publish. Check them with `npm owner ls react-native-jwt-io` — `npm view react-native-jwt-io maintainers` names the account that published the last version it knows (`maximgor` for 1.0.3), not the owners, and once made `maxweb4u` look like the wrong account. 1.0.4 and `2.0.0-alpha.0` were published as `maxweb4u`.

- `npm whoami` failing with E401 means the session expired: `npm login`, then publish.
- Publishing asks for 2FA through a browser link (`npmjs.com/auth/cli/…`).
- The registry lags: `npm view` and `npm dist-tag ls` showed a new version about a minute after `+ react-native-jwt-io@<version>` was printed (1.0.4, `2.0.0-alpha.0`). Wait before concluding that a tag did not move.

## Package contents

Through the `files` field: `lib/` and `src/` (Metro reads TypeScript through the `react-native` export condition). Tests, `example/`, `memory_bank/`, and scripts are excluded. Up to 1.0.3 there was no `files` field, so everything in the directory was published; 1.0.4 added one (`index.js`, `src`, `CHANGELOG.md`).
