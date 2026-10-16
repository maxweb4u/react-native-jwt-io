---
doc_kind: engineering
doc_function: canonical
purpose: Branch, commit, and release-tag conventions.
derived_from:
  - ../dna/governance.md
status: active
canonical_for:
  - branch_naming
  - commit_format
  - release_tagging
---

# Git Workflow

## Branches

`master` is releasable. The maintainer creates branches when work needs one; agents work on the branch that is checked out and never create branches themselves.

## Commits

Conventional Commits: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`. A breaking change carries `!` and a `BREAKING CHANGE:` footer naming the removed or changed export. A security fix names the advisory or the attack it closes.

## Releases

Tagged `v<version>`, matching an entry in `CHANGELOG.md`, on the commit that was published.

- Work for a release happens on a release branch (`release/v2.0.0`), which is **squash-merged** into `master` through a pull request; the package is published from `master` and the tag is put on the squash commit. The release branch is kept, for its detailed history.
- **`1.x`** holds the 1.0.x line once `master` carries 2.x: created from the `v1.0.4` tag on 2026-10-16, before 2.0.0-alpha.0 was merged. 1.0.x security fixes go there and are published from there.
