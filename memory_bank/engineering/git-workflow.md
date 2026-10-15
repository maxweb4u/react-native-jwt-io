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

Tagged `v<version>`, matching an entry in `CHANGELOG.md`. 1.0.x patches are cut from the last 1.0.x tag if `master` has already moved to 2.0.0.
