---
title: Two npm accounts own the package
doc_kind: ops
doc_function: canonical
purpose: 'Read before publishing, when npm whoami shows a different account than the package''s maintainers field.'
derived_from:
  - ../ops/release.md
status: draft
---
# Two npm accounts own the package

`react-native-jwt-io` has two npm owners, both on maxweb4u@gmail.com:
`maxweb4u` and `maximgor` (`npm owner ls react-native-jwt-io`). Either can
publish.

`npm view react-native-jwt-io maintainers` showed only `maximgor` on
2026-10-15 — it reflects the account that published 1.0.3, not the owner
list — which made `npm whoami` → `maxweb4u` look like the wrong account. It
was not: 1.0.4 was published as `maxweb4u`. Check owners with
`npm owner ls`, not with `maintainers`.

Publishing from that account asks for 2FA through a browser link
(`npmjs.com/auth/cli/…`), and the new version took about a minute to appear
in `npm view` after `+ react-native-jwt-io@1.0.4` was printed.
