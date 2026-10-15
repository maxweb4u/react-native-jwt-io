---
title: CocoaPods needs a UTF-8 locale
doc_kind: ops
doc_function: canonical
purpose: Read before running pod install for example/ or a scratch React Native app on the maintainer's Mac.
derived_from:
  - ../ops/development.md
status: draft
---
# CocoaPods needs a UTF-8 locale

`pod install` (CocoaPods 1.15.2 under rbenv Ruby 2.7.5) aborts with
`Unicode Normalization not appropriate for ASCII-8BIT (Encoding::CompatibilityError)`
when the shell that runs it has no UTF-8 locale — which is the case for
non-interactive shells such as an agent's Bash tool. Observed on 2026-10-15 while
building a scratch React Native 0.87.1 app for the 1.0.4 Hermes smoke test.

Fix: run it as `LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 pod install`. Keep the same
variables for the following `xcodebuild`.
