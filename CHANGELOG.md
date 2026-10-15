# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org).

## [1.0.4] — 2026-10-15

Security update of the 1.0.x line. The API and its behaviour are unchanged.

### Security

- `jsrsasign` raised from `^8.0.12` to `^11.1.5`. The 8.x line that `^8.0.12`
  installs carries advisories rated critical by `npm audit`, including
  signature-verification bypasses (GHSA-27fj-mc8w-j9wg, GHSA-h87q-g2wp-47pj,
  GHSA-3fvg-4v2m-98jf, GHSA-8qwj-4jxw-m8jw). 11.1.5 has none open, and
  `encode`, `decode`, and `verify` return the same results on it.

### Changed

- The published package contains only `index.js` and `src/`. Earlier versions
  had no `files` field and published everything in the repository directory.

### Notice

- 2.0.0, a TypeScript rewrite with a new API, is in development. Once it is
  published, 1.0.x receives security fixes for three months and is then
  deprecated.
