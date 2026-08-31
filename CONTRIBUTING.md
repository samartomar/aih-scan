# Contributing

Install dependencies with `npm ci --ignore-scripts` and run `npm run verify` before
requesting review. Keep changes scoped, preserve Scanner's evidence-only authority
boundary, and add focused tests for changed behavior.

Every PR needs exactly one `semver:none|patch|minor|major` label before merge. Labels are
maintainer-owned; external contributors need not apply them. Use `semver:none` only when
the merge requires no new public package bytes. See [VERSIONING.md](VERSIONING.md) and
[RELEASING.md](RELEASING.md).

Sign off commits under the Developer Certificate of Origin with `git commit -s`.
