# Issue #62 — Scanner 0.4.0 release preparation

## Version decision

The previous immutable release is `v-scan-0.3.0`. Three pull requests merged after that tag:

- #57 — `semver:none`; preserves Core ownership of baseline request output.
- #59 — `semver:minor`; advances the bundled Cisco analyzer from 2.0.13 to 2.0.14 and changes its exact evidence identity.
- #61 — `semver:none`; binds baseline publication addresses to the protected Scanner publisher commit as well as the request digest.

The highest package-bearing class is `semver:minor`, so the coherent next version is `0.4.0`.
The repository-only changes ride that train without changing its class.

This preparation changes source truth only. It does not create or push a tag, publish npm bytes,
approve a protected environment, create baseline evidence, or promote an npm dist-tag.

## RED and GREEN

Tests first required package identity `0.4.0`, tarball `aihq-scan-0.4.0.tgz`, the same cold Core
handoff identity, and public README truth for the exact Cisco analyzer change. The focused RED run
failed five assertions while the manifest, lock, proof helper, and README still named `0.3.0` or
omitted the new train. The mechanical source changes then made the same focused suite green.

## Publication boundary

After this preparation merges and every required check is green on the resulting exact current-main
commit, publication still requires the repository's exact full-SHA owner authorization from
`RELEASING.md`. Candidate publication uses npm `next`; public installed Scanner/Core/Catalog
acceptance and a separate exact promotion authorization are still required before `latest` moves.

## Verification

- Focused release suite: 4 files and 17 tests passed.
- Complete serial suite: 42 files passed; 266 tests passed and 19 platform/live tests skipped.
- Serial coverage: 86.35% statements, 81.23% branches, 96.88% functions, and 90.76% lines.
- Typecheck, lint, and build passed; the default parallel suite hit two unrelated Windows five-second
  timing limits that pass in the complete one-worker run.
- Online workflow-action resolution passed for all 11 unique actions.
- Dry-run pack produced exact `@aihq/scan@0.4.0`, filename `aihq-scan-0.4.0.tgz`, with 68 entries.
- The unchanged dependency lock reported zero vulnerabilities during the clean `npm ci`; a later
  explicit registry audit request did not return before the local attempt was stopped.
- `git diff --check` passed.
