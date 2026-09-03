# Issue #54 — Scanner 0.3.0 release preparation

## Version decision

The previous immutable tag is `v-scan-0.2.5`. Exactly one pull request merged after that tag:
Scanner #53, labeled `semver:minor`, adds the public baseline publication and inspection contract.
The resulting coherent release version is therefore `0.3.0`.

This change prepares source for review. It does not create a tag, publish npm bytes, approve a
protected environment, publish baseline evidence, or promote an npm dist-tag.

## RED and GREEN

The release tests were first changed to require package identity `0.3.0`, its exact tarball name,
the cold Core handoff identity, and public README release truth. The focused RED run failed four
assertions while the manifest, lock, proof helper, and README still named `0.2.5` or omitted the new
release behavior. After the mechanical version bump and truth updates, the four focused files passed
17 tests.

The first full coverage run exposed an existing package-test race: `package-install-v2.test.ts`
invoked `npm pack`, whose `prepack` rewrote `dist`, while `release-readiness.test.ts` concurrently ran
a redundant dry-run pack against the same directory. The latter read a partial `dist/cli.d.ts` and
failed with npm `EOF`. The installed-package test remains the single authoritative tarball pack,
content, install, export, and CLI boundary. Release readiness now checks the manifest and declared
public file roots without launching a second concurrent pack. The separate release-preparation
command still performs `npm pack --ignore-scripts --dry-run --json` after the build.

## Verification

- `npm run typecheck` — passed.
- `npm run lint` — 74 files passed.
- `npm run build` — passed.
- `npm test` — 42 files passed; 265 tests passed and 19 platform/live tests skipped.
- `npm run test:cov` — the same 42 files and 265 tests passed; coverage was 86.35% statements,
  81.23% branches, 96.88% functions, and 90.76% lines.
- `npm run verify:workflow-action-pins -- --online` — all 11 unique actions resolved.
- `npm audit --audit-level=high` — zero vulnerabilities.
- `npm pack --ignore-scripts --dry-run --json` — exact `@aihq/scan@0.3.0`, filename
  `aihq-scan-0.3.0.tgz`, unpacked size 1,520,808 bytes.
- `git diff --check` — passed.

Publication remains blocked on a merged release-preparation PR, green required checks on its exact
current-main SHA, and the repository-required full-SHA owner authorization.
