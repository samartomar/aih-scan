# Development

[AGENTS.md](../AGENTS.md) owns agent instructions. Use `npm ci --ignore-scripts`, focused
tests while editing, then `npm run verify` (typecheck, lint, build, tests and
pinned-action verification) and `npm run test:cov` (80% statement, branch, function and
line thresholds). Resolve current commands from package.json and protected CI, not cached
task notes.

The package range is Node `>=24.15.0 <25 || >=26.12.1 <27`. Repository CI and release
verification run on Node 24.

Tests use temporary fixture folders, local fixture services (a Git answerer, an npm
registry, an OSV service, Fulcio and Rekor built on a test-only certificate universe) and
harmless execution sentinels. Never scan the source checkout. No test contacts a live
service or a paid AI provider.

## Installed-package test

`tests/package-install.test.ts` is the primary acceptance seam. It packs one tarball (or
uses the exact tarball named by `AIH_SCAN_PACKED_TARBALL`), installs it in fresh temporary
consumers and uses only the public `@aihq/scan/host`, `/read`, `/contracts`, the schema
exports and the `aih-scan` bin: every CLI path (`scan` of a folder, Git repository, npm
package, npm tarball and `mcp-url:`; `read`; `findings`; `verify`; `sign`; `advisories`;
`--fail-at` exits; cancellation), the portable `/read` and `/contracts` graph in a realm
without Node globals or built-ins (including the shared Sigstore vectors and
`checkAdvisories`), and refusal of the retired exports and formats. A test-only `--import`
preload (`tests/support/installed-fixture-preload.mjs`) points the installed CLI's Git,
npm registry, OSV, Fulcio and Rekor traffic at those local services.

## Analyzer runtimes

SkillSpector 2.13.2 and Cisco skill-scanner 2.3.2 are locked in `tools/analyzers/<tool>`
(`pyproject.toml` + `uv.lock`). Provision them outside `PATH`:

```sh
UV_PROJECT_ENVIRONMENT="$HOME/.cache/aih-scan/skillspector" \
  uv sync --project tools/analyzers/skillspector --locked --no-install-project
UV_PROJECT_ENVIRONMENT="$HOME/.cache/aih-scan/cisco-skill-scanner" \
  uv sync --project tools/analyzers/cisco-skill-scanner --locked --no-install-project
```

Ordinary tests never run an installed analyzer: `vitest.config.ts` sets
`AIH_SCAN_SKILLSPECTOR=none` and `AIH_SCAN_SKILL_SCANNER=none`. The real proofs
(`tests/host-v1/real-analyzers.test.ts` and the installed-package test's analyzer case)
run when `AIH_SCAN_TEST_SKILLSPECTOR` and `AIH_SCAN_TEST_SKILL_SCANNER` name the
provisioned executables (`<env>/bin/skillspector`, `<env>/bin/skill-scanner`; on Windows
`<env>\Scripts\<name>.exe`). With `unshare -rn` available they run without a network.
`AIH_SCAN_REQUIRE_REAL_ANALYZERS=1` makes a missing runtime a failure instead of a skip.

## Regenerating fixtures

- Corpus (`tests/fixtures/scan-v1`): `AIH_SCAN_UPDATE_CORPUS=1 npx vitest run tests/host-v1/corpus.test.ts`.
- Sigstore vectors (`tests/fixtures/sigstore-v1`):
  `AIH_SCAN_UPDATE_SIGSTORE_VECTORS=1 npx vitest run tests/read-v1/verify-summary.test.ts`.
- Published schemas (`schemas/`): `AIH_SCAN_UPDATE_SCHEMAS=1 npx vitest run tests/contracts-v1/schema-files.test.ts`.
- Trust snapshot: `node tools/write-sigstore-trust-snapshot.mjs <trusted_root.json>` with an
  independently authenticated Sigstore trusted root; then update `verification.trustSnapshot`.
- Package identity: `npm run generate:identity` (part of `npm run build`).

## CI and release boundaries

The local pre-commit hook runs typecheck, lint, and tests. It is inactive until a clone
enables it with `git config core.hooksPath .githooks` (or `npm run repo:init`, which also
installs the optional helpers below); installing dependencies does not enable it. CI runs
`npm run verify:workflow-action-pins` and an `actionlint` job over `.github/workflows`.
Biome lints `tools/**/*.mjs` but does not format them. Any CI added here may
perform only read-only verification and must not run repository initialization.

Every PR carries exactly one `semver:none|patch|minor|major` label. Repository-only
changes marked `semver:none` cannot start a release. Package-bearing work accumulates
in one coherent train. The tag workflow publishes only under npm `next`; public
installed acceptance and separate owner authorization precede promotion of the same
bytes to `latest`. The complete release runbook is [RELEASING.md](../RELEASING.md); the
manual report workflows are described in [production-publisher.md](production-publisher.md).

## Ordinary CI selection

The required `verify` job always reports on PRs and main pushes. Superseded ordinary CI
runs are cancelled. Report and release workflows keep their own routing.

`node tools/ci-route.mjs --base <40-character-base> --head <40-character-head> --plan ci-plan.json`
records the selected scope. `node tools/ci-route.mjs --run-tests ci-plan.json` runs that
selection and propagates failures. Documentation edits run lint, action-pin verification
and routing checks. Publisher tooling selects its own tests. Source outside the shared
entries selects coverage; source in the analyzer adapters' import graph and the analyzer
locks also select the real analyzer proofs, which provision the locked runtimes and run
`tests/host-v1/real-analyzers.test.ts` and `tests/package-install.test.ts`. Shared
contracts (`src/public`, `src/contracts`, `src/read`, `src/host`, `src/shared`),
dependencies, build/workflow/routing changes and unknown paths retain full validation, as
do deleted or renamed paths, missing history and empty change sets.

The `CI` workflow's manual `full_validation` input defaults to true and runs coverage, the
installed-package test and the real analyzer proofs. The required status fails if any
selected check fails.

## Optional navigation helpers

Use source and tests directly by default. When their navigation benefit is needed,
inspect node tools/repo-ai-tools.mjs plan and npm run repo:init -- --dry-run before
running npm run repo:init. The setup installs pinned helpers, writes an ignored local
Codex projection, enables the repository pre-commit hook, and builds project-scoped
indexes. npm run repo:doctor diagnoses that optional setup; it is not a product gate.
Start a new Codex task after changing its projection.

Pins, enabled tool lists, cache roots, and transport bindings are maintained only in
tools/repo-ai-tools.mjs. Do not duplicate them in docs. Helpers do not install an
engineering workflow. Keep local projections and caches ignored; do not commit them
or delete shared caches to fix one project. Index data is advisory, never authority.
Use Token Optimizer only on demand; no per-task report, coach, or graph prerequisite.
