# Development

[AGENTS.md](../AGENTS.md) owns agent instructions. Use npm ci, focused tests while
editing, then npm run verify (typecheck, lint, build, tests, and pinned-action verification).
Run any additional contract/evidence checks required by the touched workflow.
Resolve current commands from package.json and protected CI, not cached task notes.

Use Node `>=24.15.0 <25` for the assessment host API and repository checks.
The installed-package test exercises `@aihq/scan/contracts`, `/read`, `/host`
and the versioned schema exports from a packed tarball in a temporary consumer.
It also loads the portable entry graph without Node globals or built-ins.
Assessment tests use temporary source fixtures; never scan the source checkout.

The default CI verifies Scan independently. Historical V2 Core projection checks
remain available for that API, but they do not define the immutable assessment
contract. Authentication fixtures establish only their documented scope; production
publisher activation needs the separate steps in
[production-publisher.md](production-publisher.md).

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
bytes to `latest`.

The complete release runbook is [RELEASING.md](../RELEASING.md).

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

## Ordinary CI selection

The required `verify` job always reports on PRs and main pushes. Feature-branch
pushes do not duplicate PR runs; superseded ordinary CI runs are cancelled.
Publisher, signing, release and native-admission workflows keep their own routing.

`node tools/ci-route.mjs --base <40-character-base> --head <40-character-head> --plan ci-plan.json`
records the selected scope. `node tools/ci-route.mjs --run-tests ci-plan.json`
runs that selection and propagates failures. Documentation edits run lint, action
pin verification and routing checks. Known artifact/refresh tooling selects its
module checks; source changes include affected package consumers or coverage.
The real Python proof follows the baseline runtime's local import closure and
host subprocess helpers. The packed seven-source refresh follows refresh tooling
and its dynamically loaded public host/read/contracts entries. Analyzer resources,
shared contracts, dependencies, build/workflow/routing changes and unknown paths
retain full validation. Deleted/renamed paths, missing history and empty change
sets also fail closed to full validation. Conditional and data-loaded dependencies
outside these known boundaries must receive explicit routing or full fallback.

The `CI` workflow's manual `full_validation` input defaults to true and preserves
coverage plus both real-runtime proofs. `npm run verify` remains the complete local
software check; ordinary focused checks do not claim its coverage or native-runtime
results. CI records the plan in its job summary. The required status fails if any
selected check fails; it never treats a failed selected check as inapplicable.
