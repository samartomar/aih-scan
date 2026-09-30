# Development

[AGENTS.md](../AGENTS.md) owns agent instructions. Use npm ci, focused tests while
editing, then npm run verify (typecheck, lint, build, tests, and pinned-action verification).
Run any additional contract/evidence checks required by the touched workflow.
Resolve current commands from package.json and protected CI, not cached task notes.

## CI and release boundaries

The local pre-commit hook runs typecheck, lint, and tests. Any CI added here may
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
