# aih-scan rule router

Read `ai-coding/rules/agent-behavior-core.md` and `ai-coding/project.md` before
implementation. For repository helper tooling, also read
`ai-coding/rules/repo-ai-tools.md`; for commits and CI, read
`ai-coding/rules/git-ci-discipline.md`.

## Repository facts

- TypeScript/Node.js, npm, ESM, Vitest, and Biome.
- This is private and publication-deferred. It has a private GitHub remote,
  dormant internal contracts, and a caller-fed Cisco facts adapter, but no
  scanner CLI, public API, container/process/registry execution, or release
  lifecycle.
- Never run an installed aih-scan against this checkout.

## Verification

Use `npm run typecheck`, `npm test`, `npm run lint`, and `npm run build` as
direct repository checks. `npm run repo:init` creates ignored local tooling
state; inspect its dry run first. `npm run repo:doctor` proves that local setup,
not product behavior.
