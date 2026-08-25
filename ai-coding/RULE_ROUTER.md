# aih-scan rule router

Read `ai-coding/rules/agent-behavior-core.md` and `ai-coding/project.md` before
implementation. For repository helper tooling, also read
`ai-coding/rules/repo-ai-tools.md`; for commits and CI, read
`ai-coding/rules/git-ci-discipline.md`.

## Repository facts

- TypeScript/Node.js, npm, ESM, Vitest, and Biome.
- This has a public GitHub remote, while npm publication remains deferred. It
  builds the `@aihq/scan@0.1.1` V2 API and `aih-scan` CLI for one bounded Cisco
  Linux `amd64` OCI capture/sign/verify chain. Internal V1 contracts are not
  public package exports, and scanner evidence has no qualification, approval,
  installation, or adoption authority.
- Never run an installed aih-scan against this checkout.

## Verification

Use `npm run typecheck`, `npm test`, `npm run lint`, and `npm run build` as
direct repository checks. `npm run repo:init` creates ignored local tooling
state; inspect its dry run first. `npm run repo:doctor` proves that local setup,
not product behavior.
