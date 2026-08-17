# Repository contract

`aih-scan` is a private, publication-deferred TypeScript/Node.js repository.
It contains dormant internal strict JSON, source observation, evidence, manifest,
and unverified attestation contracts, plus a caller-fed Cisco SARIF facts adapter.
There is no public export, scanner CLI, container/process/registry execution,
network integration, signing authority, remote, or publication setup.

## Commands

- `npm run typecheck`
- `npm test`
- `npm run lint`
- `npm run build`
- `npm run repo:init`
- `npm run repo:doctor`

The repository uses npm, ESM, TypeScript, Vitest, and Biome. The committed canon
is manual; never run an installed aih-scan against this checkout.
