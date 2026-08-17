# Repository contract

`aih-scan` is a private, publication-deferred TypeScript/Node.js repository.
It implements dormant internal V1 contracts for strict JSON, source sealing and
observations, evidence annexes, scanner manifests, and cryptographically
unverified attestations. Its Cisco adapter accepts caller-fed SARIF and source
file identities only; it emits raw facts and bounded annex evidence without
running a scanner. The neutral Cisco equivalence test independently compares
the shared raw-occurrence semantics with AIH using precomputed SARIF.

There is no public export, CLI, scanner, container/process/registry or network
execution, broker, snapshot transport, signing, qualification, runtime cutover,
or publication setup. The private GitHub remote provides no public API or
release surface. Structural `linux/amd64` facts are not a qualification claim.

## Commands

- `npm run typecheck`
- `npm test`
- `npm run lint`
- `npm run build`
- `npm run repo:init`
- `npm run repo:doctor`

The repository uses npm, ESM, TypeScript, Vitest, and Biome. The committed canon
is manual; never run an installed aih-scan against this checkout.
