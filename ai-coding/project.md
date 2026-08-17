# Repository contract

`aih-scan` is a private, publication-deferred TypeScript/Node.js repository.
It implements dormant internal V1 contracts for strict JSON, source sealing and
observations, evidence annexes, scanner manifests, and cryptographically
unverified attestations. It includes a private, internal, opt-in Cisco
linux/amd64 observation probe with an injected runner. The PR/manual Linux
workflow verifies the exact pinned public runtime inputs, warms that runtime,
and verifies their hashes before it runs the probe twice offline against a
generated temporary fixture. The probe seals and re-hashes the source, requires
semantic repeatability, and
retains only bounded sanitized ephemeral artifacts. The Cisco facts adapter and
neutral equivalence test preserve raw facts and bounded annex evidence.

There is no public export, CLI, OCI/container broker, registry publication,
snapshot transport, signing, qualification authority, runtime cutover, policy,
verdict, acknowledgement, or package publication. The private GitHub remote
provides no public API or release surface. Structural `linux/amd64` facts are
not a qualification claim.

## Commands

- `npm run typecheck`
- `npm test`
- `npm run lint`
- `npm run build`
- `npm run repo:init`
- `npm run repo:doctor`

The repository uses npm, ESM, TypeScript, Vitest, and Biome. The committed canon
is manual; never run an installed aih-scan against this checkout.
