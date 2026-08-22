# Repository contract

`aih-scan` is a private-remote, publication-deferred TypeScript/Node.js
repository that builds the public-ready `@aihq/scan` V2 package and `aih-scan`
CLI. V2 captures one registered Cisco Linux `amd64` OCI path, seals and
re-observes a disposable source, emits a complete detached candidate/annex
bundle, signs canonical DSSE/in-toto evidence with Ed25519, and verifies exact
claims against caller-supplied roots and replay state. Normal CI locks the
contract to the exact Core Strict V2 schema artifact. A separate three-job OCI
workflow captures, signs with a test-ephemeral key, and independently verifies
one generated public fixture.

Internal V1 contracts remain implementation details and are not package export
paths. Scanner facts never decide qualification, finding disposition, approval,
installation, projection, or adoption. SBOM/provenance annexes remain
`digest-bound-unverified`, broker enforcement remains `unverified`, and signing
claims are signer-asserted with no OIDC provenance. The private GitHub remote
and npm package are not published; visibility and publication remain separate
owner gates.

## Commands

- `npm run typecheck`
- `npm test`
- `npm run lint`
- `npm run build`
- `npm pack`
- `npm run repo:init`
- `npm run repo:doctor`

The repository uses npm, ESM, TypeScript, Vitest, and Biome. The committed canon
is manual; never run an installed aih-scan against this checkout.
