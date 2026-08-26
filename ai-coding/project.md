# Repository contract

`aih-scan` is a public-remote, npm-published TypeScript/Node.js
repository that builds the `@aihq/scan@0.1.2` V2 package and `aih-scan`
CLI. V2 captures one registered Cisco Linux `amd64` OCI path, seals and
re-observes a disposable source, emits a complete detached candidate/annex
bundle, signs canonical DSSE/in-toto evidence with Ed25519, and verifies exact
claims against caller-supplied roots and replay state. Normal CI locks the
contract to exact `@aihq/core@0.1.0` package, commit, Strict V2 decision, and
organization-evidence schema artifacts. An organization-signed, successful,
already verified V2 attestation
can be projected into one canonical Core organization-evidence envelope that
binds the caller-selected exact Core subject plus the verified evidence,
candidate, payload, source, signer, and annex identities. The envelope remains
evidence only and supplies no decision, qualification, observation, or effect
authority. A separate three-job OCI
workflow captures, signs with a test-ephemeral key, and independently verifies
one generated public fixture.

Internal V1 contracts remain implementation details and are not package export
paths. Scanner facts never decide qualification, finding disposition, approval,
installation, runtime/effect projection, or adoption. SBOM/provenance annexes remain
`digest-bound-unverified`, broker enforcement remains `unverified`, and signing
claims are signer-asserted with no OIDC provenance. The GitHub remote is public.
Exact `@aihq/scan@0.1.2` is public from immutable tag `v-scan-0.1.2` with npm
signatures/provenance, a verified five-asset GitHub Release, matching tarball
custody, and a passing disposable install/help proof. The protected environment
is tag-only and secret-free; the least-privilege Trusted Publisher allows only
`npm publish`, bypass tokens are disallowed, and the old bootstrap token is
revoked. Source state alone never establishes publication or organization
evidence custody.

## Commands

- `npm run typecheck`
- `npm test`
- `npm run test:cov`
- `npm run lint`
- `npm run build`
- `npm pack`
- `npm run verify:cold-core-evidence` (requires `AIH_SCAN_CORE_SOURCE` at the
  exact clean locked Core commit)
- `npm run repo:init`
- `npm run repo:doctor`

The repository uses npm, ESM, TypeScript, Vitest, and Biome. The committed canon
is manual; never run an installed aih-scan against this checkout.
