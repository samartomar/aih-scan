# Repository contract

`aih-scan` is a public-remote, npm-published TypeScript/Node.js
repository that builds the `@aihq/scan@0.1.3` V2 package and `aih-scan`
CLI. V2 captures one registered Cisco Linux `amd64` OCI path, seals and
re-observes a disposable source, emits a complete detached candidate/annex
bundle, signs canonical DSSE/in-toto evidence with Ed25519, and verifies exact
claims against caller-supplied roots and replay state. Normal CI locks the
contract to exact Core source
`6130dd837b8e8bd41e999fb40733e0e460e69720`, whose manifest remains
`@aihq/core@0.1.1`, plus the Strict V2 decision and
organization-evidence schema artifacts. An organization-signed, successful,
already verified V2 attestation
can be projected into one canonical Core organization-evidence envelope that
binds the caller-selected exact Core subject plus the verified evidence,
candidate, payload, source, signer, and annex identities. Its deterministic
attestor uses the existing Decision V2 stable-identifier grammar so the packed
Core Workbench can bind the exact evidence without raw JSON authoring. The
envelope remains evidence only and supplies no decision, qualification,
observation, or effect authority. A separate three-job OCI
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
evidence custody. Source `0.1.3` is an unpublished candidate until a separate
exact-SHA publication authorization and successful release prove otherwise.
The Core lock is likewise an unpublished post-`0.1.1` Core source candidate;
public `@aihq/core@0.1.1` and `v-core-0.1.1` are immutable at
`26ecc6686eef560cdee86c5ae1fccb2927e5a10c` and cannot reproduce the updated
packed Workbench handoff.

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
