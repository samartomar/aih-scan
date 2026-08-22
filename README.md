# `@aihq/scan`

`@aihq/scan` captures and verifies bounded scanner evidence without deciding
whether an organization should approve, install, or activate the scanned
subject. The current V2 path covers one registered detector: the Cisco scanner
running in a pinned Linux `amd64` OCI image against an explicitly selected
source closure.

## Status

The V2 library, `aih-scan` CLI, detached bundle format, Ed25519 DSSE signing,
and Linux `amd64` Cisco CI chain are implemented and tested in this repository.
The repository is still private and `@aihq/scan` has not been published to npm.
Repository visibility and npm publication require separate owner approval; the
commands below can be exercised from a local checkout or a reviewed package
tarball before then.

The GitHub Actions example signs with a generated `test-ephemeral` key and
uploads that public root beside the evidence. It proves the capture, signing,
and verification mechanics. It is not an organization trust root or public
qualification authority.

## Install and verify the package boundary

Node.js 20 or newer is required.

```sh
npm ci --ignore-scripts
npm run typecheck
npm run lint
npm test
npm run build
npm pack
```

Install the resulting tarball into a disposable consumer:

```sh
npm install --save-dev /path/to/aihq-scan-1.0.0.tgz
npx aih-scan --help
```

The package exports only the V2 API from `@aihq/scan`. Internal V1 modules are
implementation details and are not package export paths.

## Evidence flow

Keep capture, signing, verification, and governance as separate phases:

1. A candidate job builds or obtains the exact registered scanner runtime and
   runs `aih-scan capture` against a disposable target. It has no signing or
   repository-write authority.
2. A signing job reads the completed detached bundle and signs its exact
   candidate and annex identities. It does not run Docker or the candidate
   scanner.
3. An administrator verifies the DSSE signature, detached bundle, expected
   source and CI claims, validity window, replay state, and signer identity
   against roots supplied outside the evidence bundle.
4. A separate governance decision may use the verified facts. Scanner output
   does not approve findings or grant installation, projection, or activation
   authority.

The repository workflow at
`.github/workflows/cisco-oci-equivalence.yml` is the complete current capture
example. It builds the pinned Cisco runtime twice for OCI-layout and local
Docker identity equivalence, scans a generated public fixture offline, creates
a complete bundle, signs it in a separate job, and verifies it in a third job.

## Capture

```sh
npx aih-scan capture \
  --request /path/to/capture-request.json \
  --output /path/to/new-capture-bundle
```

`--output` must not already exist. The strict request binds:

- the canonical Cisco OCI layout and exact image/config digests;
- the source root and selected relative closure paths;
- analyzer, adapter, runtime, configuration, and execution-profile identities;
- digest-bound SBOM and provenance annex files;
- the broker identity.

The capture command seals the source before and after execution and refuses a
changed source, link/reparse escape, hard link, oversized input or output,
timeout, truncated process output, nonzero scanner result, or incomplete
container cleanup. Docker runs with no network, a read-only root filesystem,
no added capabilities, `no-new-privileges`, a non-root user, bounded CPU,
memory, process count, temporary storage, and output.

The current request producer is intentionally specific to the checked-in Cisco
workflow. There is no generic organization-defined detector registration API
in this package yet.

## Sign

Signing requires a completed bundle, an Ed25519 private key, a public signer
projection, and exact claims:

```sh
npx aih-scan sign \
  --bundle /path/to/capture-bundle \
  --signer /path/to/signer.json \
  --private-key /protected/path/to/ed25519-private.pem \
  --claims /path/to/claims.json \
  --output /path/to/new-evidence.json
```

`signer.json`:

```json
{"class":"organization","identity":"example-admin","keyId":"ed25519:<sha256-of-SPKI-DER>"}
```

`claims.json` has the following closed shape:

```json
{
  "repository": "owner/repository",
  "workflow": ".github/workflows/evidence.yml",
  "issuer": "https://token.actions.githubusercontent.com",
  "sourceRef": "refs/heads/main",
  "commit": "0123456789abcdef0123456789abcdef01234567",
  "environment": "evidence-signing",
  "runId": "123456789",
  "runAttempt": 1,
  "signedAt": "2026-08-22T17:00:00.000Z",
  "expiresAt": "2026-08-22T18:00:00.000Z"
}
```

The validity window must be positive and no longer than 24 hours. On POSIX,
the CLI refuses a private-key file accessible by group or other users. Do not
commit private keys. Windows ACL enforcement and hardware-backed/HSM signing
are outside the current CLI contract.

## Verify

```sh
npx aih-scan verify \
  --evidence /path/to/evidence.json \
  --bundle /path/to/capture-bundle \
  --roots /path/to/admin-roots.json \
  --expected /path/to/expected-policy.json \
  --seen /path/to/replay-identities.json
```

`admin-roots.json` is supplied independently by the administrator:

```json
{
  "roots": [
    {
      "identity": "example-admin",
      "class": "organization",
      "keyId": "ed25519:<sha256-of-SPKI-DER>",
      "publicKeySpkiBase64": "<canonical-base64-SPKI-DER>"
    }
  ]
}
```

`expected-policy.json` repeats every signed claim exactly and adds:

```json
{
  "now": "2026-08-22T17:30:00.000Z",
  "subjectSha256": "<exact-source-tree-sha256>",
  "signer": {
    "identity": "example-admin",
    "class": "organization",
    "keyId": "ed25519:<sha256-of-SPKI-DER>"
  }
}
```

The full file also contains all fields from `claims.json`; extra or missing
fields are rejected. The optional replay file has the shape
`{"identities":["<previous-replay-identity>"]}`. Persist an accepted
`replayIdentity` in administrator-owned state before accepting another copy.

Successful verification prints canonical JSON facts. It does not print
`PASS`, approval, a finding disposition, or an activation decision.

## What the evidence means

Verification establishes that:

- the DSSE signature is valid for the exact canonical in-toto payload under an
  administrator-supplied Ed25519 root;
- the payload binds the detached candidate, source seals, Cisco runtime and
  configuration identities, platform, raw facts, coverage, annex digests,
  cleanup result, signer, and expected claims;
- the detached candidate and all annex bytes are present and match their
  descriptors;
- the evidence is current at the caller-supplied time and has not appeared in
  the supplied replay state.

Current SBOM and provenance annexes are labeled `digest-bound-unverified`.
Broker enforcement is labeled `unverified`. GitHub claims are
`signer-asserted` with provenance `none`; this package does not verify an OIDC
token or GitHub certificate. An administrator must obtain signer roots and
expected claims through an independent trusted process.

## Limits

- Registered scanner path: Cisco only.
- Qualified capture platform: Linux `amd64` only.
- Source tree: at most 4,096 entries, 16 MiB per file, and 256 MiB total.
- Detached annex: at most 16 MiB per annex; the Cisco bundle requires raw,
  SBOM, and provenance annexes.
- Scanner process: 120-second command timeout, 64 KiB per stdout/stderr stream,
  16 MiB SARIF output, then bounded termination and cleanup.
- The package emits evidence facts only. It does not provide catalog promotion,
  organization approval, installation, runtime projection, revocation custody,
  repository publication, or npm publication.

Organizations are not required to use an AIH-maintained catalog entry. The
Core Strict V2 contract can bind organization-qualified evidence for an exact
tool, skill, MCP server, package, or profile; catalog membership remains an
optional qualification source rather than admission authority.

## Development verification

```sh
npm run typecheck
npm run lint
npm test
npm run build
npm audit --omit=dev
git diff --check
```

Never run AIH product behavior against this repository checkout. Tests exercise
scanner behavior only against disposable fixture roots.
