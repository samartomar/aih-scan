# AIH Scanner (`@aihq/scan`)

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

`@aihq/scan` captures and verifies bounded scanner evidence without deciding
whether an organization should approve, install, or activate the scanned
subject. The V2 path has one code-owned execution capability,
`cisco-oci-v1`, which can run either the built-in Cisco identity or an
organization-defined exact detector registration in a pinned Linux `amd64`
OCI image against an explicitly selected source closure. Registration does not
load organization code into the Scanner process or grant governance authority.

> Core governs. Scan produces evidence. Catalog provides AIH qualification.
> The organization provides authority.

## Status

The public `@aihq/scan@0.2.1` release contains the V2 library, `aih-scan` CLI,
strict detector-registration grammar, detached bundle format, Ed25519 DSSE
signing, Linux `amd64` OCI CI chain, Core organization-evidence projection, and
bounded baseline-vet execution. The fixed `aih-baseline-v1` profile emits
canonical receipt and annex records and separates `baseline-vet`,
`baseline-sign`, and `baseline-verify`. Projection and baseline evidence are
transport only; neither qualifies, approves, admits, observes, installs, or
activates a subject. Exact `@aihq/scan@0.2.1` is public from immutable tag
`v-scan-0.2.1` and source
`5172cc5352c2eaa7d47a72fa7558acaf13073995`.
The registry exposes signatures and npm provenance. Independent verification
matched the registry and five-asset GitHub Release tarballs at SHA-256
`7a6f81de1b26078cbe6fdfdeba9c282aaad83cf5049651fb59fc91b1ccc80191`,
verified the exact-tag GitHub attestation, installed the registry package in a
disposable root, audited npm signatures/attestations, and passed both
`aih-scan --help`, `aih-scan project-core-evidence --help`, and all three
baseline command help paths. Source state alone never proves publication; the
live checks below establish custody. Public package custody is not organization
evidence custody.

The one-use bootstrap source and GitHub environment secret are absent. The
protected environment is tag-only and secret-free. npm Trusted Publishing is
bound to `samartomar/aih-scan`, workflow `release.yml`, environment
`npm-publish`, and allows only `npm publish`; bypass tokens are disallowed and
the old bootstrap token is revoked. The current workflow rejects npm token
credentials and publishes through GitHub OIDC only. The one-use recovery
workflow was removed after success; its terminal run and the original failed
publication runs remain durable audit evidence. See [RELEASING.md](RELEASING.md).
The new package line starts at `0.1.0` to describe its current maturity; it does
not inherit the frozen Core legacy package's historical major version.

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
npm run test:cov
npm run build
npm pack
```

Install the resulting tarball into a disposable consumer:

```sh
npm install --save-dev /path/to/aihq-scan-0.2.1.tgz
npx aih-scan --help
```

The package exports only the V2 API from `@aihq/scan`. Internal V1 modules are
implementation details and are not package export paths.

For an exact candidate, publication custody is proven only when every live
registry and Release check below succeeds. Until full custody exists, at least
one leg fails; after publication every leg must succeed. Source never decides
the result:

```sh
version=0.2.1
npm view "@aihq/scan@$version" name version dist --json
npm install --save-exact "@aihq/scan@$version"
npm audit signatures
release_root="$(mktemp -d)"
gh release download "v-scan-$version" --repo samartomar/aih-scan --dir "$release_root"
release_sha="$(gh api "repos/samartomar/aih-scan/git/ref/tags/v-scan-$version" --jq .object.sha)"
(cd "$release_root" && sha256sum --strict --check SHA256SUMS.txt)
cosign verify-blob "$release_root/SHA256SUMS.txt" --bundle "$release_root/SHA256SUMS.txt.sigstore.json" --certificate-identity "https://github.com/samartomar/aih-scan/.github/workflows/release.yml@refs/tags/v-scan-$version" --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify "$release_root/aihq-scan-$version.tgz" --repo samartomar/aih-scan --bundle "$release_root/provenance.intoto.jsonl" --signer-workflow samartomar/aih-scan/.github/workflows/release.yml --source-ref "refs/tags/v-scan-$version" --source-digest "$release_sha" --deny-self-hosted-runners
npx --no-install aih-scan --help
```

The release workflow builds and smoke-installs the candidate in a read-only job.
Its protected job verifies the workflow-artifact digest, original tarball digest,
and packed identity without executing Scanner package code. It then binds
npm provenance, a GitHub build attestation, an SPDX SBOM, the tarball checksum, and a keyless
cosign checksum bundle to the exact tagged source. `npm view
"@aihq/scan@$version"` is the live registry check; source review or a local
tarball is not publication evidence. Exact `0.1.1` required a bounded recovery
after npm publication, so its checksum bundle has the historical
`recover-v-scan-0.1.1.yml@refs/heads/main` identity while its provenance bundle
remains the original tag-run build attestation. Do not use that recovery
identity for a normal `0.2.1` release or describe either signature as the other.

## Evidence flow

Keep capture, signing, verification, and governance as separate phases:

1. A candidate job builds or obtains the exact registered scanner runtime and
   runs `aih-scan capture` against a disposable target. The selected
   registration names one code-owned adapter capability and binds the exact
   runtime, adapter, configuration, execution profile, platform, SBOM,
   provenance, and broker identities. It has no signing or repository-write
   authority.
2. A signing job reads the completed detached bundle and signs its exact
   candidate and annex identities. It does not run Docker or the candidate
   scanner.
3. An administrator verifies the DSSE signature, detached bundle, expected
   source and CI claims, validity window, replay state, and signer identity
   against roots supplied outside the evidence bundle.
4. For an organization signer and successful scan, the administrator may
   project those already verified facts into Core's exact canonical
   `OrganizationEvidenceEnvelopeV1` contract.
5. An administrator uses Core's structured Workbench UI to generate and protect
   a PolicyBundle V2 file that binds the exact evidence and decision; an
   optional GitHub-attested V3 workflow remains available. Scanner output does
   not approve findings or grant installation, runtime projection, or activation
   authority.

### Core baseline-vet boundary

Scanner owns the bounded analyzer-execution half of baseline vetting. Core still
owns catalog selection, reuse, interpretation, finding dispositions, vendor-lock
and ECC-preview assembly, qualification, and organization policy. Maintainer
analyzer-offload runners provide execution capacity only; they grant no approval
authority.

Core creates one canonical `BaselineVetRequestV1` for an exact source and at
most 100 components. The fixed `aih-baseline-v1` profile requires native,
SkillSpector, and Semgrep observations for every component and Cisco for every
component declared as Skill content. Callers cannot weaken that floor or supply
commands, image names, runtime paths, adapters, targets, approvals, or effects.
Scanner acquires each required analyzer once per exact source, verifies the
pinned SkillSpector image and bundled uv locks/versions, uses hardened Docker and
lock-backed uv execution against the canonical PyPI index, re-observes every
source/component digest after the run, and writes one canonical
content-addressed receipt with detached annexes. The execution host needs Docker,
Bubblewrap, `uv`, and root-provisioned Python 3.13 on Linux.
The private analyzer snapshot preserves an exact relative source symlink only
when every raw path segment resolves inside the source root to an already
validated regular file or directory. Absolute, drive-relative, UNC, backslash,
escaping, dangling, chained, excluded `.git`, and cyclic targets fail closed.
Component hashing remains stricter: any symlink inside a selected component is
rejected before analyzer execution.
The Scanner runtime invokes the root-provisioned `/usr/bin/docker`,
`/usr/bin/bwrap`, `/usr/local/bin/uv`, and
`/usr/bin/python3.13` paths directly; it does not discover Python through the
ambient `PATH`, `HOME`, or uv environment variables. It
uses Docker's local `default` context, and terminates analyzer process groups as
one unit. Semgrep and Cisco run as PID 1 inside Bubblewrap user/PID/mount namespaces
with an empty explicit environment, no host user-manager socket, nested user
namespaces disabled, and a Scanner-owned runtime ceiling. Network is enabled only
for locked, no-build wheel acquisition, where the hostile source is not mounted,
the working directory is the bundled project, and `PYTHONSAFEPATH=1`; analyzer
execution receives the source only inside a private network namespace. Scanner acquires the exact
digest-addressed public SkillSpector image with an isolated empty Docker client
configuration and allows `uv` to acquire only the distributions selected and
hashed by the bundled lock; neither route accepts caller-provided registries,
images, commands, or configuration.

```sh
npx aih-scan baseline-vet \
  --request /path/to/canonical-baseline-request.json \
  --source /path/to/exact-pinned-source \
  --output /path/to/new-baseline-observation-bundle
```

That first command produces an unsigned observation bundle, not portable trusted
evidence. Keep the organization evidence key out of the analyzer process. In a
separate protected step, sign the exact canonical request and bundle, then verify
the signature, trust root, freshness, annexes, request binding, and replay state:

```sh
npx aih-scan baseline-sign \
  --request /path/to/canonical-baseline-request.json \
  --bundle /path/to/baseline-observation-bundle \
  --signer /protected/signer.json \
  --private-key /protected/ed25519-private.pem \
  --claims /protected/claims.json \
  --output /path/to/new-baseline-attestation.json

npx aih-scan baseline-verify \
  --evidence /path/to/baseline-attestation.json \
  --request /path/to/canonical-baseline-request.json \
  --bundle /path/to/baseline-observation-bundle \
  --roots /protected/trust-roots.json \
  --expected /protected/expected-signer-and-time.json \
  --seen /protected/seen-evidence-digests.json
```

The output directory must not exist. It contains only `receipt.json` and the
exact `annex/*.json` files named and hashed by the receipt. Duplicate, missing,
substituted, malformed, truncated, stale, drifted, unknown-profile, and
replay-conflicting states fail closed. A single bundle therefore scales to 100
requested components without importing 100 evidence files or rerunning the same
analyzer 100 times. Core must independently verify the request, receipt, annexes,
source identity, analyzer floor, and replay state before normalizing facts.
An unsigned receipt cannot satisfy the public completion contract. Scanner
evidence remains preflight evidence throughout even after organization-key
authentication; it never qualifies, approves, installs, or activates a
component.

Organization-class `baseline-sign` custody is Linux-only. It opens the bundle
and annex directories through protected `/proc/self/fd` descriptors, requires
them to be owned by the signer account and not group/world-writable, and copies
the bounded canonical bytes into process-private memory before signing. The
optional baseline replay file has the exact shape
`{"digests":["<accepted-evidence-sha256>"],"receipts":[{"requestSha256":"<request-sha256>","receiptSha256":"<accepted-receipt-sha256>"}]}`;
both envelope replay and conflicting receipts for one request fail closed.

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

`--output` must not already exist. A built-in Cisco request binds:

- the canonical Cisco OCI layout and exact image/config digests;
- the source root and selected relative closure paths;
- analyzer, adapter, runtime, configuration, and execution-profile identities;
- digest-bound SBOM and provenance annex files;
- the broker identity.

An organization-defined request replaces the top-level `runtime` and `broker`
fields with `registration` and `detectorId`. `registration` has the strict
authoring shape below; every digest is 64 lowercase hexadecimal characters and
the OCI reference must end in the same manifest digest:

```json
{
  "protocol": "DetectorRegistrationV1",
  "registrations": [
    {
      "detector": {
        "detectorId": "detector.example.policy",
        "analyzerIdentity": "native.0123456789ab",
        "ociImage": {
          "reference": "local.invalid/aih-scan/cisco@sha256:<manifest-sha256>",
          "sha256": "<manifest-sha256>"
        },
        "adapter": {
          "identity": "adapter.0123456789ab",
          "sha256": "<adapter-sha256>"
        },
        "observationConfigurationSha256": "<configuration-sha256>",
        "executionProfileSha256": "<execution-profile-sha256>",
        "supportedPlatforms": [{ "os": "linux", "architecture": "amd64" }],
        "sbom": { "mediaType": "application/spdx+json", "sha256": "<sbom-sha256>" },
        "provenance": {
          "mediaType": "application/vnd.in-toto+json",
          "sha256": "<provenance-sha256>"
        }
      },
      "runtime": {
        "sourceReference": "local.invalid/aih-scan/cisco@sha256:<manifest-sha256>",
        "sourceSha256": "<manifest-sha256>",
        "configSha256": "<image-config-sha256>"
      },
      "adapterCapability": "cisco-oci-v1",
      "broker": { "identity": "broker.0123456789ab", "capability": "cisco-oci-v1" }
    }
  ]
}
```

The selected `detectorId` need not appear in an AIH-maintained catalog. The
code-owned `detector.cisco` identity is reserved for the direct built-in path
and cannot be claimed by an organization registration. The current adapter
requires the selected image to be loaded under the canonical
local execution alias shown above; the registration, OCI layout, loaded image,
SBOM, and provenance still bind its exact organization-chosen bytes. Scanner
does not fetch or execute an arbitrary registry reference. The registration is
strict, canonically hashed, deterministically ordered, capped at 128 entries
and 512 KiB, and rejects duplicate IDs, mutable OCI references, unsupported
platforms, unknown fields, digest mismatches, and unknown adapter capabilities.
The V2 candidate records the selected identity under the neutral
`scanner.detector` field and binds the complete registration digest. It does
not claim that every registered entry ran.

The only executable capability is the checked-in `cisco-oci-v1` adapter. An
organization may select its own exact compatible OCI detector runtime and
evidence identities, but cannot supply JavaScript, a command line, a host path,
or another adapter implementation for Scanner to execute. A new execution
capability requires reviewed Scanner code and tests.

The capture command seals the source before and after execution and refuses a
changed source, link/reparse escape, hard link, oversized input or output,
timeout, truncated process output, nonzero scanner result, or incomplete
container cleanup. It also safely re-reads the capture request after execution
and before bundle creation, refusing changed canonical request bytes. Docker
runs with no network, a read-only root filesystem,
no added capabilities, `no-new-privileges`, a non-root user, bounded CPU,
memory, process count, temporary storage, and output.

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

## Project verified evidence for Core

After successful verification, write one canonical Core evidence envelope:

```sh
npx aih-scan project-core-evidence \
  --evidence /path/to/evidence.json \
  --bundle /path/to/capture-bundle \
  --roots /path/to/admin-roots.json \
  --expected /path/to/expected-policy.json \
  --seen /path/to/replay-identities.json \
  --subject-digest sha256:<exact-core-subject-digest> \
  --output /path/to/new-core-evidence.json
```

Public `@aihq/scan@0.2.1` exposes the same command surface through
`aih-scan project-core-evidence --help`.

`--seen` is optional; all other options are required exactly once. The command
repeats the complete V2 verification before writing anything. It accepts only
an organization-class signer and a successful scan, and it refuses an existing
output, linked output parent, malformed or mismatched evidence, stale validity,
replay, incomplete annex custody, changed source, failed cleanup, or a failed or
refused scan.

The caller supplies the exact canonical Core subject digest. Scanner binds that
digest to the verified evidence, candidate, payload, source-seal, and annex
identities, but it neither derives the Core subject nor decides whether the
organization should associate that evidence with it. The output validity comes
only from the signed scan claims. Its deterministic attestor binds the verified
organization signer identity and key id. The `0.2.1` stdout reports
`envelopeSha256`, the raw output-file hash, and `organizationEvidenceDigest`, Core's domain-separated
qualification digest. Enter `organizationEvidenceDigest`—not
`envelopeSha256`—in Policy Workbench's organization-evidence digest field. The
must-not-exist output file is the evidence handoff, and the caller must preserve
its custody until a separate authorized Core decision binds that exact
qualification digest.

Core still requires exact organization authority and an exact decision before
the envelope can qualify anything. The default Enterprise path is the protected
PolicyBundle V2 file generated by Core's Workbench and supplied through an
absolute `AIH_ORG_POLICY` path outside the governed target. The administrator's
OS or MDM must make that file read-only to the AIH process; optional
GitHub-attested V3 authority remains available. A matching live observation or
registered AIH-managed effect is a further boundary. Evidence projection alone
is never effective state.

## What the evidence means

Verification establishes that:

- the DSSE signature is valid for the exact canonical in-toto payload under an
  administrator-supplied Ed25519 root;
- the payload binds the detached candidate, source seals, selected detector,
  registration and code-owned adapter capability, runtime and configuration
  identities, platform, raw facts, coverage, annex digests, cleanup result,
  signer, and expected claims;
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

- Registered execution capability: `cisco-oci-v1` only. Organizations can bind
  their own exact compatible detector identities and OCI bytes; Scanner does
  not dynamically load arbitrary adapters.
- Qualified capture platform: Linux `amd64` only.
- Source tree: at most 4,096 entries, 16 MiB per file, and 256 MiB total.
  The canonical `SourceSealV2` record is also capped at 512 KiB. Selected
  files appear in both the complete file inventory and the selected-closure
  binding, so long paths or large selected closures can reach the canonical
  record cap before the entry or aggregate-byte limits.
- Detached annex: at most 16 MiB per annex; the Cisco bundle requires raw,
  SBOM, and provenance annexes.
- Scanner process: 120-second command timeout, 64 KiB per stdout/stderr stream,
  16 MiB SARIF output, then bounded termination and cleanup.
- The package emits evidence facts only. It does not provide catalog promotion,
  organization approval, installation, runtime/effect projection, revocation
  custody, or publication authority.
- Exact public `0.2.1` has an immutable tag, npm registry signatures and
  provenance, a verified five-asset Release, a passing disposable install, and
  an independently observed least-privilege Trusted Publisher. The protected
  environment is tag-only and secret-free, bypass tokens are disallowed, and
  the old bootstrap token is revoked.

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
npm run verify:workflow-action-pins -- --online
npm audit --omit=dev
git diff --check
```

The packed compatibility proof additionally requires
`AIH_SCAN_CORE_SOURCE` to be the filesystem path of a clean Core checkout whose
HEAD is exactly `6130dd837b8e8bd41e999fb40733e0e460e69720`. Its manifest still
identifies as `@aihq/core@0.1.1`, but it is a post-`0.1.1` compatibility fixture
rather than the public package. Public `@aihq/core@0.2.0` and immutable tag
`v-core-0.2.0` carry the released Workbench handoff from later source
`0d63a9853bd51072a5108eee21013d5fb8a8472b`; the cold lock preserves the exact
schema bytes Scanner targets:

```sh
AIH_SCAN_CORE_SOURCE=/path/to/exact-clean-core-checkout \
  npm run verify:cold-core-evidence
```

The proof builds and packs that exact locked Core source, packs the
`@aihq/scan@0.2.1` source, installs both tarballs in
disposable roots, captures a catalog-absent organization detector through the
registered adapter boundary, signs and independently verifies the resulting V2
bundle, projects the evidence, validates the exact packaged Core schema, and
uses the packed Core Workbench form to generate a protected policy file, and
invokes packed Core's real `policy resolve` command. Without the protected file
the same request refuses `authority-unverified`; with it, Core verifies the
authority, accepts the exact envelope as `organization-qualified`, and stops
honestly at `observation-missing` without an effect. The deterministic runner,
generated organization-class key, and generated policy are disposable test
mechanics—not human approval, public attestation, production authority, or a
production effect.

The completed public clean-machine acceptance used `@aihq/core@0.2.0` and
`@aihq/scan@0.1.3` from npm in a disposable installed root. Exact public
`@aihq/scan@0.2.1` carries bounded baseline-vet execution, safely preserves
validated in-root relative source symlinks in private analyzer snapshots, and
independently passes its release-custody checks. The complete cross-package
acceptance is repeated after the corresponding Core release; it is not
publication authority.

Never run AIH product behavior against this repository checkout. Tests exercise
scanner behavior only against disposable fixture roots.

## License

[Apache-2.0](LICENSE). Scanner evidence and software are provided on an "AS IS"
basis without organization approval, qualification, warranty, support, or effect
authority.
