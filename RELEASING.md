# Releasing AIH Scanner

`@aihq/scan` is the Apache-2.0 Scanner package. A `v-scan-X.Y.Z` tag on the
exact current `main` commit starts `.github/workflows/release.yml`. The workflow
uses a read-only `verify-and-pack` job to re-run repository verification, pack
once, record the tarball SHA256 digest, smoke-install the exact tarball in a
disposable root, and upload only that tarball. The protected `npm-publish` job
downloads the artifact by ID, verifies GitHub's artifact digest plus the
original tarball digest and packed identity, and runs no Scanner package code.
It then produces a tarball-scoped SPDX SBOM and GitHub build attestation, signs
a checksum reconstructed from the trusted digest, re-observes current `main`
and the tag, publishes the same tarball with npm provenance, and
creates the GitHub Release.

Scanner evidence is not organization authority. A release makes Scanner bytes
publicly obtainable with provenance; it does not approve a subject, create a
Core decision, establish an organization trust root, or prove successful Core
custody.

## Current release and steady-state custody

Exact `@aihq/scan@0.1.4` is public on npm from immutable tag
`v-scan-0.1.4` and source `3c84f4decc804e19a876d0120e2ece439bda8229`.
The registry exposes signatures and npm provenance, and the five-asset GitHub
Release binds the same tarball at SHA-256
`801249dee266b7280f1b587022e11556d639f2f578e8e6a726874fa0355d8ec7`.
Independent verification covered the registry and Release tarballs, GitHub
attestation, registry signatures/attestations, disposable install, and
`aih-scan --help`, and `aih-scan project-core-evidence --help`. Source,
package-manifest, or local-tarball state alone is never publication evidence;
use the live checks in the README.

Exact `0.1.1` remains public with its bounded recovery evidence. Its authorized
release run published the tarball, then failed because checkout-free `gh release
create` omitted `--repo`. Recovery run `32903155702` completed the five-asset
Release without republishing. Immutable `v-scan-0.1.0` separately passed
read-only verification before npm refused the protected publish with `EOTP`.
Preserve every immutable tag and all failed and recovery runs as audit evidence;
never delete, move, or reuse a tag.

The one-use bootstrap source is absent. The GitHub bootstrap secret is absent.
Current `.github/workflows/release.yml` rejects nonempty `NODE_AUTH_TOKEN` and
`NPM_TOKEN`, accepts only an unambiguous stable npm CLI at or above `11.5.1`, and
publishes through GitHub OIDC. The least-privilege binding is active and can be
re-observed with npm CLI 11.15.0 or newer:

```sh
npm trust github @aihq/scan --file release.yml --repo samartomar/aih-scan --env npm-publish --allow-publish
npm trust list @aihq/scan
```

The observed tuple names `samartomar/aih-scan`, workflow `release.yml`,
environment `npm-publish`, and allows only `npm publish`. The protected
environment is tag-only and secret-free, package settings require 2FA and
disallow traditional/bypass tokens, and the old bootstrap token is revoked.
Every future release still requires full-SHA publication authorization.
Environment, ruleset, credential, tag, and trusted-publisher mutations are not
source-code changes and require their own authorization.

## Recovered 0.1.1 Release evidence

The bounded one-use `.github/workflows/recover-v-scan-0.1.1.yml` path completed
successfully in run `32903155702` and is no longer present on `main`. Its
read-only job verified the authorized `0.1.1` source, original release run,
retained artifact ID and service digest, exact tarball identities, npm identity,
immutable tag, original GitHub build attestation, and missing Release. Its
protected job received only that rehashed tarball, ran no Scanner package code,
could not call `npm publish`, and repeated live tag/npm/Release checks immediately
before signing and Release creation.
The Release retains the original tag-run build attestation. Its checksum is
newly signed under the
`recover-v-scan-0.1.1.yml@refs/heads/main` certificate identity, and the Release
notes record the exact recovery workflow source SHA. Independent verification
confirmed the five-asset set, every checksum, exact retained tarball SHA-256
`ac80c7a2254d796aa30e489f6c3b7c2b72afa1194a3e5ed9e31a128b8e7ae8ec`,
recovery certificate identity, original tag/source attestation, and exact SBOM
subject. The recovery signature must not be described as the original tag-run
checksum signature.

## Normal release

1. Re-observe the issue/milestone and current npm state. Prerelease versions
   publish to `next`, while stable versions publish to `latest`.
2. Ensure `package.json` and `package-lock.json` name the exact version and the
   public README documents the shipped behavior.
3. Run, sequentially:

   ```sh
   npm run typecheck
   npm run lint
   npm run build
   npm test
   npm run test:cov
   npm run verify:workflow-action-pins -- --online
   npm audit --audit-level=high
   npm pack --ignore-scripts --dry-run --json
   git diff --check
   ```

4. Merge the release candidate and wait for every required `main` check.
5. Obtain full-SHA publication authorization using the exact statement:

   ```text
   Authorize publishing @aihq/scan@X.Y.Z from <full-main-SHA> as v-scan-X.Y.Z.
   ```

6. Tag only that unchanged current-main commit, then push the tag normally:

   ```sh
   git tag v-scan-X.Y.Z <full-main-SHA>
   git push origin v-scan-X.Y.Z
   ```

7. Confirm the read-only `verify-and-pack` job is green, then approve the
   protected `npm-publish` environment. That job rechecks artifact custody and
   live `main`/tag state before publication. Drive both jobs to terminal, then
   verify the published result from a disposable consumer:

   ```sh
   version=X.Y.Z # replace with the exact authorized release version
   npm view "@aihq/scan@$version"
   npm install --save-exact "@aihq/scan@$version"
   npm audit signatures
   gh release download "v-scan-$version" --repo samartomar/aih-scan --pattern "aihq-scan-$version.tgz"
   release_sha="$(gh api "repos/samartomar/aih-scan/git/ref/tags/v-scan-$version" --jq .object.sha)"
   gh attestation verify "./aihq-scan-$version.tgz" --repo samartomar/aih-scan --signer-workflow samartomar/aih-scan/.github/workflows/release.yml --source-ref "refs/tags/v-scan-$version" --source-digest "$release_sha" --deny-self-hosted-runners
   npx --no-install aih-scan --help
   ```

Compare `release_sha` to the separately authorized full SHA. Also download the
GitHub Release's `SHA256SUMS.txt`, cosign bundle, provenance bundle, and SBOM;
verify the checksum, keyless signature, and SBOM subject before claiming the
release complete.

## Failure and immutability

Once a tag or npm version exists, never delete, move, or reuse the tag or
version. Preserve the failed run as audit evidence, correct the defect on a new
reviewed commit/version, and fix forward. A green tag workflow is not evidence
of organization authority, evidence acceptance, or a successful Core effect.

If npm publication succeeds before a later workflow step fails, npm package
existence is the cleanup trigger. Remove the bootstrap credential and source
path before repairing missing GitHub Release evidence. For `0.1.1`, both are
absent, the missing Release was recovered, and the one-use recovery workflow was
removed. Retain its terminal run as audit evidence.
