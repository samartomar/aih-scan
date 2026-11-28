# Releasing AIH Scan

`@aihq/scan` is the Apache-2.0 Scan package. The replacement tag `v0.1.0` and
the established `v-scan-X.Y.Z` tags for other versions trigger
`.github/workflows/release.yml`. The tag must identify the exact current `main`
commit. The read-only `verify-and-pack` job checks the source, builds and packs
once, records the tarball SHA-256, runs the tests with the locked analyzers and
the exact tarball, smoke-installs it in a disposable root, and uploads only
that tarball. The protected `npm-publish` job
downloads the artifact by ID, verifies GitHub's artifact digest plus the
original tarball digest and packed identity, and runs no Scanner package code.
It then produces a tarball-scoped SPDX SBOM and GitHub build attestation, signs
a checksum reconstructed from the trusted digest, re-observes current `main`
and the tag, publishes the same tarball with npm provenance under `next`, and
creates a prerelease GitHub Release. It never changes `latest`.

Scan results are not organization authority. A release makes Scan bytes publicly
obtainable with provenance; it does not approve or block any content, and its results
inform the person or organization that decides whether to install.

## The 0.1.0 replacement package

`0.1.0` is the replacement content-assessment package. Its local candidate is
one exact `npm pack` tarball whose SHA-256 and source commit are
recorded with the installed-package test (`tests/package-install.test.ts`) run against
that tarball. Building, testing and recording a local tarball does not publish it.

The replacement package requires the exact tag `v0.1.0`. The immutable historical
tag `v-scan-0.1.0` already exists and retains its original source and evidence.
Before cutting the replacement release, verify that the `npm-publish` deployment
policy admits the exact new tag and that a tag ruleset protects it against update
and deletion. Retain the existing protections on historical tags and on the
publication environment.

## Report signing

Report signing is separate from package release. The manual
[report workflows](docs/production-publisher.md) scan reviewed pinned sources with the
packed CLI (`scan-report-candidate-upload.yml`) and sign the reviewed summaries with
`aih-scan sign` (`scan-report-publisher.yml`). The signer job runs in
`.github/workflows/scan-report-publisher.yml` on `main`, so its keyless certificate carries
the default trusted publisher identity (`defaultSigners`). Both workflows admit only the
reviewed main commit, sole maintainer `samartomar`, the first run attempt and selected
immutable candidate custody; the signer also requires protected human approval in the
`scan-report-signing-prod` environment. Source integration does not run either workflow,
establish protected settings or authorize signing. Report signing does not publish this
package.

## Historical release custody

Exact `@aihq/scan@0.2.1` is public on npm from immutable tag
`v-scan-0.2.1` and source `5172cc5352c2eaa7d47a72fa7558acaf13073995`.
The registry exposes signatures and npm provenance, and the five-asset GitHub
Release binds the same tarball at SHA-256
`7a6f81de1b26078cbe6fdfdeba9c282aaad83cf5049651fb59fc91b1ccc80191`.
Independent verification covered the registry and Release tarballs, GitHub
attestation, registry signatures/attestations, disposable install, and
`aih-scan --help`, `aih-scan project-core-evidence --help`, and the three
baseline command help paths. Source,
package-manifest, or local-tarball state alone is never publication evidence;
verify each historical artifact using its original tag and source SHA.

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

1. Re-observe the issue/milestone and current npm state. Reconcile every merged
   PR since the previous tag with exactly one `semver:none|patch|minor|major`
   label. `semver:none` rides the train without requesting package bytes; an
   all-`none` train cannot be cut. Related package-bearing work accumulates in
   one release PR. Do not create an immediate release for ordinary docs, CI, or
   low-impact cleanup; [VERSIONING.md](VERSIONING.md) defines the hotfix triggers.
2. For the replacement cut use the agreed `0.1.0` version and `v0.1.0` tag.
   For later trains compute the version from the highest package-bearing class
   and use `v-scan-X.Y.Z`. Ensure `package.json` and `package-lock.json` name the
   exact version and the public README documents the shipped behavior.
3. Run, sequentially:

   ```sh
   npm run typecheck
   npm run lint
   npm run build
   npm test
   npm run test:cov
   npx vitest run tests/host-v1/real-analyzers.test.ts tests/package-install.test.ts  # with the locked analyzer runtimes provisioned (docs/DEVELOPMENT.md)
   npm run verify:workflow-action-pins -- --online
   npm audit --audit-level=high
   npm pack --ignore-scripts --dry-run --json
   git diff --check
   ```

4. Merge the release candidate and wait for every required `main` check.
5. Obtain full-SHA publication authorization using the exact statement:

   ```text
   Authorize publishing @aihq/scan@X.Y.Z from <full-main-SHA> as <release-tag>.
   ```

6. Tag only that unchanged current-main commit, then push the tag normally:

   ```sh
   tag=v0.1.0 # replace with v-scan-X.Y.Z for a later train
   git tag "$tag" <full-main-SHA>
   git push origin "refs/tags/$tag"
   ```

7. Confirm the read-only `verify-and-pack` job is green, then approve the
   protected `npm-publish` environment. That job rechecks artifact custody and
   live `main`/tag state before publishing under npm `next` and creating a
   prerelease GitHub Release. Drive both jobs to terminal, then verify the public
   candidate from a disposable consumer:

   ```sh
   version=0.1.0 # replace with the exact authorized release version for a later train
   npm view "@aihq/scan@$version"
   npm install --save-exact "@aihq/scan@$version"
   npm audit signatures
   gh release download "$tag" --repo samartomar/aih-scan --pattern "aihq-scan-$version.tgz"
   release_sha="$(gh api "repos/samartomar/aih-scan/git/ref/tags/$tag" --jq .object.sha)"
   gh attestation verify "./aihq-scan-$version.tgz" --repo samartomar/aih-scan --signer-workflow samartomar/aih-scan/.github/workflows/release.yml --source-ref "refs/tags/$tag" --source-digest "$release_sha" --deny-self-hosted-runners
   npx --no-install aih-scan --help
   ```

Compare `release_sha` to the separately authorized full SHA. Also download the
GitHub Release's `SHA256SUMS.txt`, cosign bundle, provenance bundle, and SBOM;
verify the checksum, keyless signature, and SBOM subject before claiming the
candidate publication complete. Then run the installed-package test against the
registry tarball (`AIH_SCAN_PACKED_TARBALL=<downloaded tarball> npx vitest run
tests/package-install.test.ts`) from a checkout of the tagged commit. Source checkout or
local tarball execution cannot satisfy this gate. Consumer applications' acceptance is
separate and theirs.

8. After that acceptance, obtain separate promotion authorization:

   ```text
   Authorize promoting @aihq/scan@X.Y.Z from next to latest after installed acceptance of <full-main-SHA>.
   ```

9. Promote the same bytes without rebuilding or republishing, then re-observe:

   ```sh
   npm dist-tag add @aihq/scan@X.Y.Z latest
   npm dist-tag rm @aihq/scan next
   gh release edit "$tag" --repo samartomar/aih-scan --prerelease=false --latest
   npm view @aihq/scan dist-tags --json
   ```

Only this promoted stable train is the supported default. Release notes state whether
adoption is no action, recommended, required by date, or security urgent.

## Failure and immutability

Once a tag or npm version exists, never delete, move, or reuse the tag or
version. Preserve the failed run as audit evidence, correct the defect on a new
reviewed commit/version, and fix forward. Never promote a candidate that fails public
installed acceptance. A green tag workflow is not evidence
of organization authority or of any consumer's acceptance.

If npm publication succeeds before a later workflow step fails, npm package
existence is the cleanup trigger. Remove the bootstrap credential and source
path before repairing missing GitHub Release evidence. For `0.1.1`, both are
absent, the missing Release was recovered, and the one-use recovery workflow was
removed. Retain its terminal run as audit evidence.
