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

Exact `@aihq/scan@0.1.1` is public on npm from immutable tag
`v-scan-0.1.1` and source `a1f3541cf36af7a128d4ce4554a4b6bbc3d53fa8`.
The registry exposes signatures and npm provenance. The authorized release run
published the exact tarball, then failed because its checkout-free `gh release
create` command omitted `--repo`; the GitHub Release and assets are absent. The
immutable `v-scan-0.1.0` attempt separately passed read-only verification before
npm refused the protected publish with `EOTP`. Preserve both tags and failed runs
as audit evidence; never delete, move, or reuse the tag.

The one-use bootstrap source is absent. The GitHub bootstrap secret is absent.
Current `.github/workflows/release.yml` rejects nonempty `NODE_AUTH_TOKEN` and
`NPM_TOKEN`, accepts only an unambiguous stable npm CLI at or above `11.5.1`, and
publishes through GitHub OIDC. The owner must still bind the steady-state trusted
publisher with npm CLI 11.15.0 or newer and revoke the npm token:

```sh
npm trust github @aihq/scan --file release.yml --repo samartomar/aih-scan --env npm-publish --allow-publish
npm trust list @aihq/scan
```

The observed tuple must name `samartomar/aih-scan`, workflow `release.yml`,
environment `npm-publish`, and `npm publish` permission. Future Scanner tags remain blocked
until that binding and token revocation are independently observed. Finally require
2FA and disallow traditional tokens in the package settings. Environment,
ruleset, credential, tag, and trusted-publisher mutations are not source-code
changes and require their own authorization.

## Exact 0.1.1 Release-evidence recovery

`.github/workflows/recover-v-scan-0.1.1.yml` is a bounded one-use recovery path.
It is fixed to the authorized `0.1.1` source, original release run, retained
artifact ID and service digest, original tarball SHA-256/SHA-1/integrity, and npm
identity. Its read-only job verifies those facts, the exact immutable tag, the
original GitHub build attestation, and an exact missing-Release observation. Its
protected job receives only that rehashed tarball, runs no Scanner package code,
cannot call `npm publish`, repeats live tag/npm/Release checks immediately before
each public effect, and uses an explicit `--repo` plus `--verify-tag` to create
the Release.
The Release retains the original tag-run build attestation. Its checksum is
newly signed under the
`recover-v-scan-0.1.1.yml@refs/heads/main` certificate identity, and the Release
notes record the exact recovery workflow source SHA; that signature must not be
described as the original tag-run checksum signature. After success, verify
every asset and remove the one-use recovery workflow in a reviewed cleanup.

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
already absent and only the exact bounded recovery workflow may create the
missing Release.
