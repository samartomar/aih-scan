# Releasing AIH Scanner

`@aihq/scan` is the Apache-2.0 Scanner package. A `v-scan-X.Y.Z` tag on the
exact current `main` commit starts `.github/workflows/release.yml`. The workflow
re-runs repository verification, packs once, hashes and smoke-installs that
exact tarball, produces an SPDX SBOM and GitHub build attestation, signs the
checksum with keyless cosign, publishes the same tarball through npm trusted
publishing, and creates the GitHub Release.

Scanner evidence is not organization authority. A release makes Scanner bytes
publicly obtainable with provenance; it does not approve a subject, create a
Core decision, establish an organization trust root, or prove successful Core
custody.

## First-package bootstrap

The `@aihq/scan` package has not been published. npm's trusted-publisher
contract requires that the package must already exist before an owner can bind
GitHub OIDC. That makes the first registry creation an exceptional owner action.
Do not fall back to an unprovenanced local publish.

For the first version:

1. Merge and fully verify the exact release candidate.
2. Obtain full-SHA publication authorization naming `@aihq/scan@0.1.0` and the
   exact `main` SHA.
3. If npm still refuses a pre-publication trust binding, stop and prepare a
   separately reviewed, exact-SHA, one-use GitHub bootstrap path using an
   owner-controlled short-lived credential and the protected `npm-publish`
   environment. The bootstrap must publish the exact reviewed tarball with npm
   provenance; it must not become a standing token lane.
4. Immediately after the package exists, remove the bootstrap path and credential,
   then bind the steady-state trusted publisher with npm CLI 11.5.1 or newer:

   ```sh
   npm trust github @aihq/scan --file release.yml --repo samartomar/aih-scan --env npm-publish --allow-publish
   npm trust list @aihq/scan
   ```

   The observed tuple must name samartomar/aih-scan, workflow `release.yml`, environment `npm-publish`,
   and `npm publish` permission. Then require 2FA and disallow traditional tokens
   in the package settings.

The owner must also create the GitHub `npm-publish` environment with a required
reviewer and protect immutable `v-scan-*` tags. Environment, ruleset, credential,
tag, and trusted-publisher mutations are not source-code changes and require
their own authorization.

## Normal release

1. Re-observe the issue/milestone and current npm state. A stable `0.1.0` cut is
   preferred unless an RC is justified; prerelease versions publish to `next`,
   while stable versions publish to `latest`.
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
5. Obtain the exact authorization statement:

   ```text
   Authorize publishing @aihq/scan@X.Y.Z from <full-main-SHA> as v-scan-X.Y.Z.
   ```

6. Tag only that unchanged current-main commit, then push the tag normally:

   ```sh
   git tag v-scan-X.Y.Z <full-main-SHA>
   git push origin v-scan-X.Y.Z
   ```

7. Approve the protected `npm-publish` environment and drive the release run to
   terminal. Verify the published result from a disposable consumer:

   ```sh
   npm view @aihq/scan@0.1.0
   npm install --save-exact @aihq/scan@0.1.0
   npm audit signatures
   gh attestation verify ./node_modules/@aihq/scan --repo samartomar/aih-scan
   npx --no-install aih-scan --help
   ```

Also download the GitHub Release's `SHA256SUMS.txt`, cosign bundle, provenance
bundle, SBOM, and tarball; verify the checksum and keyless signature before
claiming the release complete.

## Failure and immutability

Once a tag or npm version exists, never delete, move, or reuse the tag or
version. Preserve the failed run as audit evidence, correct the defect on a new
reviewed commit/version, and fix forward. A green tag workflow is not evidence
of organization authority, evidence acceptance, or a successful Core effect.
