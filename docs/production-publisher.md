# Restricted Scan report publisher

The reusable frozen seven-source operation is described in [production refresh](production-refresh.md).
Both manual workflows require the exact reviewed main commit, repository and owner IDs,
first run attempt and dispatcher `stomar-tech` (GitHub user 333589491). Merges do not dispatch them.
Only the `scan-report-signing-prod` signer receives OIDC and attestation-write permissions.
Candidate acquisition and assembly have read-only authority. Actions finishes with
`scan-refresh-final-publication`; it has no release-write job. Final immutable release
transport uses the normal maintainer's existing `gh` authentication, without extracting
or exporting credentials. External Actions are full-commit pinned.

The maintained signing identity remains
`https://github.com/samartomar/aih-scan/.github/workflows/scan-report-publisher.yml@refs/heads/main`,
issuer `https://token.actions.githubusercontent.com`, repository ID `1336836161`, owner ID `9993940`.
The exact independently maintained `.github/scan-report-trust.json` bytes and public Sigstore
roots remain unchanged. The certificate policy pins signer URI, GitHub-hosted runner,
repository/owner identity, main ref, top-level caller, manual event and public visibility.
Package consumers still select their own trust; this operational policy is not a runtime default.

The current branch protection requires the unique `verify` check, administrator enforcement,
stale-approval dismissal and resolved conversations, and prevents force pushes/deletion.
It currently requires zero PR approvals and does not require code-owner or latest-push approval.
CODEOWNERS records ownership; it does not establish an enforced approval requirement.
The signing environment is main-only with reviewer `samartomar`, prevent-self-review enabled
and administrator bypass disabled. Reobserve these actual settings before activation.
The dispatcher and reviewer accounts belong to one human. Account and permission separation
preserves the existing role/protection boundary and does not establish independent human review.
Dispatcher access and the protected environment's human approval remain external activation gates.
The immutable-release setting must be enabled before any report-release write is admitted.
Its administration-read endpoint is queried by the normal maintainer route; the workflow's
contents-read token cannot establish this setting. Disabled settings or permission refusal
stop publication before any release write. The operation never changes repository settings.

The operator independently selects the successful publisher run, first attempt, reviewed
current main head, immutable final artifact ID/service digest, manifest/selection digests,
and independently prepared reader installation digest. The final CLI checks normal operator
`samartomar`, repository identity, current main, exact publisher workflow/dispatcher and all
three run artifacts before downloading the selected archive. It verifies the raw service ZIP
digest and bounds, refuses unsafe/duplicate/linked/extra entries, and authenticates every
supplied assessment using exact retained package/lock bytes and maintained independent trust.
The reader's actual runtime and installation remain separate from frozen Linux execution claims.
See [production refresh](production-refresh.md) for the closed selection and CLI arguments.

`publish-final.mjs` is the production entrypoint. The former `publish-refresh-release.mjs`
command always refuses; its lower-level exports exist for boundary fixtures. The separately
published `publication-custody.json` binds final selectors, service ZIP bytes, original receipt,
package/lock, trust and actual verifier identity without changing the original receipt or inventory.

The original one-shot template, detached-statement helper, promotion helper, historical reader
and historical production proof remain available as compatibility evidence. They do not
establish success for a current frozen batch. A durable partial inventory retains all seven
sources, including no-ID diagnostics and unsigned/refused rows. Retirement acceptance still
requires every target to have a complete, authenticated assessment for the declared profile,
or an explicit owner decision addressing a refusal or profile change.

This operation does not allocate a version or publish an npm package. Clear the reviewed-head
admission variable after the authorized bounded operation reaches a terminal state, preserving
all selected immutable IDs, digests, published bytes and failed-run evidence.
