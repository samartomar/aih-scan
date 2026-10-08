# Restricted Scan report publisher

The reusable frozen seven-source operation is described in [production refresh](production-refresh.md).
Both manual workflows require the exact reviewed main commit, repository and owner IDs,
first run attempt and dispatcher `stomar-tech` (GitHub user 333589491). Merges do not dispatch them.
Only the `scan-report-signing-prod` signer receives OIDC and attestation-write permissions.
Candidate acquisition and assembly have read-only authority; final immutable release publication
has contents-write authority and no signing token. External Actions are full-commit pinned.

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

The original one-shot template, detached-statement helper, promotion helper, historical reader
and historical production proof remain available as compatibility evidence. They do not
establish success for a current frozen batch. A durable partial inventory retains all seven
sources, including no-ID diagnostics and unsigned/refused rows. Retirement acceptance still
requires every target to have a complete, authenticated assessment for the declared profile,
or an explicit owner decision addressing a refusal or profile change.

This operation does not allocate a version or publish an npm package. Clear the reviewed-head
admission variable after the authorized bounded operation reaches a terminal state, preserving
all selected immutable IDs, digests, published bytes and failed-run evidence.
