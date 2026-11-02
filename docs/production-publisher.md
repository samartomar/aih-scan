# Report workflows and the default trusted publisher

Scan's own published results are produced by two manual workflows. Neither runs on a
push, pull request or merge; source integration does not dispatch them, change protected
settings or authorize signing. Results are stored and served by whoever runs the store;
these workflows only produce and sign the files.

## Default trusted publisher

`verifySummary` trusts only the signers the caller passes in `allowedSigners`. When the
caller passes none, the default list is `defaultSigners` from `@aihq/scan/contracts`: one
entry, `aihq-scan-production`, matched by certificate issuer, subject and these Fulcio
extensions:

| Field | Value |
|---|---|
| Issuer | `https://token.actions.githubusercontent.com` |
| Subject (SAN) and build signer URI (`.9`), build config URI (`.18`) | `https://github.com/samartomar/aih-scan/.github/workflows/scan-report-publisher.yml@refs/heads/main` |
| Runner environment (`.11`) | `github-hosted` |
| Source repository (`.12`), ref (`.14`) | `https://github.com/samartomar/aih-scan`, `refs/heads/main` |
| Repository ID (`.15`), owner (`.16`), owner ID (`.17`) | `1336836161`, `https://github.com/samartomar`, `9993940` |
| Trigger (`.20`), visibility (`.22`) | `workflow_dispatch`, `public` |

Extensions are `1.3.6.1.4.1.57264.1.N`. A matching subject alone is not enough; every
listed extension must match. Passing `allowedSigners` replaces the default (an empty list
trusts nobody). Any other cryptographically valid signature is reported as "signed, not
by a trusted publisher". The workflow file path is part of this identity: renaming or
moving `scan-report-publisher.yml` changes what the default identity can sign.

## Candidate: `scan-report-candidate-upload.yml`

Dispatched with the exact reviewed sources JSON, whose SHA-256 must equal the repository
variable `SCAN_REPORT_SOURCES_SHA256`. Each source is a public GitHub repository at a full
commit (optionally one item path) or an npm package at an exact version
(`tools/publisher/candidate.mjs sources` validates them). The job packs the reviewed main
commit once, installs that tarball in a fresh consumer, provisions the locked SkillSpector
and Cisco runtimes from `tools/analyzers`, and runs the installed
`aih-scan scan <source> --origin published --json --out …` for every source in static
mode. It uploads the unsigned `scan-report-candidate` artifact (the output folders, each
source's scan result, the sources and the scanner tarball's SHA-256). It has read-only
repository permission and no OIDC token.

## Signing: `scan-report-publisher.yml`

Dispatched with the reviewed candidate run ID and the SHA-256 of the reviewed selection
listing (`<sha256>  <path>` per `summary.json`, in path order). Repository variables name
the reviewed head, candidate run, artifact ID and digest, and selection digest; the
inputs must equal them.

1. `bounded-candidate` (read-only) first builds and packs the exact CLI, installs its
   runtime dependencies in a fresh folder from the committed lockfile
   (`npm ci --omit=dev --ignore-scripts`), unpacks the CLI there and uploads that runtime
   with its SHA-256 as a job output, all before any candidate step. It then checks the
   candidate run's custody with `tools/publisher/candidate.mjs check-run` (one successful
   first-attempt `workflow_dispatch` run of the candidate workflow on the reviewed main
   head, by `samartomar`, with exactly the selected unexpired artifact and digest),
   downloads the artifact by ID with digest checking, selects the reviewed summaries
   (`candidate.mjs select`, which refuses links, a changed summary or a different listing)
   and reads each with `aih-scan read`.
2. `signer` runs in the protected `scan-report-signing-prod` environment with
   `id-token: write` only. It checks out, installs and builds nothing: it checks the
   runtime's SHA-256 against the read-only job's output and runs only that CLI. It
   rechecks the listing and every summary digest, signs each
   summary with `aih-scan sign` (GitHub Actions OIDC, public Fulcio and Rekor), and
   verifies each bundle with `aih-scan verify` under the default signers, requiring
   `verified`, a trusted signer and no withdrawal. It uploads `scan-report-signed`: the
   summaries, their SARIF and `summary.sigstore` bundles (`aih-sigstore-keyless/1`
   messageSignature bundles).

Both jobs admit only public repository visibility, repository `samartomar/aih-scan`
(ID `1336836161`, owner ID `9993940`), `refs/heads/main`, this workflow ref, the reviewed
head, dispatcher and triggering actor `samartomar`, and the first run attempt. The sole
maintainer initiates the run and supplies the protected environment approval, including
for their own run; this does not establish independent human review. External actions are
pinned to full commits.

## Owner-controlled operations

Choosing sources, revisions and the store layout, setting the repository variables,
protecting the signing environment, dispatching either workflow and publishing signed
results are operations the owner authorizes separately. Clear the reviewed-head variable
after an authorized operation reaches a terminal state. Withdrawals
(`aih-scan-withdrawn/1`) are signed the same way with `aih-scan sign <withdrawn.json>`.
