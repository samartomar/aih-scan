# Restricted Scan report publisher

The reusable frozen seven-source operation is described in [production refresh](production-refresh.md).
The explicit [Catalog input-capture mode](catalog-capture.md) uses the same publisher
and independently maintained trust, with one target and no supplied executable input.
The separate [independent capture batch mode](independent-captures.md) uses up to
seven keyed captures and the same single protected approval and signing capacity.
Both manual workflows require the exact reviewed main commit, repository and owner IDs,
first run attempt and dispatcher `samartomar` (GitHub user 9993940). The triggering actor
must also be `samartomar`. Active freeze, candidate and final custody require both actors'
exact login and numeric ID. Merges do not dispatch these workflows.
Only the `scan-report-signing-prod` signer receives OIDC and attestation-write permissions.
Candidate acquisition and assembly have read-only authority. Actions finishes with
`scan-refresh-final-publication`; it has no release-write job. Final immutable release
transport uses the normal maintainer's existing `gh` authentication, without extracting
or exporting credentials. External Actions are full-commit pinned.
Actions ZIP API downloads negotiate `application/vnd.github+json` while retaining
the redirected ZIP response as exact binary bytes. Release-asset downloads use
`application/octet-stream`; release uploads negotiate JSON responses with a
separate `Content-Type: application/octet-stream` for their original binary body.

## Prepared signing path and caller-selected identity

Scan evidence release signing reuses this manual report publisher. The npm package
release in `release.yml` remains a separate operation; it does not sign Scan reports.
The pinned `actions/attest` action uses ephemeral OIDC credentials and the public
Sigstore service for events whose repository visibility is `public`, with public
transparency-log inclusion and no stored long-lived signing key. The publisher
admits only that exact event visibility, refusing private or missing visibility
before the signer can run. It does not opt into private signing. The existing
first-attempt, reviewed-head, exact-custody and protected human approval gates
remain required. A PR or ordinary main merge cannot dispatch report signing.

This is software preparation only. Integration does not select or protect a new
production signer, populate maintained publisher trust, perform signing, or make
evidence Verified. A later, separately authorized release operation must choose
and protect the complete signer tuple and independently select trust. Existing
maintained trust bytes are unchanged. Documented settings below describe the
historical publisher policy; verify live settings before any authorized operation.

Consumers explicitly pass `trust: { keys, publishers }` to `authenticateArtifact`
from `@aihq/scan/host`. There is no default publisher, and an evidence-adjacent key
or certificate never selects trust. A publisher has `profile: "sigstore-public"`,
a caller-chosen `identity`, `purposes: ["scan-report"]`, independently obtained
`trustedRoot`, and `policy`. The identity is a local attribution label; the
certificate policy determines which signer is accepted.

| Tuple field | Consumer policy and meaning | Documented historical publisher (not a new selection) |
| --- | --- | --- |
| Workflow | Exact workflow path in SAN and top-level caller extension | `.github/workflows/scan-report-publisher.yml` |
| Ref | Exact SAN suffix and source-ref extension | `refs/heads/main` |
| Issuer | `policy.issuer` | `https://token.actions.githubusercontent.com` |
| SAN | Literal `policy.subjectAlternativeName`, not a pattern | `https://github.com/samartomar/aih-scan/.github/workflows/scan-report-publisher.yml@refs/heads/main` |
| Repository | Required immutable repository ID extension; repository URL is also bound by SAN | `samartomar/aih-scan`, ID `1336836161` |
| Owner policy | Required immutable owner ID extension plus workflow admission/protected environment | Owner ID `9993940`; sole maintainer manual dispatch and protected human approval |

`policy.requiredCertificateExtensions` is an array of `{ oid: number[],
valueDerBase64: string }`. Values are base64 of the exact DER-encoded extension
value, not plain text base64. The historical policy uses Fulcio OIDs
`1.3.6.1.4.1.57264.1.N`: `N=11` for `github-hosted`, `14` for the ref,
`15` for repository ID, `17` for owner ID, `18` for the full top-level caller URI,
`20` for `workflow_dispatch`, and `22` for `public`. Keep the entire selected
policy; a matching SAN alone is not equivalent to that policy.

For example, a consumer selecting a hypothetical `example-org/evidence` publisher
would independently choose its workflow and ref, derive the exact SAN such as
`https://github.com/example-org/evidence/.github/workflows/reports.yml@refs/heads/main`,
and select its issuer, immutable repository/owner IDs, additional certificate
constraints and Sigstore roots. These illustrative names are not production trust.
The future owner-selected production tuple may differ from the historical tuple;
this ticket does not choose it or install any example into maintained trust.

## Unchanged statement and summary behavior

The statement remains `https://in-toto.io/Statement/v1`, with exactly one subject:
`scan-report` and its SHA-256 digest. Predicate type
`urn:aihq:scan:artifact-attestation:1.0.0` binds `scanId`, `reportSchema`,
`reportByteLength` and `annexManifestSha256`. There are no item subjects. The
existing artifact container `urn:aihq:scan:artifact:1.0.0` admits report 2.0.0;
items remain bound through derived records and captured report digests.

Offline fixtures exercise the packed public exports with an ephemeral local
certificate/log universe, a nonempty annex, and the unchanged report 2.0.0
statement. They prove caller-selected authentication and refusal for an
unselected SAN and an evidence-adjacent key, plus statement/annex tamper refusal.
They make no OIDC or signing-service request and establish no production trust.

`authenticateArtifact` returns `unverifiable` for an unselected identity; supplying
that host result for the selected assessment to `summariseItem` produces
`not-verified` / `not-authenticated` (row 10). A host reporting selected trust data
as `expired` or `unavailable` produces `not-verified` / `offline` (row 9), including
when authentication was skipped. A historically authenticated bundle can remain
authentic after its leaf certificate expires; current trust-data availability is
a separate host input. Static caller-selected trust remains the default. Any
optional trust-update client belongs to the consumer, not the artifact or this
publisher. See [the current summary decision table](item-summaries.md).

## Historical production identity and operational gates

The documented maintained signing identity remains
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
The single-maintainer signing policy requires a main-only environment with reviewer
`samartomar`, prevent-self-review disabled and administrator bypass disabled. Verify these
actual settings before activation; the operation does not change them. Human approval is
still required: the sole maintainer initiates the run and may approve their own signing job.
This policy does not establish independent human review or require an alternate account.
The protected environment's human approval remains an external activation gate.
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
establish success for a current frozen batch. The legacy `check-candidate-run.mjs` and its
historical dispatcher policy remain unchanged; active batch custody uses
`check-refresh-run.mjs` with the single-maintainer policy above.
A durable partial inventory retains all seven sources, including no-ID diagnostics
and unsigned/refused rows. Retirement acceptance still
requires every target to have a complete, authenticated assessment for the declared profile,
or an explicit owner decision addressing a refusal or profile change.

This operation does not allocate a version or publish an npm package. Clear the reviewed-head
admission variable after the authorized bounded operation reaches a terminal state, preserving
all selected immutable IDs, digests, published bytes and failed-run evidence.
