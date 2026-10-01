# Restricted Scan report publisher

The manual workflows `.github/workflows/scan-report-candidate-upload.yml` and
`.github/workflows/scan-report-publisher.yml` prepare one reviewed report operation.
Neither runs on a merge. Both refuse admission without the exact reviewed main
commit in `SCAN_REPORT_REVIEWED_HEAD`; their presence does not establish protected
settings, signing authorization, authenticated publication or an npm release.
The original files under `.github/workflow-templates/` remain inert references.

Submit and dispatch from the single authenticated independent account designated
for this operation. The owner is code owner and signing-environment reviewer.

The signer identity is
`https://github.com/samartomar/aih-scan/.github/workflows/scan-report-publisher.yml@refs/heads/main`,
issuer `https://token.actions.githubusercontent.com`, repository ID `1336836161`,
owner ID `9993940`. Exact actor login/ID, initial triggering actor and run attempt
one are enforced in each job. Reruns are refused, including owner-initiated reruns.
All external Actions are full-commit pinned. Candidate acquisition has read-only
repository/Actions permissions; only the protected signer receives `id-token`
and attestation-write permissions.

The independently selected trust file is `.github/scan-report-trust.json`, an
exact-byte copy of the reviewed candidate. Its publisher identity remains
`aihq-scan-production-candidate`; activation does not rename or weaken its policy.
Its DER constraints pin signer URI, GitHub-hosted runner, repository/owner URI,
source ref, top-level caller workflow, manual trigger and public visibility.
Only the reviewed public Sigstore roots are selected, not the GitHub private
instance or research smoke identity. This operational configuration supplies no
runtime default trust to package consumers.

## Protect and review before admitting a run

Protect `main`, including administrators: require a pull request, independent
approval, code-owner review, dismissal of stale approvals, approval of the latest
push, resolved conversations and the unique CI check `verify`. Disallow force
push/deletion and unrestricted bypass. `.github/CODEOWNERS` protects itself,
workflows, independent trust, dependency/TypeScript configuration, executable
source, tools, schemas and artifact boundary tests. The Cisco verification check
has its own display name, `verify-cisco-oci-equivalence`.

Create the dedicated `scan-report-signing-prod` environment with required reviewer
`samartomar`, prevent self review, disable admin bypass and restrict deployment
branches to `main`. No environment secret is required. Reobserve actual settings
and access; another baseline or npm environment does not establish these gates.
After the activation commit is independently reviewed, approved and merged,
set `SCAN_REPORT_REVIEWED_HEAD` to that exact full main commit. An absent or stale
value disables admission. Do not insert a proposed commit or bypass a reviewer.

## One unsigned upload, then one protected signing request

The upload workflow contains only the exact harmless retained data. It performs
no checkout, scan, candidate execution or signing. It rechecks the byte lengths
and SHA-256 values before writing the two files exclusively and uploading them
as separate immutable artifacts. Their retention is 30 days.
This operation's fixed harmless report and complete annex bytes are embedded in
the public upload workflow and are therefore public. Only the minimal detached
statement is submitted to Sigstore; those report/annex bytes are outside its payload.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| artifact.json | 5585 | bac82f592646ca58eaea3eb38c9f48ddd430f4440612ba7ef76a908552d61634 |
| statement.json | 483 | 15844fd0e376154a85a52fc8eb7a6c1b5b1fe906deb62408c2e222afe4cb5e33 |

The immutable Scan ID is
`scan:sha256:fd5e886dc290901110d82ec45e2f444b8fa1b2c05f1bbe7028cbbb4e880bc4dd`.
The complete native annex is 246 bytes, SHA-256
`6096cd35014a208ac6d62d5bb5f80efb0d863a02464d38f440cac7412c3b1ff9`.
The publisher's admission guards fix that statement digest and Scan ID.

Dispatch the upload once at the reviewed main commit. After success, independently
record its actual run and artifact IDs/service digests and populate:

- `SCAN_REPORT_CANDIDATE_RUN_ID`
- `SCAN_REPORT_UNSIGNED_ARTIFACT_ID` and `SCAN_REPORT_UNSIGNED_ARTIFACT_DIGEST`
- `SCAN_REPORT_STATEMENT_ARTIFACT_ID` and `SCAN_REPORT_STATEMENT_ARTIFACT_DIGEST`

IDs are exact positive decimal service IDs; digests use `sha256:` plus 64 lowercase
hex characters. Service archive digests differ from the file digests above. Missing
selection refuses all publisher jobs. Never invent a run or artifact identity.

Dispatch the publisher once with that selected `candidate_run_id`, the exact
`statement_sha256` and `expected_scan_id` above. Before signing, bounded
`check-candidate-run.mjs` validates successful first-attempt manual upload provenance,
exact repository/head/workflow/actor and the two selected immutable artifacts.
It refuses ambiguity, expiry, oversized uploads and mismatching IDs/digests.
Refusals emit only fixed stage codes for selectors, raw run/artifact metadata,
run/actor custody and artifact custody/ambiguity; no input or dependency errors
are echoed. Preserve the code and retained metadata when diagnosing a failed run.
Downloads use exact artifact IDs. Trusted `check-statement.mjs` rechecks the
reviewed detached bytes and closed minimal statement before and inside the signer.

The signer receives only bounded detached statement data, not a scanner, report,
target checkout or candidate executable. The managed public action signs its
fixed subject/predicate. Public witnesses disclose only this minimal statement,
digests/Scan ID and signer metadata; report/annex bytes are outside the payload.
Trusted final assembly separately obtains the unsigned artifact and bundle;
`verify-promotion.mjs` independently authenticates their exact bindings under
selected trust before writing/uploading the authenticated result. Failed
authentication creates no promoted output. Final assembly has no signing token.

## Acceptance and stop conditions

Retain the actual bundle, output and independently selected trust/root bytes.
Verify the production predicate and nonempty annex with the isolated installed
offline consumer: exact issuer/SAN/OIDs and original payload bytes, altered
annex/statement refusal, missing/wrong roots and witnesses, equivalent historical
policy consolidation and disagreement refusal. Reverify after the real leaf
expires using witnessed signing time. Local synthetic/research successes do not
complete this production gate; acceptance stays open until the real proof exists.

Authorize only the recorded upload and one protected signing run. Any failed run
is retained as evidence; another signing attempt requires explicit authorization.
Monitor the run and environment approval, then retain exact output custody.
Disable each manual workflow after its single authorized run reaches a terminal
state. After the publisher terminates, clear `SCAN_REPORT_REVIEWED_HEAD` while
retaining selected IDs/digests and evidence. To stop admission early, clear that
head variable and cancel pending runs before approval. Existing
immutable bytes and failed-run records remain; no deletion or re-signing is an
automatic rollback. This operation does not publish an npm package.
