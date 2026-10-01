# Restricted publisher candidate

The publisher and trust files under `.github/workflow-templates/` are **inert
candidates**. They are outside `.github/workflows`, expose no runtime default
trust, and cannot run on a merge. Software integration does not activate signing,
publish an npm package or establish authenticated report publication.

The chosen future signer identity is
`https://github.com/samartomar/aih-scan/.github/workflows/scan-report-publisher.yml@refs/heads/main`,
issuer `https://token.actions.githubusercontent.com`, repository ID `1336836161`,
owner ID `9993940`. Candidate DER constraints additionally pin signer URI,
GitHub-hosted runner, repository/owner URI, source ref, top-level caller workflow,
manual trigger and public visibility. No smoke workflow identity is selected.
The public Sigstore root snapshot is independently retained review data; the
candidate record does not make it activated maintained publisher trust.

Untrusted scanning occurs separately with no `id-token` or attestation-write
permissions. `tools/artifact/prepare-candidate.mjs RUN_RESULT NEW_DIRECTORY`
validates a retained result and produces unsigned `artifact.json`, detached
`statement.json` and a digest manifest. It writes into its owned stage, refuses
existing destinations and never signs. Upload statement and unsigned artifact as
separate named workflow artifacts `scan-detached-statement` and
`scan-unsigned-artifact`. The operator reviews their exact run, statement hash,
Scan ID and nonempty-annex bytes before a signing request.

The publisher candidate downloads only detached statement data into its signer.
Trusted `check-statement.mjs` verifies the independently reviewed hash, 128 KiB
ceiling and closed minimal statement, then derives only subject digest/predicate.
The managed action signs that fixed production predicate. No scanner, report,
target checkout or candidate-supplied executable is imported into the signer.
Trusted final assembly separately obtains the unsigned artifact and bundle;
`verify-promotion.mjs` independently authenticates all bytes under selected trust
before writing/uploading an authenticated output. Failed authentication produces
no promoted file. The flow has no signing token in its final assembly job.

Activation requires an explicit owner-approved operation that first protects
`main` and workflow/trust changes, creates dedicated `scan-report-signing-prod`
with required independent reviewer, prevents self review/admin bypass and limits
deployment branches to `main`, fixes `SCAN_REPORT_REVIEWED_HEAD` to the reviewed
full commit, and reviews exact workflow/trust/root bytes. An existing baseline
environment must not be assumed protected. Missing certificate constraints fail
closed; an environment OID is not assumed emitted by the managed action.

Only after those settings and signing are separately authorized may the exact
candidate be activated for a bounded manual run. Retain a real production-format
artifact with at least one nonempty annex and verify it through the packed offline
consumer, including exact issuer/SAN/OIDs, original statement bytes, changed-annex
refusal, invalid/missing root/witness refusal, identity ambiguity and historical
verification after real leaf expiry. Research bundles cannot satisfy that gate.
Until that evidence exists, production acceptance remains open.
