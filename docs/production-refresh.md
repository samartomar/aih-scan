# Frozen production refresh

The refresh is a finite maintainer operation with three separately reviewed phases:
freeze input, execute the frozen batch, then publish selected assessments. The two
manual workflows run only the reviewed main commit and first run attempt by
`stomar-tech`. Each new invocation needs its own authorization and bounded budget.
This operation does not allocate or publish an npm version.

## Freeze and execute

Prepare the closed input described in [the producer contract](../tools/refresh/README.md).
Use the seven ordered repositories and reviewed full commits. Declare
`independent-linux-v1`, Node `v24.15.0`, Linux x64, every requested detector,
whole-tree selection, explicit exclusions and trust-lint discovery configuration.
Empty `mcpConfigPaths` establishes no MCP server coverage. Cisco/SkillSpector
released rule material is unavailable; Snyk is outside this profile. Native
identity evidence does not establish a security finding.

Set `SCAN_REPORT_REVIEWED_HEAD` to the reviewed main commit and
`SCAN_REFRESH_INPUT_SHA256` to the SHA-256 of the exact dispatch `input_json` UTF-8
bytes. Dispatch `scan-report-candidate-upload.yml` with `phase=freeze`. It builds,
packs and installs Scan without package lifecycle scripts, resolves source identity,
and uploads one `scan-refresh-frozen` artifact containing `manifest.json`,
`scanner.tgz`, `consumer-package-lock.json` and `custody.json`. It does not scan targets.

Review the full manifest and retained package, dependency lock, runtime, profile,
source pins and discovery inputs. Record the successful freeze run ID, reviewed
head, immutable artifact ID, service SHA-256 digest and exact manifest SHA-256.
Set `SCAN_REFRESH_FROZEN_RUN_ID`, `SCAN_REFRESH_FROZEN_ARTIFACT_ID`,
`SCAN_REFRESH_FROZEN_ARTIFACT_DIGEST` and `SCAN_REPORT_MANIFEST_SHA256` from that
review. Dispatch the same workflow with `phase=run`. Source jobs have read-only
repository/Actions authority and no signing token.

The run downloads only the selected freeze artifact after verifying GitHub run
and artifact metadata. It restores the exact tarball and locked dependencies and
requires the full installation digest to match. Windows freeze preparation is
allowed by the CLI, but Windows installation bytes do not establish the Linux
installation or execution tuple. A different installation is refused, not relabeled.
Targets run serially. A complete seven-row inventory with partial assessments or
diagnostic capture failures is retained; a source without a valid assessment has
no Scan ID. Exit 0 means all assessments complete, exit 1 means a completed
truthful partial/diagnostic batch, and exit 2 means custody/preparation failed.
An exit-2 directory is inspection evidence and cannot enter publication.

## Select and publish

The completed candidate contains the original producer inventory and every
result, original unsigned artifact, detached statement and eight-field candidate
record, together with exact package/lock custody. Download and inspect the candidate
with the reviewed tools and installed package:

```sh
node tools/artifact/install-retained-scanner.mjs candidate MANIFEST_SHA scratch/consumer
node tools/artifact/refresh-publication.mjs check candidate scratch/consumer MANIFEST_SHA selection.json
```

Review every source and detector terminal row, scope, resource measurement and the
canonical signing selection. Record the candidate run ID, artifact ID/service
digest, manifest digest and selection digest independently. Set
`SCAN_REPORT_CANDIDATE_RUN_ID`, `SCAN_REPORT_CANDIDATE_ARTIFACT_ID`,
`SCAN_REPORT_CANDIDATE_ARTIFACT_DIGEST`, `SCAN_REPORT_MANIFEST_SHA256` and
`SCAN_REPORT_SELECTION_SHA256`. Dispatch `scan-report-publisher.yml` with matching
`candidate_run_id`, `manifest_sha256` and `selection_sha256`.

Only the protected `scan-report-signing-prod` job receives OIDC/attestation
permissions. It receives bounded detached statements and their independently
selected signing list, rechecks them, and makes at most seven attestations in one
signing run. It receives no target source, report, annex, tarball or candidate
executable. The next job independently attaches and authenticates each supplied
bundle under `.github/scan-report-trust.json`. Bad supplied bundles refuse assembly;
missing bundles remain explicitly unsigned. Partial assessments remain partial.

The final job has contents-write authority and no signing token. It restores the
same installed package, independently reauthenticates the exact selected artifacts
and inventory, and checks the repository immutable-release setting before any
release write. That setting must already be enabled; the workflow does not change
repository protection or settings. It creates a draft release, uploads exclusive
asset names, and publishes only after the complete asset set is present. Existing
equal bytes are a safe retry; changed bytes or a missing asset on a published
release refuse. A failed draft retains completed uploads for bounded recovery.

## Durable discovery and offline acceptance

The report release tag is `scan-report-batch-<batch SHA-256>`, separate from
software releases. Root assets are `manifest.json`, `producer-inventory.json`,
`inventory.json`, `selection.json`, `scanner.tgz`, `consumer-package-lock.json`,
`custody.json` and `publication.json`. Target paths are flattened by replacing `/`
with `--`: for example `targets--anthropics--skills--authenticated.json`.
`publication.json` records original relative paths, asset names, lengths and hashes.
Restore those paths before using the local verifier.

The versioned publication inventory accounts for all seven roster entries. It
retains source diagnostics, every detector terminal row, original measurements,
unsigned/refused rows and successful siblings. Authenticated rows additionally
name exact authenticated artifact bytes and consumer authentication results. The
inventory retains the checked candidate run/head/artifact/service-digest custody
when assembled by Actions; locally assembled fixtures explicitly have no Actions
custody. Detached assessment signatures do not turn diagnostics into assessments.

From exact published bytes, use the retained packed Scan installation and an
independently selected trust file to verify publication offline:

```sh
node tools/artifact/refresh-publication.mjs verify-publication publication scratch/consumer MANIFEST_SHA SELECTION_SHA TRUST_JSON
```

Read/authenticate each exact artifact and Scan ID through installed public Scan
APIs and the current maintained installed Core consumer. Verify the legacy reader
still reads the retained historical seven-report proof. Baseline retirement has
a stricter acceptance gate: all seven current targets must be authenticated,
complete and relevant to the declared four-detector profile, or an explicit owner
decision must address the refusal/profile change. Durable partial publication
alone does not satisfy that gate.

## Bounds and operator diagnosis

The single Actions archive admission ceiling is 768 MiB. It is not a worst-case
fit guarantee: result files duplicate report and encoded annex data held in
artifacts. Expanded candidate/publication files are independently bounded at
2 GiB, each result at 128 MiB and each artifact at the frozen public limit.
Before each uncompressed candidate or assembled-publication upload the operation deliberately refuses when measured file
bytes plus 1 KiB per file plus 64 KiB archive slack exceed 768 MiB. The receiving
checker additionally verifies the actual service archive size and selected digest.
No target, annex or terminal row is dropped to fit transport.

First inspect the structured boundary event (`event`, `phase`, run correlation
where available), then the manifest/custody and all seven inventory rows. Check
source capture versus detector refusal, actual installation/runtime mismatch,
resource measurements and missing final inventory before requesting another run.
Preserve failed outputs and draft assets. Authentication failure never becomes an
authenticated row. Stop admission by clearing the reviewed-head variable and
canceling a pending run before environment approval. A retry, new signing run,
profile change or changed selection needs its own reviewed authorization.
