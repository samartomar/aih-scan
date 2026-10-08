# Frozen production refresh

The refresh is a finite maintainer operation: freeze input, execute the frozen batch,
review the candidate, protected signing/assembly, review final custody, maintainer release
publication, offline acceptance, then any authorized baseline retirement. The two
manual workflows run only the reviewed main commit and first run attempt by
`samartomar` (GitHub user 9993940), including the triggering actor. The same sole
maintainer supplies the protected signing environment's human approval and may
approve their own initiated run. This does not establish independent human review.
Each new invocation needs its own authorization and bounded budget.
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
The maintainer run CLI connects SIGINT/SIGTERM to the installed producer's abort
signal. Graceful interruption stops new source/detector work, retains completed
original siblings, and writes all seven rows with diagnostic/no-ID states for
unfinished sources. It emits `scan-refresh.cancelled` and exits 2. Cancellation
does not grant another attempt or make the interrupted batch promotable.

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

Actions ends with the bounded `scan-refresh-final-publication` artifact after strict
restoration, independent reauthentication and measured transport admission. Every
Actions job except the protected signer has read-only authority; none writes releases.

Review the successful publisher run and all three artifact records. Independently select
its final immutable artifact ID/service digest, reviewed current main head, manifest digest
and signing-selection digest. Download the selected exact archive for reader preparation,
check its service ZIP digest and bounded receipt contents, then install its retained package:

```sh
node tools/artifact/install-retained-scanner.mjs reviewed-final MANIFEST_SHA scratch/reader independent-reader
```

This explicit mode retains exact tarball/lock/name/version/source identity and verifies
every packed Scan file, but measures the actual reader installation/runtime separately.
Read `scratch/reader/reader-custody.json`, independently select its installation SHA,
and create canonical `final-selection.json` with exactly these fields:

```json
{"finalArtifactDigest":"sha256:<64 lowercase hex>","finalArtifactId":"<positive decimal ID>","manifestSha256":"<64 lowercase hex>","publisherRunId":"<positive decimal ID>","readerInstallationSha256":"<independently selected 64 lowercase hex>","repository":"samartomar/aih-scan","schema":"urn:aihq:scan:final-publication-selection:1.0.0","selectionSha256":"<64 lowercase hex>","sourceHead":"<reviewed current main 40 lowercase hex>"}
```

Producer/check/sign/assembly paths keep strict frozen installation and runtime defaults.
The final artifact cannot select its own verifier identity. A Windows maintainer reader
does not relabel the recorded Linux execution tuple. With the reviewed clean tools on
the selected main commit and normal `samartomar` gh authentication, publish:

```sh
node tools/artifact/publish-final.mjs final-selection.json scratch/reader scratch/final-custody
```

The exclusive output retains raw `final.zip`, operator selection, run/artifact metadata,
independent maintained trust, original publication files and `publication-custody.json`.
The CLI rechecks current main/operator, successful publisher attempt/workflow/actor,
immutable artifact ID and raw ZIP digest before extracting; it refuses traversal,
duplicate/link/extra entries and archive/expanded bounds. It checks every original
receipt file and reauthenticates all supplied assessments using the installed public APIs.
Maintained trust comes from the reviewed checkout, never the downloaded artifact.

Normal gh API authentication then queries the live immutable-release setting. Disabled
settings or administration permission refusal stop before writes. The operation creates
a draft, uploads exclusive names, and publishes only after all exact assets exist.
Published tag lookup does not find drafts: authenticated discovery inspects at most
five pages of 100 releases and refuses ambiguity or exhausted pagination. A failed
draft retains completed uploads; equal published retries do not overwrite bytes.
Recovery needs separately reviewed authorization. No command deletes or replaces assets.

## Durable discovery and offline acceptance

The report release tag is `scan-report-batch-<batch SHA-256>`, separate from
software releases. Root assets are `manifest.json`, `producer-inventory.json`,
`inventory.json`, `selection.json`, `scanner.tgz`, `consumer-package-lock.json`,
`custody.json`, `publication.json` and the additional final `publication-custody.json`.
The latter binds the original receipt SHA, raw ZIP, final run/artifact selectors,
producer attribution, independent reader runtime/tree, package lock and trust SHA.
It is a separate transport asset; original receipt and inventory bytes remain exact.
Target paths are flattened by replacing `/`
with `--`: for example `targets--anthropics--skills--authenticated.json`.
`publication.json` records original relative paths, asset names, lengths and hashes.
Restore those paths before using the local verifier. Keep the additional
`publication-custody.json` beside the restored publication directory; the original
receipt verifier deliberately refuses extra files inside that directory.

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

Preparation or aggregate transport refusal keeps the run failed and retains clearly
nonpublishable recovery evidence through eight separate artifact names:
`scan-refresh-NONPUBLISHABLE-root` and one `scan-refresh-NONPUBLISHABLE-<owner>--<repo>`
per roster source. The root index records every original as retained, absent or refused,
including unfinished sources. Valid original result/artifact/statement/candidate bytes
and available manifest/inventory/custody/package/lock remain exact. Each source archive
is bounded by 128 MiB result + 96 MiB artifact + 128 KiB statement + 2 MiB candidate;
root originals have 204 MiB total allowance plus a 2 MiB index. Including file metadata
and 64 KiB ZIP slack, every archive is below 256 MiB. No annex is truncated to fit.
These names and failed/incomplete run metadata cannot enter signing or final publication.
Upload/network/platform failure can still prevent retention; inspect each upload outcome
and preserve any available exact originals. There is no platform-wide durability guarantee.
The producer job preserves the original identity guards with `always()` so bounded
cleanup remains eligible after cancellation. Ordinary setup/run/candidate-upload
steps require success and a noncancelled state. Only NONPUBLISHABLE cleanup uses
`failure() || cancelled()`, including cancellation with no preceding failed step.
The execution step replaces its entry shell with `run-workflow.sh`. That wrapper
forwards entry-PID SIGINT/SIGTERM to the active Node CLI and waits for its graceful
seven-row cleanup. Cancellation exits 2 and prevents retention/check from admitting
the output as a candidate; only the separate NONPUBLISHABLE path remains eligible.
GitHub's cancellation cleanup window is finite; SIGKILL, forced runner loss or
failed cleanup/upload can prevent retention. No recovery from those states is promised.

First inspect the structured boundary event (`event`, `phase`, run correlation
where available), then the manifest/custody and all seven inventory rows. Check
source capture versus detector refusal, actual installation/runtime mismatch,
resource measurements and missing final inventory before requesting another run.
Preserve failed outputs and draft assets. Authentication failure never becomes an
authenticated row. Stop admission by clearing the reviewed-head variable and
canceling a pending run before environment approval. A retry, new signing run,
profile change or changed selection needs its own reviewed authorization.

The real installed seven-source Linux CI fixture retains complete four-detector/Semgrep
assertions. Its child process has an 18-minute deadline and the test a 20-minute outer
deadline, within the 30-minute job. A timeout reports child status, signal and bounded
output. These test deadlines do not change production detector/resource limits.
