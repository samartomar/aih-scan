# Contracts published by `@aihq/scan`

Every format this package produces or reads across a package boundary, with the source
that defines it, the field that carries its identity, the bound on its size, and the
exact refusal a reader produces for a version it does not know.

This document is not the contract. The source is. Each row is pinned by
`tests/contracts/contract-inventory.test.ts`, which re-reads the constants and the named
source lines, so a renamed constant, a bumped literal or a moved definition fails CI
rather than leaving this page quietly wrong.

Scanner evidence carries no authority. Nothing named here approves a subject, creates a
Core decision, establishes an organization trust root, qualifies a component, or proves
successful Core custody.

## Reading this table

- **Identity** is the field a reader checks before it reads anything else.
- **Refusal** is what a reader returns or throws for an identity it does not know. Every
  refusal is named: an unknown version is never read as though it were a known one.
- **Mirror** names any place the same value is restated, and how drift is detected.

## Evidence Scan produces

| Contract | Authoritative definition | Identity | Bound | Refusal of an unknown identity | Mirror |
| --- | --- | --- | --- | --- | --- |
| Scan attestation v2 envelope | `src/observation/scan-attestation-v2.ts:225` | `predicateType: "https://aih.dev/ScanAttestationV2"`, `payloadType: "application/vnd.in-toto+json"`, `_type: "https://in-toto.io/Statement/v1"` | decoded payload 2 MiB (`src/observation/scan-attestation-v2.ts:316`, and again before DSSE PAE at `src/observation/scan-attestation-v2.ts:740`); no separate envelope byte bound | a `ZodError` from `parseScanAttestationEnvelopeV2Json` whose issue path names `payloadType`, `_type` or `predicateType`; other malformed or noncanonical input throws `TypeError("invalid ScanAttestationV2: …")` | none |
| Scan attestation v2 predicate | `src/observation/scan-attestation-v2.ts:228` | `protocol: "ScanAttestationV2"` | as above | a `ZodError` whose issue path is `predicate.protocol` | none |
| Scan candidate v2 | `src/observation/scan-attestation-v2.ts:132` | `protocol: "ScanCandidateV2"` | `candidate.json` 2 MiB when read from a capture bundle (`src/observation/scan-bundle-v2.ts:116`) | a `ZodError` from `parseScanCandidateV2Json` or `createScanCandidateV2` whose issue path is `protocol` | none |
| Core contract identity inside the candidate | `src/observation/scan-attestation-v2.ts:138` | `coreContract.commit` and `coreContract.decisionSchemaSha256`, together one accepted pair | two strings | a `ZodError` from `parseScanCandidateV2Json` or `createScanCandidateV2`: its issue path is `coreContract.commit` or `coreContract.decisionSchemaSha256` for a value outside the accepted sets, and `coreContract` for an accepted commit declared with another accepted commit's digest | the same accepted pairs in `src/core/core-contract-lock-v2.ts:19` |
| Verified attestation facts | `src/observation/scan-attestation-v2.ts:265` | custody, not a version: only a value minted by `verifyScanAttestationV2` is accepted | n/a | `isVerifiedScanAttestationV2` (`src/observation/scan-attestation-v2.ts:1073`) returns `false` for a structurally identical literal, and each reader returns `{status:"unverified"}` | none |
| Source seal v2 | `src/observation/source-seal-v2.ts:40` | `protocol: "SourceSealV2"`, `algorithm: "code-unit-canonical-json-v1"` (`src/observation/source-seal-v2.ts:41`) | 4096 entries, 16 MiB per file (`src/observation/source-seal-v2.ts:24`), 256 MiB total (`src/observation/source-seal-v2.ts:25`), 512 KiB canonical seal (`src/observation/source-seal-v2.ts:26`) | a `ZodError` for a schema violation, whose issue path names `protocol` or `algorithm` for an unknown identity; the checks after the schema (ordering, total bytes, canonical seal bytes, bindings) throw `TypeError("invalid SourceSealV2: …")` | Core re-declares the same shape by hand in `ai-harness/src/org-policy/governance-input-v1.ts`; a structural mirror, not a digest lock |
| Scan capture bundle v2 | `src/observation/scan-bundle-v2.ts:130` | `manifest.protocol: "ScanBundleV2"` | 128 annexes, 16 MiB each (`src/observation/scan-bundle-v2.ts:171`) | `TypeError("invalid ScanBundleV2: …")` | none |
| Scanner manifest v1 | `src/observation/scanner-manifest-v1.ts:50` | `protocol: "ScannerManifestV1"` | 128 detectors | a `ZodError` from `createScannerManifestV1` whose issue path is `protocol` | none |
| Baseline vet request v1 | `src/baseline/batch-v1.ts:74` | `protocol: "BaselineVetRequestV1"`, `profile: "aih-baseline-v1"` | 100 components, 4096 paths each | `TypeError("invalid BaselineVetRequestV1: …")` | Core imports the producer through the published export map only |
| Baseline vet receipt v1 | `src/baseline/batch-v1.ts:111` | `protocol: "BaselineVetReceiptV1"` | 16 MiB per annex (`src/baseline/batch-v1.ts:38`) | `TypeError("invalid BaselineVetReceiptV1: …")` | as above |
| Organization evidence envelope v1 (producer side) | `src/core/organization-evidence-envelope-v1.ts:16` | `format: "aih-organization-evidence"`, `version: 1` (`src/core/organization-evidence-envelope-v1.ts:17`) | no byte bound of its own: it is projected only from an already verified attestation, whose payload is bounded as above | `TypeError` from the producer | Core owns the schema (`ai-harness/schemas/aih-organization-evidence-envelope-v1.schema.json`); Scan locks its bytes by digest, see below |

## Contracts Scan reads

| Contract | Authoritative definition | Identity | Refusal of an unknown identity |
| --- | --- | --- | --- |
| Core contract lock v2 — accepted pairs | `src/core/core-contract-lock-v2.ts:19` | `AI_HARNESS_CORE_CONTRACTS_ACCEPTED`, each entry a Core commit with the exact decision-schema digest Core carries at that commit, newest last; the two sets below are derived from it | `"schema digest mismatch"` for an accepted commit presented with another accepted commit's digest or schema bytes |
| Core contract lock v2 — accepted commits | `src/core/core-contract-lock-v2.ts:35` | `AI_HARNESS_STRICT_V2_COMMIT_ACCEPTED`, newest last; the newest is the default emitted `AI_HARNESS_STRICT_V2_COMMIT` | `"unexpected Core commit"` for a commit outside the set |
| Core contract lock v2 — accepted decision-schema digests | `src/core/core-contract-lock-v2.ts:39` | `AI_HARNESS_DECISION_V2_SCHEMA_SHA256_ACCEPTED`, newest last; the newest is the default emitted `AI_HARNESS_DECISION_V2_SCHEMA_SHA256` | `"schema digest mismatch"` for a digest outside the set, and for bytes that do not hash to the declared digest |
| Core organization-evidence envelope schema | `src/core/core-contract-lock-v2.ts:49` | one pinned digest, `88c0a36e9177201660e773351958d89059c7d5b54e1c437d0afd06f48c5288bc`; the schema is byte-identical at every accepted Core commit | `"unexpected organization evidence schema digest"` |
| Core checkout gate | `tools/verify-core-contract-lock-v2.mjs` | a Core tree at an accepted commit, paired with that commit's exact decision-schema digest | `"unexpected Core commit"`, `"schema digest drift: <path>"`, `"a tree without git history requires --core-commit"`, `"declared commit is not the checked-out commit"` |

**Why a set and not one value.** Core's governance-decision schema changed additively
between the two accepted commits. A single pinned digest made the gate pass forever
against one old Core while newer Core artifacts went unrecognised; re-pinning to the new
digest alone would have silently stopped accepting evidence that is still valid.
Accepting a digest states only that this Scanner knows that contract and can read
evidence produced against it. It is not approval of a Core release, and it is not a
range: a third value is refused by name.

## Records Scan hands to a consumer

| Contract | Authoritative definition | Identity | Refusal of an unknown identity |
| --- | --- | --- | --- |
| Scan result record v1 | `src/scan-result-record.ts:30` | `format: "aih-scan-result-record"`, `version: 1` (`src/scan-result-record.ts:31`), `subject.name: "source-tree"` (`src/scan-result-record.ts:32`) | `parseScanResultRecordV1` (`src/scan-result-record.ts:457`) returns `{status:"refused", reason}` with `unknown-format`, `unknown-version`, `unknown-subject-name`, `malformed-record` or `not-an-object`. It checks the declared identity only, so `{status:"read"}` carries only a new frozen `ScanResultRecordIdentityV1` (`format`, `version`, `subject`), never the rest of the record: a verified record comes only from `readScanResultRecordV1` |
| Detector capability v1 | `src/capability/detector-capability-v1.ts:122` | `protocol: "DetectorCapabilityV1"`, `contracts.capabilityVersion: 1`, `capabilitySha256` over the canonical record | `resolveDetectorCapabilityV1` returns `undefined` for a detector this package does not own |
| Detector execution profile document v1 | `src/capability/detector-capability-v1.ts:98` | `protocol: "DetectorExecutionProfileDocumentV1"`; its canonical sha256 is the capability's `executionProfile.sha256` | `resolveDetectorExecutionProfileDocumentV1` returns `undefined` for an unknown profile id |
| Detector run result v1 | `src/runner/run-detector-v1.ts:589` | the `outcome` discriminant; refusal reasons at `src/runner/run-detector-v1.ts:67` | `runDetectorV1` returns `{outcome:"refused", reason, detail}`; `unknown-detector`, `unsupported-platform`, `unsupported-subject-kind`, `subject-requirement-unmet`, `prerequisite-missing`, `execution-profile-unavailable`. Refusals and failures are returned values, never thrown, and every refusal happens before any process is spawned. The promise never rejects: the request is read once, so an accessor that throws on the request refuses `unknown-detector` (the class of a request that is not an object) and one on its subject refuses `subject-requirement-unmet`, each detail naming the field; a request that cannot be inspected at all, such as a revoked Proxy, also refuses `unknown-detector`; an `executionProfileId` that is present but not a non-empty string, an `env` that is not an object of string (or absent) values, and an `ociCapture` that is not an object are refused `execution-profile-unavailable` before any of them is interpolated or used, the detail naming the field and its shape but never coercing its value; a run that executed but whose private analyzer snapshot cannot then be removed is `failed` at stage `cleanup` if it had otherwise succeeded, and keeps its own earlier failure if it had not; a caller-supplied `prerequisiteProbe` that throws, is not callable or answers outside `present`, `missing` and `not-probed` makes the run `failed` at stage `availability`, with that prerequisite and every later one reported `not-probed`. A `skill-directory` selection that holds nested `SKILL.md` files and none at its top is refused `subject-requirement-unmet` with a detail saying Scan runs one skill root per request and how to shard. A run that started (`failed` or `succeeded`) also names the package that executed it, `producer: {name:"@aihq/scan", version}` (`src/runner/run-detector-v1.ts:175`), read from the manifest shipped beside that code and `null` rather than guessed when unreadable; a refusal executed nothing and carries none |
| Accepted SkillSpector image digests (request field) | `src/runner/run-detector-v1.ts:151`, checked by `src/baseline/runtime-v1.ts:423` | `acceptedImageDigests`: 1 to 32 distinct `sha256:` + 64 lowercase hex digests, for `docker-hardened-skillspector-v1` only; the image that ran is recorded as `observation.image` (`src/runner/run-detector-v1.ts:119`), `{digest, reference, acceptance: "scan-pinned" \| "caller-accepted", pinnedPullFailure?}`, and `analyzerVersion` names the matched digest | a malformed list, or one given to another profile, is refused `execution-profile-unavailable` before anything is spawned. The list never replaces Scan's own acquisition. Scan's pinned image, when present, runs as `scan-pinned`; when absent, Scan attempts its pinned pull exactly as without the list, and an image that pull yields also runs as `scan-pinned`. The pinned digest check is unchanged: a pinned reference that resolves to another image still fails, whatever the list says. Only if the pinned image is still absent after that pull (refused, failed, offline or not runnable) are the accepted digests inspected, in order, against local images only; the first present one runs by its local image ID as `caller-accepted`, with the pinned pull's bounded failure reason in `pinnedPullFailure`, and nothing more is pulled. When none is present the run is `failed` at stage `availability` rather than refused, because Docker had to be asked; without the list a failed pinned pull stays a `failed` result at stage `acquisition`. `caller-accepted` means Scan verified the digest the caller named, not that image's provenance or source revision; the profile document still names Scan's pinned image, so a reader takes the executed image from `observation.image` |
| Scan coverage v1 | `src/runner/run-detector-v1.ts:83` | `kind`, plus `coveredPaths`, `excludedPaths` and `uncoveredPaths`, so `complete` is computed rather than claimed | n/a — it is emitted, never parsed |
| Scan findings v1 | `src/findings/scan-findings-v1.ts:66` | `protocol: "ScanFindingsV1"`, `source: "annex" \| "attestation-facts-only" \| "analyzer-output-digest-bound"` | `readScanFindingsV1` (`src/findings/scan-findings-v1.ts:368`) returns `{status:"unverified"}` for anything not minted by the verifier, and `{status:"invalid-input", reason}` when annex bytes do not match the declared descriptor or an entry does not bind to exactly one declared occurrence fact |

**What an unavailable field means.** `FindingFieldV1`
(`src/findings/scan-findings-v1.ts:44`) is `present` or `unavailable` with a reason.
Findings are produced only from annex bytes whose digest matches the declared descriptor;
without those bytes every field except the occurrence fingerprint and its multiplicity is
`unavailable`. An empty findings list is never reported as "nothing was found": the gaps
say why the list is empty.

## The reproducibility rule

Every compatibility run records the exact tarball sha256 of each package it tested, the
resolved version and dist-tag (or the git SHA for a branch-built tarball), and the sha256
of the consumer's `package-lock.json`. A promotion authorization is valid only for the
byte set it names; if `next` moves to different bytes, the earlier result cannot
authorize that candidate.

Scan's promotion gate (`.github/workflows/promotion-readiness.yml`) reads Core's
`core-sibling-compatibility` version 2 artifact and refuses version 1 by name. It accepts
only the one `scan-candidate` combination, which names Scan at `next` together with the
Core and Catalog it was installed with at `latest`, and it re-observes those two live:
if either `latest` moved or its bytes changed, the evidence no longer applies. Core owns
the artifact's shape; Scan only reads it.

These records are evidence for the gate, not dependency pins imposed on users. No
consumer is required to install a tested trio, and no release of one package requires a
release of the other two. Compatibility is decided by the declared `format` and `version`
of each artifact and by the accepted digest sets each package publishes — never by
version-number equality and never by a frozen trio. A recorded hash answers *what did we
test*; it never answers *what may you install*.

## Changing a contract here

A new accepted digest or an additive export is `semver:minor`
([VERSIONING.md](VERSIONING.md)). Removing an accepted value, renaming a format or
bumping a version is `semver:major`, because an installed consumer that reads the old
identity would start being refused. Add the new value to the accepted set, keep the old
one until the evidence produced against it is out of support, and move the default to the
newest member in the same change.
