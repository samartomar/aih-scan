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
| Scan attestation v2 envelope | `src/observation/scan-attestation-v2.ts:215` | `predicateType: "https://aih.dev/ScanAttestationV2"`, `payloadType: "application/vnd.in-toto+json"`, `_type: "https://in-toto.io/Statement/v1"` | envelope 8 MiB | `TypeError("invalid ScanAttestationV2: …")` from `parseScanAttestationEnvelopeV2Json` | none |
| Scan attestation v2 predicate | `src/observation/scan-attestation-v2.ts:218` | `protocol: "ScanAttestationV2"` | as above | same throw | none |
| Scan candidate v2 | `src/observation/scan-attestation-v2.ts:131` | `protocol: "ScanCandidateV2"` | canonical candidate 2 MiB | same throw | none |
| Core contract identity inside the candidate | `src/observation/scan-attestation-v2.ts:136` | `coreContract.commit` and `coreContract.decisionSchemaSha256`, each a member of the accepted set | two strings | `TypeError` naming the invalid field; a candidate declaring a Core contract outside the accepted sets is refused | the same accepted sets in `src/core/core-contract-lock-v2.ts:15` and `:19` |
| Verified attestation facts | `src/observation/scan-attestation-v2.ts:255` | custody, not a version: only a value minted by `verifyScanAttestationV2` is accepted | n/a | `isVerifiedScanAttestationV2` (`src/observation/scan-attestation-v2.ts:1063`) returns `false` for a structurally identical literal, and each reader returns `{status:"unverified"}` | none |
| Source seal v2 | `src/observation/source-seal-v2.ts:40` | `protocol: "SourceSealV2"`, `algorithm: "code-unit-canonical-json-v1"` (`src/observation/source-seal-v2.ts:41`) | 4096 entries, 16 MiB per file, 256 MiB total, 512 KiB canonical seal | `TypeError("invalid SourceSealV2: …")` | Core re-declares the same shape by hand in `ai-harness/src/org-policy/governance-input-v1.ts`; a structural mirror, not a digest lock |
| Scan capture bundle v2 | `src/observation/scan-bundle-v2.ts:130` | `manifest.protocol: "ScanBundleV2"` | 128 annexes, 16 MiB each | `TypeError("invalid ScanBundleV2: …")` | none |
| Scanner manifest v1 | `src/observation/scanner-manifest-v1.ts:50` | `protocol: "ScannerManifestV1"` | 128 detectors | `TypeError` from `createScannerManifestV1` | none |
| Baseline vet request v1 | `src/baseline/batch-v1.ts:74` | `protocol: "BaselineVetRequestV1"`, `profile: "aih-baseline-v1"` | 100 components, 4096 paths each | `TypeError("invalid BaselineVetRequestV1: …")` | Core imports the producer through the published export map only |
| Baseline vet receipt v1 | `src/baseline/batch-v1.ts:111` | `protocol: "BaselineVetReceiptV1"` | 16 MiB per annex | `TypeError("invalid BaselineVetReceiptV1: …")` | as above |
| Organization evidence envelope v1 (producer side) | `src/core/organization-evidence-envelope-v1.ts:16` | `format: "aih-organization-evidence"`, `version: 1` (`src/core/organization-evidence-envelope-v1.ts:17`) | 2 MiB | `TypeError` from the producer | Core owns the schema (`ai-harness/schemas/aih-organization-evidence-envelope-v1.schema.json`); Scan locks its bytes by digest, see below |

## Contracts Scan reads

| Contract | Authoritative definition | Identity | Refusal of an unknown identity |
| --- | --- | --- | --- |
| Core contract lock v2 — accepted commits | `src/core/core-contract-lock-v2.ts:15` | `AI_HARNESS_STRICT_V2_COMMIT_ACCEPTED`, newest last; the newest is the default emitted `AI_HARNESS_STRICT_V2_COMMIT` | `"unexpected Core commit"` for a commit outside the set |
| Core contract lock v2 — accepted decision-schema digests | `src/core/core-contract-lock-v2.ts:19` | `AI_HARNESS_DECISION_V2_SCHEMA_SHA256_ACCEPTED`, newest last; the newest is the default emitted `AI_HARNESS_DECISION_V2_SCHEMA_SHA256` | `"schema digest mismatch"` for a digest outside the set, and for bytes that do not hash to the declared digest |
| Core organization-evidence envelope schema | `src/core/core-contract-lock-v2.ts:30` | one pinned digest, `88c0a36e9177201660e773351958d89059c7d5b54e1c437d0afd06f48c5288bc`; the schema is byte-identical at every accepted Core commit | `"unexpected organization evidence schema digest"` |
| Core checkout gate | `tools/verify-core-contract-lock-v2.mjs` | a Core tree at an accepted commit, paired with that commit's exact decision-schema digest | `"unexpected Core commit"`, `"schema digest drift: <path>"` |

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
| Scan result record v1 | `src/scan-result-record.ts:30` | `format: "aih-scan-result-record"`, `version: 1` (`src/scan-result-record.ts:31`), `subject.name: "source-tree"` (`src/scan-result-record.ts:32`) | `parseScanResultRecordV1` (`src/scan-result-record.ts:444`) returns `{status:"refused", reason}` with `unknown-format`, `unknown-version`, `unknown-subject-name`, `malformed-record` or `not-an-object` |
| Detector capability v1 | `src/capability/detector-capability-v1.ts:122` | `protocol: "DetectorCapabilityV1"`, `contracts.capabilityVersion: 1`, `capabilitySha256` over the canonical record | `resolveDetectorCapabilityV1` returns `undefined` for a detector this package does not own |
| Detector execution profile document v1 | `src/capability/detector-capability-v1.ts:98` | `protocol: "DetectorExecutionProfileDocumentV1"`; its canonical sha256 is the capability's `executionProfile.sha256` | `resolveDetectorExecutionProfileDocumentV1` returns `undefined` for an unknown profile id |
| Detector run result v1 | `src/runner/run-detector-v1.ts:364` | the `outcome` discriminant; refusal reasons at `src/runner/run-detector-v1.ts:65` | `runDetectorV1` returns `{outcome:"refused", reason, detail}`; `unknown-detector`, `unsupported-platform`, `unsupported-subject-kind`, `subject-requirement-unmet`, `prerequisite-missing`, `execution-profile-unavailable`. Refusals and failures are returned values, never thrown, and every refusal happens before any process is spawned |
| Scan coverage v1 | `src/runner/run-detector-v1.ts:81` | `kind`, plus `coveredPaths`, `excludedPaths` and `uncoveredPaths`, so `complete` is computed rather than claimed | n/a — it is emitted, never parsed |
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
