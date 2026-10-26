import { schemas, schemasV2 } from "../assessment/types.js";
import { packageIdentity } from "./package-identity.js";

export type {
  Artifact,
  ArtifactAnnex,
  ArtifactResult,
  ArtifactStatement,
  AssociationResult,
  AuthenticationTrust,
  ReadArtifactResult,
  SigstoreBundle,
} from "../artifact/types.js";
export type { DetectorDefinitionV1 } from "../assessment/detector-definition.js";
export type * from "../assessment/summary-types.js";
export * from "../assessment/types.js";
export type * from "../material-change/types.js";
// Portable installed-distribution declaration in exactly the
// urn:aihq:package-support:1.0.0 shape, which admits no other fields. Lifecycle
// status lives in the sibling `entrySupport`, which shares the same package identity.
export const contractSupport = Object.freeze({
  schema: "urn:aihq:package-support:1.0.0",
  package: packageIdentity,
  contracts: Object.freeze([
    Object.freeze({
      id: "urn:aihq:scan:evidence-policy:1.0.0",
      role: "accepts",
      schemaExport: "@aihq/scan/schemas/evidence-policy/1.0.0.json",
    }),
    Object.freeze({
      id: "urn:aihq:scan:severity-profile:1.0.0",
      role: "accepts",
      schemaExport: "@aihq/scan/schemas/severity-profile/1.0.0.json",
    }),
    Object.freeze({
      id: "urn:aihq:scan:item-summary:1.0.0",
      role: "produces",
      schemaExport: "@aihq/scan/schemas/item-summary/1.0.0.json",
    }),
    Object.freeze({
      id: "urn:aihq:scan:item-record:1.0.0",
      role: "both",
      schemaExport: "@aihq/scan/schemas/item-record/1.0.0.json",
    }),
    Object.freeze({
      id: schemasV2.request,
      role: "accepts",
      schemaExport: "@aihq/scan/schemas/request/2.0.0.json",
    }),
    Object.freeze({
      id: schemasV2.runResult,
      role: "produces",
      schemaExport: "@aihq/scan/schemas/run-result/2.0.0.json",
    }),
    Object.freeze({
      id: schemasV2.report,
      role: "both",
      schemaExport: "@aihq/scan/schemas/report/2.0.0.json",
    }),
    Object.freeze({
      id: "urn:aihq:scan:detector-definition:1.0.0",
      role: "accepts",
      schemaExport: "@aihq/scan/schemas/detector-definition/1.0.0.json",
    }),
    Object.freeze({
      id: schemas.request,
      role: "accepts",
      schemaExport: "@aihq/scan/schemas/request/1.0.0.json",
    }),
    Object.freeze({
      id: schemas.runResult,
      role: "produces",
      schemaExport: "@aihq/scan/schemas/run-result/1.0.0.json",
    }),
    Object.freeze({
      id: schemas.report,
      role: "both",
      schemaExport: "@aihq/scan/schemas/report/1.0.0.json",
    }),
    Object.freeze({
      id: schemas.artifact,
      role: "both",
      schemaExport: "@aihq/scan/schemas/artifact/1.0.0.json",
    }),
    Object.freeze({
      id: schemas.evidenceAssociation,
      role: "accepts",
      schemaExport: "@aihq/scan/schemas/evidence-association/1.0.0.json",
    }),
    Object.freeze({
      id: schemas.materialChange,
      role: "both",
      schemaExport: "@aihq/scan/schemas/material-change/1.0.0.json",
    }),
  ]),
  entries: Object.freeze([
    Object.freeze({ export: "@aihq/scan/contracts", runtime: "portable" }),
    Object.freeze({ export: "@aihq/scan/read", runtime: "portable" }),
    Object.freeze({ export: "@aihq/scan/host", runtime: "node", nodeRange: ">=24.15.0 <25" }),
    Object.freeze({ export: "@aihq/scan", runtime: "node", nodeRange: ">=24.15.0 <25" }),
  ]),
} as const);

/**
 * `current` entries and groups are the recommended way to start new work;
 * `compatibility-only` ones keep existing evidence readable and existing callers
 * working without new capability; `deprecated` ones still work but carry
 * `@deprecated` and are scheduled for removal with the legacy root window.
 */
export type EntryStatus = "current" | "compatibility-only" | "deprecated";

/**
 * Lifecycle status of every package entry, in the order of `contractSupport.entries`.
 * The `@aihq/scan` root entry also lists its operation groups: each group's status,
 * the entry that replaces it for new work (null when nothing replaces it) and every
 * runtime export in it. Each runtime export of the root belongs to exactly one group.
 * Discovery data only: it does not execute, negotiate or gate anything.
 */
export const entrySupport = Object.freeze({
  package: packageIdentity,
  entries: Object.freeze([
    Object.freeze({ export: "@aihq/scan/contracts", status: "current" }),
    Object.freeze({ export: "@aihq/scan/read", status: "current" }),
    Object.freeze({ export: "@aihq/scan/host", status: "current" }),
    Object.freeze({
      export: "@aihq/scan",
      status: "compatibility-only",
      groups: Object.freeze([
        Object.freeze({
          group: "v2-evidence-readers",
          status: "compatibility-only",
          use: "@aihq/scan/read",
          exports: Object.freeze([
            "parseScanAttestationEnvelopeV2Json",
            "verifyScanAttestationV2",
            "readScanCaptureBundleV2",
            "readScanFindingsV1",
            "parseScanResultRecordV1",
            "readScanResultRecordV1",
            "readScanResultSubjectBindingV1",
            "SCAN_RESULT_RECORD_FORMAT_V1",
            "SCAN_RESULT_RECORD_VERSION_V1",
            "SCAN_RESULT_SUBJECT_NAME_V1",
          ]),
        }),
        Object.freeze({
          group: "baseline-evidence-readers",
          status: "compatibility-only",
          use: null,
          exports: Object.freeze([
            "parseBaselineVetRequestV1Json",
            "parseBaselineVetReceiptV1Json",
            "readBaselineVetBundleV1",
            "parseBaselineVetAttestationEnvelopeV1Json",
            "verifyBaselineVetAttestationV1",
            "parseBaselineVetPublicationV1Json",
            "baselineVetPublicationResultV1",
            "parseBaselineVetDiscoveryV1Json",
            "resolveBaselineVetDiscoveryV1",
          ]),
        }),
        Object.freeze({
          group: "detector-execution",
          status: "compatibility-only",
          use: "@aihq/scan/host",
          exports: Object.freeze([
            "listDetectorCapabilitiesV1",
            "resolveDetectorCapabilityV1",
            "resolveDetectorExecutionProfileDocumentV1",
            "probeDetectorAvailabilityV1",
            "runDetectorV1",
            "runCiscoShardV1",
          ]),
        }),
        Object.freeze({
          group: "v2-capture-and-signing",
          status: "compatibility-only",
          use: "@aihq/scan/host",
          exports: Object.freeze([
            "captureCiscoOciCandidateV2",
            "captureRegisteredDetectorCandidateV2",
            "createDetectorRegistrationV1",
            "parseDetectorRegistrationV1Json",
            "sealSourceV2",
            "createScanCandidateV2",
            "parseScanCandidateV2Json",
            "signScanCandidateV2",
            "writeScanCaptureBundleV2",
          ]),
        }),
        Object.freeze({
          group: "legacy-core-evidence",
          status: "compatibility-only",
          use: null,
          exports: Object.freeze([
            "AI_HARNESS_CORE_CONTRACTS_ACCEPTED",
            "AI_HARNESS_STRICT_V2_COMMIT",
            "AI_HARNESS_STRICT_V2_COMMIT_ACCEPTED",
            "AI_HARNESS_DECISION_V2_SCHEMA_SHA256",
            "AI_HARNESS_DECISION_V2_SCHEMA_SHA256_ACCEPTED",
            "AI_HARNESS_ORGANIZATION_EVIDENCE_ENVELOPE_V1_SCHEMA_SHA256",
            "verifyAiHarnessStrictV2Contract",
            "verifyAiHarnessCoreEvidenceContractV1",
            "verifyCoreOrganizationEvidenceEnvelopeSchemaLockV1",
            "projectVerifiedScanAttestationToCoreEvidenceEnvelopeV1",
            "coreOrganizationEvidenceEnvelopeDigestV1",
            "canonicalCoreOrganizationEvidenceEnvelopeV1Bytes",
          ]),
        }),
        Object.freeze({
          group: "baseline-production",
          status: "deprecated",
          use: "@aihq/scan/host",
          exports: Object.freeze([
            "BASELINE_ANALYZERS_V1",
            "createBaselineVetRequestV1",
            "canonicalBaselineVetRequestV1Bytes",
            "canonicalBaselineVetReceiptV1Bytes",
            "signBaselineVetBundleV1",
            "canonicalBaselineVetAttestationEnvelopeV1Bytes",
            "createBaselineVetPublicationV1",
            "canonicalBaselineVetPublicationV1Bytes",
            "createBaselineVetDiscoveryV1",
            "canonicalBaselineVetDiscoveryV1Bytes",
          ]),
        }),
        Object.freeze({
          group: "v2-internal-helpers",
          status: "deprecated",
          use: null,
          exports: Object.freeze([
            "assertCompleteScanAnnexArtifactsV2",
            "canonicalDssePaeV2",
            "canonicalScanAttestationEnvelopeBytesV2",
            "canonicalScanCandidateBytesV2",
            "canonicalSourceSealsV2Bytes",
            "ed25519KeyIdV2",
            "isVerifiedScanAttestationV2",
            "canonicalDetectorRegistrationV1Bytes",
          ]),
        }),
      ]),
    }),
  ]),
} as const);

// Fails to compile if a status is outside EntryStatus.
type CheckedEntries<
  T extends readonly {
    readonly status: EntryStatus;
    readonly groups?: readonly { readonly status: EntryStatus }[];
  }[],
> = T;
export type EntrySupportEntry = CheckedEntries<typeof entrySupport.entries>[number];

export type {
  ItemAssessment,
  ItemDescriptor,
  ItemMaterial,
  ItemRecord,
  ItemRecordBatchResult,
  ItemRecordResult,
  ItemSubject,
} from "../assessment/item-record.js";

export type {
  EvidencePolicy,
  ItemAuthentication,
  ItemSummary,
  ItemTrustStatus,
  SeverityProfile,
  SummariseItemInput,
  SummariseItemResult,
} from "../assessment/item-summary.js";
