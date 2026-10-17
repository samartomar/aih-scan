// Legacy compatibility root of @aihq/scan. New assessment consumers use the
// @aihq/scan/contracts, @aihq/scan/read and @aihq/scan/host entries. Every name
// here is compatibility-only, except the bindings re-exported from ./legacy-root/
// (retired baseline production and low-level serialization helpers), which are
// deprecated.
// The per-group status is published as the root entry of contractSupport and
// described in the README "Legacy root" section.
export {
  type BaselineVetTrustRootV1,
  parseBaselineVetAttestationEnvelopeV1Json,
  type SignedBaselineVetAttestationV1,
  type VerifiedBaselineVetAttestationV1,
  verifyBaselineVetAttestationV1,
} from "./baseline/attestation-v1.js";
export {
  type BaselineAnalyzerV1,
  type BaselineVetAnnexArtifactV1,
  type BaselineVetBatchResultV1,
  type BaselineVetReceiptV1,
  type BaselineVetRequestV1,
  parseBaselineVetReceiptV1Json,
  parseBaselineVetRequestV1Json,
} from "./baseline/batch-v1.js";
export { readBaselineVetBundleV1 } from "./baseline/bundle-v1.js";
export {
  type BaselineVetDiscoveryV1,
  type BaselineVetPublicationV1,
  baselineVetPublicationResultV1,
  parseBaselineVetDiscoveryV1Json,
  parseBaselineVetPublicationV1Json,
  resolveBaselineVetDiscoveryV1,
} from "./baseline/publication-v1.js";
export {
  type DetectorBackendKindV1,
  type DetectorCapabilityV1,
  type DetectorExecutionProfileDocumentV1,
  type DetectorExecutionProfileV1,
  type DetectorPlatformV1,
  type DetectorPrerequisiteV1,
  type DetectorSubjectKindV1,
  listDetectorCapabilitiesV1,
  resolveDetectorCapabilityV1,
  resolveDetectorExecutionProfileDocumentV1,
} from "./capability/detector-capability-v1.js";
export { type CiscoCaptureV2, captureCiscoOciCandidateV2 } from "./cisco/capture-v2.js";
export {
  AI_HARNESS_CORE_CONTRACTS_ACCEPTED,
  AI_HARNESS_DECISION_V2_SCHEMA_SHA256,
  AI_HARNESS_DECISION_V2_SCHEMA_SHA256_ACCEPTED,
  AI_HARNESS_ORGANIZATION_EVIDENCE_ENVELOPE_V1_SCHEMA_SHA256,
  AI_HARNESS_STRICT_V2_COMMIT,
  AI_HARNESS_STRICT_V2_COMMIT_ACCEPTED,
  verifyAiHarnessCoreEvidenceContractV1,
  verifyAiHarnessStrictV2Contract,
  verifyCoreOrganizationEvidenceEnvelopeSchemaLockV1,
} from "./core/core-contract-lock-v2.js";
export {
  type CoreOrganizationEvidenceEnvelopeV1,
  canonicalCoreOrganizationEvidenceEnvelopeV1Bytes,
  coreOrganizationEvidenceEnvelopeDigestV1,
  projectVerifiedScanAttestationToCoreEvidenceEnvelopeV1,
} from "./core/organization-evidence-envelope-v1.js";
export {
  type FindingFieldV1,
  type ReadScanFindingsV1Request,
  readScanFindingsV1,
  type ScanFindingsReadV1,
  type ScanFindingsV1,
  type ScanFindingV1,
} from "./findings/scan-findings-v1.js";
export {
  BASELINE_ANALYZERS_V1,
  canonicalBaselineVetAttestationEnvelopeV1Bytes,
  canonicalBaselineVetDiscoveryV1Bytes,
  canonicalBaselineVetPublicationV1Bytes,
  canonicalBaselineVetReceiptV1Bytes,
  canonicalBaselineVetRequestV1Bytes,
  createBaselineVetDiscoveryV1,
  createBaselineVetPublicationV1,
  createBaselineVetRequestV1,
  signBaselineVetBundleV1,
} from "./legacy-root/baseline-production-v1.js";
export {
  assertCompleteScanAnnexArtifactsV2,
  canonicalDetectorRegistrationV1Bytes,
  canonicalDssePaeV2,
  canonicalScanAttestationEnvelopeBytesV2,
  canonicalScanCandidateBytesV2,
  canonicalSourceSealsV2Bytes,
  ed25519KeyIdV2,
  isVerifiedScanAttestationV2,
} from "./legacy-root/serialization-helpers-v2.js";
export {
  createScanCandidateV2,
  parseScanAttestationEnvelopeV2Json,
  parseScanCandidateV2Json,
  type ScanCandidateV2,
  type ScanTrustRootV2,
  type SignedScanAttestationV2,
  signScanCandidateV2,
  type VerifiedScanAttestationV2,
  verifyScanAttestationV2,
} from "./observation/scan-attestation-v2.js";
export { readScanCaptureBundleV2, writeScanCaptureBundleV2 } from "./observation/scan-bundle-v2.js";
export { type SourceSealV2, sealSourceV2 } from "./observation/source-seal-v2.js";
export { captureRegisteredDetectorCandidateV2 } from "./registration/capture-registered-detector-v2.js";
export {
  createDetectorRegistrationV1,
  type DetectorRegistrationEntryV1,
  type DetectorRegistrationV1,
  parseDetectorRegistrationV1Json,
} from "./registration/detector-registration-v1.js";
export type {
  CiscoDetectorOptionsV1,
  CiscoMcpScannerDetectorOptionsV1,
  DetectorOptionsV1,
  TrustLintDetectorOptionsV1,
} from "./runner/detector-options-v1.js";
export {
  type CiscoShardJobSarifOutputV1,
  type CiscoShardJobV1,
  type RunCiscoShardRefusalReasonV1,
  type RunCiscoShardV1Result,
  runCiscoShardV1,
} from "./runner/run-cisco-shard-v1.js";
export {
  type BaselineAnalyzerObservationV1,
  type DetectorAvailabilityV1Result,
  type DetectorPrerequisiteStateV1,
  probeDetectorAvailabilityV1,
  type RunDetectorFailureStageV1,
  type RunDetectorProducerV1,
  type RunDetectorRefusalReasonV1,
  type RunDetectorSeamsV1,
  type RunDetectorV1Request,
  type RunDetectorV1Result,
  runDetectorV1,
  type ScanCoverageV1,
  type SkillspectorImageMatchV1,
} from "./runner/run-detector-v1.js";
export {
  parseScanResultRecordV1,
  type ReadScanResultRecordV1Request,
  type ReadScanResultSubjectBindingV1Request,
  readScanResultRecordV1,
  readScanResultSubjectBindingV1,
  SCAN_RESULT_RECORD_FORMAT_V1,
  SCAN_RESULT_RECORD_VERSION_V1,
  SCAN_RESULT_SUBJECT_NAME_V1,
  type ScanResultGapKindV1,
  type ScanResultGapV1,
  type ScanResultObservationV1,
  type ScanResultReadStatusV1,
  type ScanResultReadV1,
  type ScanResultRecordIdentityV1,
  type ScanResultRecordParseRefusalV1,
  type ScanResultRecordParseV1,
  type ScanResultRecordV1,
  type ScanResultSubjectBindingV1,
} from "./scan-result-record.js";
