/**
 * `detector.cisco` multi-skill engine: planning, SARIF merging and shard
 * execution for trees that hold several skill directories.
 *
 * A runtime drives it in three moves:
 *
 * 1. plan — {@link planCiscoSourceTreeJobsV1} derives one job per SELECTED
 *    `SKILL.md` directory from Core's `selectedClosurePaths` (C2a §3.1),
 *    {@link validateCiscoDetectorOptionsV1} validates `detectorOptions`
 *    (C2a §3.3), {@link ciscoSkillScannerRunArgvV1} /
 *    {@link ciscoSkillScannerVersionArgvV1} build the locked offline uv argv,
 *    {@link scrubCiscoScanEnvV1} reduces the environment, and
 *    {@link resolveCiscoScanConcurrencyV1} bounds parallelism
 *    (`AIH_CISCO_SCAN_CONCURRENCY`, default 4, maximum 64);
 * 2. execute — {@link runCiscoSourceTreeScanV1} runs the C2a §3 source-tree
 *    scan as a typed outcome union (§3.5 stages), and {@link runCiscoShardV1}
 *    runs one shard with exact source-identity re-verification around every
 *    job (C2a §3.7);
 * 3. classify — {@link probeCiscoSkillScannerV1} and
 *    {@link ciscoScanFailureReasonV1} turn process results into Core's exact
 *    availability/failure text, typed by stage.
 *
 * Behaviour is ported from Core's `src/trust/detectors.ts` multi-skill scan
 * and `runCiscoSourceShard`. Grading, posture, policy, shard manifest
 * construction, evidence digests and shard joining stay in Core and are deliberately absent.
 */

export {
  type CiscoJobSarifFailureStageV1,
  type CiscoJobSarifV1,
  type CiscoSarifArtifactLocationV1,
  type CiscoSarifLocationV1,
  type CiscoSarifLogV1,
  type CiscoSarifPhysicalLocationV1,
  type CiscoSarifResultV1,
  type CiscoSarifRunV1,
  ciscoJobSarifV1,
  MAX_CISCO_SARIF_BYTES_V1,
  mergedCiscoSarifTextV1,
  prefixSafeCiscoUriV1,
} from "./merge-v1.js";
export {
  CISCO_MULTI_SKILL_SCAN_TIMEOUT_MS_V1,
  CISCO_MULTI_SKILL_SCANNER_PROJECT_V1,
  CISCO_MULTI_SKILL_SCANNER_VERSION_V1,
  type CiscoDetectorOptionsValidationV1,
  type CiscoMultiSkillPlatformV1,
  type CiscoMultiSkillRunnerV1,
  type CiscoMultiSkillRunOptionsV1,
  type CiscoMultiSkillRunResultV1,
  type CiscoSourceTreeJobV1,
  ciscoSkillScannerRunArgvV1,
  ciscoSkillScannerVersionArgvV1,
  DEFAULT_CISCO_SCAN_CONCURRENCY_V1,
  MAX_CISCO_SCAN_CONCURRENCY_V1,
  planCiscoSourceTreeJobsV1,
  resolveCiscoScanConcurrencyV1,
  scrubCiscoScanEnvV1,
  validateCiscoDetectorOptionsV1,
} from "./plan-v1.js";
export {
  boundedCiscoDetailV1,
  type CiscoScanFailureStageV1,
  type CiscoSkillDirectoryScanOutcomeV1,
  type CiscoSkillDirectoryScanRequestV1,
  type CiscoSkillScannerAvailabilityRequestV1,
  type CiscoSkillScannerProbeOutcomeV1,
  type CiscoSourceTreeScanOutcomeV1,
  type CiscoSourceTreeScanRequestV1,
  ciscoScanFailureReasonV1,
  mapConcurrentStableV1,
  probeCiscoSkillScannerV1,
  runCiscoSourceTreeScanV1,
  scanCiscoSkillDirectoryOutcomeV1,
} from "./scan-v1.js";
export {
  type CiscoShardJobSarifOutputV1,
  type CiscoShardJobV1,
  type CiscoShardRunFailureStageV1,
  type CiscoShardRunOutcomeV1,
  type CiscoShardRunRefusalReasonV1,
  type CiscoShardRunRequestV1,
  ciscoSkillScannerLockSha256V1,
  runCiscoShardV1,
} from "./shard-v1.js";
