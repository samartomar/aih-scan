/**
 * `detector.cisco` multi-skill engine: planning, SARIF merging and shard
 * execution for trees that hold several skill directories.
 *
 * A runtime drives it in three moves:
 *
 * 1. plan — {@link collectCiscoSkillDirsV1} finds every `SKILL.md` directory,
 *    {@link ciscoSkillScannerRunArgvV1} / {@link ciscoSkillScannerVersionArgvV1}
 *    build the locked offline uv argv, {@link scrubCiscoScanEnvV1} reduces the
 *    environment, and {@link resolveCiscoScanConcurrencyV1} bounds parallelism
 *    (`AIH_CISCO_SCAN_CONCURRENCY`, default 4, maximum 64);
 * 2. execute — {@link runCiscoSkillScanV1} scans each skill directory once
 *    through the injected runner seam and returns the merged SARIF text, or
 *    {@link runCiscoSourceShardV1} runs one manifest-declared shard with
 *    Core's exact source-identity re-verification around every job;
 * 3. classify — {@link checkCiscoSkillScannerAvailableV1} and
 *    {@link ciscoScanFailureReasonV1} turn process results into Core's exact
 *    availability/failure text.
 *
 * Behaviour is ported from Core's `src/trust/detectors.ts` multi-skill scan
 * and `runCiscoSourceShard`. Grading, posture, policy, shard manifest
 * construction and shard joining stay in Core and are deliberately absent.
 */

export {
  type CiscoSarifArtifactLocationV1,
  type CiscoSarifLocationV1,
  type CiscoSarifLogV1,
  type CiscoSarifPhysicalLocationV1,
  type CiscoSarifResultV1,
  type CiscoSarifRunV1,
  MAX_CISCO_SARIF_BYTES_V1,
  mergedCiscoSarifTextV1,
  parseCiscoSarifLogV1,
  prefixCiscoSarifUrisV1,
  prefixSafeCiscoUriV1,
} from "./merge-v1.js";
export {
  CISCO_MULTI_SKILL_SCAN_TIMEOUT_MS_V1,
  CISCO_MULTI_SKILL_SCANNER_PROJECT_V1,
  CISCO_MULTI_SKILL_SCANNER_VERSION_V1,
  CISCO_SKILL_SKIP_DIRS_V1,
  type CiscoMultiSkillPlatformV1,
  type CiscoMultiSkillRunnerV1,
  type CiscoMultiSkillRunOptionsV1,
  type CiscoMultiSkillRunResultV1,
  type CiscoSkillInventoryEntryV1,
  type CiscoSkillInventoryV1,
  ciscoSkillScannerRunArgvV1,
  ciscoSkillScannerVersionArgvV1,
  collectCiscoSkillDirsV1,
  DEFAULT_CISCO_SCAN_CONCURRENCY_V1,
  MAX_CISCO_SCAN_CONCURRENCY_V1,
  resolveCiscoScanConcurrencyV1,
  scrubCiscoScanEnvV1,
} from "./plan-v1.js";
export {
  type CiscoSkillDirectoryScanRequestV1,
  type CiscoSkillScannerAvailabilityRequestV1,
  type CiscoSkillScanRequestV1,
  checkCiscoSkillScannerAvailableV1,
  ciscoScanFailureReasonV1,
  mapConcurrentStableV1,
  runCiscoSkillScanV1,
  scanCiscoSkillDirectoryV1,
} from "./scan-v1.js";
export {
  type CiscoShardJobInputV1,
  type CiscoShardJobV1,
  type CiscoShardManifestV1,
  type CiscoShardOutputV1,
  type CiscoShardResultV1,
  type CiscoSourceShardRunOptionsV1,
  canonicalCiscoShardJsonV1,
  ciscoShardSha256V1,
  parseCiscoShardManifestV1,
  runCiscoShardJobsV1,
  runCiscoSourceShardV1,
  verifyCiscoShardSourceV1,
} from "./shard-v1.js";
