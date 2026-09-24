/**
 * `detector.skillspector` engine: approved-image identity, argv planning, and
 * scan execution behind an injected runner seam. Ported from Core's
 * `src/trust/images.ts` and the SkillSpector section of
 * `src/trust/detectors.ts`; accept/reject decisions, argv, environment
 * scrubbing, cleanup and failure text mirror Core exactly.
 *
 * A runtime drives it in three steps:
 *
 * 1. availability — {@link checkSkillspectorAvailableV1} or
 *    {@link resolveVerifiedSkillspectorImageV1} prove which local image may run
 *    (pinned or org-approved digest; the tag alone never runs, nothing pulls);
 * 2. execution — {@link runSkillspectorScanV1} plans the hardened
 *    `docker run` argv, runs it through the supplied runner, force-removes the
 *    bounded container on spawn error or truncated output, and returns raw
 *    SARIF stdout or a classified failure;
 * 3. output — {@link parseSkillspectorSarifLogV1} gates the stdout shape.
 *
 * Grading, posture, policy decisions and evidence acceptance stay with the
 * caller (Core keeps them); this module never spawns a process itself.
 */

export {
  execArgvV1,
  type SkillspectorPlatformV1,
  skillspectorDockerBindMountArgV1,
  skillspectorDockerCleanupArgvV1,
  skillspectorDockerRunArgvV1,
  skillspectorDockerVersionArgvV1,
  skillspectorImageInspectArgvV1,
} from "./docker-argv-v1.js";
export { scrubDockerClientEnvV1, scrubFetchEnvV1 } from "./env-v1.js";
export {
  parseSkillspectorImageApprovalsV1,
  SKILLSPECTOR_IMAGE_DIGEST_V1,
  SKILLSPECTOR_IMAGE_TAG_V1,
  SKILLSPECTOR_SOURCE_REVISION_V1,
  type SkillspectorImageApprovalV1,
  verifiedSkillspectorImageReferenceV1,
} from "./image-identity-v1.js";
export {
  checkSkillspectorAvailableV1,
  parseSkillspectorSarifLogV1,
  resolveVerifiedSkillspectorImageV1,
  runSkillspectorScanV1,
  SKILLSPECTOR_AVAILABILITY_TIMEOUT_MS_V1,
  SKILLSPECTOR_CLEANUP_TIMEOUT_MS_V1,
  SKILLSPECTOR_SCAN_TIMEOUT_MS_V1,
  type SkillspectorImageResolutionV1,
  type SkillspectorRunnerV1,
  type SkillspectorRunOptionsV1,
  type SkillspectorRunResultV1,
  type SkillspectorSarifLogV1,
  type SkillspectorScanFailureStageV1,
  type SkillspectorScanFailureV1,
  type SkillspectorScanOutcomeV1,
  type SkillspectorScanRequestV1,
} from "./run-v1.js";
