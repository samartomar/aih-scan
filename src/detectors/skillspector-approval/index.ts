/**
 * `detector.skillspector` engine: approved-image identity, argv planning, and
 * scan execution behind an injected runner seam. Ported from Core's
 * `src/trust/images.ts` and the SkillSpector section of
 * `src/trust/detectors.ts`; accept/reject decisions, argv, environment
 * scrubbing, cleanup and failure text mirror Core exactly.
 *
 * The C2a §6 surface (what Core consumes) drives the never-pull local profile
 * `docker-host-local-skillspector-v1` in three steps:
 *
 * 1. availability — {@link checkLocalSkillspectorAvailableV1} or
 *    {@link resolveLocalSkillspectorImageV1} prove which local image may run
 *    (`docker --version`, then `docker image inspect` of the pinned tag, then a
 *    digest match against the pinned digest plus `acceptedImageDigests`), with
 *    typed prerequisite refusals instead of throws; nothing is pulled and the
 *    tag alone never runs;
 * 2. execution — {@link runSkillspectorScanV1} validates
 *    `acceptedImageDigests` (§6.2: `sha256:<64 hex>`, unique, at most 16; the
 *    field is refused for any other profile — this engine only plans the local
 *    profile), refuses an unmountable source path before spawning (§6.3), runs
 *    the hardened `docker run` argv (900 000 ms), force-removes the bounded
 *    container on spawn error, truncated output, timeout or abort, and
 *    classifies exit/stdout shortfalls into `execution`/`output` stages;
 * 3. output — the SARIF shape gate ({@link parseSkillspectorSarifLogV1}) plus
 *    the §6.3 URI rule ({@link skillspectorSarifUriV1}): a leading `/scan/` or
 *    `scan/` is stripped and any URI that cannot be made source-relative
 *    becomes `skillspector.sarif`.
 *
 * The success outcome records a `SkillspectorImageAdmissionV1` — which digest
 * admitted the image and whether it was pinned or caller-accepted — the
 * engine's `SkillspectorImageMatchV1`-style value for the observation.
 *
 * Grading, posture, policy decisions (including
 * the org-policy approval filter that produces `acceptedImageDigests`) and
 * evidence acceptance stay with the caller (Core keeps them); this module never
 * spawns a process itself.
 */

export {
  execArgvV1,
  hasUnsupportedDockerMountSourceCharV1,
  type SkillspectorPlatformV1,
  skillspectorDockerBindMountArgV1,
  skillspectorDockerCleanupArgvV1,
  skillspectorDockerRunArgvV1,
  skillspectorDockerVersionArgvV1,
  skillspectorImageInspectArgvV1,
} from "./docker-argv-v1.js";
export { scrubDockerClientEnvV1, scrubFetchEnvV1 } from "./env-v1.js";
export {
  admitLocalSkillspectorImageV1,
  SKILLSPECTOR_ACCEPTED_IMAGE_DIGESTS_MAX_LOCAL_V1,
  SKILLSPECTOR_IMAGE_DIGEST_V1,
  SKILLSPECTOR_IMAGE_TAG_V1,
  SKILLSPECTOR_SOURCE_REVISION_V1,
  type SkillspectorImageAdmissionV1,
  skillspectorAcceptedImageDigestsRefusalV1,
} from "./image-identity-v1.js";
export {
  checkLocalSkillspectorAvailableV1,
  parseSkillspectorSarifLogV1,
  resolveLocalSkillspectorImageV1,
  runSkillspectorScanV1,
  SKILLSPECTOR_AVAILABILITY_TIMEOUT_MS_V1,
  SKILLSPECTOR_CLEANUP_TIMEOUT_MS_V1,
  SKILLSPECTOR_FALLBACK_SARIF_URI_V1,
  SKILLSPECTOR_SCAN_TIMEOUT_MS_V1,
  type SkillspectorLocalImageResolutionV1,
  type SkillspectorPrerequisiteRefusalV1,
  type SkillspectorRunnerV1,
  type SkillspectorRunOptionsV1,
  type SkillspectorRunRefusalV1,
  type SkillspectorRunResultV1,
  type SkillspectorSarifLogV1,
  type SkillspectorScanFailureStageV1,
  type SkillspectorScanFailureV1,
  type SkillspectorScanOutcomeV1,
  type SkillspectorScanRequestV1,
  skillspectorSarifUriV1,
} from "./run-v1.js";
