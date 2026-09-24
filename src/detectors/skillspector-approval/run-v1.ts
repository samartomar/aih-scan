import { randomUUID } from "node:crypto";
import {
  type SkillspectorPlatformV1,
  skillspectorDockerCleanupArgvV1,
  skillspectorDockerRunArgvV1,
  skillspectorDockerVersionArgvV1,
  skillspectorImageInspectArgvV1,
} from "./docker-argv-v1.js";
import { scrubDockerClientEnvV1 } from "./env-v1.js";
import {
  SKILLSPECTOR_IMAGE_DIGEST_V1,
  SKILLSPECTOR_IMAGE_TAG_V1,
  type SkillspectorImageApprovalV1,
  verifiedSkillspectorImageReferenceV1,
} from "./image-identity-v1.js";

/**
 * Execution for `detector.skillspector` behind an injected runner seam, ported
 * verbatim in behaviour from Core's `src/trust/images.ts`
 * (`resolveVerifiedSkillspectorImage`) and `src/trust/detectors.ts`
 * (`runSkillspectorScan`, `checkSkillspectorAvailable`). This module never
 * spawns a process: the runtime supplies {@link SkillspectorRunnerV1}.
 *
 * Failure behaviour mirrors Core message-for-message; instead of throwing, the
 * scan returns a classified failure whose `detail` is Core's exact text.
 */

/** Process result shape the runtime's runner must report. */
export interface SkillspectorRunResultV1 {
  /** Process exit code; null when terminated by signal. */
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
  /** True when the executable could not be found / spawned (ENOENT, timeout). */
  readonly spawnError?: boolean;
  /** True when captured output exceeded the configured bound and is incomplete. */
  readonly truncated?: boolean;
}

export interface SkillspectorRunOptionsV1 {
  readonly env?: NodeJS.ProcessEnv;
  readonly timeoutMs?: number;
}

export type SkillspectorRunnerV1 = (
  argv: readonly string[],
  options?: SkillspectorRunOptionsV1,
) => Promise<SkillspectorRunResultV1>;

export const SKILLSPECTOR_AVAILABILITY_TIMEOUT_MS_V1 = 30_000;
/**
 * Full pinned catalogs are CPU-bound in SkillSpector and exceed a two-minute
 * budget even on dedicated vet hosts; one exact source-wide run stays bounded
 * at fifteen minutes, as in Core.
 */
export const SKILLSPECTOR_SCAN_TIMEOUT_MS_V1 = 900_000;
export const SKILLSPECTOR_CLEANUP_TIMEOUT_MS_V1 = 30_000;

const MAX_RUN_SUMMARY_LENGTH_V1 = 400;

function runSummaryV1(result: SkillspectorRunResultV1): string {
  const output = (result.stderr || result.stdout).trim();
  if (output.length > 0) return output.slice(0, MAX_RUN_SUMMARY_LENGTH_V1);
  if (result.code === null) return "process ended without an exit code";
  return `exit ${result.code}`;
}

function runFailureReasonV1(result: SkillspectorRunResultV1, fallback: string): string | undefined {
  if (!result.spawnError && result.code === 0) return undefined;
  return result.stderr || result.stdout || fallback;
}

export type SkillspectorImageResolutionV1 =
  | Readonly<{ image: string }>
  | Readonly<{ reason: string }>;

/**
 * Proves which local image may run: Docker answers, the pinned tag inspects,
 * and the inspected identity matches the pinned or an org-approved digest.
 * Every shortfall is a `reason`, never an exception; nothing is pulled.
 */
export async function resolveVerifiedSkillspectorImageV1(
  run: SkillspectorRunnerV1,
  platform: SkillspectorPlatformV1,
  env: NodeJS.ProcessEnv,
  timeoutMs: number,
  approvedImages: readonly SkillspectorImageApprovalV1[] = [],
): Promise<SkillspectorImageResolutionV1> {
  const childEnv = scrubDockerClientEnvV1(env);
  const docker = await run(skillspectorDockerVersionArgvV1(platform), {
    env: childEnv,
    timeoutMs,
  });
  if (docker.spawnError || docker.code === 127) {
    return Object.freeze({ reason: `Docker is unavailable (${runSummaryV1(docker)})` });
  }
  if (docker.code !== 0)
    return Object.freeze({ reason: `docker --version failed (${runSummaryV1(docker)})` });

  const image = await run(skillspectorImageInspectArgvV1(platform), {
    env: childEnv,
    timeoutMs,
  });
  if (image.spawnError || image.code === 127) {
    return Object.freeze({
      reason: `sandbox image ${SKILLSPECTOR_IMAGE_TAG_V1} is unavailable (${runSummaryV1(image)})`,
    });
  }
  if (image.code !== 0 || image.stdout.trim().length === 0) {
    return Object.freeze({
      reason: `sandbox image ${SKILLSPECTOR_IMAGE_TAG_V1} could not be inspected (${runSummaryV1(image)})`,
    });
  }
  const verifiedImage = verifiedSkillspectorImageReferenceV1(image.stdout, approvedImages);
  if (verifiedImage === undefined) {
    const approved = approvedImages.length > 0 ? " or an org-policy approved local digest" : "";
    return Object.freeze({
      reason: `sandbox image ${SKILLSPECTOR_IMAGE_TAG_V1} could not verify expected image digest ${SKILLSPECTOR_IMAGE_DIGEST_V1}${approved}`,
    });
  }
  return Object.freeze({ image: verifiedImage });
}

/** Availability probe: the resolution's reason, or `undefined` when the image may run. */
export async function checkSkillspectorAvailableV1(
  run: SkillspectorRunnerV1,
  platform: SkillspectorPlatformV1,
  env: NodeJS.ProcessEnv,
  approvedImages: readonly SkillspectorImageApprovalV1[] = [],
): Promise<string | undefined> {
  const image = await resolveVerifiedSkillspectorImageV1(
    run,
    platform,
    env,
    SKILLSPECTOR_AVAILABILITY_TIMEOUT_MS_V1,
    approvedImages,
  );
  return "reason" in image ? image.reason : undefined;
}

export type SkillspectorScanFailureStageV1 = "availability" | "execution" | "output";

export interface SkillspectorScanFailureV1 {
  readonly stage: SkillspectorScanFailureStageV1;
  /** Core's exact failure text for the equivalent thrown error. */
  readonly detail: string;
}

export type SkillspectorScanOutcomeV1 =
  | Readonly<{
      ok: true;
      /** Raw SARIF stdout from the detector; parse it with {@link parseSkillspectorSarifLogV1}. */
      sarif: string;
      /** The verified image reference that ran (bare digest or `repo@digest`), never the tag. */
      image: string;
      containerName: string;
    }>
  | Readonly<{ ok: false; failure: SkillspectorScanFailureV1 }>;

export interface SkillspectorScanRequestV1 {
  readonly run: SkillspectorRunnerV1;
  readonly platform: SkillspectorPlatformV1;
  readonly env: NodeJS.ProcessEnv;
  /** Absolute source root; becomes the read-only `/scan` bind mount. */
  readonly tree: string;
  readonly approvedImages?: readonly SkillspectorImageApprovalV1[];
  /** Test seam for a deterministic container name; production leaves it generated. */
  readonly containerName?: string;
}

function scanFailure(
  stage: SkillspectorScanFailureStageV1,
  detail: string,
): SkillspectorScanOutcomeV1 {
  return Object.freeze({ ok: false as const, failure: Object.freeze({ stage, detail }) });
}

/**
 * Resolves the verified image, runs the hardened container, and applies Core's
 * cleanup rule: on spawn error or truncated output the bounded container is
 * force-removed (`docker rm --force --volumes <name>`) before the failure is
 * reported, and a failed cleanup is appended to the failure detail. Exit 0 or 1
 * with non-empty stdout returns the SARIF; anything else is a failure. Never
 * throws for a scan shortfall.
 */
export async function runSkillspectorScanV1(
  request: SkillspectorScanRequestV1,
): Promise<SkillspectorScanOutcomeV1> {
  const image = await resolveVerifiedSkillspectorImageV1(
    request.run,
    request.platform,
    request.env,
    SKILLSPECTOR_AVAILABILITY_TIMEOUT_MS_V1,
    request.approvedImages,
  );
  if ("reason" in image) return scanFailure("availability", image.reason);

  const containerName = request.containerName ?? `aih-skillspector-${randomUUIDSuffixV1()}`;
  const dockerEnv = scrubDockerClientEnvV1(request.env);
  const scan = await request.run(
    skillspectorDockerRunArgvV1(request.platform, request.tree, image.image, containerName),
    { env: dockerEnv, timeoutMs: SKILLSPECTOR_SCAN_TIMEOUT_MS_V1 },
  );
  const exitLabel = scan.code ?? "signal";
  if (scan.spawnError || scan.truncated) {
    const cleanup = await request.run(
      skillspectorDockerCleanupArgvV1(request.platform, containerName),
      { env: dockerEnv, timeoutMs: SKILLSPECTOR_CLEANUP_TIMEOUT_MS_V1 },
    );
    const cleanupDetail =
      cleanup.spawnError || cleanup.code !== 0
        ? `; container cleanup failed: ${
            runFailureReasonV1(cleanup, `docker exit ${cleanup.code ?? "signal"}`) ??
            `docker exit ${cleanup.code ?? "signal"}`
          }`
        : "";
    return scanFailure(
      "execution",
      `${
        runFailureReasonV1(scan, `detector exit ${exitLabel}`) ?? `detector exit ${exitLabel}`
      }${cleanupDetail}`,
    );
  }
  if (scan.code !== 0 && scan.code !== 1) {
    const output = (scan.stderr || scan.stdout).trim();
    return scanFailure(
      "execution",
      `detector exit ${exitLabel}${output.length > 0 ? `: ${output}` : ""}`,
    );
  }
  if (scan.stdout.trim().length === 0) {
    return scanFailure(
      "output",
      scan.stderr.trim() || `detector exit ${exitLabel} emitted no SARIF`,
    );
  }
  return Object.freeze({
    ok: true as const,
    sarif: scan.stdout,
    image: image.image,
    containerName,
  });
}

function randomUUIDSuffixV1(): string {
  return randomUUID();
}

/** Minimal SARIF shape this engine reads: a JSON object with a `runs` array. */
export interface SkillspectorSarifLogV1 {
  readonly version?: unknown;
  readonly runs: readonly unknown[];
  readonly [key: string]: unknown;
}

/**
 * Output gate for detector stdout, mirroring Core's `parseSarifLog`: parseable
 * JSON whose root holds a `runs` array, or `undefined` — the caller classifies
 * `undefined` as "detector did not emit valid SARIF". Deeper SARIF validation,
 * rule mapping and grading stay with the caller (Core keeps them).
 */
export function parseSkillspectorSarifLogV1(raw: string): SkillspectorSarifLogV1 | undefined {
  try {
    const parsed = JSON.parse(raw) as { runs?: unknown };
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return undefined;
    if (!Array.isArray(parsed.runs)) return undefined;
    return Object.freeze({ ...parsed, runs: Object.freeze([...parsed.runs]) });
  } catch {
    return undefined;
  }
}
