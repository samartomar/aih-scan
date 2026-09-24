import { randomUUID } from "node:crypto";
import { deepFreezeStrictJsonV1 } from "../../contract/strict-json-v1.js";
import {
  hasUnsupportedDockerMountSourceCharV1,
  type SkillspectorPlatformV1,
  skillspectorDockerCleanupArgvV1,
  skillspectorDockerRunArgvV1,
  skillspectorDockerVersionArgvV1,
  skillspectorImageInspectArgvV1,
} from "./docker-argv-v1.js";
import { scrubDockerClientEnvV1 } from "./env-v1.js";
import {
  admitLocalSkillspectorImageV1,
  SKILLSPECTOR_IMAGE_DIGEST_V1,
  SKILLSPECTOR_IMAGE_TAG_V1,
  type SkillspectorImageAdmissionV1,
  skillspectorAcceptedImageDigestsRefusalV1,
} from "./image-identity-v1.js";

/**
 * Execution for `detector.skillspector` behind an injected runner seam, ported
 * verbatim in behaviour from Core's `src/trust/images.ts`
 * (`resolveVerifiedSkillspectorImage`) and `src/trust/detectors.ts`
 * (`runSkillspectorScan`, `checkSkillspectorAvailable`), narrowed to the
 * never-pull local profile. This module never
 * spawns a process: the runtime supplies {@link SkillspectorRunnerV1}.
 *
 * Failure behaviour mirrors Core message-for-message; instead of throwing, the
 * scan returns a classified outcome whose `detail` is Core's exact text.
 *
 * The C2a surface (profile `docker-host-local-skillspector-v1`, never-pull):
 * {@link runSkillspectorScanV1} returns a three-way typed outcome —
 * `succeeded` (SARIF with `/scan/` URIs rewritten source-relative, plus the
 * image admission of §6.1), `refused` (§6.2 digest-list violations, §6.3
 * unmountable source paths, §6.1 missing prerequisites) or `failed` (§6.3
 * execution/output stages).
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

// ---------------------------------------------------------------------------
// C2a §6.1/§6.2: typed never-pull local mode (docker-host-local-skillspector-v1)
// ---------------------------------------------------------------------------

/**
 * Why a `detector.skillspector` request was refused before the container ran.
 * The B2 wiring maps `reason` to Core's refusal reason of the same name;
 * `prerequisite` names which prerequisite is missing (the docker client, or
 * the verified container image).
 */
export type SkillspectorRunRefusalV1 =
  | Readonly<{
      reason: "prerequisite-missing";
      prerequisite: "docker" | "container-image";
      detail: string;
    }>
  | Readonly<{ reason: "execution-profile-unavailable"; detail: string }>
  | Readonly<{ reason: "subject-requirement-unmet"; detail: string }>;

/** A prerequisite refusal from the image-resolution probes (C2a §6.1). */
export type SkillspectorPrerequisiteRefusalV1 = Extract<
  SkillspectorRunRefusalV1,
  { reason: "prerequisite-missing" }
>;

export type SkillspectorLocalImageResolutionV1 =
  | Readonly<{ status: "resolved"; match: SkillspectorImageAdmissionV1 }>
  | Readonly<{ status: "refused"; refusal: SkillspectorPrerequisiteRefusalV1 }>;

function prerequisiteRefusal(
  prerequisite: "docker" | "container-image",
  detail: string,
): SkillspectorLocalImageResolutionV1 {
  return Object.freeze({
    status: "refused" as const,
    refusal: Object.freeze({ reason: "prerequisite-missing" as const, prerequisite, detail }),
  });
}

/**
 * C2a §6.1 never-pull image resolution, with Core's exact probe sequence and
 * detail texts but typed refusals instead of reason strings: `docker
 * --version` must succeed (else the docker prerequisite is missing), the
 * pinned local tag must inspect (else the container-image prerequisite is
 * missing), and the inspected identity must match the pinned digest or a
 * caller-accepted one (else a refusal naming the pinned digest). Nothing is
 * pulled; the tag alone never runs.
 */
export async function resolveLocalSkillspectorImageV1(
  run: SkillspectorRunnerV1,
  platform: SkillspectorPlatformV1,
  env: NodeJS.ProcessEnv,
  timeoutMs: number,
  acceptedImageDigests: readonly string[] = [],
): Promise<SkillspectorLocalImageResolutionV1> {
  const childEnv = scrubDockerClientEnvV1(env);
  const docker = await run(skillspectorDockerVersionArgvV1(platform), {
    env: childEnv,
    timeoutMs,
  });
  if (docker.spawnError || docker.code === 127)
    return prerequisiteRefusal("docker", `Docker is unavailable (${runSummaryV1(docker)})`);
  if (docker.code !== 0)
    return prerequisiteRefusal("docker", `docker --version failed (${runSummaryV1(docker)})`);

  const image = await run(skillspectorImageInspectArgvV1(platform), {
    env: childEnv,
    timeoutMs,
  });
  if (image.spawnError || image.code === 127)
    return prerequisiteRefusal(
      "container-image",
      `sandbox image ${SKILLSPECTOR_IMAGE_TAG_V1} is unavailable (${runSummaryV1(image)})`,
    );
  if (image.code !== 0 || image.stdout.trim().length === 0)
    return prerequisiteRefusal(
      "container-image",
      `sandbox image ${SKILLSPECTOR_IMAGE_TAG_V1} could not be inspected (${runSummaryV1(image)})`,
    );
  const match = admitLocalSkillspectorImageV1(image.stdout, acceptedImageDigests);
  if (match === undefined) {
    const accepted =
      acceptedImageDigests.length > 0 ? " or an org-policy approved local digest" : "";
    return prerequisiteRefusal(
      "container-image",
      `sandbox image ${SKILLSPECTOR_IMAGE_TAG_V1} could not verify expected image digest ${SKILLSPECTOR_IMAGE_DIGEST_V1}${accepted}`,
    );
  }
  return Object.freeze({ status: "resolved" as const, match });
}

/** Availability probe for the local profile: the refusal, or `undefined` when runnable. */
export async function checkLocalSkillspectorAvailableV1(
  run: SkillspectorRunnerV1,
  platform: SkillspectorPlatformV1,
  env: NodeJS.ProcessEnv,
  acceptedImageDigests: readonly string[] = [],
): Promise<SkillspectorPrerequisiteRefusalV1 | undefined> {
  const image = await resolveLocalSkillspectorImageV1(
    run,
    platform,
    env,
    SKILLSPECTOR_AVAILABILITY_TIMEOUT_MS_V1,
    acceptedImageDigests,
  );
  return image.status === "refused" ? image.refusal : undefined;
}

export type SkillspectorScanFailureStageV1 = "execution" | "output";

export interface SkillspectorScanFailureV1 {
  readonly stage: SkillspectorScanFailureStageV1;
  /** Core's exact failure text for the equivalent thrown error. */
  readonly detail: string;
}

export type SkillspectorScanOutcomeV1 =
  | Readonly<{
      status: "succeeded";
      /** The SARIF with `/scan/`-prefixed URIs rewritten source-relative (§6.3). */
      sarif: SkillspectorSarifLogV1;
      /** The exact observation bytes (UTF-8 of the rewritten SARIF). */
      sarifText: string;
      /** The image admission that ran (never the tag), with the admitting digest. */
      image: SkillspectorImageAdmissionV1;
      containerName: string;
    }>
  | Readonly<{ status: "refused"; refusal: SkillspectorRunRefusalV1 }>
  | Readonly<{ status: "failed"; failure: SkillspectorScanFailureV1 }>;

export interface SkillspectorScanRequestV1 {
  readonly run: SkillspectorRunnerV1;
  readonly platform: SkillspectorPlatformV1;
  readonly env: NodeJS.ProcessEnv;
  /** Absolute source root; becomes the read-only `/scan` bind mount. */
  readonly tree: string;
  /**
   * C2a §6.2: extra image digests (`sha256:` + 64 lowercase hex, unique, at
   * most 16) the caller accepts for the `docker-host-local-skillspector-v1`
   * profile. The field is refused for any other profile; this engine only ever
   * plans the local never-pull profile.
   */
  readonly acceptedImageDigests?: readonly string[];
  /** Test seam for a deterministic container name; production leaves it generated. */
  readonly containerName?: string;
}

function scanFailure(
  stage: SkillspectorScanFailureStageV1,
  detail: string,
): SkillspectorScanOutcomeV1 {
  return Object.freeze({
    status: "failed" as const,
    failure: Object.freeze({ stage, detail }),
  });
}

function scanRefusal(refusal: SkillspectorRunRefusalV1): SkillspectorScanOutcomeV1 {
  return Object.freeze({ status: "refused" as const, refusal });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** C2a §1.4: the fallback URI when the analyzer's URI cannot be made source-relative. */
export const SKILLSPECTOR_FALLBACK_SARIF_URI_V1 = "skillspector.sarif";

function isSourceRelativePosixUriV1(uri: string): boolean {
  if (uri.length === 0 || uri.includes("\\")) return false;
  if (uri.startsWith("/") || /^[A-Za-z]:/.test(uri)) return false;
  if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(uri)) return false;
  return !uri
    .split("/")
    .some((segment) => segment.length === 0 || segment === "." || segment === "..");
}

/**
 * C2a §6.3 URI rule for one SkillSpector artifact location: strip a leading
 * `/scan/` or `scan/` (the container's view of the bind mount, exactly as
 * Core's `normalizeSarifUri` strips it), then accept only a source-relative
 * POSIX path (§1.4); anything else — missing, empty, absolute, a scheme, a
 * drive letter, a backslash or a dot segment — becomes `skillspector.sarif`.
 */
export function skillspectorSarifUriV1(raw: unknown): string {
  if (typeof raw !== "string" || raw.length === 0) return SKILLSPECTOR_FALLBACK_SARIF_URI_V1;
  const stripped = raw.replace(/^\/scan\/?/, "").replace(/^scan\/?/, "");
  return isSourceRelativePosixUriV1(stripped) ? stripped : SKILLSPECTOR_FALLBACK_SARIF_URI_V1;
}

function rewriteSarifUrisV1(sarif: Record<string, unknown>): void {
  if (!Array.isArray(sarif.runs)) return;
  for (const run of sarif.runs) {
    if (!isRecord(run) || !Array.isArray(run.results)) continue;
    for (const result of run.results) {
      if (!isRecord(result) || !Array.isArray(result.locations)) continue;
      for (const location of result.locations) {
        if (!isRecord(location)) continue;
        const physical = location.physicalLocation;
        if (!isRecord(physical)) continue;
        const artifact = physical.artifactLocation;
        if (!isRecord(artifact)) continue;
        artifact.uri = skillspectorSarifUriV1(artifact.uri);
      }
    }
  }
}

/**
 * Validates `acceptedImageDigests` for the local profile (C2a §6.2), returning
 * a typed refusal (`execution-profile-unavailable`) instead of throwing.
 */
function acceptedDigestsOrRefusalV1(
  value: readonly string[] | undefined,
): { digests: readonly string[] } | { refusal: SkillspectorRunRefusalV1 } {
  if (value === undefined) return { digests: [] };
  const detail = skillspectorAcceptedImageDigestsRefusalV1(value);
  if (detail !== undefined)
    return {
      refusal: Object.freeze({ reason: "execution-profile-unavailable" as const, detail }),
    };
  return { digests: value };
}

/**
 * C2a §6 local-mode scan: validates `acceptedImageDigests` (§6.2), refuses a
 * bind-mount source with a comma or control character before spawning (§6.3),
 * resolves the verified local image (§6.1, typed prerequisite refusals, never
 * pulling), runs the hardened container (§6.3 argv, 900 000 ms), and applies
 * Core's cleanup rule: on a spawn error, truncated output, a timeout or an
 * abort (the runner reports the latter two as `spawnError`) the bounded
 * container is force-removed (`docker rm --force --volumes <name>`, 30 000 ms)
 * and a failed cleanup is appended to the failure detail. Exit 0 or 1 with
 * non-empty stdout returns the SARIF with `/scan/` URIs rewritten
 * source-relative; anything else is a failure. An empty tree completes with
 * zero results. Never throws for a scan shortfall.
 */
export async function runSkillspectorScanV1(
  request: SkillspectorScanRequestV1,
): Promise<SkillspectorScanOutcomeV1> {
  const accepted = acceptedDigestsOrRefusalV1(request.acceptedImageDigests);
  if ("refusal" in accepted) return scanRefusal(accepted.refusal);

  if (hasUnsupportedDockerMountSourceCharV1(request.tree))
    return scanRefusal(
      Object.freeze({
        reason: "subject-requirement-unmet" as const,
        detail: "unsupported Docker bind mount source path: comma/control characters",
      }),
    );

  const image = await resolveLocalSkillspectorImageV1(
    request.run,
    request.platform,
    request.env,
    SKILLSPECTOR_AVAILABILITY_TIMEOUT_MS_V1,
    accepted.digests,
  );
  if (image.status === "refused") return scanRefusal(image.refusal);

  const containerName = request.containerName ?? `aih-skillspector-${randomUUIDSuffixV1()}`;
  const dockerEnv = scrubDockerClientEnvV1(request.env);
  const scan = await request.run(
    skillspectorDockerRunArgvV1(
      request.platform,
      request.tree,
      image.match.reference,
      containerName,
    ),
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
  let parsed: unknown;
  try {
    parsed = JSON.parse(scan.stdout);
  } catch {
    parsed = undefined;
  }
  if (!isRecord(parsed) || !Array.isArray(parsed.runs))
    return scanFailure("output", "detector did not emit valid SARIF");
  rewriteSarifUrisV1(parsed);
  const sarif = deepFreezeStrictJsonV1(parsed) as SkillspectorSarifLogV1;
  return Object.freeze({
    status: "succeeded" as const,
    sarif,
    sarifText: JSON.stringify(parsed),
    image: image.match,
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
