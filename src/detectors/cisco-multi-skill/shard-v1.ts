import { createHash } from "node:crypto";
import { readFileSync, realpathSync, statSync } from "node:fs";
import { join } from "node:path";
import { hashComponentTreeV1 } from "../../observation/source-hash-v1.js";
import {
  ciscoJobDirectoryProblemTextV1,
  resolveContainedCiscoJobDirectoryV1,
} from "./job-dir-v1.js";
import {
  CISCO_MULTI_SKILL_SCANNER_PROJECT_V1,
  type CiscoMultiSkillPlatformV1,
  type CiscoMultiSkillRunnerV1,
} from "./plan-v1.js";
import {
  boundedCiscoDetailV1,
  type CiscoScanFailureStageV1,
  mapConcurrentStableV1,
  probeCiscoSkillScannerV1,
  scanCiscoSkillDirectoryOutcomeV1,
} from "./scan-v1.js";

/**
 * Execution of one exact-source Cisco shard for Core's baseline vet (C2a
 * §3.7), ported behaviour-for-behaviour from the execution half of Core's
 * `runCiscoSourceShard` (`src/trust/detectors.ts`): the local analyzer
 * `uv.lock` is proven against the expected identity, the expected analyzer
 * version is checked by the version gate, and every job's input identity is
 * re-proven before the shard, around each job's scan, and after the shard.
 *
 * Shard MANIFEST construction, evidence digests and the shard JOIN stay in
 * Core and are not here. This module never spawns a process; the runtime
 * supplies the runner seam.
 */

/** One shard job as Core's manifest lists it. */
export interface CiscoShardJobV1 {
  readonly id: string;
  /** POSIX path to the exact skill directory within the pinned source tree. */
  readonly path: string;
  /** Core's component-tree digest of the job's input. */
  readonly inputSha256: string;
}

const SHA256_V1 = /^[0-9a-f]{64}$/;
const MAX_SHARD_JOBS_V1 = 4096;
const MAX_SHARD_TEXT_V1 = 1024;

/** Core's shard job path rule (`safePath`), kept byte-for-byte. */
function isSafeShardPathV1(value: string): boolean {
  return !(
    value.length === 0 ||
    value.startsWith("/") ||
    value.startsWith("./") ||
    value.includes("\\") ||
    value.endsWith("/") ||
    value.split("/").some((part) => part.length === 0 || part === "." || part === "..")
  );
}

/**
 * sha256 of the bundled analyzer project's `uv.lock` — the digest a profile's
 * future `analyzerLock` publishes and the value a shard request's
 * `expected.lockSha256` must equal (C2a §3.7).
 */
export function ciscoSkillScannerLockSha256V1(
  project: string = CISCO_MULTI_SKILL_SCANNER_PROJECT_V1,
): string {
  return createHash("sha256")
    .update(readFileSync(join(project, "uv.lock")))
    .digest("hex");
}

/**
 * The shard execution request behind Core's future `runCiscoShardV1` export
 * (C2a §3.7): one shard's jobs in manifest order, the manifest's expected
 * analyzer identity, and the caller's worker bound. The execution profile id
 * and its echo are B2 wiring and deliberately not part of this engine seam.
 */
export interface CiscoShardRunRequestV1 {
  readonly run: CiscoMultiSkillRunnerV1;
  readonly platform: CiscoMultiSkillPlatformV1;
  readonly env: NodeJS.ProcessEnv;
  /** The pinned baseline source root. */
  readonly sourceRoot: string;
  /** The shard's jobs, in manifest order. */
  readonly jobs: readonly CiscoShardJobV1[];
  /** The manifest's analyzer identity (`version` may carry a `+` suffix). */
  readonly expected: { readonly analyzerVersion: string; readonly lockSha256: string };
  /** Worker bound, Core's `resolveCiscoScanConcurrency` result: 1..64. */
  readonly concurrency: number;
  /** Analyzer lock project override (tests); defaults to the bundled project. */
  readonly analyzerProject?: string;
}

/** One job's output: the §3.4-adjusted SARIF bytes and their plain sha256. */
export interface CiscoShardJobSarifOutputV1 {
  readonly jobId: string;
  readonly path: string;
  readonly inputSha256: string;
  readonly sarif: Uint8Array;
  /** sha256 hex over `sarif`. */
  readonly sha256: string;
}

/** Refusal reasons the shard runner can return before anything runs. */
export type CiscoShardRunRefusalReasonV1 = "shard-request-invalid" | "analyzer-lock-mismatch";

/** Failure stages of a shard run: the §3.5 stages plus source `coverage`. */
export type CiscoShardRunFailureStageV1 = CiscoScanFailureStageV1 | "coverage";

/** Typed outcome of one shard's execution (C2a §3.7); it never throws. */
export type CiscoShardRunOutcomeV1 = Readonly<
  | {
      kind: "completed";
      /** The verified analyzer identity; `version` is before any `+` suffix. */
      analyzer: { readonly version: string; readonly lockSha256: string };
      /** Per-job outputs in the shard's job order. */
      outputs: readonly CiscoShardJobSarifOutputV1[];
      /** Tree seals over all job paths, taken at the start and the end. */
      sourceSeal: { readonly before: string; readonly after: string };
    }
  | { kind: "refused"; reason: CiscoShardRunRefusalReasonV1; detail: string }
  | { kind: "failed"; stage: CiscoShardRunFailureStageV1; detail: string }
>;

function refusedShardRunV1(
  reason: CiscoShardRunRefusalReasonV1,
  detail: string,
): CiscoShardRunOutcomeV1 {
  return Object.freeze({ kind: "refused" as const, reason, detail });
}

function failedShardRunV1(
  stage: CiscoShardRunFailureStageV1,
  detail: string,
): CiscoShardRunOutcomeV1 {
  return Object.freeze({ kind: "failed" as const, stage, detail });
}

/** One failing shard job's stage and detail, carried through the drain. */
class CiscoShardJobFailureV1 extends Error {
  readonly stage: CiscoShardRunFailureStageV1;
  constructor(stage: CiscoShardRunFailureStageV1, detail: string) {
    super(detail);
    this.name = "CiscoShardJobFailureV1";
    this.stage = stage;
  }
}

/** Boundary shape validation of a shard run request; never throws. */
function validateCiscoShardRunRequestV1(request: CiscoShardRunRequestV1): string | undefined {
  if (typeof request.sourceRoot !== "string" || request.sourceRoot.length === 0) {
    return "sourceRoot must be a non-empty path";
  }
  if (!Array.isArray(request.jobs) || request.jobs.length === 0) {
    return "a shard run requires at least one job";
  }
  if (request.jobs.length > MAX_SHARD_JOBS_V1) {
    return `a shard run accepts at most ${MAX_SHARD_JOBS_V1} jobs`;
  }
  const ids = new Set<string>();
  for (const job of request.jobs) {
    if (typeof job.id !== "string" || job.id.length === 0 || job.id.length > MAX_SHARD_TEXT_V1) {
      return "every job id must be a non-empty bounded string";
    }
    if (ids.has(job.id)) return `duplicate shard job id: ${job.id}`;
    ids.add(job.id);
    if (
      typeof job.path !== "string" ||
      job.path.length > MAX_SHARD_TEXT_V1 ||
      !isSafeShardPathV1(job.path)
    ) {
      return `job path must be a safe POSIX source-relative path: ${String(job.path)}`;
    }
    if (typeof job.inputSha256 !== "string" || !SHA256_V1.test(job.inputSha256)) {
      return `job inputSha256 must be a sha256 hex digest: ${job.path}`;
    }
  }
  const expected = request.expected;
  if (
    typeof expected !== "object" ||
    expected === null ||
    typeof expected.analyzerVersion !== "string" ||
    expected.analyzerVersion.length === 0 ||
    expected.analyzerVersion.length > MAX_SHARD_TEXT_V1
  ) {
    return "expected.analyzerVersion must be a non-empty bounded string";
  }
  if (typeof expected.lockSha256 !== "string" || !SHA256_V1.test(expected.lockSha256)) {
    return "expected.lockSha256 must be a sha256 hex digest";
  }
  if (
    !Number.isSafeInteger(request.concurrency) ||
    request.concurrency < 1 ||
    request.concurrency > 64
  ) {
    return "shard worker concurrency must be an integer from 1 through 64";
  }
  return undefined;
}

/**
 * One shard's execution behind Core's future `runCiscoShardV1` (C2a §3.7).
 * The request is validated at the boundary (safe POSIX job paths each holding
 * a `SKILL.md`, unique job ids, 1..64 concurrency); the bundled `uv.lock`
 * digest must equal `expected.lockSha256` or the request is refused before
 * anything runs; the expected analyzer version before any `+` suffix is
 * checked against the version gate (§3.2). Every job path is sealed at the
 * start and the end of the shard, and each job's input identity is re-proven
 * immediately before and after its scan (as Core's `runCiscoSourceShard` did);
 * any difference fails with stage `coverage` ("source changed"). Jobs run with
 * §3.2–§3.4 semantics at the given concurrency in stable job order; on any
 * failure no new job starts, in-flight jobs drain, the lowest-index failure is
 * reported and no partial output is returned.
 */
export async function runCiscoShardV1(
  request: CiscoShardRunRequestV1,
): Promise<CiscoShardRunOutcomeV1> {
  const invalid = validateCiscoShardRunRequestV1(request);
  if (invalid !== undefined) return refusedShardRunV1("shard-request-invalid", invalid);
  const analyzerProject = request.analyzerProject ?? CISCO_MULTI_SKILL_SCANNER_PROJECT_V1;
  let localLockSha256: string;
  try {
    localLockSha256 = ciscoSkillScannerLockSha256V1(analyzerProject);
  } catch (error) {
    return failedShardRunV1(
      "acquisition",
      boundedCiscoDetailV1(
        error instanceof Error ? error.message : "the bundled analyzer uv.lock is unreadable",
      ),
    );
  }
  if (localLockSha256 !== request.expected.lockSha256) {
    return refusedShardRunV1(
      "analyzer-lock-mismatch",
      `Cisco shard analyzer lock does not match the expected identity: ${localLockSha256}`,
    );
  }
  let safeRoot: string;
  try {
    safeRoot = realpathSync(request.sourceRoot);
  } catch {
    return refusedShardRunV1("shard-request-invalid", "sourceRoot must be a readable directory");
  }
  for (const job of request.jobs) {
    // Every job path is a real directory chain inside the root: a linked
    // ancestor would pass the component hash and escape the declared source.
    const resolved = resolveContainedCiscoJobDirectoryV1(safeRoot, job.path);
    if (!resolved.ok) {
      return refusedShardRunV1(
        "shard-request-invalid",
        `Cisco shard job path ${ciscoJobDirectoryProblemTextV1(resolved.problem)}: ${job.path}`,
      );
    }
    let holdsSkill = false;
    try {
      holdsSkill = statSync(join(resolved.skillDir, "SKILL.md")).isFile();
    } catch {
      holdsSkill = false;
    }
    if (!holdsSkill) {
      return refusedShardRunV1(
        "shard-request-invalid",
        `Cisco shard job path holds no SKILL.md: ${job.path}`,
      );
    }
  }
  const jobPaths = request.jobs.map((job) => job.path);
  const sealJobs = (when: string): string | CiscoShardRunOutcomeV1 => {
    try {
      const seal = hashComponentTreeV1(safeRoot, jobPaths).treeSha256;
      for (const job of request.jobs) {
        if (hashComponentTreeV1(safeRoot, [job.path]).treeSha256 !== job.inputSha256) {
          return failedShardRunV1(
            "coverage",
            `source changed ${when}: ${job.path} no longer matches its declared input identity`,
          );
        }
      }
      return seal;
    } catch (error) {
      return failedShardRunV1(
        "coverage",
        boundedCiscoDetailV1(error instanceof Error ? error.message : `source changed ${when}`),
      );
    }
  };
  const before = sealJobs("before the shard");
  if (typeof before !== "string") return before;
  const expectedVersion =
    request.expected.analyzerVersion.split("+", 1)[0] ?? request.expected.analyzerVersion;
  const probe = await probeCiscoSkillScannerV1({
    run: request.run,
    platform: request.platform,
    env: request.env,
    expectedVersion,
    analyzerProject,
  });
  if (probe.kind !== "available") return failedShardRunV1(probe.stage, probe.detail);
  let outputs: CiscoShardJobSarifOutputV1[];
  try {
    outputs = await mapConcurrentStableV1(
      request.jobs,
      request.concurrency,
      async (job): Promise<CiscoShardJobSarifOutputV1> => {
        const resolved = resolveContainedCiscoJobDirectoryV1(safeRoot, job.path);
        if (!resolved.ok) {
          throw new CiscoShardJobFailureV1("coverage", `source changed before scan: ${job.path}`);
        }
        const skillDir = resolved.skillDir;
        if (hashComponentTreeV1(safeRoot, [job.path]).treeSha256 !== job.inputSha256) {
          throw new CiscoShardJobFailureV1("coverage", `source changed before scan: ${job.path}`);
        }
        const outcome = await scanCiscoSkillDirectoryOutcomeV1({
          run: request.run,
          platform: request.platform,
          env: request.env,
          root: safeRoot,
          skillDir,
          analyzerProject,
        });
        if (outcome.kind === "failed") {
          throw new CiscoShardJobFailureV1(outcome.stage, outcome.detail);
        }
        if (hashComponentTreeV1(safeRoot, [job.path]).treeSha256 !== job.inputSha256) {
          throw new CiscoShardJobFailureV1("coverage", `source changed during scan: ${job.path}`);
        }
        const sarif: Uint8Array = Buffer.from(JSON.stringify(outcome.log), "utf8");
        return Object.freeze({
          jobId: job.id,
          path: job.path,
          inputSha256: job.inputSha256,
          sarif,
          sha256: createHash("sha256").update(sarif).digest("hex"),
        });
      },
    );
  } catch (error) {
    if (error instanceof CiscoShardJobFailureV1) {
      // The per-job boundary already bounded and encoded this detail.
      return failedShardRunV1(error.stage, error.message);
    }
    return failedShardRunV1(
      "execution",
      boundedCiscoDetailV1(error instanceof Error ? error.message : "Cisco shard job failed"),
    );
  }
  const after = sealJobs("after the shard");
  if (typeof after !== "string") return after;
  if (after !== before) {
    return failedShardRunV1("coverage", "source changed during the shard");
  }
  return Object.freeze({
    kind: "completed" as const,
    analyzer: Object.freeze({ version: expectedVersion, lockSha256: localLockSha256 }),
    outputs: Object.freeze(outputs),
    sourceSeal: Object.freeze({ before, after }),
  });
}
