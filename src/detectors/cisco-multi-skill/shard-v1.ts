import { createHash } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { hashComponentTreeV1 } from "../../observation/source-hash-v1.js";
import {
  CISCO_MULTI_SKILL_SCANNER_PROJECT_V1,
  type CiscoMultiSkillPlatformV1,
  type CiscoMultiSkillRunnerV1,
  resolveCiscoScanConcurrencyV1,
} from "./plan-v1.js";
import { checkCiscoSkillScannerAvailableV1, scanCiscoSkillDirectoryV1 } from "./scan-v1.js";

/**
 * Execution side of Core's exact-source Cisco shards, ported
 * behaviour-for-behaviour from `runCiscoSourceShard`,
 * `verifyCiscoShardSource` and the async shard run loop in Core's
 * `src/trust/detectors.ts` and `src/trust/cisco-shards.ts`
 * (`buildCiscoShardResultAsync`).
 *
 * A shard runner re-proves everything it relies on: the manifest's own digest,
 * the source tree and every job input hash (before the run, around each job's
 * scan, and after the run), the local analyzer `uv.lock` against the manifest,
 * and the analyzer version the manifest names. Evidence digests use Core's
 * exact canonicalization so Core's retained join accepts these results.
 *
 * Shard MANIFEST construction and shard JOIN stay in Core and are not here.
 * This module never spawns a process; the runtime supplies the runner seam.
 */

export interface CiscoShardJobInputV1 {
  /** POSIX path to the exact skill directory within the pinned source tree. */
  readonly path: string;
  /** Digest of the complete scanner input projection for this job. */
  readonly inputSha256: string;
}

export interface CiscoShardJobV1 extends CiscoShardJobInputV1 {
  readonly id: string;
}

export interface CiscoShardManifestV1 {
  readonly schemaVersion: 1;
  readonly qualificationId: string;
  readonly manifestSha256: string;
  readonly source: {
    readonly id: string;
    readonly pinnedSha: string;
    readonly treeSha256: string;
  };
  readonly analyzer: {
    readonly name: "cisco";
    readonly version: string;
    readonly lockSha256: string;
  };
  readonly policy: {
    readonly version: string;
    readonly profile: string;
  };
  readonly jobs: readonly CiscoShardJobV1[];
  readonly shards: readonly {
    readonly id: string;
    readonly jobs: readonly CiscoShardJobV1[];
  }[];
}

export interface CiscoShardOutputV1 {
  readonly jobId: string;
  readonly path: string;
  readonly inputSha256: string;
  readonly evidenceSha256: string;
  readonly evidence: unknown;
}

export interface CiscoShardResultV1 {
  readonly schemaVersion: 1;
  readonly manifestSha256: string;
  readonly qualificationId: string;
  readonly shardId: string;
  readonly analyzer: CiscoShardManifestV1["analyzer"];
  readonly outputs: readonly CiscoShardOutputV1[];
}

const SHA256_V1 = /^[0-9a-f]{64}$/;
const GIT_SHA_V1 = /^[0-9a-f]{40}$/;
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

const sha256TextV1 = z.string().regex(SHA256_V1);
const shardJobSchemaV1 = z.strictObject({
  id: sha256TextV1,
  path: z
    .string()
    .min(1)
    .max(MAX_SHARD_TEXT_V1)
    .refine(isSafeShardPathV1, { message: "must be a safe POSIX source-relative path" }),
  inputSha256: sha256TextV1,
});
const shardManifestSchemaV1 = z.strictObject({
  schemaVersion: z.literal(1),
  qualificationId: sha256TextV1,
  manifestSha256: sha256TextV1,
  source: z.strictObject({
    id: z.string().min(1).max(MAX_SHARD_TEXT_V1),
    pinnedSha: z.string().regex(GIT_SHA_V1),
    treeSha256: sha256TextV1,
  }),
  analyzer: z.strictObject({
    name: z.literal("cisco"),
    version: z.string().min(1).max(MAX_SHARD_TEXT_V1),
    lockSha256: sha256TextV1,
  }),
  policy: z.strictObject({
    version: z.string().min(1).max(MAX_SHARD_TEXT_V1),
    profile: z.string().min(1).max(MAX_SHARD_TEXT_V1),
  }),
  jobs: z.array(shardJobSchemaV1).min(1).max(MAX_SHARD_JOBS_V1),
  shards: z
    .array(
      z.strictObject({
        id: z.string().min(1).max(MAX_SHARD_TEXT_V1),
        jobs: z.array(shardJobSchemaV1).max(MAX_SHARD_JOBS_V1),
      }),
    )
    .min(1)
    .max(MAX_SHARD_JOBS_V1),
});

/**
 * Boundary validation for a manifest received from Core, as plain data. The
 * digest self-consistency check is not repeated here; it runs again inside
 * {@link runCiscoShardJobsV1}, exactly where Core performs it.
 */
export function parseCiscoShardManifestV1(value: unknown): CiscoShardManifestV1 {
  const parsed = shardManifestSchemaV1.safeParse(value);
  if (!parsed.success) {
    throw new TypeError(
      `invalid Cisco shard manifest V1: ${parsed.error.issues[0]?.message ?? "schema"}`,
    );
  }
  return parsed.data as CiscoShardManifestV1;
}

function canonicalShardValueV1(value: unknown, seen = new Set<object>()): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  ) {
    return value;
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) throw new Error("Cisco shard evidence must not contain cycles");
    seen.add(value);
    const output = value.map((entry) => canonicalShardValueV1(entry, seen));
    seen.delete(value);
    return output;
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    if (seen.has(record)) throw new Error("Cisco shard evidence must not contain cycles");
    seen.add(record);
    const output: Record<string, unknown> = {};
    // Core orders evidence keys with `localeCompare`, not code units; the
    // evidence digest must match Core's join byte-for-byte, so this ordering
    // is mirrored exactly rather than swapped for `codeUnitCompare`.
    for (const key of Object.keys(record).sort((left, right) => left.localeCompare(right))) {
      const entry = record[key];
      if (entry === undefined) continue;
      output[key] = canonicalShardValueV1(entry, seen);
    }
    seen.delete(record);
    return output;
  }
  throw new Error(`Cisco shard evidence contains unsupported ${typeof value} value`);
}

/** Core's canonical shard JSON: sorted keys, `undefined` values skipped. */
export function canonicalCiscoShardJsonV1(value: unknown): string {
  return JSON.stringify(canonicalShardValueV1(value));
}

/** sha256 hex of {@link canonicalCiscoShardJsonV1}, as Core computes it. */
export function ciscoShardSha256V1(value: unknown): string {
  return createHash("sha256").update(canonicalCiscoShardJsonV1(value), "utf8").digest("hex");
}

function computedManifestSha256V1(manifest: CiscoShardManifestV1): string {
  const { manifestSha256: _manifestSha256, ...unsigned } = manifest;
  return ciscoShardSha256V1(unsigned);
}

/**
 * The async shard run loop, ported from Core's `buildCiscoShardResultAsync`:
 * the manifest digest is re-verified, the shard id must be one the manifest
 * declares, worker concurrency is bounded to 1..64, and on any failure no new
 * job starts, in-flight jobs are awaited, and the lowest-index failure is
 * thrown. Outputs land in the shard's job order, each evidence value digest-
 * bound with Core's canonicalization.
 */
export async function runCiscoShardJobsV1(
  manifest: CiscoShardManifestV1,
  requestedShardId: string,
  evidenceFor: (job: CiscoShardJobV1) => Promise<unknown>,
  concurrency = 1,
): Promise<CiscoShardResultV1> {
  if (computedManifestSha256V1(manifest) !== manifest.manifestSha256) {
    throw new Error("Cisco shard manifest identity does not match its contents");
  }
  const shard = manifest.shards.find((candidate) => candidate.id === requestedShardId);
  if (shard === undefined) throw new Error(`unexpected Cisco shard id: ${requestedShardId}`);
  if (!Number.isSafeInteger(concurrency) || concurrency < 1 || concurrency > 64) {
    throw new Error("Cisco shard worker concurrency must be an integer from 1 through 64");
  }
  const outputs = new Array<CiscoShardOutputV1>(shard.jobs.length);
  let nextIndex = 0;
  let stopped = false;
  const failures: Array<{ index: number; error: unknown }> = [];
  const workers = Array.from(
    { length: Math.min(concurrency, shard.jobs.length) },
    async (): Promise<void> => {
      while (!stopped && nextIndex < shard.jobs.length) {
        const index = nextIndex++;
        const job = shard.jobs[index];
        if (job === undefined) throw new Error(`Cisco shard job ${index} is missing`);
        try {
          const evidence = await evidenceFor(job);
          outputs[index] = Object.freeze({
            jobId: job.id,
            path: job.path,
            inputSha256: job.inputSha256,
            evidenceSha256: ciscoShardSha256V1(evidence),
            evidence,
          });
        } catch (error) {
          failures.push({ index, error });
          stopped = true;
        }
      }
    },
  );
  await Promise.all(workers);
  const firstFailure = failures.sort((left, right) => left.index - right.index)[0];
  if (firstFailure !== undefined) throw firstFailure.error;
  return Object.freeze({
    schemaVersion: 1 as const,
    manifestSha256: manifest.manifestSha256,
    qualificationId: manifest.qualificationId,
    shardId: shard.id,
    analyzer: manifest.analyzer,
    outputs: Object.freeze(outputs),
  });
}

/**
 * Re-proves the exact source identity the manifest pins: the tree hash over
 * all job paths, then each job's own input hash. Ported from Core's
 * `verifyCiscoShardSource`.
 */
export function verifyCiscoShardSourceV1(root: string, manifest: CiscoShardManifestV1): void {
  const paths = manifest.jobs.map((job) => job.path);
  const sourceTree = hashComponentTreeV1(root, paths);
  if (sourceTree.treeSha256 !== manifest.source.treeSha256) {
    throw new Error("Cisco shard source tree does not match the exact manifest identity");
  }
  for (const job of manifest.jobs) {
    if (hashComponentTreeV1(root, [job.path]).treeSha256 !== job.inputSha256) {
      throw new Error(`Cisco shard input identity changed: ${job.path}`);
    }
  }
}

export interface CiscoSourceShardRunOptionsV1 {
  readonly run: CiscoMultiSkillRunnerV1;
  readonly platform: CiscoMultiSkillPlatformV1;
  readonly env: NodeJS.ProcessEnv;
  /** Overrides `AIH_CISCO_SCAN_CONCURRENCY` when set; bounded to 1..64. */
  readonly concurrency?: number;
  /** Analyzer lock project override (tests); defaults to the bundled project. */
  readonly analyzerProject?: string;
}

/**
 * One source shard's execution, ported from Core's `runCiscoSourceShard`:
 * verify the source tree and job inputs against the manifest, prove the local
 * analyzer `uv.lock` equals the manifest's, take the expected analyzer version
 * from the manifest (build metadata after `+` dropped), probe availability,
 * then run this shard's jobs — re-checking each job's input hash immediately
 * before and after its scan — and verify the whole source tree once more
 * before returning.
 */
export async function runCiscoSourceShardV1(
  root: string,
  manifest: CiscoShardManifestV1,
  shardId: string,
  options: CiscoSourceShardRunOptionsV1,
): Promise<CiscoShardResultV1> {
  const safeRoot = realpathSync(root);
  verifyCiscoShardSourceV1(safeRoot, manifest);
  const expectedVersion = manifest.analyzer.version.split("+", 1)[0] ?? manifest.analyzer.version;
  const analyzerProject = options.analyzerProject ?? CISCO_MULTI_SKILL_SCANNER_PROJECT_V1;
  const localLockSha256 = createHash("sha256")
    .update(readFileSync(join(analyzerProject, "uv.lock")))
    .digest("hex");
  if (localLockSha256 !== manifest.analyzer.lockSha256) {
    throw new Error(
      `Cisco shard analyzer lock does not match manifest identity: ${localLockSha256}`,
    );
  }
  const unavailable = await checkCiscoSkillScannerAvailableV1({
    run: options.run,
    platform: options.platform,
    env: options.env,
    expectedVersion,
    analyzerProject,
  });
  if (unavailable !== undefined)
    throw new Error(`Cisco shard analyzer unavailable: ${unavailable}`);
  const result = await runCiscoShardJobsV1(
    manifest,
    shardId,
    async (job) => {
      const skillDir = join(safeRoot, ...job.path.split("/"));
      if (hashComponentTreeV1(safeRoot, [job.path]).treeSha256 !== job.inputSha256) {
        throw new Error(`Cisco shard input identity changed before scan: ${job.path}`);
      }
      const sarif = await scanCiscoSkillDirectoryV1({
        run: options.run,
        platform: options.platform,
        env: options.env,
        root: safeRoot,
        skillDir,
        analyzerProject,
      });
      if (hashComponentTreeV1(safeRoot, [job.path]).treeSha256 !== job.inputSha256) {
        throw new Error(`Cisco shard input identity changed during scan: ${job.path}`);
      }
      return sarif;
    },
    options.concurrency ?? resolveCiscoScanConcurrencyV1(options.env),
  );
  verifyCiscoShardSourceV1(safeRoot, manifest);
  return result;
}
