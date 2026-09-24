import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type CiscoSarifLogV1,
  type CiscoSarifRunV1,
  mergedCiscoSarifTextV1,
  prefixCiscoSarifUrisV1,
} from "./merge-v1.js";
import {
  CISCO_MULTI_SKILL_SCAN_TIMEOUT_MS_V1,
  CISCO_MULTI_SKILL_SCANNER_VERSION_V1,
  type CiscoMultiSkillPlatformV1,
  type CiscoMultiSkillRunnerV1,
  type CiscoMultiSkillRunResultV1,
  type CiscoSkillInventoryV1,
  ciscoSkillScannerRunArgvV1,
  ciscoSkillScannerVersionArgvV1,
  collectCiscoSkillDirsV1,
  resolveCiscoScanConcurrencyV1,
  scrubCiscoScanEnvV1,
} from "./plan-v1.js";

/**
 * Execution for the `detector.cisco` multi-skill scan behind the injected
 * runner seam, ported behaviour-for-behaviour from Core's
 * `src/trust/detectors.ts` (`checkCiscoAvailable`, `scanCiscoSkillDirectory`,
 * `mapConcurrentStable`, `runCiscoSkillScan`). This module never spawns a
 * process itself; the runtime supplies {@link CiscoMultiSkillRunnerV1}.
 *
 * Failure behaviour mirrors Core message-for-message and is thrown as an
 * `Error`: one failing skill fails the whole scan, in-flight jobs are drained,
 * and the lowest-index failure is the one reported.
 */

/**
 * Core's `runFailureReason`: `undefined` for a clean exit, otherwise the
 * process's own words (stderr, else stdout) or the caller's fallback.
 */
export function ciscoScanFailureReasonV1(
  result: CiscoMultiSkillRunResultV1,
  fallback: string,
): string | undefined {
  if (!result.spawnError && result.code === 0) return undefined;
  return result.stderr || result.stdout || fallback;
}

export interface CiscoSkillScannerAvailabilityRequestV1 {
  readonly run: CiscoMultiSkillRunnerV1;
  readonly platform: CiscoMultiSkillPlatformV1;
  readonly env: NodeJS.ProcessEnv;
  /** Defaults to the pinned {@link CISCO_MULTI_SKILL_SCANNER_VERSION_V1}. */
  readonly expectedVersion?: string;
  readonly analyzerProject?: string;
}

/**
 * Availability probe, ported from Core's `checkCiscoAvailable`: runs
 * `skill-scanner --version` under the locked offline project and returns why
 * the scanner cannot run, or `undefined` when it can. A reported version must
 * equal `skill-scanner <expectedVersion>` exactly.
 */
export async function checkCiscoSkillScannerAvailableV1(
  request: CiscoSkillScannerAvailabilityRequestV1,
): Promise<string | undefined> {
  const expectedVersion = request.expectedVersion ?? CISCO_MULTI_SKILL_SCANNER_VERSION_V1;
  const version = await request.run(
    ciscoSkillScannerVersionArgvV1(request.platform, request.analyzerProject),
    {
      env: scrubCiscoScanEnvV1(request.env),
      timeoutMs: CISCO_MULTI_SKILL_SCAN_TIMEOUT_MS_V1,
    },
  );
  const reason = ciscoScanFailureReasonV1(version, `uvx exit ${version.code ?? "signal"}`);
  if (reason !== undefined) return reason;
  const reportedVersion = version.stdout.trim();
  if (reportedVersion.length === 0) {
    return "skill-scanner version check emitted no output";
  }
  if (reportedVersion !== `skill-scanner ${expectedVersion}`) {
    return `skill-scanner version ${JSON.stringify(reportedVersion)} does not match ${expectedVersion}`;
  }
  return undefined;
}

export interface CiscoSkillDirectoryScanRequestV1 {
  readonly run: CiscoMultiSkillRunnerV1;
  readonly platform: CiscoMultiSkillPlatformV1;
  readonly env: NodeJS.ProcessEnv;
  /** Absolute source root the skill directory is prefixed against. */
  readonly root: string;
  /** Absolute skill directory; also the scan's working directory. */
  readonly skillDir: string;
  readonly analyzerProject?: string;
}

/**
 * One skill's scan, ported from Core's `scanCiscoSkillDirectory`: the scanner
 * writes SARIF to a private temporary file, a non-zero/spawn-failed run throws
 * its failure reason, and the parsed log is returned with URIs prefixed and
 * invocation timestamps removed. The temporary directory is always removed.
 */
export async function scanCiscoSkillDirectoryV1(
  request: CiscoSkillDirectoryScanRequestV1,
): Promise<CiscoSarifLogV1> {
  const tmp = mkdtempSync(join(tmpdir(), "aih-cisco-sarif-"));
  const output = join(tmp, "results.sarif");
  try {
    const scan = await request.run(
      ciscoSkillScannerRunArgvV1(
        request.platform,
        request.skillDir,
        output,
        request.analyzerProject,
      ),
      {
        cwd: request.skillDir,
        env: scrubCiscoScanEnvV1(request.env),
        timeoutMs: CISCO_MULTI_SKILL_SCAN_TIMEOUT_MS_V1,
      },
    );
    const reason = ciscoScanFailureReasonV1(scan, `detector exit ${scan.code ?? "signal"}`);
    if (reason !== undefined) throw new Error(reason);
    return prefixCiscoSarifUrisV1(readFileSync(output, "utf8"), request.root, request.skillDir);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

/**
 * Core's `mapConcurrentStable`: at most `limit` workers, results kept in input
 * order, and on any failure no new work starts, in-flight work is awaited, and
 * the lowest-index failure is thrown.
 */
export async function mapConcurrentStableV1<T, R>(
  items: readonly T[],
  limit: number,
  worker: (item: T) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  const failures: Array<{ error: unknown; index: number }> = [];
  let nextIndex = 0;
  let stopped = false;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (!stopped && nextIndex < items.length) {
      const index = nextIndex++;
      const item = items[index];
      if (item === undefined) throw new Error(`concurrent work item ${index} is missing`);
      try {
        results[index] = await worker(item);
      } catch (error) {
        failures.push({ error, index });
        stopped = true;
      }
    }
  });
  await Promise.all(workers);
  const firstFailure = failures.sort((left, right) => left.index - right.index)[0];
  if (firstFailure !== undefined) throw firstFailure.error;
  return results;
}

export interface CiscoSkillScanRequestV1 {
  readonly run: CiscoMultiSkillRunnerV1;
  readonly platform: CiscoMultiSkillPlatformV1;
  readonly env: NodeJS.ProcessEnv;
  /** Absolute source tree root; Core passes it already realpath-resolved. */
  readonly tree: string;
  /** Caller-built file inventory; absent, the tree is walked on disk. */
  readonly inventory?: CiscoSkillInventoryV1;
  readonly analyzerProject?: string;
}

/**
 * The whole multi-skill scan, ported from Core's `runCiscoSkillScan`: every
 * `SKILL.md` directory is scanned once at bounded concurrency
 * (`AIH_CISCO_SCAN_CONCURRENCY`, default 4, maximum 64), and the merged SARIF
 * text is returned. A tree with no skill directories, or any failing skill,
 * throws.
 */
export async function runCiscoSkillScanV1(request: CiscoSkillScanRequestV1): Promise<string> {
  const skillDirs = collectCiscoSkillDirsV1(request.tree, request.inventory);
  if (skillDirs.length === 0) throw new Error("no SKILL.md directories found for Cisco scan");
  const runsBySkill = await mapConcurrentStableV1(
    skillDirs,
    resolveCiscoScanConcurrencyV1(request.env),
    async (skillDir): Promise<CiscoSarifRunV1[]> =>
      (
        await scanCiscoSkillDirectoryV1({
          run: request.run,
          platform: request.platform,
          env: request.env,
          root: request.tree,
          skillDir,
          ...(request.analyzerProject === undefined
            ? {}
            : { analyzerProject: request.analyzerProject }),
        })
      ).runs ?? [],
  );
  return mergedCiscoSarifTextV1(runsBySkill);
}
