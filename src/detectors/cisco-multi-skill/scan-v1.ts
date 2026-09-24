import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import {
  AnalyzerOutputReadErrorV1,
  readBoundedAnalyzerOutputV1,
} from "../../baseline/bounded-output-read-v1.js";
import {
  CiscoAnalyzerFailureV1,
  ciscoSingleSkillReportV1,
} from "../../baseline/cisco-analyzer-failures-v1.js";
import {
  assertCiscoSingleSkillAnalyzersCompleteV1,
  assertCiscoSingleSkillReportSkillV1,
  ciscoSarifResultIdentitiesV1,
} from "../../baseline/cisco-report-skills-v1.js";
import {
  ciscoJobDirectoryProblemTextV1,
  resolveContainedCiscoJobDirectoryV1,
} from "./job-dir-v1.js";
import {
  type CiscoSarifLogV1,
  type CiscoSarifRunV1,
  ciscoJobSarifV1,
  mergedCiscoSarifTextV1,
} from "./merge-v1.js";
import {
  CISCO_MULTI_SKILL_SCAN_TIMEOUT_MS_V1,
  CISCO_MULTI_SKILL_SCANNER_VERSION_V1,
  type CiscoDetectorOptionsValidationV1,
  type CiscoMultiSkillPlatformV1,
  type CiscoMultiSkillRunnerV1,
  type CiscoMultiSkillRunResultV1,
  type CiscoSourceTreeJobV1,
  ciscoSkillScannerRunArgvV1,
  ciscoSkillScannerVersionArgvV1,
  planCiscoSourceTreeJobsV1,
  scrubCiscoScanEnvV1,
  validateCiscoDetectorOptionsV1,
} from "./plan-v1.js";

/**
 * Execution for the `detector.cisco` multi-skill scan behind the injected
 * runner seam, ported behaviour-for-behaviour from Core's
 * `src/trust/detectors.ts` (`checkCiscoAvailable`, `scanCiscoSkillDirectory`,
 * `mapConcurrentStable`, `runCiscoSkillScan`). This module never spawns a
 * process itself; the runtime supplies {@link CiscoMultiSkillRunnerV1}.
 *
 The C2a typed-outcome surface ({@link runCiscoSourceTreeScanV1},
 * {@link probeCiscoSkillScannerV1} and {@link scanCiscoSkillDirectoryOutcomeV1})
 * keeps Core's per-job behaviour and messages but never throws on bad input:
 * options and the subject are validated at the boundary, and every failure
 * carries its stage (`acquisition`, `availability`, `execution` or `output`,
 * C2a §3.5) so the B2 wiring can map it to Core's refusal and failure reasons.
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

/**
 * Failure stages the C2a typed surface reports (C2a §3.5 and §8.4). U1i, coordinator decision
 * D30: `coverage` when Cisco reports a failed analyzer other than the matched skill_loader
 * fallback.
 */
export type CiscoScanFailureStageV1 =
  | "acquisition"
  | "availability"
  | "execution"
  | "output"
  | "coverage";

const MAX_CISCO_DETAIL_CHARACTERS_V1 = 1024;

/**
 * Bounded, control-character-encoded diagnostic text for the typed surface.
 * Analyzer stderr/stdout is untrusted, so only an encoded, capped projection
 * of it reaches a result detail.
 */
export function boundedCiscoDetailV1(value: string): string {
  const encoded = JSON.stringify(value).slice(1, -1);
  if (encoded.length <= MAX_CISCO_DETAIL_CHARACTERS_V1) return encoded;
  const marker = "… middle omitted …";
  const retained = MAX_CISCO_DETAIL_CHARACTERS_V1 - marker.length;
  const headLength = Math.ceil(retained / 2);
  return `${encoded.slice(0, headLength)}${marker}${encoded.slice(-(retained - headLength))}`;
}

function errorDetailV1(error: unknown, fallback: string): string {
  return boundedCiscoDetailV1(error instanceof Error ? error.message : fallback);
}

/** Typed availability probe verdict (C2a §3.2 version gate, §3.5 stages). */
export type CiscoSkillScannerProbeOutcomeV1 = Readonly<
  | { kind: "available" }
  | { kind: "unavailable"; stage: "acquisition" | "availability"; detail: string }
>;

/**
 * Core's `checkCiscoAvailable` version gate, typed: the locked offline
 * `skill-scanner --version` probe, with the failure classified by
 * stage. A probe that cannot run at all (spawn failure, non-zero exit, a
 * runner that throws) is an `acquisition` failure — the analyzer environment
 * could not be acquired; a probe that answered wrongly (empty output, version
 * mismatch) is an `availability` failure (C2a §3.5).
 */
export async function probeCiscoSkillScannerV1(
  request: CiscoSkillScannerAvailabilityRequestV1,
): Promise<CiscoSkillScannerProbeOutcomeV1> {
  const expectedVersion = request.expectedVersion ?? CISCO_MULTI_SKILL_SCANNER_VERSION_V1;
  let version: CiscoMultiSkillRunResultV1;
  try {
    version = await request.run(
      ciscoSkillScannerVersionArgvV1(request.platform, request.analyzerProject),
      {
        env: scrubCiscoScanEnvV1(request.env),
        timeoutMs: CISCO_MULTI_SKILL_SCAN_TIMEOUT_MS_V1,
      },
    );
  } catch (error) {
    return Object.freeze({
      kind: "unavailable" as const,
      stage: "acquisition" as const,
      detail: errorDetailV1(error, "Cisco skill-scanner version check could not run"),
    });
  }
  if (version.spawnError || version.code !== 0) {
    return Object.freeze({
      kind: "unavailable" as const,
      stage: "acquisition" as const,
      detail: boundedCiscoDetailV1(
        version.stderr || version.stdout || `uvx exit ${version.code ?? "signal"}`,
      ),
    });
  }
  const reportedVersion = version.stdout.trim();
  if (reportedVersion.length === 0) {
    return Object.freeze({
      kind: "unavailable" as const,
      stage: "availability" as const,
      detail: "skill-scanner version check emitted no output",
    });
  }
  if (reportedVersion !== `skill-scanner ${expectedVersion}`) {
    return Object.freeze({
      kind: "unavailable" as const,
      stage: "availability" as const,
      detail: `skill-scanner version ${JSON.stringify(reportedVersion)} does not match ${expectedVersion}`,
    });
  }
  return Object.freeze({ kind: "available" as const });
}

/** Typed outcome of one skill directory's scan (C2a §3.2). */
export type CiscoSkillDirectoryScanOutcomeV1 = Readonly<
  | { kind: "completed"; log: CiscoSarifLogV1 }
  | { kind: "failed"; stage: "execution" | "output" | "coverage"; detail: string }
>;

/**
 * Core's `scanCiscoSkillDirectory`, typed: the same argv, cwd, timeout and
 * exit-0 requirement, but failures are returned, not thrown. A
 * process failure is stage `execution`; a SARIF file that is missing, does
 * not parse or does not prove completion is stage `output`, and one whose
 * invocation reports the analyzer's own failure is stage `execution`
 * ({@link ciscoJobSarifV1}). U1i, coordinator decision D30 (revised 20:58Z): the job's
 * single-skill JSON report is then read with the one strict parser; a missing, unreadable or
 * malformed report, or a malformed `analyzers_failed`, is stage `output` (never a fallback
 * to SARIF alone), and a failed analyzer other than the matched skill_loader fallback is stage
 * `coverage`. U1j: a report whose `skill_path` does not name exactly this job's directory
 * (`assertCiscoSingleSkillReportSkillV1`) is stage `output`, before its `analyzers_failed` is
 * read. The private temporary directory is always removed.
 */
export async function scanCiscoSkillDirectoryOutcomeV1(
  request: CiscoSkillDirectoryScanRequestV1,
): Promise<CiscoSkillDirectoryScanOutcomeV1> {
  const tmp = mkdtempSync(join(tmpdir(), "aih-cisco-sarif-"));
  const output = join(tmp, "results.sarif");
  const jsonOutput = join(tmp, "results.json");
  try {
    let scan: CiscoMultiSkillRunResultV1;
    try {
      scan = await request.run(
        ciscoSkillScannerRunArgvV1(
          request.platform,
          request.skillDir,
          output,
          jsonOutput,
          request.analyzerProject,
        ),
        {
          cwd: request.skillDir,
          env: scrubCiscoScanEnvV1(request.env),
          timeoutMs: CISCO_MULTI_SKILL_SCAN_TIMEOUT_MS_V1,
        },
      );
    } catch (error) {
      return Object.freeze({
        kind: "failed" as const,
        stage: "execution" as const,
        detail: errorDetailV1(error, "Cisco skill-scanner runner failed"),
      });
    }
    const reason = ciscoScanFailureReasonV1(scan, `detector exit ${scan.code ?? "signal"}`);
    if (reason !== undefined) {
      return Object.freeze({
        kind: "failed" as const,
        stage: "execution" as const,
        detail: boundedCiscoDetailV1(reason),
      });
    }
    // U1j: both output files are read as bounded regular files (the analyzer-output cap).
    let raw: Buffer;
    try {
      raw = readBoundedAnalyzerOutputV1(output, "Cisco SARIF");
    } catch (error) {
      if (!(error instanceof AnalyzerOutputReadErrorV1)) throw error;
      return Object.freeze({
        kind: "failed" as const,
        stage: "output" as const,
        detail:
          error.reason === "missing"
            ? "detector did not emit valid SARIF"
            : boundedCiscoDetailV1(`detector did not emit valid SARIF: ${error.message}`),
      });
    }
    const sarif = ciscoJobSarifV1(raw, request.root, request.skillDir);
    if (!sarif.ok)
      return Object.freeze({
        kind: "failed" as const,
        stage: sarif.stage,
        detail: boundedCiscoDetailV1(sarif.detail),
      });
    const skill = relative(request.root, request.skillDir).split(sep).join("/");
    const label = `job ${skill === "" ? "." : skill}`;
    let reportBytes: Buffer;
    try {
      reportBytes = readBoundedAnalyzerOutputV1(jsonOutput, "Cisco JSON report");
    } catch (error) {
      if (!(error instanceof AnalyzerOutputReadErrorV1)) throw error;
      return Object.freeze({
        kind: "failed" as const,
        stage: "output" as const,
        detail:
          error.reason === "missing"
            ? "detector did not emit its Cisco JSON report"
            : boundedCiscoDetailV1(`Cisco JSON report of ${label} is unreadable: ${error.message}`),
      });
    }
    try {
      const report = ciscoSingleSkillReportV1(reportBytes, label);
      // U1j (review of U1i, P1): the report is evidence only for the skill this job scanned.
      assertCiscoSingleSkillReportSkillV1(report, {
        label,
        sourceRoots: [request.root],
        skill,
        platform: request.platform === "windows" ? "win32" : request.platform,
      });
      assertCiscoSingleSkillAnalyzersCompleteV1(
        report,
        // U1j: the job log keeps each result's D28 identity for the fallback pairing.
        ciscoSarifResultIdentitiesV1(sarif.log),
        skill,
      );
    } catch (error) {
      if (!(error instanceof CiscoAnalyzerFailureV1)) throw error;
      return Object.freeze({
        kind: "failed" as const,
        stage: error.stage,
        detail: boundedCiscoDetailV1(error.message),
      });
    }
    return Object.freeze({ kind: "completed" as const, log: sarif.log });
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

/** One failing job's stage and detail, carried through the worker drain. */
class CiscoJobFailureV1 extends Error {
  readonly stage: CiscoScanFailureStageV1;
  constructor(stage: CiscoScanFailureStageV1, detail: string) {
    super(detail);
    this.name = "CiscoJobFailureV1";
    this.stage = stage;
  }
}

/** The C2a §3 `source-tree` scan request as Core's B2 wiring will send it. */
export interface CiscoSourceTreeScanRequestV1 {
  readonly run: CiscoMultiSkillRunnerV1;
  readonly platform: CiscoMultiSkillPlatformV1;
  readonly env: NodeJS.ProcessEnv;
  /** Absolute realpath of the scanned root (Core's `subject.sourceRoot`). */
  readonly sourceRoot: string;
  /** Core's trust inventory; the jobs come from it, never from a walk. */
  readonly selectedClosurePaths: readonly string[];
  /** Strictly validated per C2a §3.3; absent selects the default concurrency. */
  readonly detectorOptions?: unknown;
  readonly analyzerProject?: string;
  /**
   * The version the gate requires; defaults to the pinned
   * {@link CISCO_MULTI_SKILL_SCANNER_VERSION_V1}. Only for a caller that runs a
   * project locked at another version (e.g. replaying evidence recorded at an
   * earlier pin); never widens the gate to more than one version.
   */
  readonly expectedVersion?: string;
}

/** Typed outcome of a `source-tree` Cisco scan (C2a §3.5). */
export type CiscoSourceTreeScanOutcomeV1 = Readonly<
  | {
      kind: "completed";
      /** The merged SARIF document: `{"version":"2.1.0","runs":[…]}`. */
      sarifText: string;
      /** The planned jobs in job order; `""` names the root job. */
      skillDirectories: readonly string[];
    }
  | {
      kind: "refused";
      reason: "detector-options-invalid" | "subject-requirement-unmet";
      detail: string;
    }
  | { kind: "failed"; stage: CiscoScanFailureStageV1; detail: string }
>;

function refusedSourceTreeScanV1(
  reason: "detector-options-invalid" | "subject-requirement-unmet",
  detail: string,
): CiscoSourceTreeScanOutcomeV1 {
  return Object.freeze({ kind: "refused" as const, reason, detail });
}

function failedSourceTreeScanV1(
  stage: CiscoScanFailureStageV1,
  detail: string,
): CiscoSourceTreeScanOutcomeV1 {
  return Object.freeze({ kind: "failed" as const, stage, detail });
}

/**
 * The C2a §3 engine function for `detector.cisco` over a `source-tree`
 * subject: validate `detectorOptions` (§3.3), plan one job per selected
 * `SKILL.md` directory (§3.1), refuse when the selection holds none (§3.5,
 * before any runner call), gate on the analyzer version before any job
 * (§3.2), then scan every job at the validated concurrency with stable job
 * order and merge per §3.4.
 *
 * Failure semantics (§3.5): a failing job stops new work, in-flight jobs are
 * drained, the lowest-index job's error is reported with its stage, and no
 * partial SARIF is produced.
 */
export async function runCiscoSourceTreeScanV1(
  request: CiscoSourceTreeScanRequestV1,
): Promise<CiscoSourceTreeScanOutcomeV1> {
  const options: CiscoDetectorOptionsValidationV1 = validateCiscoDetectorOptionsV1(
    request.detectorOptions,
  );
  if (!options.ok) return refusedSourceTreeScanV1("detector-options-invalid", options.detail);
  const jobs = planCiscoSourceTreeJobsV1(request.sourceRoot, request.selectedClosurePaths);
  if (jobs.length === 0) {
    return refusedSourceTreeScanV1(
      "subject-requirement-unmet",
      "no SKILL.md directories found for Cisco scan",
    );
  }
  // Every job directory must be a real directory chain inside the root: a
  // linked ancestor (symlink or junction) would send the analyzer outside it.
  for (const job of jobs) {
    const resolved = resolveContainedCiscoJobDirectoryV1(request.sourceRoot, job.path);
    if (!resolved.ok) {
      return refusedSourceTreeScanV1(
        "subject-requirement-unmet",
        boundedCiscoDetailV1(
          `Cisco job path ${ciscoJobDirectoryProblemTextV1(resolved.problem)}: ${job.path}`,
        ),
      );
    }
  }
  const probe = await probeCiscoSkillScannerV1({
    run: request.run,
    platform: request.platform,
    env: request.env,
    ...(request.analyzerProject === undefined ? {} : { analyzerProject: request.analyzerProject }),
    ...(request.expectedVersion === undefined ? {} : { expectedVersion: request.expectedVersion }),
  });
  if (probe.kind !== "available") return failedSourceTreeScanV1(probe.stage, probe.detail);
  const scanJob = async (job: CiscoSourceTreeJobV1): Promise<CiscoSarifRunV1[]> => {
    // Re-proven immediately before the scan: a link swapped in after the
    // boundary check must not redirect the analyzer.
    if (!resolveContainedCiscoJobDirectoryV1(request.sourceRoot, job.path).ok) {
      throw new CiscoJobFailureV1(
        "execution",
        boundedCiscoDetailV1(`Cisco job directory changed before its scan: ${job.path}`),
      );
    }
    const outcome = await scanCiscoSkillDirectoryOutcomeV1({
      run: request.run,
      platform: request.platform,
      env: request.env,
      root: request.sourceRoot,
      skillDir: job.skillDir,
      ...(request.analyzerProject === undefined
        ? {}
        : { analyzerProject: request.analyzerProject }),
    });
    if (outcome.kind === "failed") throw new CiscoJobFailureV1(outcome.stage, outcome.detail);
    return outcome.log.runs ?? [];
  };
  let runsByJob: CiscoSarifRunV1[][];
  try {
    runsByJob = await mapConcurrentStableV1(jobs, options.concurrency, scanJob);
  } catch (error) {
    if (error instanceof CiscoJobFailureV1) {
      // The per-job boundary already bounded and encoded this detail.
      return failedSourceTreeScanV1(error.stage, error.message);
    }
    return failedSourceTreeScanV1("execution", errorDetailV1(error, "Cisco skill scan failed"));
  }
  return Object.freeze({
    kind: "completed" as const,
    sarifText: mergedCiscoSarifTextV1(runsByJob),
    skillDirectories: Object.freeze(jobs.map((job) => job.path)),
  });
}
