import { relative } from "node:path";
import { rewriteSarifRunLocationsV1 } from "../../baseline/sarif-source-relative-v1.js";
import { deepFreezeStrictJsonV1 } from "../../contract/strict-json-v1.js";
import { isSourceRelativeArtifactUriV1 } from "../source-relative-uri-v1.js";

/**
 * SARIF pass-through and merge for the `detector.cisco` multi-skill scan,
 * ported behaviour-for-behaviour from Core's `src/trust/detectors.ts`
 * (`parseSarifLog`, `prefixSafeCiscoUri`, `prefixCiscoSarifUris` and the merge
 * in `runCiscoSkillScan`).
 *
 * The per-skill SARIF log is evidence: it passes through structurally
 * untouched except that artifact URIs are prefixed with the source-relative
 * skill directory (unsafe URIs rewritten to `cisco.sarif`, C2a §3.4) and
 * volatile invocation timestamps are removed, so merged output is projection-
 * and time-independent. Rule mapping, grading and verdicts stay with the
 * caller (Core keeps them).
 *
 * Unlike Core's `parseSarifLog`, which required only a `runs` array, a job's
 * SARIF must prove the job completed (S2e): version 2.1.0, at least one run,
 * each with a tool driver, a results array and successful invocations. Every
 * location's `uriBaseId` is resolved before any prefix is applied, with the
 * baseline's base rules, so a base outside the root fails the job.
 */

export interface CiscoSarifArtifactLocationV1 {
  readonly uri?: unknown;
}

export interface CiscoSarifPhysicalLocationV1 {
  readonly artifactLocation?: CiscoSarifArtifactLocationV1;
}

export interface CiscoSarifLocationV1 {
  readonly physicalLocation?: CiscoSarifPhysicalLocationV1;
}

export interface CiscoSarifResultV1 {
  readonly ruleId?: unknown;
  readonly rule?: { readonly id?: unknown };
  readonly level?: unknown;
  readonly message?: { readonly text?: unknown };
  readonly locations?: CiscoSarifLocationV1[];
}

export interface CiscoSarifRunV1 {
  readonly invocations?: Array<Record<string, unknown>>;
  readonly results?: CiscoSarifResultV1[];
}

export interface CiscoSarifLogV1 {
  readonly runs?: CiscoSarifRunV1[];
  readonly version?: string;
}

/**
 * Bound on one detector-emitted SARIF log. Core did not bound it; Scan fails
 * closed past this size with the same "did not emit valid SARIF" outcome.
 */
export const MAX_CISCO_SARIF_BYTES_V1 = 16 * 1024 * 1024;

/**
 * Core's fallback artifact URI for this detector (C2a §1.4 and §3.4): an
 * analyzer URI that cannot be made a safe source-relative path is rewritten
 * to it, exactly as legacy Core's `normalizeSarifUri` mapped it downstream.
 */
export const CISCO_SARIF_FALLBACK_URI_V1 = "cisco.sarif";

function isRecordV1(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Where a job's SARIF fell short: the analyzer's own failure report, or unusable output. */
export type CiscoJobSarifFailureStageV1 = "execution" | "output";

/** A job's SARIF once validated and normalized, or why it is not evidence (C2a §3.5). */
export type CiscoJobSarifV1 = Readonly<
  | { ok: true; log: CiscoSarifLogV1 }
  | { ok: false; stage: CiscoJobSarifFailureStageV1; detail: string }
>;

class CiscoJobSarifProblemV1 extends Error {
  readonly stage: CiscoJobSarifFailureStageV1;
  constructor(stage: CiscoJobSarifFailureStageV1, detail: string) {
    super(detail);
    this.stage = stage;
  }
}

const INVALID_SARIF = "detector did not emit valid SARIF";

function sarifProblem(stage: CiscoJobSarifFailureStageV1, detail: string): never {
  throw new CiscoJobSarifProblemV1(stage, `detector SARIF ${detail}`);
}

/** An invocation's notification list holding an `error`-level (or malformed) entry. */
function hasErrorNotification(value: unknown, where: string): boolean {
  if (value === undefined) return false;
  if (!Array.isArray(value)) sarifProblem("output", `${where} notifications are malformed`);
  return value.some((entry) => !isRecordV1(entry) || entry.level === "error");
}

/**
 * The completion evidence one skill-scanner job must carry (S2e, the owner principle): the
 * analyzer's own SARIF proves the job ran to completion, or the job fails. Real
 * skill-scanner 2.0.14 output is `version` "2.1.0" with runs that each name a tool driver,
 * hold a `results` array and report their invocations with `executionSuccessful: true`.
 * An unparseable or oversized file, another version, no runs, a run without a driver or a
 * results array, a malformed result and a run without invocations are `output` failures;
 * an invocation that is not `executionSuccessful: true`, or that carries an `error`-level
 * tool execution or configuration notification, is the analyzer's own `execution` failure.
 */
function validatedCiscoJobSarifV1(raw: string): Record<string, unknown> & { runs: unknown[] } {
  if (Buffer.byteLength(raw, "utf8") > MAX_CISCO_SARIF_BYTES_V1)
    throw new CiscoJobSarifProblemV1("output", INVALID_SARIF);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new CiscoJobSarifProblemV1("output", INVALID_SARIF);
  }
  if (!isRecordV1(parsed)) throw new CiscoJobSarifProblemV1("output", INVALID_SARIF);
  if (parsed.version !== "2.1.0") sarifProblem("output", "is not version 2.1.0");
  const runs = parsed.runs;
  if (!Array.isArray(runs) || runs.length === 0) sarifProblem("output", "holds no runs");
  runs.forEach((run: unknown, index) => {
    const where = `run ${index}`;
    if (!isRecordV1(run)) sarifProblem("output", `${where} is malformed`);
    const driver = isRecordV1(run.tool) ? run.tool.driver : undefined;
    if (!isRecordV1(driver) || typeof driver.name !== "string" || driver.name.length === 0)
      sarifProblem("output", `${where} names no tool driver`);
    const results = run.results;
    if (!Array.isArray(results)) sarifProblem("output", `${where} holds no results array`);
    results.forEach((result: unknown, resultIndex) => {
      if (
        !isRecordV1(result) ||
        (result.locations !== undefined && !Array.isArray(result.locations))
      )
        sarifProblem("output", `${where} result ${resultIndex} is malformed`);
    });
    const invocations = run.invocations;
    if (!Array.isArray(invocations) || invocations.length === 0)
      sarifProblem("output", `${where} reports no invocation`);
    for (const invocation of invocations) {
      if (!isRecordV1(invocation) || invocation.executionSuccessful !== true)
        sarifProblem(
          "execution",
          `${where} reports an invocation that did not complete successfully`,
        );
      if (
        hasErrorNotification(invocation.toolExecutionNotifications, where) ||
        hasErrorNotification(invocation.toolConfigurationNotifications, where)
      )
        sarifProblem("execution", `${where} reports an error notification`);
    }
  });
  return parsed as Record<string, unknown> & { runs: unknown[] };
}

function toPosixV1(path: string): string {
  return path.replace(/\\/g, "/");
}

/**
 * Prefixes one artifact URI with the skill's source-relative directory. A
 * `file://` prefix is stripped and backslashes become `/` first (C2a §3.4);
 * the analyzer URI and the FINAL prefixed URI must then satisfy the complete C2a §1.4 rule
 * ({@link isSourceRelativeArtifactUriV1}: no `.`, `..` or empty segment, no
 * scheme, drive letter or leading `/`), or it is rewritten to
 * {@link CISCO_SARIF_FALLBACK_URI_V1}, because Core fails the whole detector
 * on any URI that is not source-relative. A missing URI stays missing (Core's
 * boundary maps it to the same fallback); any other non-string value becomes
 * the fallback.
 */
export function prefixSafeCiscoUriV1(prefix: string, raw: unknown): unknown {
  if (raw === undefined) return raw;
  if (typeof raw !== "string") return CISCO_SARIF_FALLBACK_URI_V1;
  const stripped = toPosixV1(raw.replace(/^file:\/\//, ""));
  // The analyzer's own URI must be a safe relative path (a scheme or drive is
  // only visible before prefixing), and so must the final prefixed URI.
  if (!isSourceRelativeArtifactUriV1(stripped)) return CISCO_SARIF_FALLBACK_URI_V1;
  const prefixed = prefix.length > 0 ? `${prefix}/${stripped}` : stripped;
  return isSourceRelativeArtifactUriV1(prefixed) ? prefixed : CISCO_SARIF_FALLBACK_URI_V1;
}

/**
 * One job's SARIF as evidence: validated for completion ({@link validatedCiscoJobSarifV1}),
 * every invocation's `startTimeUtc`/`endTimeUtc` removed, and every artifact location of
 * every run rewritten source-relative. Each location's `uriBaseId` is resolved first, with
 * the base rules of the baseline's SARIF normalization (`rewriteSarifRunLocationsV1`): an
 * undeclared, cyclic or malformed base, or one that resolves outside the source root, fails
 * the job at stage `output`; a base inside the root yields a URI relative to the root; a URI
 * under the analyzer's own `%SRCROOT%` (the job directory) is prefixed with the job's
 * source-relative directory ({@link prefixSafeCiscoUriV1}, C2a §3.4). Obsolete base
 * references and `originalUriBaseIds` are removed. The returned log is deeply frozen. The
 * source-tree scan and the shard both take each job's SARIF through here.
 */
export function ciscoJobSarifV1(
  sarifText: string,
  root: string,
  skillRoot: string,
): CiscoJobSarifV1 {
  let parsed: Record<string, unknown> & { runs: unknown[] };
  try {
    parsed = validatedCiscoJobSarifV1(sarifText);
  } catch (error) {
    if (error instanceof CiscoJobSarifProblemV1)
      return Object.freeze({ ok: false as const, stage: error.stage, detail: error.message });
    throw error;
  }
  const prefix = toPosixV1(relative(root, skillRoot));
  // The validated document is a fresh parse, so it is rewritten in place and then frozen.
  const runs = parsed.runs as Array<Record<string, unknown> & { invocations: unknown[] }>;
  try {
    for (const run of runs) {
      run.invocations = run.invocations.map((invocation) => {
        const {
          startTimeUtc: _startTimeUtc,
          endTimeUtc: _endTimeUtc,
          ...stableInvocation
        } = invocation as Record<string, unknown>;
        return stableInvocation;
      });
      rewriteSarifRunLocationsV1(run, [root], (target) =>
        prefixSafeCiscoUriV1(target.kind === "source-relative" ? "" : prefix, target.uri),
      );
    }
  } catch (error) {
    return Object.freeze({
      ok: false as const,
      stage: "output" as const,
      detail: `detector SARIF location: ${error instanceof Error ? error.message : "unresolvable"}`,
    });
  }
  return Object.freeze({
    ok: true as const,
    log: deepFreezeStrictJsonV1(parsed) as CiscoSarifLogV1,
  });
}

/**
 * The merged detector log: one SARIF `2.1.0` document whose runs are every
 * skill's runs in skill-directory order, serialized exactly as Core's
 * `runCiscoSkillScan` serializes it.
 */
export function mergedCiscoSarifTextV1(runsBySkill: readonly CiscoSarifRunV1[][]): string {
  return JSON.stringify({ version: "2.1.0", runs: runsBySkill.flat() });
}
