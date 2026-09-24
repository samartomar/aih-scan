import { relative } from "node:path";
import {
  rewriteSarifRunLocationsV1,
  sarifPathInsideDirectoryV1,
  sarifResultFilesV1,
} from "../../baseline/sarif-source-relative-v1.js";
import {
  decodeStrictUtf8V1,
  deepFreezeStrictJsonV1,
  parseStrictJsonObjectV1,
} from "../../contract/strict-json-v1.js";
import { assertSarifCompletedV1, SarifCompletionErrorV1 } from "../sarif-completion-v1.js";
import { isSourceRelativeArtifactUriV1 } from "../source-relative-uri-v1.js";

/**
 * SARIF pass-through and merge for the `detector.cisco` multi-skill scan,
 * ported behaviour-for-behaviour from Core's `src/trust/detectors.ts`
 * (`parseSarifLog`, `prefixSafeCiscoUri`, `prefixCiscoSarifUris` and the merge
 * in `runCiscoSkillScan`).
 *
 * The per-skill SARIF log is evidence: it passes through structurally
 * untouched except that artifact URIs are prefixed with the source-relative
 * skill directory (an unsafe URI fails the job at `output`, S2g; C2a §3.4) and
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

/**
 * The completion evidence one skill-scanner job must carry (S2e, the owner principle; the
 * shared {@link assertSarifCompletedV1}): the analyzer's own SARIF proves the job ran to
 * completion, or the job fails. An oversized file, bytes that are not well-formed UTF-8, or a
 * text that is not one strict JSON value ({@link parseStrictJsonObjectV1}: a repeated key at
 * any depth, a BOM or trailing data among others, S2h) is an `output` failure with Core's
 * "did not emit valid SARIF" and the reason. Names need not be NFC here, as the job's sealed
 * inventory does not require it.
 */
function validatedCiscoJobSarifV1(
  bytes: Uint8Array,
): Record<string, unknown> & { runs: unknown[] } {
  if (bytes.byteLength > MAX_CISCO_SARIF_BYTES_V1)
    throw new CiscoJobSarifProblemV1("output", INVALID_SARIF);
  let parsed: unknown;
  try {
    parsed = parseStrictJsonObjectV1(
      decodeStrictUtf8V1(bytes, "detector SARIF"),
      "detector SARIF",
      {
        requireNfc: false,
      },
    );
  } catch (error) {
    throw new CiscoJobSarifProblemV1(
      "output",
      `${INVALID_SARIF}: ${error instanceof Error ? error.message : "JSON"}`,
    );
  }
  try {
    assertSarifCompletedV1(parsed);
  } catch (error) {
    if (error instanceof SarifCompletionErrorV1)
      throw new CiscoJobSarifProblemV1(error.stage, `detector SARIF ${error.message}`);
    throw error;
  }
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
 * scheme, drive letter or leading `/`). S2g (review of U1d): anything else throws, and the
 * job fails at stage `output`; no file name is ever substituted, because a substitute such
 * as legacy Core's `cisco.sarif` can bind a finding to an unrelated sealed file of that
 * name. With `directory` (a notification or run-artifact location), a URI ending in one
 * `/` names a contained directory and keeps its slash. A missing URI stays missing; any
 * other non-string value throws.
 */
export function prefixSafeCiscoUriV1(prefix: string, raw: unknown, directory = false): unknown {
  if (raw === undefined) return raw;
  if (typeof raw !== "string") throw new TypeError("a Cisco artifact URI is not a string");
  const unsafe = (): never => {
    throw new TypeError(`${JSON.stringify(raw)} is not a safe source-relative artifact URI`);
  };
  const stripped = toPosixV1(raw.replace(/^file:\/\//, ""));
  const slash = directory && stripped.endsWith("/") ? "/" : "";
  const path = slash === "" ? stripped : stripped.slice(0, -1);
  // The analyzer's own URI must be a safe relative path (a scheme or drive is
  // only visible before prefixing), and so must the final prefixed URI.
  if (!isSourceRelativeArtifactUriV1(path)) unsafe();
  const prefixed = prefix.length > 0 ? `${prefix}/${path}` : path;
  if (!isSourceRelativeArtifactUriV1(prefixed)) unsafe();
  return `${prefixed}${slash}`;
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
 * references and `originalUriBaseIds` are removed. U1h: every file a result names, directly
 * or through a shared reference (`sarifResultFilesV1`), and (U1i) every parentIndex ancestor
 * of an artifact it names by index, must lie in the job's skill directory, or the job fails
 * at `output`. The returned log is deeply frozen. The
 * source-tree scan and the shard both take each job's SARIF through here.
 */
export function ciscoJobSarifV1(
  sarifBytes: Uint8Array,
  root: string,
  skillRoot: string,
): CiscoJobSarifV1 {
  let parsed: Record<string, unknown> & { runs: unknown[] };
  try {
    parsed = validatedCiscoJobSarifV1(sarifBytes);
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
        prefixSafeCiscoUriV1(
          target.kind === "source-relative" ? "" : prefix,
          target.uri,
          target.directory,
        ),
      );
    }
    // U1h (review of U1g, P1): every file a result names (its own locations and those of the
    // shared thread-flow locations and graphs it references, resolved for this result) lies
    // in this job's skill directory, on the source-tree scan and the shard alike.
    let index = 0;
    for (const run of runs)
      for (const result of run.results as unknown[]) {
        for (const file of sarifResultFilesV1(result, run))
          if (!sarifPathInsideDirectoryV1(prefix, file))
            throw new TypeError(
              `SARIF result ${index} names ${JSON.stringify(file)}, which is not in the job's skill ${prefix === "" ? "." : prefix}`,
            );
        index += 1;
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
