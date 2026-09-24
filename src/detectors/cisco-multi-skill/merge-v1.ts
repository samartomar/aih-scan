import { isAbsolute, relative } from "node:path";
import { deepFreezeStrictJsonV1 } from "../../contract/strict-json-v1.js";

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

/**
 * Output gate for one skill scan's SARIF file, mirroring Core's
 * `parseSarifLog`: parseable JSON whose root holds a `runs` array, or
 * `undefined`. Deeper validation is deliberately not done here.
 */
export function parseCiscoSarifLogV1(
  raw: string,
): (CiscoSarifLogV1 & { runs: CiscoSarifRunV1[] }) | undefined {
  if (Buffer.byteLength(raw, "utf8") > MAX_CISCO_SARIF_BYTES_V1) return undefined;
  try {
    const parsed = JSON.parse(raw) as CiscoSarifLogV1;
    return Array.isArray(parsed.runs) ? { ...parsed, runs: parsed.runs } : undefined;
  } catch {
    return undefined;
  }
}

function toPosixV1(path: string): string {
  return path.replace(/\\/g, "/");
}

function isSafeRelativeSarifUriV1(uri: string): boolean {
  if (uri.length === 0 || isAbsolute(uri) || /^[A-Za-z]:/.test(uri)) return false;
  return !uri.split("/").some((part) => part === "..");
}

/**
 * Prefixes one artifact URI with the skill's source-relative directory. A
 * `file://` prefix is stripped first; an unsafe URI (absolute, drive-relative,
 * or escaping through `..`) is rewritten to {@link CISCO_SARIF_FALLBACK_URI_V1}
 * (C2a §3.4), because C2a Core fails closed on any URI that is not
 * source-relative instead of sanitizing downstream. A non-string or empty
 * value passes through untouched; Core's boundary maps a missing URI to the
 * same fallback.
 */
export function prefixSafeCiscoUriV1(prefix: string, raw: unknown): unknown {
  if (typeof raw !== "string" || raw.length === 0) return raw;
  const stripped = toPosixV1(raw.replace(/^file:\/\//, ""));
  if (!isSafeRelativeSarifUriV1(stripped)) return CISCO_SARIF_FALLBACK_URI_V1;
  return prefix.length > 0 ? `${prefix}/${stripped}` : stripped;
}

/**
 * Parses one skill scan's SARIF and returns it with every artifact URI
 * prefixed by the skill's source-relative directory and every invocation's
 * `startTimeUtc`/`endTimeUtc` removed. Unparseable output throws Core's exact
 * failure text. The returned log is deeply frozen.
 */
export function prefixCiscoSarifUrisV1(
  sarifText: string,
  root: string,
  skillRoot: string,
): CiscoSarifLogV1 {
  const parsed = parseCiscoSarifLogV1(sarifText);
  if (parsed === undefined) throw new Error("detector did not emit valid SARIF");
  const prefix = toPosixV1(relative(root, skillRoot));
  return deepFreezeStrictJsonV1({
    ...parsed,
    runs: parsed.runs.map((run) => ({
      ...run,
      invocations: run.invocations?.map((invocation) => {
        const {
          startTimeUtc: _startTimeUtc,
          endTimeUtc: _endTimeUtc,
          ...stableInvocation
        } = invocation;
        return stableInvocation;
      }),
      results: run.results?.map((result) => ({
        ...result,
        locations: result.locations?.map((location) => ({
          ...location,
          physicalLocation:
            location.physicalLocation === undefined
              ? undefined
              : {
                  ...location.physicalLocation,
                  artifactLocation: {
                    ...location.physicalLocation.artifactLocation,
                    uri: prefixSafeCiscoUriV1(
                      prefix,
                      location.physicalLocation.artifactLocation?.uri,
                    ),
                  },
                },
        })),
      })),
    })),
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
