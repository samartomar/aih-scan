import {
  mcpConfigPathsProblemV1,
  visibleOptionsDetailV1,
} from "../detectors/mcp-config-paths-v1.js";
import { trustLintInternalScopesProblemV1 } from "../detectors/trust-lint/options.js";

/**
 * Per-detector `detectorOptions` (C2a §2.1, §3.3, §4.1). Each detector that takes options
 * has one exact key set; every other detector takes none, and `detector.aih-binding-gate`
 * takes at most an empty object. Options are read once into a frozen copy, validated without
 * coercion and refused, never repaired: Scan does not normalize, sort, deduplicate or clamp
 * what the caller sent. The internal-scope and MCP-config-path rules are the engines' own
 * validators (`mcpConfigPathsProblemV1` orders skill directories with Core's localeCompare);
 * whether each MCP config path exists is checked against the seal afterwards.
 */

export type CiscoDetectorOptionsV1 = Readonly<{ concurrency: number }>;
export type TrustLintDetectorOptionsV1 = Readonly<{
  internalScopes: readonly string[];
  mcpConfigPaths: readonly string[];
}>;
export type CiscoMcpScannerDetectorOptionsV1 = Readonly<{ mcpConfigPaths: readonly string[] }>;
/** `detector.aih-binding-gate` accepts an empty object and nothing else. */
export type EmptyDetectorOptionsV1 = Readonly<Record<string, never>>;
export type DetectorOptionsV1 =
  | EmptyDetectorOptionsV1
  | CiscoDetectorOptionsV1
  | TrustLintDetectorOptionsV1
  | CiscoMcpScannerDetectorOptionsV1;

export type DetectorOptionsReadV1 =
  | { readonly ok: true; readonly options: DetectorOptionsV1 | undefined }
  | { readonly ok: false; readonly detail: string };

type OptionKey = "concurrency" | "internalScopes" | "mcpConfigPaths";

const RULES: Readonly<
  Record<string, { readonly keys: readonly OptionKey[]; readonly required: boolean }>
> = Object.freeze({
  "detector.cisco": { keys: ["concurrency"], required: false },
  "detector.aih-trust-lint": { keys: ["internalScopes", "mcpConfigPaths"], required: true },
  "detector.cisco-mcp-scanner": { keys: ["mcpConfigPaths"], required: true },
  "detector.aih-binding-gate": { keys: [], required: false },
});

const MIN_CONCURRENCY = 1;
const MAX_CONCURRENCY = 64;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function kind(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "an array";
  return typeof value === "object" ? "an object" : `a ${typeof value}`;
}

/** A copy of a caller array, so validation and the kept options read the same values. */
function copied(value: unknown): unknown {
  return Array.isArray(value) ? Object.freeze([...value]) : value;
}

/**
 * Reads and validates `detectorOptions` for one detector against the declared selection.
 * Returns a frozen copy the runner keeps; the caller's object is never read again.
 */
export function readDetectorOptionsV1(
  detectorId: string,
  raw: unknown,
  selectedClosurePaths: readonly string[],
): DetectorOptionsReadV1 {
  const rule = RULES[detectorId];
  if (rule === undefined) {
    if (raw === undefined) return { ok: true, options: undefined };
    return { ok: false, detail: `${detectorId} takes no detectorOptions; remove them.` };
  }
  if (raw === undefined) {
    if (!rule.required) return { ok: true, options: undefined };
    return {
      ok: false,
      detail: `${detectorId} requires detectorOptions with exactly ${rule.keys.join(" and ")}.`,
    };
  }
  const exactly =
    rule.keys.length === 0
      ? "no key at all (an empty object)"
      : `exactly ${rule.keys.join(" and ")}`;
  if (!isPlainObject(raw))
    return {
      ok: false,
      detail: `detectorOptions for ${detectorId} must be a plain object with ${exactly}, not ${kind(raw)}.`,
    };
  const read: Partial<Record<OptionKey, unknown>> = {};
  let keys: string[];
  let reading = "";
  try {
    keys = Object.keys(raw);
    for (const key of rule.keys) {
      reading = key;
      if (Object.hasOwn(raw, key)) read[key] = copied(raw[key]);
    }
  } catch (error) {
    return {
      ok: false,
      detail: `detectorOptions could not be read: reading ${reading || "its keys"} threw: ${
        error instanceof Error ? error.message : "unknown failure"
      }.`,
    };
  }
  const unknown = keys.find((key) => !(rule.keys as readonly string[]).includes(key));
  if (unknown !== undefined)
    return {
      ok: false,
      detail: `detectorOptions for ${detectorId} has unknown key ${unknown}; it takes ${exactly}.`,
    };
  const absent = rule.keys.find((key) => !keys.includes(key));
  if (absent !== undefined)
    return {
      ok: false,
      detail: `detectorOptions for ${detectorId} is missing ${absent}; it takes exactly ${rule.keys.join(" and ")}.`,
    };

  const options: Record<string, unknown> = {};
  if (rule.keys.includes("concurrency")) {
    const value = read.concurrency;
    if (
      typeof value !== "number" ||
      !Number.isSafeInteger(value) ||
      value < MIN_CONCURRENCY ||
      value > MAX_CONCURRENCY
    )
      return {
        ok: false,
        detail: `concurrency must be a whole number from ${MIN_CONCURRENCY} to ${MAX_CONCURRENCY}, not ${
          typeof value === "number" ? String(value) : kind(value)
        }.`,
      };
    // Every Cisco profile runs one skill per request with the analyzer's own scheduling, so a
    // valid concurrency would change nothing. It is refused until a profile applies it.
    return {
      ok: false,
      detail: `concurrency is not applied by this profile: no ${detectorId} execution profile in this package runs skills concurrently, so the option would have no effect. Remove it.`,
    };
  }
  if (rule.keys.includes("internalScopes")) {
    const refusal = trustLintInternalScopesProblemV1(read.internalScopes);
    if (refusal !== undefined) return { ok: false, detail: refusal };
    options.internalScopes = read.internalScopes;
  }
  if (rule.keys.includes("mcpConfigPaths")) {
    // Existence is settled against the seal (detectorOptionsSealRefusalV1), not here.
    const refusal = mcpConfigPathsProblemV1(read.mcpConfigPaths, selectedClosurePaths, () => true);
    if (refusal !== undefined) return { ok: false, detail: visibleOptionsDetailV1(refusal) };
    options.mcpConfigPaths = read.mcpConfigPaths;
  }
  return { ok: true, options: Object.freeze(options) as DetectorOptionsV1 };
}

/**
 * After sealing: every declared MCP config path must exist in the sealed tree. A path that
 * exists but is not a regular file (a directory or a symlink) is accepted; the detector
 * handles it as Core does.
 */
export function detectorOptionsSealRefusalV1(
  options: DetectorOptionsV1 | undefined,
  entries: readonly { readonly kind: string; readonly path: string }[],
): string | undefined {
  if (options === undefined || !("mcpConfigPaths" in options)) return undefined;
  const present = new Set(entries.map((entry) => entry.path));
  const missing = options.mcpConfigPaths.find((path) => !present.has(path));
  return missing === undefined
    ? undefined
    : `mcpConfigPaths entry ${missing} does not exist in the sealed source tree.`;
}
