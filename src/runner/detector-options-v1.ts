import { assertSafeRelativePosixPathV1 } from "../contract/strict-json-v1.js";

/**
 * Per-detector `detectorOptions` (C2a §2.1, §3.3, §4.1). Each detector that takes options
 * has one exact key set; every other detector takes none. Options are read once into a
 * frozen copy, validated without coercion and refused, never repaired: Scan does not
 * normalize, sort, deduplicate or clamp what the caller sent.
 */

export type CiscoDetectorOptionsV1 = Readonly<{ concurrency: number }>;
export type TrustLintDetectorOptionsV1 = Readonly<{
  internalScopes: readonly string[];
  mcpConfigPaths: readonly string[];
}>;
export type CiscoMcpScannerDetectorOptionsV1 = Readonly<{ mcpConfigPaths: readonly string[] }>;
export type DetectorOptionsV1 =
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
});

const MIN_CONCURRENCY = 1;
const MAX_CONCURRENCY = 64;
const MAX_INTERNAL_SCOPES = 256;
const MAX_MCP_CONFIG_PATHS = 1024;
const INTERNAL_SCOPE = /^@[a-z0-9][a-z0-9._~-]*$/;

/**
 * Core's incoming MCP config names (`src/trust/mcp-configs.ts`), in its discovery order.
 * Core looks under the source root, then under each selected skill directory in selection
 * order, and in each place tries these names in this order.
 */
export const MCP_CONFIG_NAMES_V1: readonly string[] = Object.freeze([
  ".mcp.json",
  ".cursor/mcp.json",
  ".kiro/settings/mcp.json",
  "mcp-configs/mcp-servers.json",
  ".vscode/mcp.json",
  "opencode.json",
  "mcp.json",
]);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function kind(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "an array";
  return typeof value === "object" ? "an object" : `a ${typeof value}`;
}

/** The skill directories Core discovers from, in selection order; the root is "". */
function discoveryDirectories(selectedClosurePaths: readonly string[]): string[] {
  const directories = [""];
  for (const path of selectedClosurePaths) {
    if (typeof path !== "string" || !path.endsWith("/SKILL.md")) continue;
    const directory = path.slice(0, -"/SKILL.md".length);
    if (!directories.includes(directory)) directories.push(directory);
  }
  return directories;
}

function stringArray(value: unknown, key: string, max: number): string[] | string {
  if (!Array.isArray(value)) return `${key} must be an array of strings, not ${kind(value)}.`;
  if (value.length > max)
    return `${key} holds ${value.length} entries; at most ${max} are allowed.`;
  const copy: string[] = [];
  for (const [index, entry] of value.entries()) {
    if (typeof entry !== "string")
      return `${key}[${index}] must be a string, not ${kind(entry)}; Scan does not coerce options.`;
    copy.push(entry);
  }
  return copy;
}

function internalScopesRefusal(scopes: readonly string[]): string | undefined {
  for (const [index, scope] of scopes.entries()) {
    if (!INTERNAL_SCOPE.test(scope))
      return `internalScopes[${index}] ${JSON.stringify(scope)} is not a normalized npm scope (@ followed by lowercase letters, digits, ".", "_", "~" or "-"); Scan does not normalize scopes, so send them the way Core resolves them.`;
    const previous = scopes[index - 1];
    if (previous !== undefined && previous.localeCompare(scope) >= 0)
      return `internalScopes must be unique and sorted with localeCompare, as Core resolves them; ${JSON.stringify(previous)} is followed by ${JSON.stringify(scope)}.`;
  }
  return undefined;
}

function mcpConfigPathsRefusal(
  paths: readonly string[],
  selectedClosurePaths: readonly string[],
): string | undefined {
  const directories = discoveryDirectories(selectedClosurePaths);
  let previousRank = -1;
  for (const [index, path] of paths.entries()) {
    try {
      assertSafeRelativePosixPathV1(path, `mcpConfigPaths[${index}]`);
    } catch (error) {
      return error instanceof Error ? `${error.message}.` : `mcpConfigPaths[${index}] is unsafe.`;
    }
    const ranks: number[] = [];
    directories.forEach((directory, directoryIndex) => {
      MCP_CONFIG_NAMES_V1.forEach((name, nameIndex) => {
        if (path === (directory === "" ? name : `${directory}/${name}`))
          ranks.push(directoryIndex * MCP_CONFIG_NAMES_V1.length + nameIndex);
      });
    });
    if (ranks.length === 0)
      return `mcpConfigPaths[${index}] ${path} is not an MCP config name under the root or a selected skill directory (${MCP_CONFIG_NAMES_V1.join(", ")}).`;
    const rank = ranks.find((candidate) => candidate > previousRank);
    if (rank === undefined)
      return `mcpConfigPaths must be unique and in Core's discovery order (the root, then each selected skill directory in selection order, the names in the order ${MCP_CONFIG_NAMES_V1.join(", ")}); ${path} is out of order.`;
    previousRank = rank;
  }
  return undefined;
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
  if (!isPlainObject(raw))
    return {
      ok: false,
      detail: `detectorOptions for ${detectorId} must be a plain object with exactly ${rule.keys.join(" and ")}, not ${kind(raw)}.`,
    };
  const read: Partial<Record<OptionKey, unknown>> = {};
  let keys: string[];
  let reading = "";
  try {
    keys = Object.keys(raw);
    for (const key of rule.keys) {
      reading = key;
      if (Object.hasOwn(raw, key)) read[key] = raw[key];
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
      detail: `detectorOptions for ${detectorId} has unknown key ${unknown}; it takes exactly ${rule.keys.join(" and ")}.`,
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
    options.concurrency = value;
  }
  if (rule.keys.includes("internalScopes")) {
    const scopes = stringArray(read.internalScopes, "internalScopes", MAX_INTERNAL_SCOPES);
    if (typeof scopes === "string") return { ok: false, detail: scopes };
    const refusal = internalScopesRefusal(scopes);
    if (refusal !== undefined) return { ok: false, detail: refusal };
    options.internalScopes = Object.freeze(scopes);
  }
  if (rule.keys.includes("mcpConfigPaths")) {
    const paths = stringArray(read.mcpConfigPaths, "mcpConfigPaths", MAX_MCP_CONFIG_PATHS);
    if (typeof paths === "string") return { ok: false, detail: paths };
    const refusal = mcpConfigPathsRefusal(paths, selectedClosurePaths);
    if (refusal !== undefined) return { ok: false, detail: refusal };
    options.mcpConfigPaths = Object.freeze(paths);
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
