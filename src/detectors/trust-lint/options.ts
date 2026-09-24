import { assertSafeRelativePosixPathV1 } from "../../contract/strict-json-v1.js";
import type { TrustLintTreeV1 } from "./inventory.js";
import { INCOMING_MCP_CONFIG_FILES_V1 } from "./secrets.js";

/**
 * C2a §2.1 request-option validation for `detector.aih-trust-lint`
 * (coordinator decisions 6 and 8). The validator never throws and never
 * coerces: anything malformed is a typed `detector-options-invalid` result
 * that the B2 runner wiring maps to the Core refusal reason of the same
 * name, before anything is read.
 *
 * The options are a plain object with EXACTLY the keys `internalScopes` and
 * `mcpConfigPaths`, both required:
 *
 * - `internalScopes`: 0–256 unique strings matching
 *   `^@[a-z0-9][a-z0-9._~-]*$`, already normalized the way Core's
 *   `resolveInternalScopes` produces them (trimmed, `@`-prefixed,
 *   lowercased, deduplicated, localeCompare-sorted). The pattern enforces
 *   trimmed/@-prefixed/lowercased; uniqueness and sort order are checked
 *   separately. An entry that is not in normalized form is refused — Scan
 *   does not normalize again.
 * - `mcpConfigPaths`: 0–1 024 unique source-relative POSIX paths
 *   (`assertSafeRelativePosixPathV1` semantics) whose names match Core's
 *   incoming config names, each at the root or under a directory holding a
 *   selected `SKILL.md`, in Core's discovery order (root first, then each
 *   skill directory in Core's localeCompare order, the names in
 *   `INCOMING_MCP_CONFIG_FILES_V1` order). A path absent from the tree is
 *   refused; a directory or symlink at the path is ACCEPTED and handled per
 *   §2.2(4)-(5).
 */

export const TRUST_LINT_OPTIONS_INVALID_REASON_V1 = "detector-options-invalid";

const MAX_INTERNAL_SCOPES = 256;
const MAX_MCP_CONFIG_PATHS = 1024;
const INTERNAL_SCOPE_PATTERN = /^@[a-z0-9][a-z0-9._~-]*$/;
const MAX_DETAIL_LENGTH = 300;

export interface TrustLintDetectorOptionsV1 {
  readonly internalScopes: readonly string[];
  readonly mcpConfigPaths: readonly string[];
}

export type TrustLintOptionsValidationV1 =
  | { readonly ok: true; readonly options: TrustLintDetectorOptionsV1 }
  | {
      readonly ok: false;
      readonly reason: typeof TRUST_LINT_OPTIONS_INVALID_REASON_V1;
      readonly detail: string;
    };

/** One actionable sentence, bounded and free of control characters (§8.4). */
function refusal(detail: string): TrustLintOptionsValidationV1 {
  const visible = detail.replace(/[\p{C}]/gu, " ");
  return {
    ok: false,
    reason: TRUST_LINT_OPTIONS_INVALID_REASON_V1,
    detail: visible.length > MAX_DETAIL_LENGTH ? `${visible.slice(0, 297)}...` : visible,
  };
}

function shown(value: unknown): string {
  const text = typeof value === "string" ? value : (JSON.stringify(value) ?? String(value));
  return text.length > 80 ? `${text.slice(0, 77)}...` : text;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function validateInternalScopes(value: unknown): TrustLintOptionsValidationV1 | undefined {
  if (!Array.isArray(value)) return refusal("detectorOptions.internalScopes must be an array");
  if (value.length > MAX_INTERNAL_SCOPES) {
    return refusal(
      `detectorOptions.internalScopes has ${value.length} entries; the bound is ${MAX_INTERNAL_SCOPES}`,
    );
  }
  const seen = new Set<string>();
  let previous: string | undefined;
  for (const [index, entry] of value.entries()) {
    const at = `detectorOptions.internalScopes[${index}]`;
    if (typeof entry !== "string" || !INTERNAL_SCOPE_PATTERN.test(entry)) {
      return refusal(`${at} is not a normalized internal scope: ${shown(entry)}`);
    }
    if (seen.has(entry)) return refusal(`${at} duplicates an earlier scope: ${shown(entry)}`);
    seen.add(entry);
    if (previous !== undefined && previous.localeCompare(entry) > 0) {
      return refusal(`${at} is out of Core's normalized (localeCompare) order: ${shown(entry)}`);
    }
    previous = entry;
  }
  return undefined;
}

/**
 * Core's incoming-MCP discovery order (C2a §2.1): for the root, then each
 * directory holding a selected `SKILL.md`, the incoming config names in
 * `INCOMING_MCP_CONFIG_FILES_V1` order. Core's `collectSkillDirs` sorts the
 * skill directories by their relative path with `localeCompare`, which is
 * not always the order of their `SKILL.md` paths in the selection (`a-b/`
 * sorts before `a/`, while directory `a` sorts before `a-b`); Core's order
 * wins. Maps each candidate path to its discovery rank.
 */
function discoveryRanks(selection: readonly string[]): Map<string, number> {
  const skillDirs: string[] = [];
  const seenDirs = new Set<string>();
  for (const rel of selection) {
    if (rel.split("/").at(-1) !== "SKILL.md") continue;
    const index = rel.lastIndexOf("/");
    const dir = index === -1 ? "" : rel.slice(0, index);
    if (seenDirs.has(dir)) continue;
    seenDirs.add(dir);
    skillDirs.push(dir);
  }
  skillDirs.sort((left, right) => left.localeCompare(right));
  const ranks = new Map<string, number>();
  let rank = 0;
  for (const dir of ["", ...skillDirs]) {
    for (const name of INCOMING_MCP_CONFIG_FILES_V1) {
      const path = dir.length === 0 ? name : `${dir}/${name}`;
      if (!ranks.has(path)) ranks.set(path, rank++);
    }
  }
  return ranks;
}

function validateMcpConfigPaths(
  value: unknown,
  tree: TrustLintTreeV1,
  selection: readonly string[],
): TrustLintOptionsValidationV1 | undefined {
  if (!Array.isArray(value)) return refusal("detectorOptions.mcpConfigPaths must be an array");
  if (value.length > MAX_MCP_CONFIG_PATHS) {
    return refusal(
      `detectorOptions.mcpConfigPaths has ${value.length} entries; the bound is ${MAX_MCP_CONFIG_PATHS}`,
    );
  }
  const ranks = discoveryRanks(selection);
  const seen = new Set<string>();
  let previousRank = -1;
  for (const [index, entry] of value.entries()) {
    const at = `detectorOptions.mcpConfigPaths[${index}]`;
    if (typeof entry !== "string") return refusal(`${at} must be a string`);
    try {
      assertSafeRelativePosixPathV1(entry, at);
    } catch {
      return refusal(`${at} is not a safe source-relative POSIX path: ${shown(entry)}`);
    }
    if (seen.has(entry)) return refusal(`${at} duplicates an earlier path: ${shown(entry)}`);
    seen.add(entry);
    const rank = ranks.get(entry);
    if (rank === undefined) {
      return refusal(
        `${at} is not an incoming MCP config name at the root or under a selected SKILL.md directory: ${shown(entry)}`,
      );
    }
    if (rank <= previousRank) {
      return refusal(`${at} is out of Core's incoming MCP config discovery order: ${shown(entry)}`);
    }
    previousRank = rank;
    if (tree.pathKind(entry) === "absent") {
      return refusal(`${at} does not exist in the source tree: ${shown(entry)}`);
    }
  }
  return undefined;
}

/**
 * Validates `detectorOptions` for `detector.aih-trust-lint` against the
 * request's selection and the sealed tree. Returns the frozen options on
 * success; a typed invalid-options result otherwise.
 */
export function validateTrustLintDetectorOptionsV1(
  input: unknown,
  tree: TrustLintTreeV1,
  selection: readonly string[],
): TrustLintOptionsValidationV1 {
  if (!isPlainObject(input)) {
    return refusal("detectorOptions must be a plain object with internalScopes and mcpConfigPaths");
  }
  const keys = Object.keys(input).sort((a, b) => a.localeCompare(b));
  if (keys.length !== 2 || keys[0] !== "internalScopes" || keys[1] !== "mcpConfigPaths") {
    return refusal(
      "detectorOptions must have exactly the keys internalScopes and mcpConfigPaths, both required",
    );
  }
  const internalScopes = validateInternalScopes(input.internalScopes);
  if (internalScopes !== undefined) return internalScopes;
  const mcpConfigPaths = validateMcpConfigPaths(input.mcpConfigPaths, tree, selection);
  if (mcpConfigPaths !== undefined) return mcpConfigPaths;
  return {
    ok: true,
    options: Object.freeze({
      internalScopes: Object.freeze([...(input.internalScopes as readonly string[])]),
      mcpConfigPaths: Object.freeze([...(input.mcpConfigPaths as readonly string[])]),
    }),
  };
}
