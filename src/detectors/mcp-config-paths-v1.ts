import { assertSafeRelativePosixPathV1 } from "../contract/strict-json-v1.js";
import { INCOMING_MCP_CONFIG_FILES_V1 } from "./trust-lint/secrets.js";

/**
 * The one C2a §2.1 validator for Core-declared `mcpConfigPaths`, shared by
 * `detector.aih-trust-lint` and `detector.cisco-mcp-scanner` (§4.1 is
 * "validated as §2.1"), so both detectors refuse exactly the same requests.
 *
 * `mcpConfigPaths` holds 0–1 024 unique source-relative POSIX paths
 * (`assertSafeRelativePosixPathV1` semantics) whose names match Core's
 * incoming config names, each at the root or under a directory holding a
 * selected `SKILL.md`, in Core's discovery order (root first, then each
 * skill directory in Core's localeCompare order, the names in
 * `INCOMING_MCP_CONFIG_FILES_V1` order). A path absent from the tree is
 * refused; a directory or symlink at the path is accepted (each detector
 * handles it per its own section).
 */

export const MAX_MCP_CONFIG_PATHS_V1 = 1024;

const MAX_DETAIL_LENGTH = 300;

/** One actionable sentence, bounded and free of control characters (§8.4). */
export function visibleOptionsDetailV1(detail: string): string {
  const visible = detail.replace(/[\p{C}]/gu, " ");
  return visible.length > MAX_DETAIL_LENGTH ? `${visible.slice(0, 297)}...` : visible;
}

function shown(value: unknown): string {
  const text = typeof value === "string" ? value : (JSON.stringify(value) ?? String(value));
  return text.length > 80 ? `${text.slice(0, 77)}...` : text;
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

/**
 * Validates `detectorOptions.mcpConfigPaths` against the request's selection
 * and the sealed tree (`exists` answers whether a path is present, links and
 * directories included). Returns the refusal detail (raw; pass it through
 * {@link visibleOptionsDetailV1}), or `undefined` when valid. Never throws.
 */
export function mcpConfigPathsProblemV1(
  value: unknown,
  selection: readonly string[],
  exists: (path: string) => boolean,
): string | undefined {
  if (!Array.isArray(value)) return "detectorOptions.mcpConfigPaths must be an array";
  if (value.length > MAX_MCP_CONFIG_PATHS_V1) {
    return `detectorOptions.mcpConfigPaths has ${value.length} entries; the bound is ${MAX_MCP_CONFIG_PATHS_V1}`;
  }
  const ranks = discoveryRanks(selection);
  const seen = new Set<string>();
  let previousRank = -1;
  for (const [index, entry] of value.entries()) {
    const at = `detectorOptions.mcpConfigPaths[${index}]`;
    if (typeof entry !== "string") return `${at} must be a string`;
    try {
      assertSafeRelativePosixPathV1(entry, at);
    } catch {
      return `${at} is not a safe source-relative POSIX path: ${shown(entry)}`;
    }
    if (seen.has(entry)) return `${at} duplicates an earlier path: ${shown(entry)}`;
    seen.add(entry);
    const rank = ranks.get(entry);
    if (rank === undefined) {
      return `${at} is not an incoming MCP config name at the root or under a selected SKILL.md directory: ${shown(entry)}`;
    }
    if (rank <= previousRank) {
      return `${at} is out of Core's incoming MCP config discovery order: ${shown(entry)}`;
    }
    previousRank = rank;
    if (!exists(entry)) return `${at} does not exist in the source tree: ${shown(entry)}`;
  }
  return undefined;
}
