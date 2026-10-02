import { lstatSync, readdirSync } from "node:fs";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { type Json, limitCeilings } from "../assessment/types.js";
import { mcpConfigPathsProblemV1 } from "../detectors/mcp-config-paths-v1.js";
import { trustLintInternalScopesProblemV1 } from "../detectors/trust-lint/options.js";
import { INCOMING_MCP_CONFIG_FILES_V1 } from "../detectors/trust-lint/secrets.js";

/**
 * Target-contained trust-lint input resolution for the scan command. Discovers Core's
 * incoming MCP configuration names inside the target only — at the root and inside
 * directories that hold a `SKILL.md` — and resolves explicit `--mcp-config` /
 * `--internal-scope` values into the exact `configuration` each selected detector
 * validates. The walk matches capture: it never follows links, omits the root `.git`
 * (a nested `.git` is ordinary content) and is bounded by `limitCeilings.maxSourceEntries`.
 */

export const TRUST_LINT_DETECTOR_ID = "detector.aih-trust-lint";
export const CISCO_MCP_SCANNER_DETECTOR_ID = "detector.cisco-mcp-scanner";
/** The detectors that read MCP configuration (C2a §2.1, §4.1). */
const MCP_CONFIG_READERS: readonly string[] = [
  TRUST_LINT_DETECTOR_ID,
  CISCO_MCP_SCANNER_DETECTOR_ID,
];

/** The per-detector `configuration` values and the input notes the command reports. */
export interface ScanInputs {
  readonly configurations: ReadonlyMap<string, Json>;
  readonly notes: readonly string[];
}

export type ScanInputsResolution =
  | { readonly ok: true; readonly inputs: ScanInputs }
  | { readonly ok: false; readonly detail: string };

/** Explicit `--mcp-config` / `--internal-scope` values, in command-line order. */
export interface ExplicitScanInputs {
  readonly mcpConfigPaths: readonly string[];
  readonly internalScopes: readonly string[];
}

/** Every entry path in the target and every directory holding a `SKILL.md` entry. */
interface TargetTree {
  readonly paths: ReadonlySet<string>;
  readonly skillDirs: readonly string[];
}

/**
 * Walks the real target without following links, skipping the root `.git` exactly as
 * capture does, bounded by the source-entry ceiling. An unreadable directory is left
 * to capture, which reports it; discovery stays silent rather than failing differently.
 */
function walkTarget(root: string): TargetTree {
  const paths = new Set<string>();
  const skillDirs = new Set<string>();
  let entries = 0;
  const visit = (directory: string, relative: string): void => {
    let names: string[];
    try {
      names = readdirSync(directory).sort();
    } catch {
      return;
    }
    for (const name of names) {
      if (relative === "" && name === ".git") continue;
      if (entries >= limitCeilings.maxSourceEntries) return;
      entries += 1;
      const path = relative === "" ? name : `${relative}/${name}`;
      paths.add(path);
      let stat: ReturnType<typeof lstatSync>;
      try {
        stat = lstatSync(join(directory, name));
      } catch {
        continue;
      }
      // A linked entry is never descended into; a link named SKILL.md still marks its
      // directory, because capture records the link itself in the selection.
      if (stat.isSymbolicLink()) {
        if (name === "SKILL.md") skillDirs.add(relative);
      } else if (stat.isDirectory()) {
        visit(join(directory, name), path);
      } else if (stat.isFile() && name === "SKILL.md") {
        skillDirs.add(relative);
      }
    }
  };
  visit(root, "");
  return { paths, skillDirs: [...skillDirs].sort((left, right) => left.localeCompare(right)) };
}

/**
 * Core's incoming-MCP discovery order (C2a §2.1): the root first, then each skill
 * directory in localeCompare order, the names in `INCOMING_MCP_CONFIG_FILES_V1` order —
 * the exact order `mcpConfigPathsProblemV1` requires. Only paths present in the tree.
 */
function discoverMcpConfigPaths(tree: TargetTree): string[] {
  const found: string[] = [];
  for (const dir of new Set(["", ...tree.skillDirs])) {
    for (const name of INCOMING_MCP_CONFIG_FILES_V1) {
      const path = dir === "" ? name : `${dir}/${name}`;
      if (tree.paths.has(path)) found.push(path);
    }
  }
  return found;
}

/** Every candidate path in Core's discovery order, mapped to its rank. */
function discoveryRanks(tree: TargetTree): Map<string, number> {
  const ranks = new Map<string, number>();
  let rank = 0;
  for (const dir of new Set(["", ...tree.skillDirs])) {
    for (const name of INCOMING_MCP_CONFIG_FILES_V1) {
      const path = dir === "" ? name : `${dir}/${name}`;
      if (!ranks.has(path)) ranks.set(path, rank++);
    }
  }
  return ranks;
}

/**
 * Resolves explicit `--mcp-config` values against the real target. A value is relative
 * to the target or absolute inside it; anything escaping the target (`..`, absolute
 * elsewhere), passing through a linked or non-directory parent, naming a missing entry
 * or repeating an earlier value is refused. The survivors are sorted into Core's
 * discovery order and checked by the one shared validator, `mcpConfigPathsProblemV1`.
 */
function explicitMcpConfigPaths(
  target: string,
  supplied: readonly string[],
  tree: TargetTree,
):
  | { readonly ok: true; readonly paths: string[] }
  | { readonly ok: false; readonly detail: string } {
  const resolved: string[] = [];
  for (const raw of supplied) {
    // Containment is lexical plus a real-parent check: the target is already a real
    // path and every containing directory must be a real directory, never a link.
    const rel = relative(target, resolve(target, raw));
    if (rel === "" || rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel))
      return { ok: false, detail: `--mcp-config ${raw} is outside the target directory` };
    const segments = rel.split(sep);
    let parent = target;
    for (const segment of segments.slice(0, -1)) {
      parent = join(parent, segment);
      let stat: ReturnType<typeof lstatSync>;
      try {
        stat = lstatSync(parent);
      } catch {
        return { ok: false, detail: `--mcp-config ${raw} does not exist inside the target` };
      }
      if (!stat.isDirectory() || stat.isSymbolicLink())
        return {
          ok: false,
          detail: `--mcp-config ${raw} passes through a linked or non-directory parent`,
        };
    }
    try {
      lstatSync(join(target, ...segments));
    } catch {
      return { ok: false, detail: `--mcp-config ${raw} does not exist inside the target` };
    }
    const path = segments.join("/");
    if (resolved.includes(path))
      return { ok: false, detail: `--mcp-config ${raw} duplicates an earlier --mcp-config` };
    resolved.push(path);
  }
  const ranks = discoveryRanks(tree);
  const ordered = [...resolved].sort(
    (left, right) =>
      (ranks.get(left) ?? Number.MAX_SAFE_INTEGER) - (ranks.get(right) ?? Number.MAX_SAFE_INTEGER),
  );
  // The selection the validator derives its skill directories from, and the existence
  // check against the entries just confirmed above.
  const selection = tree.skillDirs.map((dir) => (dir === "" ? "SKILL.md" : `${dir}/SKILL.md`));
  const present = new Set(resolved);
  const problem = mcpConfigPathsProblemV1(ordered, selection, (path) => present.has(path));
  if (problem !== undefined) return { ok: false, detail: problem };
  return { ok: true, paths: ordered };
}

/** Core's `resolveInternalScopes` normalization: trim, lowercase, `@`-prefix, dedupe, sort. */
function normalizeInternalScopes(supplied: readonly string[]): string[] {
  const normalized = supplied.map((scope) => {
    const trimmed = scope.trim().toLowerCase();
    return trimmed.startsWith("@") ? trimmed : `@${trimmed}`;
  });
  return [...new Set(normalized)].sort((left, right) => left.localeCompare(right));
}

/**
 * Resolves every selected detector's `configuration` from the target and the explicit
 * command-line inputs. Discovery runs only inside the target; explicit paths must name
 * contained, existing entries. A refusal detail means exit 2 before any scan work.
 */
export function resolveScanInputs(
  target: string,
  detectorIds: readonly string[],
  explicit: ExplicitScanInputs,
): ScanInputsResolution {
  // Fail closed: a specialized input with no selected detector that consumes it.
  const readers = detectorIds.filter((detectorId) => MCP_CONFIG_READERS.includes(detectorId));
  if (explicit.mcpConfigPaths.length > 0 && readers.length === 0)
    return {
      ok: false,
      detail: `--mcp-config requires a selected detector that reads MCP configuration (${MCP_CONFIG_READERS.join(" or ")})`,
    };
  if (explicit.internalScopes.length > 0 && !detectorIds.includes(TRUST_LINT_DETECTOR_ID))
    return {
      ok: false,
      detail: `--internal-scope requires ${TRUST_LINT_DETECTOR_ID} to be selected`,
    };
  const tree = walkTarget(target);
  let mcpConfigPaths: string[];
  let supplied: boolean;
  if (explicit.mcpConfigPaths.length > 0) {
    const resolvedPaths = explicitMcpConfigPaths(target, explicit.mcpConfigPaths, tree);
    if (!resolvedPaths.ok) return resolvedPaths;
    mcpConfigPaths = resolvedPaths.paths;
    supplied = true;
  } else {
    mcpConfigPaths = discoverMcpConfigPaths(tree);
    supplied = false;
  }
  const internalScopes = normalizeInternalScopes(explicit.internalScopes);
  const scopesProblem = trustLintInternalScopesProblemV1(internalScopes);
  if (scopesProblem !== undefined) return { ok: false, detail: scopesProblem };
  const notes: string[] = [];
  for (const detectorId of readers) {
    if (mcpConfigPaths.length === 0)
      notes.push(`${detectorId}: no MCP configuration found inside the target`);
    else
      notes.push(
        supplied
          ? `${detectorId}: using supplied MCP configuration: ${mcpConfigPaths.join(", ")}`
          : `${detectorId}: discovered MCP configuration inside the target: ${mcpConfigPaths.join(", ")}`,
      );
  }
  if (detectorIds.includes(TRUST_LINT_DETECTOR_ID) && internalScopes.length === 0)
    notes.push(`${TRUST_LINT_DETECTOR_ID}: no internal scopes supplied`);
  const configurations = new Map<string, Json>();
  for (const detectorId of detectorIds) {
    if (detectorId === TRUST_LINT_DETECTOR_ID)
      configurations.set(detectorId, { internalScopes, mcpConfigPaths });
    else if (detectorId === CISCO_MCP_SCANNER_DETECTOR_ID)
      configurations.set(detectorId, { mcpConfigPaths });
  }
  return { ok: true, inputs: { configurations, notes } };
}
