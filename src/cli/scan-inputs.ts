import { lstatSync, readdirSync, realpathSync, statSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { type Json, limitCeilings } from "../assessment/types.js";
import { CISCO_MCP_SCANNER_DETECTOR_ID_V1 } from "../detectors/cisco-mcp-scanner/index.js";
import { mcpConfigPathsProblemV1 } from "../detectors/mcp-config-paths-v1.js";
import { TRUST_LINT_DETECTOR_ID_V1 } from "../detectors/trust-lint/findings.js";
import { trustLintInternalScopesProblemV1 } from "../detectors/trust-lint/options.js";
import { INCOMING_MCP_CONFIG_FILES_V1 } from "../detectors/trust-lint/secrets.js";

/**
 * Target-contained trust-lint input resolution for the scan command. Discovers Core's
 * incoming MCP configuration names inside the target only — at the root and inside
 * directories that hold a `SKILL.md` — and resolves explicit `--mcp-config` /
 * `--internal-scope` values into the exact `configuration` each selected detector
 * validates. The walk matches capture: it never descends through links (a `SKILL.md`
 * link is only inspected to see whether it names a file), omits the root `.git`
 * (a nested `.git` is ordinary content) and is bounded by `limitCeilings.maxSourceEntries`.
 */

/** The detectors that read MCP configuration (C2a §2.1, §4.1). */
const MCP_CONFIG_READERS: readonly string[] = [
  TRUST_LINT_DETECTOR_ID_V1,
  CISCO_MCP_SCANNER_DETECTOR_ID_V1,
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

/** Whether a link resolves to a regular file; a broken link or a directory link does not. */
function linksToFile(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
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
      // A linked entry is never descended into. A SKILL.md marks its directory only when
      // capture would select it: a regular file, or a link to a file (a link to a
      // directory is recorded as a directory link, which is never selected).
      if (stat.isSymbolicLink()) {
        if (name === "SKILL.md" && linksToFile(join(directory, name))) skillDirs.add(relative);
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
 * the exact order `mcpConfigPathsProblemV1` requires. Every candidate path appears once,
 * at its first position: `.cursor/mcp.json` is both a root name and `mcp.json` inside a
 * `.cursor` skill directory.
 */
function discoveryOrder(tree: TargetTree): string[] {
  const order = new Set<string>();
  for (const dir of new Set(["", ...tree.skillDirs]))
    for (const name of INCOMING_MCP_CONFIG_FILES_V1)
      order.add(dir === "" ? name : `${dir}/${name}`);
  return [...order];
}

/** The candidates present in the tree, in discovery order. */
function discoverMcpConfigPaths(tree: TargetTree): string[] {
  return discoveryOrder(tree).filter((path) => tree.paths.has(path));
}

/**
 * Where an absolute value sits below the target, however it is spelled. The shallowest
 * ancestor of the value whose real path is the target is the anchor, so a link in an
 * ancestor of the target (or a link to the target itself) is accepted; `undefined` when
 * no ancestor is the target. Choosing the shallowest anchor keeps a link inside the
 * target, even one that points back at the target, below the anchor, where the caller
 * refuses it.
 */
function relativeBelowTarget(target: string, absolute: string): string | undefined {
  const value = resolve(absolute);
  const ancestors: string[] = [];
  for (let current = dirname(value); ; current = dirname(current)) {
    ancestors.unshift(current);
    if (dirname(current) === current) break;
  }
  for (const ancestor of ancestors) {
    let real: string;
    try {
      real = realpathSync.native(ancestor);
    } catch {
      continue;
    }
    if (real === target) return relative(ancestor, value);
  }
  return undefined;
}

/**
 * Resolves explicit `--mcp-config` values against the real target. A relative value
 * resolves against the target; an absolute value must lead into it, directly or through
 * a link in an ancestor of the target (see `relativeBelowTarget`). Anything escaping the
 * target (`..`, absolute elsewhere), passing through a linked or non-directory parent
 * inside the target, naming a missing entry or repeating an earlier value is refused.
 * The survivors are sorted into Core's discovery order and checked by the one shared
 * validator, `mcpConfigPathsProblemV1`.
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
    // Containment is lexical for a relative value and anchored at the target's real path
    // for an absolute one; either way every directory below the target must be a real
    // directory, never a link.
    const rel = isAbsolute(raw)
      ? relativeBelowTarget(target, raw)
      : relative(target, resolve(target, raw));
    if (
      rel === undefined ||
      rel === "" ||
      rel === ".." ||
      rel.startsWith(`..${sep}`) ||
      isAbsolute(rel)
    )
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
  const ranks = new Map(discoveryOrder(tree).map((path, rank) => [path, rank]));
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
  if (explicit.internalScopes.length > 0 && !detectorIds.includes(TRUST_LINT_DETECTOR_ID_V1))
    return {
      ok: false,
      detail: `--internal-scope requires ${TRUST_LINT_DETECTOR_ID_V1} to be selected`,
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
  if (detectorIds.includes(TRUST_LINT_DETECTOR_ID_V1) && internalScopes.length === 0)
    notes.push(`${TRUST_LINT_DETECTOR_ID_V1}: no internal scopes supplied`);
  const configurations = new Map<string, Json>();
  for (const detectorId of detectorIds) {
    if (detectorId === TRUST_LINT_DETECTOR_ID_V1)
      configurations.set(detectorId, { internalScopes, mcpConfigPaths });
    else if (detectorId === CISCO_MCP_SCANNER_DETECTOR_ID_V1)
      configurations.set(detectorId, { mcpConfigPaths });
  }
  return { ok: true, inputs: { configurations, notes } };
}
