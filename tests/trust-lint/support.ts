import { existsSync } from "node:fs";
import { join } from "node:path";
import type { TrustLintFindingV1 } from "../../src/trust-lint/findings.js";
import type { TrustLintTreeV1 } from "../../src/trust-lint/inventory.js";
import { scanMaliciousCodeTextV1 } from "../../src/trust-lint/malicious-code.js";
import { INCOMING_MCP_CONFIG_FILES_V1 } from "../../src/trust-lint/secrets.js";
import { DEFAULT_TRUST_LINT_SKIP_DIRS_V1 } from "./disk-tree.js";
import { isMaliciousCodeScanFilePathV1 } from "./script-files.js";

/**
 * Test helpers that derive the file selection and MCP config paths the
 * trust-lint checks read from a fixture tree, so the ported check fixtures
 * keep their meaning:
 *
 * - {@link coreSelectionV1} — Core's `buildTrustFileInventory`: every listed
 *   file whose directory path has no skip-directory segment, in the tree's
 *   localeCompare order.
 * - {@link coreMcpConfigPathsV1} — Core's `collectIncomingMcpConfigFiles`:
 *   the root, then each selected `SKILL.md` directory in localeCompare
 *   order, each incoming config name that `existsSync` finds there.
 */

export function coreSelectionV1(tree: TrustLintTreeV1): string[] {
  return tree.files
    .map((entry) => entry.relativePath)
    .filter((rel) =>
      rel
        .split("/")
        .slice(0, -1)
        .every((segment) => !DEFAULT_TRUST_LINT_SKIP_DIRS_V1.has(segment)),
    );
}

export function coreMcpConfigPathsV1(root: string, selection: readonly string[]): string[] {
  const skillDirs = [
    ...new Set(
      selection
        .filter((rel) => rel.split("/").at(-1) === "SKILL.md")
        .map((rel) => (rel.includes("/") ? rel.slice(0, rel.lastIndexOf("/")) : "")),
    ),
  ].sort((left, right) => left.localeCompare(right));
  const paths: string[] = [];
  for (const dir of ["", ...skillDirs]) {
    for (const name of INCOMING_MCP_CONFIG_FILES_V1) {
      const rel = dir.length === 0 ? name : `${dir}/${name}`;
      if (!paths.includes(rel) && existsSync(join(root, ...rel.split("/")))) paths.push(rel);
    }
  }
  return paths;
}

/**
 * The malicious-code check over the script-like files of a selection (at most 512 KiB each),
 * in selection order: the ported fixtures' file choice over the product's per-text check.
 */
export function scanNativeMaliciousCodeV1(
  tree: TrustLintTreeV1,
  selection: readonly string[],
): TrustLintFindingV1[] {
  const checks: TrustLintFindingV1[] = [];
  const occurrences = new Map<string, number>();
  for (const rel of selection) {
    if (!isMaliciousCodeScanFilePathV1(rel)) continue;
    const entry = tree.fileEntry(rel);
    if (entry === undefined || entry.size > 512 * 1024) continue;
    const source = tree.readText(rel);
    if (source === undefined) throw new TypeError(`trust-lint: unreadable script file ${rel}`);
    checks.push(...scanMaliciousCodeTextV1(rel, source, occurrences));
  }
  return checks;
}
