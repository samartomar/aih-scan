import { existsSync } from "node:fs";
import { join } from "node:path";
import {
  DEFAULT_TRUST_LINT_SKIP_DIRS_V1,
  INCOMING_MCP_CONFIG_FILES_V1,
  type TrustLintTreeV1,
} from "../../../src/detectors/trust-lint/index.js";

/**
 * Test stand-ins for the two inputs Core declares in a trust-lint request
 * (C2a decision 1: Scan never enumerates the subject for Core). They
 * reproduce Core's own derivations so the ported Core fixtures keep their
 * meaning:
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
