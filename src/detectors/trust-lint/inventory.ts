import { lstatSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join, relative, resolve } from "node:path";

/**
 * Port of Core's `src/trust/inventory.ts` walker, exposed as the
 * inventory/file-read seam every trust-lint scanner runs against. The walker
 * semantics are unchanged: skip directories, symlink-to-file followed via the
 * target's size, deterministic localeCompare ordering, progress every 250
 * files. File contents are read lazily through `readText` so scanners stay
 * pure functions of the tree.
 */

export const DEFAULT_TRUST_LINT_SKIP_DIRS_V1: ReadonlySet<string> = new Set([
  ".git",
  ".hg",
  ".svn",
  ".aih",
  "coverage",
  "dist",
  "node_modules",
  "vendor",
]);

export interface TrustLintTreeEntryV1 {
  readonly relativePath: string;
  readonly size: number;
}

export interface TrustLintTreeV1 {
  /** Every regular file under the root (skips excluded), localeCompare-sorted. */
  readonly files: readonly TrustLintTreeEntryV1[];
  matching(predicate: (entry: TrustLintTreeEntryV1) => boolean): Iterable<TrustLintTreeEntryV1>;
  /** True when `rel` is a visited directory (skipped directories report false). */
  isDirectory(rel: string): boolean;
  hasFile(rel: string): boolean;
  /** UTF-8 text of a file, or undefined when missing/unreadable. */
  readText(rel: string): string | undefined;
}

export interface TrustLintTreeOptionsV1 {
  readonly skipDirs?: ReadonlySet<string>;
  readonly onProgress?: (processed: number) => void;
}

function toPosix(path: string): string {
  return path.replace(/\\/g, "/");
}

export function buildTrustLintTreeV1(
  root: string,
  options: TrustLintTreeOptionsV1 = {},
): TrustLintTreeV1 {
  const absoluteRoot = resolve(root);
  const skipDirs = options.skipDirs ?? DEFAULT_TRUST_LINT_SKIP_DIRS_V1;
  const files: TrustLintTreeEntryV1[] = [];
  const absoluteByRel = new Map<string, string>();
  const directories = new Set<string>([""]);
  let processed = 0;
  const visit = (absolutePath: string): void => {
    const stats = lstatSync(absolutePath);
    if (stats.isSymbolicLink()) {
      const target = statSync(absolutePath);
      if (target.isFile()) {
        const relativePath = toPosix(relative(absoluteRoot, absolutePath));
        files.push({ relativePath, size: target.size });
        absoluteByRel.set(relativePath, absolutePath);
        processed++;
        if (processed % 250 === 0) options.onProgress?.(processed);
      }
      return;
    }
    if (stats.isDirectory()) {
      const relativePath = toPosix(relative(absoluteRoot, absolutePath));
      if (absolutePath !== absoluteRoot && skipDirs.has(basename(absolutePath))) return;
      directories.add(relativePath);
      for (const entry of readdirSync(absolutePath).sort()) visit(join(absolutePath, entry));
      return;
    }
    if (!stats.isFile()) return;
    const relativePath = toPosix(relative(absoluteRoot, absolutePath));
    files.push({ relativePath, size: stats.size });
    absoluteByRel.set(relativePath, absolutePath);
    processed++;
    if (processed % 250 === 0) options.onProgress?.(processed);
  };
  visit(absoluteRoot);
  files.sort((left, right) => left.relativePath.localeCompare(right.relativePath));
  const stableFiles = Object.freeze(files.map((entry) => Object.freeze(entry)));
  return Object.freeze({
    files: stableFiles,
    *matching(predicate: (entry: TrustLintTreeEntryV1) => boolean): Iterable<TrustLintTreeEntryV1> {
      for (const entry of stableFiles) {
        if (predicate(entry)) yield entry;
      }
    },
    isDirectory: (rel: string) => directories.has(rel),
    hasFile: (rel: string) => absoluteByRel.has(rel),
    readText: (rel: string) => {
      const absolute = absoluteByRel.get(rel);
      if (absolute === undefined) return undefined;
      try {
        return readFileSync(absolute, "utf8");
      } catch {
        return undefined;
      }
    },
  });
}
