import { lstatSync, readdirSync, readFileSync, realpathSync, type Stats, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import type {
  TrustLintPathKindV1,
  TrustLintTreeEntryV1,
  TrustLintTreeV1,
} from "../../src/trust-lint/inventory.js";

/**
 * TEST-ONLY: builds a trust-lint tree from a fixture folder on disk, so the ported check
 * fixtures can be written as files. The product builds its tree in memory from snapshot
 * bytes (src/host/trust-lint-tool.ts).
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

export interface TrustLintTreeOptionsV1 {
  readonly onProgress?: (processed: number) => void;
}

function toPosix(path: string): string {
  return path.replace(/\\/g, "/");
}

function canonical(path: string): string {
  return process.platform === "win32" ? path.toLowerCase() : path;
}

function isInsideRoot(rootReal: string, targetReal: string): boolean {
  const rel = relative(canonical(rootReal), canonical(targetReal));
  return rel === "" || (!rel.startsWith("..") && !isAbsolutePath(rel));
}

function isAbsolutePath(path: string): boolean {
  return path.startsWith("/") || /^[A-Za-z]:[\\/]/.test(path) || path.startsWith("\\\\");
}

export function buildTrustLintTreeV1(
  root: string,
  options: TrustLintTreeOptionsV1 = {},
): TrustLintTreeV1 {
  const absoluteRoot = resolve(root);
  let rootReal: string;
  try {
    rootReal = realpathSync(absoluteRoot);
  } catch {
    rootReal = absoluteRoot;
  }
  const files: TrustLintTreeEntryV1[] = [];
  const absoluteByRel = new Map<string, string>();
  let processed = 0;
  const noteProgress = (): void => {
    processed++;
    if (processed % 250 === 0) options.onProgress?.(processed);
  };
  const realpathContained = (absolutePath: string): boolean => {
    try {
      return isInsideRoot(rootReal, realpathSync(absolutePath));
    } catch {
      return false;
    }
  };
  const visit = (absolutePath: string): void => {
    const stats = lstatSync(absolutePath);
    const relativePath = toPosix(relative(absoluteRoot, absolutePath));
    if (stats.isSymbolicLink()) {
      let target: Stats;
      try {
        target = statSync(absolutePath);
      } catch {
        return;
      }
      // A symlink to a directory is never traversed, exactly like Core's
      // inventory; only symlink-to-file entries are listed, by link path.
      if (target.isFile()) {
        files.push({
          relativePath,
          size: target.size,
          symlink: true,
          executable: (target.mode & 0o111) !== 0,
          realpathContained: realpathContained(absolutePath),
        });
        absoluteByRel.set(relativePath, absolutePath);
        noteProgress();
      }
      return;
    }
    if (stats.isDirectory()) {
      for (const entry of readdirSync(absolutePath).sort()) visit(join(absolutePath, entry));
      return;
    }
    if (!stats.isFile()) return;
    files.push({
      relativePath,
      size: stats.size,
      symlink: false,
      executable: (stats.mode & 0o111) !== 0,
      realpathContained: realpathContained(absolutePath),
    });
    absoluteByRel.set(relativePath, absolutePath);
    noteProgress();
  };
  visit(absoluteRoot);
  const absoluteOf = (rel: string): string => join(absoluteRoot, ...rel.split("/"));
  // lstat of the real path, like Core's `inspectContainedPath`: a parent
  // component that is a contained directory symlink is resolved by the OS, the
  // final component is never followed.
  const pathKind = (rel: string): TrustLintPathKindV1 => {
    const absolute = absoluteOf(rel);
    let stats: Stats;
    try {
      stats = lstatSync(absolute);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      return code === "ENOENT" || code === "ENOTDIR" ? "absent" : "other";
    }
    if (stats.isSymbolicLink()) return "symlink";
    if (!realpathContained(absolute)) return "escaping";
    if (stats.isFile()) return "file";
    return stats.isDirectory() ? "directory" : "other";
  };
  files.sort((left, right) => left.relativePath.localeCompare(right.relativePath));
  const stableFiles = Object.freeze(files.map((entry) => Object.freeze(entry)));
  const entryByRel = new Map(stableFiles.map((entry) => [entry.relativePath, entry]));
  return Object.freeze({
    files: stableFiles,
    *matching(predicate: (entry: TrustLintTreeEntryV1) => boolean): Iterable<TrustLintTreeEntryV1> {
      for (const entry of stableFiles) {
        if (predicate(entry)) yield entry;
      }
    },
    fileEntry: (rel: string) => entryByRel.get(rel),
    pathKind,
    isDirectory: (rel: string) => pathKind(rel) === "directory",
    hasFile: (rel: string) => entryByRel.has(rel),
    readText: (rel: string) => {
      let absolute = absoluteByRel.get(rel);
      if (absolute === undefined) {
        const kind = pathKind(rel);
        if (kind !== "file" && kind !== "symlink") return undefined;
        absolute = absoluteOf(rel);
        if (!realpathContained(absolute)) return undefined;
      }
      try {
        return readFileSync(absolute, "utf8");
      } catch {
        return undefined;
      }
    },
  });
}
