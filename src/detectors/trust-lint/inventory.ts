import { lstatSync, readdirSync, readFileSync, realpathSync, type Stats, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";

/**
 * The inventory/file-read seam every trust-lint scanner runs against (C2a
 * §1.3, §2.2, §2.6). The walker enumerates the WHOLE sealed tree — Core's
 * skip directories included — because §2.2(4) plaintext-secret discovery and
 * the §2.6 per-file facts cover files outside the declared selection. Which
 * paths are analyzed for findings is the caller's selection
 * (`selectedClosurePaths`, Core's `buildTrustFileInventory`), never this
 * enumeration.
 *
 * Walker semantics match Core's `src/trust/inventory.ts`, extended to descend
 * into skip directories: symlink-to-file entries are listed by their link
 * path with the target's size; directory symlinks are never traversed
 * (Core's inventory does not descend into them either); deterministic
 * localeCompare ordering; progress every 250 files. Entries additionally
 * carry the metadata §2.2(4)-(5) and §2.6 need: whether the path is a
 * symlink, the POSIX exec bit (always false on Windows), and whether the
 * entry's realpath stays inside the root's realpath.
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

export type TrustLintPathKindV1 =
  | "file"
  | "directory"
  | "symlink"
  | "escaping"
  | "other"
  | "absent";

export interface TrustLintTreeEntryV1 {
  readonly relativePath: string;
  /** Byte size of the file (the link target's size for a symlink), like Core. */
  readonly size: number;
  /** True when the path itself is a symbolic link (lstat), whatever its target. */
  readonly symlink: boolean;
  /** POSIX exec bit on the (target) file — `(mode & 0o111) !== 0`; false on Windows. */
  readonly executable: boolean;
  /** True when the entry's realpath stays inside the root's realpath. */
  readonly realpathContained: boolean;
}

export interface TrustLintTreeV1 {
  /**
   * Every regular file under the root — plus every symlink whose target is a
   * file, by its link path — skip directories INCLUDED, localeCompare-sorted.
   */
  readonly files: readonly TrustLintTreeEntryV1[];
  matching(predicate: (entry: TrustLintTreeEntryV1) => boolean): Iterable<TrustLintTreeEntryV1>;
  /** The entry for `rel`, when it is a regular file or a symlink to a file. */
  fileEntry(rel: string): TrustLintTreeEntryV1 | undefined;
  /**
   * lstat of the path on disk, like Core's `inspectContainedPath`: "symlink"
   * for a symbolic link final component (even a symlink to a file, which also
   * appears in `files`), "escaping" when its realpath leaves the root, then
   * "file", "directory" or "other"; "absent" when nothing is there.
   */
  pathKind(rel: string): TrustLintPathKindV1;
  /** True when `rel` is a real (non-symlink) directory inside the root. */
  isDirectory(rel: string): boolean;
  /** True when `rel` is a listed file (a regular file or a symlink to a file). */
  hasFile(rel: string): boolean;
  /**
   * UTF-8 text of a listed file, or of a contained file or symlink-to-file
   * path on disk (symlinks followed); undefined when missing, escaping or
   * unreadable.
   */
  readText(rel: string): string | undefined;
}

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
