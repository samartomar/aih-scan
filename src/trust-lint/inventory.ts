/**
 * The read-only file tree every trust-lint check runs against. The host adapter
 * (src/host/trust-lint-tool.ts) builds it in memory from the item's snapshot bytes, so the
 * checks read exactly the scanned working copy and never the disk.
 */

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
