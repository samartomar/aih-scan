import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readSync,
  type Stats,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { FileMode } from "../contracts/git-tree.js";
import { limits } from "../contracts/limits.js";
import { pathProblem } from "../contracts/text.js";
import { createTemporaryRoot } from "../shared/emergency-stop.js";
import {
  readSourceEntryNamesV1,
  UnrepresentableSourcePathErrorV1,
} from "../shared/source-entry-name.js";
import { cloneIndexModes } from "./git-index.js";

/** One regular file of a folder as Scan read it: these exact bytes are hashed and given to every tool. */
export interface SnapshotFile {
  readonly path: string;
  readonly mode: FileMode;
  readonly bytes: Uint8Array;
  readonly sha256: string;
}

export type FolderRefusalReason =
  | "not-a-folder"
  | "link"
  | "hard-link"
  | "special-file"
  | "invalid-name"
  | "escaping-path"
  | "changed"
  | "unreadable"
  | "cancelled"
  | "files"
  | "file-size"
  | "source-size"
  | "path-length"
  | "depth";

export type ReadFolderResult =
  | Readonly<{ status: "ok"; files: readonly SnapshotFile[] }>
  | Readonly<{ status: "refused"; reason: FolderRefusalReason; detail: string }>
  | Readonly<{ status: "invalid"; reason: "executable"; detail: string }>;

export interface ReadFolderOptions {
  /** Item-relative paths recorded as `100755` when the disk does not mark them executable. */
  readonly executable?: readonly string[];
  readonly signal?: AbortSignal;
  /** Bytes and files already used by earlier folders of the same request. */
  readonly used?: Readonly<{ bytes: number; files: number }>;
  /** The host platform (default `process.platform`); tests simulate Windows with it. */
  readonly platform?: NodeJS.Platform;
}

class Refusal extends Error {
  constructor(
    readonly reason: FolderRefusalReason,
    detail: string,
  ) {
    super(detail);
  }
}

const sameIdentity = (a: Stats, b: Stats) =>
  a.dev === b.dev &&
  a.ino === b.ino &&
  a.size === b.size &&
  a.mtimeMs === b.mtimeMs &&
  a.ctimeMs === b.ctimeMs &&
  a.mode === b.mode;

const shown = (path: string) => JSON.stringify(path).slice(0, 200);

/** Stable descriptor read: the bytes returned are the bytes the identity checks covered. */
function readStable(path: string, expected: Stats, display: string): Uint8Array {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const before = fstatSync(descriptor);
    if (!before.isFile() || !sameIdentity(expected, before))
      throw new Refusal("changed", `${shown(display)} changed while it was read`);
    if (before.nlink !== 1) throw new Refusal("hard-link", `${shown(display)} is a hard link`);
    const bytes = new Uint8Array(before.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count <= 0) throw new Refusal("changed", `${shown(display)} changed while it was read`);
      offset += count;
    }
    if (!sameIdentity(before, fstatSync(descriptor)) || !sameIdentity(before, lstatSync(path)))
      throw new Refusal("changed", `${shown(display)} changed while it was read`);
    return bytes;
  } catch (error) {
    if (error instanceof Refusal) throw error;
    throw new Refusal("unreadable", `${shown(display)} could not be read`);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");

/**
 * Reads a folder by the identity rules: every regular file byte for byte (ignored files
 * included; empty folders do not count), `.git` omitted at every depth, and refusal before
 * anything is scanned of symbolic links, junctions, hard links, other special files, names that
 * are not valid text and paths over the published limits. Modes come from the disk; where the
 * disk cannot say (Windows), from Git's index when the folder is a clone (a `.git` folder
 * directly inside it, read as data), else from the caller's `executable` list, else `100644`.
 * On a disk that records modes, a listed file is also `100755`.
 */
export function readFolder(root: string, options: ReadFolderOptions = {}): ReadFolderResult {
  const used = options.used ?? { bytes: 0, files: 0 };
  try {
    let rootStat: Stats;
    try {
      rootStat = lstatSync(root);
    } catch {
      throw new Refusal("not-a-folder", "the folder does not exist or cannot be read");
    }
    if (rootStat.isSymbolicLink()) throw new Refusal("link", "the folder itself is a link");
    if (!rootStat.isDirectory()) throw new Refusal("not-a-folder", "the path is not a folder");
    const listed = new Set(options.executable ?? []);
    const diskModes = (options.platform ?? process.platform) !== "win32";
    const indexed = diskModes ? undefined : cloneIndexModes(root);
    const files: SnapshotFile[] = [];
    let bytes = used.bytes;
    const visit = (directory: string, parent: string) => {
      if (options.signal?.aborted) throw new Refusal("cancelled", "cancelled");
      const before = lstatSync(directory);
      let names: string[];
      try {
        names = readSourceEntryNamesV1(directory, parent, {
          maximum: limits.input.files + 1,
          onBound: () => {
            throw new Refusal("files", `more than ${limits.input.files} files`);
          },
        });
      } catch (error) {
        if (error instanceof UnrepresentableSourcePathErrorV1)
          throw new Refusal("invalid-name", error.message);
        throw error;
      }
      names.sort();
      for (const name of names) {
        if (name === ".git") continue;
        const path = parent ? `${parent}/${name}` : name;
        const problem = pathProblem(path, limits.input.pathLength, limits.input.depth);
        if (problem === "path-length")
          throw new Refusal("path-length", `a path exceeds ${limits.input.pathLength} characters`);
        if (problem === "depth")
          throw new Refusal("depth", `a path exceeds folder depth ${limits.input.depth}`);
        if (problem !== undefined) throw new Refusal("invalid-name", `${shown(path)}: ${problem}`);
        const absolute = join(directory, name);
        const stat = lstatSync(absolute);
        if (stat.isSymbolicLink())
          throw new Refusal("link", `${shown(path)} is a symbolic link or junction`);
        if (stat.isDirectory()) {
          visit(absolute, path);
          continue;
        }
        if (!stat.isFile())
          throw new Refusal("special-file", `${shown(path)} is not a regular file`);
        if (stat.nlink !== 1) throw new Refusal("hard-link", `${shown(path)} is a hard link`);
        if (used.files + files.length + 1 > limits.input.files)
          throw new Refusal("files", `more than ${limits.input.files} files`);
        if (stat.size > limits.input.fileBytes)
          throw new Refusal("file-size", `${shown(path)} exceeds ${limits.input.fileBytes} bytes`);
        if (bytes + stat.size > limits.input.sourceBytes)
          throw new Refusal("source-size", `the files exceed ${limits.input.sourceBytes} bytes`);
        const content = readStable(absolute, stat, path);
        bytes += content.length;
        const fromIndex = indexed?.get(path);
        const executable = diskModes
          ? (stat.mode & 0o111) !== 0 || listed.has(path)
          : fromIndex !== undefined
            ? fromIndex === "100755"
            : listed.has(path);
        files.push(
          Object.freeze({
            path,
            mode: executable ? "100755" : "100644",
            bytes: content,
            sha256: sha256(content),
          }),
        );
      }
      const after = lstatSync(directory);
      if (!after.isDirectory() || after.isSymbolicLink() || !sameIdentity(before, after))
        throw new Refusal("changed", "the folder changed while it was read");
    };
    visit(root, "");
    const present = new Set(files.map((file) => file.path));
    for (const path of listed)
      if (!present.has(path))
        return Object.freeze({
          status: "invalid" as const,
          reason: "executable" as const,
          detail: `executable lists ${shown(path)}, which is not a regular file of the folder`,
        });
    files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    return Object.freeze({ status: "ok" as const, files: Object.freeze(files) });
  } catch (error) {
    if (error instanceof Refusal)
      return Object.freeze({
        status: "refused" as const,
        reason: error.reason,
        detail: error.message,
      });
    return Object.freeze({
      status: "refused" as const,
      reason: "unreadable" as const,
      detail: "the folder could not be read",
    });
  }
}

const WINDOWS_RESERVED =
  /^(?:con|prn|aux|nul|com[0-9\u00b9\u00b2\u00b3]|lpt[0-9\u00b9\u00b2\u00b3])(?:\..*)?$/i;
const WINDOWS_INVALID = /[<>:"|?*]/;

/**
 * Why this host cannot write an item's files as their own names, checked before the working
 * copy is made: on Windows, reserved device names (`CON`, `aux.txt`, `COM1`…), the characters
 * `< > : " | ? *` and names ending in a dot or space; on Windows and macOS, paths that differ
 * only by letter case (macOS also by Unicode normalisation) or a file whose folded name is also
 * a folder. Undefined when every name can be written. The paths are already valid item paths.
 */
export function hostNameProblem(
  files: readonly Pick<SnapshotFile, "path">[],
  platform: NodeJS.Platform = process.platform,
): Readonly<{ reason: "reserved-name" | "case-collision"; detail: string }> | undefined {
  const windows = platform === "win32";
  if (windows)
    for (const file of files)
      for (const segment of file.path.split("/"))
        if (
          WINDOWS_RESERVED.test(segment) ||
          WINDOWS_INVALID.test(segment) ||
          /[. ]$/.test(segment)
        )
          return {
            reason: "reserved-name",
            detail: `${shown(file.path)} cannot be written on Windows`,
          };
  if (!windows && platform !== "darwin") return undefined;
  const fold = (path: string) =>
    (platform === "darwin" ? path.normalize("NFC") : path).toLowerCase();
  const seen = new Map<string, string>();
  const folders = new Map<string, string>();
  for (const file of files) {
    const key = fold(file.path);
    const other = seen.get(key);
    if (other !== undefined && other !== file.path)
      return {
        reason: "case-collision",
        detail: `${shown(file.path)} and ${shown(other)} differ only by letter case or normalisation`,
      };
    seen.set(key, file.path);
    const parts = file.path.split("/");
    for (let depth = 1; depth < parts.length; depth += 1) {
      const folder = parts.slice(0, depth).join("/");
      folders.set(fold(folder), folder);
    }
  }
  for (const [key, path] of seen) {
    const folder = folders.get(key);
    if (folder !== undefined)
      return {
        reason: "case-collision",
        detail: `${shown(path)} and the folder ${shown(folder)} differ only by letter case or normalisation`,
      };
  }
  return undefined;
}

/** A Scan-owned read-only working copy. Tools read only this copy. */
export interface Snapshot {
  readonly root: string;
  dispose(): void;
}

/** Writes the exact bytes into a new private folder and makes it read-only. */
export function writeSnapshot(files: readonly SnapshotFile[], parent = tmpdir()): Snapshot {
  const temporary = createTemporaryRoot("aih-scan-snapshot-", parent);
  const stage = temporary.path;
  const root = join(stage, "item");
  mkdirSync(root, { mode: 0o700 });
  const folders = new Set<string>([root]);
  for (const file of files) {
    const target = join(root, ...file.path.split("/"));
    const folder = dirname(target);
    if (!folders.has(folder)) {
      mkdirSync(folder, { recursive: true, mode: 0o700 });
      for (let current = folder; current.length > root.length; current = dirname(current))
        folders.add(current);
    }
    writeFileSync(target, file.bytes, { flag: "wx", mode: 0o600 });
    chmodSync(target, file.mode === "100755" ? 0o555 : 0o444);
  }
  const ordered = [...folders].sort((a, b) => b.length - a.length);
  for (const folder of ordered) chmodSync(folder, 0o555);
  let disposed = false;
  return Object.freeze({
    root,
    dispose() {
      if (disposed) return;
      disposed = true;
      try {
        for (const folder of [...ordered].reverse()) chmodSync(folder, 0o700);
      } catch {
        // Best effort: removal below reports nothing either way.
      }
      temporary.dispose();
    },
  });
}
