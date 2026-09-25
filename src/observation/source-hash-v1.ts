import { createHash } from "node:crypto";
import { lstatSync, readFileSync, readlinkSync, realpathSync, type Stats } from "node:fs";
import { isAbsolute, posix, relative, resolve, sep } from "node:path";
import { readSourceEntryNamesV1 } from "./source-entry-name-v1.js";

export type SourceHashedFileV1 = { path: string; bytes: number; sha256: string };
export type SourceTreeHashV1 = { treeSha256: string; files: SourceHashedFileV1[] };
type Entry = {
  type: "directory" | "file" | "symlink";
  path: string;
  bytes?: number;
  sha256?: string;
  target?: string;
};
const fail = (message: string): never => {
  throw new TypeError(message);
};
const codeUnitCompare = (left: string, right: string): number =>
  left < right ? -1 : left > right ? 1 : 0;
const file = (path: string) => {
  const bytes = readFileSync(path);
  return { bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") };
};
// S2h: only the platform separator is rewritten; a POSIX name never holds a backslash, as
// readSourceEntryNamesV1 refuses one before it could be read as a separator.
const rel = (root: string, target: string) => {
  const value = relative(root, target).split(sep).join("/");
  if (!value || value === ".." || value.startsWith("../") || isAbsolute(value))
    fail(`source path escapes root: ${target}`);
  return value;
};
const declared = (value: string) => {
  if (!value || value.includes("\\") || value.startsWith("/"))
    fail("component path must be source-relative POSIX text");
  const normalized = posix.normalize(value);
  if (
    normalized === "." ||
    normalized === ".." ||
    normalized.startsWith("../") ||
    isAbsolute(normalized)
  )
    fail("component path escapes root");
  return normalized;
};
function rootOf(sourceRoot: string) {
  const stat = lstatSync(sourceRoot);
  if (stat.isSymbolicLink() || !stat.isDirectory()) fail("source root must be a real directory");
  return realpathSync(sourceRoot);
}
export function hashComponentTreeV1(
  sourceRoot: string,
  declaredPaths: readonly string[],
): SourceTreeHashV1 {
  const root = rootOf(sourceRoot);
  if (!declaredPaths.length) fail("component declares no paths");
  const roots = declaredPaths.map(declared);
  if (new Set(roots).size !== roots.length) fail("duplicate normalized component root");
  const entries = new Map<string, Entry>();
  const visit = (path: string) => {
    let stat: Stats;
    try {
      stat = lstatSync(path);
    } catch {
      throw new TypeError("component path missing");
    }
    const pathRel = rel(root, path);
    if (entries.has(pathRel)) fail("duplicate component tree entry");
    if (stat.isSymbolicLink()) fail("symbolic link in component");
    if (stat.isDirectory()) {
      entries.set(pathRel, { type: "directory", path: pathRel });
      for (const child of readSourceEntryNamesV1(path, pathRel).sort(codeUnitCompare))
        visit(resolve(path, child));
      return;
    }
    if (!stat.isFile()) fail("unsupported component entry");
    if (stat.nlink > 1) fail("hard link in component");
    entries.set(pathRel, { type: "file", path: pathRel, ...file(path) });
  };
  for (const item of [...roots].sort(codeUnitCompare)) visit(resolve(root, ...item.split("/")));
  const ordered = [...entries.values()].sort((a, b) => codeUnitCompare(a.path, b.path));
  return {
    treeSha256: createHash("sha256").update(JSON.stringify(ordered)).digest("hex"),
    files: ordered.flatMap((e) =>
      e.type === "file" ? [{ path: e.path, bytes: e.bytes ?? 0, sha256: e.sha256 ?? "" }] : [],
    ),
  };
}
/**
 * `omittedDirectoryLinks` (D26) names, by source-relative POSIX path, the directory links an
 * analyzer snapshot left out, with the target each had in the source. They are hashed as the
 * source's own links, so a snapshot and the source it was taken from have one digest.
 */
export function hashSourceTreeV1(
  sourceRoot: string,
  omittedDirectoryLinks: ReadonlyMap<string, string> = new Map(),
): SourceTreeHashV1 {
  const root = rootOf(sourceRoot);
  const entries = new Map<string, Entry>();
  const visit = (path: string) => {
    const stat = lstatSync(path);
    const pathRel = rel(root, path);
    if (entries.has(pathRel)) fail("duplicate source tree entry");
    if (stat.isSymbolicLink()) {
      entries.set(pathRel, { type: "symlink", path: pathRel, target: readlinkSync(path) });
      return;
    }
    if (stat.isDirectory()) {
      entries.set(pathRel, { type: "directory", path: pathRel });
      for (const child of readSourceEntryNamesV1(path, pathRel).sort(codeUnitCompare))
        visit(resolve(path, child));
      return;
    }
    if (!stat.isFile()) fail("unsupported source entry");
    if (stat.nlink > 1) fail("hard link in source");
    entries.set(pathRel, { type: "file", path: pathRel, ...file(path) });
  };
  const names = readSourceEntryNamesV1(root, "")
    .filter((x) => x !== ".git")
    .sort(codeUnitCompare);
  if (!names.length && !omittedDirectoryLinks.size) fail("source tree has no content");
  for (const name of names) visit(resolve(root, name));
  for (const [path, target] of omittedDirectoryLinks) {
    const parent = posix.dirname(path);
    if (
      declared(path) !== path ||
      path === ".git" ||
      path.startsWith(".git/") ||
      entries.has(path) ||
      (parent !== "." && entries.get(parent)?.type !== "directory")
    )
      fail(`omitted directory link is not a free source path: ${path}`);
    entries.set(path, { type: "symlink", path, target });
  }
  const ordered = [...entries.values()].sort((a, b) => codeUnitCompare(a.path, b.path));
  return {
    treeSha256: createHash("sha256").update(JSON.stringify(ordered)).digest("hex"),
    files: ordered.flatMap((e) =>
      e.type === "file" ? [{ path: e.path, bytes: e.bytes ?? 0, sha256: e.sha256 ?? "" }] : [],
    ),
  };
}
