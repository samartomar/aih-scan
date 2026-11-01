import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from "node:fs";
import { join } from "node:path";
import { limits } from "../contracts/limits.js";
import { pathProblem } from "../contracts/text.js";
import type { FolderRefusalReason } from "./snapshot.js";

/** One entry of an acquired inventory, checked before its bytes are read. */
export interface InventoryEntry {
  readonly path: string;
  readonly size: number;
}

export type InventoryProblem = Readonly<{ reason: FolderRefusalReason; detail: string }>;

const shown = (path: string) => JSON.stringify(path).slice(0, 200);

/**
 * The same path and size constraints `readFolder` applies, for inventories that do not come
 * from a folder (a Git tree, an npm archive): file count, path length, folder depth, valid
 * names, one file's size and the source size. A path that is both a file and a folder is refused.
 */
export function inventoryProblem(entries: readonly InventoryEntry[]): InventoryProblem | undefined {
  if (entries.length > limits.input.files)
    return { reason: "files", detail: `more than ${limits.input.files} files` };
  let total = 0;
  const files = new Set<string>();
  const folders = new Set<string>();
  for (const entry of entries) {
    const problem = pathProblem(entry.path, limits.input.pathLength, limits.input.depth);
    if (problem === "path-length")
      return {
        reason: "path-length",
        detail: `a path exceeds ${limits.input.pathLength} characters`,
      };
    if (problem === "depth")
      return { reason: "depth", detail: `a path exceeds folder depth ${limits.input.depth}` };
    if (problem !== undefined)
      return { reason: "invalid-name", detail: `${shown(entry.path)}: ${problem}` };
    if (entry.path === ".git" || entry.path.startsWith(".git/") || entry.path.includes("/.git/"))
      return { reason: "invalid-name", detail: `${shown(entry.path)} is reserved Git metadata` };
    if (entry.size > limits.input.fileBytes)
      return {
        reason: "file-size",
        detail: `${shown(entry.path)} exceeds ${limits.input.fileBytes} bytes`,
      };
    total += entry.size;
    if (total > limits.input.sourceBytes)
      return {
        reason: "source-size",
        detail: `the files exceed ${limits.input.sourceBytes} bytes`,
      };
    if (files.has(entry.path))
      return { reason: "invalid-name", detail: `${shown(entry.path)} is listed twice` };
    files.add(entry.path);
    const parts = entry.path.split("/");
    for (let index = 1; index < parts.length; index += 1)
      folders.add(parts.slice(0, index).join("/"));
  }
  for (const folder of folders)
    if (files.has(folder))
      return { reason: "invalid-name", detail: `${shown(folder)} is both a file and a folder` };
  return undefined;
}

function readSmall(path: string): string | undefined {
  let descriptor: number | undefined;
  try {
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.size > 1024 * 1024) return undefined;
    descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const bytes = Buffer.alloc(fstatSync(descriptor).size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count <= 0) break;
      offset += count;
    }
    return bytes.subarray(0, offset).toString("utf8");
  } catch {
    return undefined;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

const COMMIT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;

/**
 * The commit a local clone has checked out, read from its `.git` folder as data (Git itself is
 * never run): a detached `HEAD`, or the branch `HEAD` names in a loose ref or `packed-refs`.
 * The remote address is never read. Undefined when the folder is not a plain clone.
 */
export function cloneCommit(folder: string): string | undefined {
  const git = join(folder, ".git");
  try {
    if (!lstatSync(git).isDirectory()) return undefined;
  } catch {
    return undefined;
  }
  const head = readSmall(join(git, "HEAD"))?.trim();
  if (head === undefined) return undefined;
  if (COMMIT.test(head)) return head;
  const match = /^ref: (refs\/heads\/[^\0-\x20\x7f~^:?*[\\]+)$/.exec(head);
  if (match === null) return undefined;
  const ref = match[1] as string;
  if (ref.split("/").some((part) => part === "" || part === "." || part === "..")) return undefined;
  const loose = readSmall(join(git, ...ref.split("/")))?.trim();
  if (loose !== undefined) return COMMIT.test(loose) ? loose : undefined;
  for (const line of (readSmall(join(git, "packed-refs")) ?? "").split("\n")) {
    const [commit, name] = line.trim().split(" ");
    if (name === ref && commit !== undefined && COMMIT.test(commit)) return commit;
  }
  return undefined;
}
