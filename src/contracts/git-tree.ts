import { webCryptoSubtle } from "../shared/values.js";
import type { Problem } from "./formats.js";
import { limits } from "./limits.js";
import { isBytes, pathProblem } from "./text.js";

/**
 * Portable Git object hashing for scan keys (WebCrypto only). A scan key is the Git tree
 * hash of one folder, prefixed with its algorithm: `git-sha1:<40 hex>` or `git-sha256:<64 hex>`.
 */
export type GitAlgorithm = "sha1" | "sha256";
export type FileMode = "100644" | "100755";

export interface TreeFile {
  readonly path: string;
  readonly mode: FileMode;
  readonly bytes: Uint8Array;
}

export const SCAN_KEY_PATTERN = /^git-(sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})$/;

const encoder = new TextEncoder();

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function hex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

async function digest(algorithm: "SHA-1" | "SHA-256", bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(
    await webCryptoSubtle().digest(algorithm, bytes as Uint8Array<ArrayBuffer>),
  );
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return hex(await digest("SHA-256", bytes));
}

async function gitObject(
  algorithm: GitAlgorithm,
  type: string,
  body: Uint8Array,
): Promise<Uint8Array> {
  const header = encoder.encode(`${type} ${body.length}\0`);
  return digest(algorithm === "sha1" ? "SHA-1" : "SHA-256", concat([header, body]));
}

export async function gitBlobHex(algorithm: GitAlgorithm, bytes: Uint8Array): Promise<string> {
  return hex(await gitObject(algorithm, "blob", bytes));
}

interface Directory {
  readonly files: Map<string, { mode: FileMode; bytes: Uint8Array }>;
  readonly folders: Map<string, Directory>;
}

const newDirectory = (): Directory => ({ files: new Map(), folders: new Map() });

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (left[index] as number) - (right[index] as number);
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
}

async function treeHash(algorithm: GitAlgorithm, directory: Directory): Promise<Uint8Array> {
  const entries: { sortKey: Uint8Array; record: Uint8Array }[] = [];
  for (const [name, file] of directory.files) {
    const id = await gitObject(algorithm, "blob", file.bytes);
    entries.push({
      sortKey: encoder.encode(name),
      record: concat([encoder.encode(`${file.mode} ${name}\0`), id]),
    });
  }
  for (const [name, folder] of directory.folders) {
    const id = await treeHash(algorithm, folder);
    entries.push({
      sortKey: encoder.encode(`${name}/`),
      record: concat([encoder.encode(`40000 ${name}\0`), id]),
    });
  }
  entries.sort((a, b) => compareBytes(a.sortKey, b.sortKey));
  return gitObject(algorithm, "tree", concat(entries.map((entry) => entry.record)));
}

/**
 * The tree key of an inventory already checked by `checkTreeFiles` (or produced by Scan
 * itself). Throws only when WebCrypto is unavailable.
 */
export async function treeKeyOf(
  files: readonly TreeFile[],
  algorithm: GitAlgorithm = "sha1",
): Promise<string> {
  const root = newDirectory();
  for (const file of files) {
    const parts = file.path.split("/");
    const name = parts.pop() as string;
    let directory = root;
    for (const part of parts) {
      let next = directory.folders.get(part);
      if (next === undefined) {
        next = newDirectory();
        directory.folders.set(part, next);
      }
      directory = next;
    }
    directory.files.set(name, { mode: file.mode, bytes: file.bytes });
  }
  return `git-${algorithm}:${hex(await treeHash(algorithm, root))}`;
}

const invalid = (reason: string, detail: string): Problem =>
  Object.freeze({ status: "invalid", reason, detail });
const refused = (reason: string, detail: string): Problem =>
  Object.freeze({ status: "refused", reason, detail });

/**
 * Checks a caller-supplied `{ path, mode, bytes }` inventory by the identity rules: an array
 * within the file and size limits, safe item-relative POSIX paths (`unsafe-path`, or the limit's
 * name, `refused`), modes `100644`/`100755`, `Uint8Array` bytes, no repeated path and no path
 * that is both a file and a folder (`invalid`).
 */
export function checkTreeFiles(files: unknown): TreeFile[] | Problem {
  if (!Array.isArray(files))
    return invalid("files", "files must be an array of { path, mode, bytes }");
  if (files.length > limits.input.files)
    return refused("files", `more than ${limits.input.files} files`);
  const seen = new Set<string>();
  let total = 0;
  const out: TreeFile[] = [];
  for (const [index, entry] of files.entries()) {
    if (typeof entry !== "object" || entry === null)
      return invalid("files", `files[${index}] must be an object`);
    const { path, mode, bytes } = entry as Record<string, unknown>;
    const problem = pathProblem(path, limits.input.pathLength, limits.input.depth);
    if (problem !== undefined)
      return problem === "path-length" || problem === "depth"
        ? refused(problem, `files[${index}] exceeds the ${problem} limit`)
        : refused("unsafe-path", `files[${index}]: ${problem}`);
    if (mode !== "100644" && mode !== "100755")
      return invalid("mode", `files[${index}].mode must be 100644 or 100755`);
    if (!isBytes(bytes)) return invalid("bytes", `files[${index}].bytes must be a Uint8Array`);
    if (bytes.length > limits.input.fileBytes)
      return refused("file-size", `files[${index}] exceeds the file size limit`);
    total += bytes.length;
    if (total > limits.input.sourceBytes)
      return refused("source-size", "files exceed the source size limit");
    if (seen.has(path as string)) return invalid("files", `files[${index}] repeats a path`);
    seen.add(path as string);
    out.push({ path: path as string, mode, bytes });
  }
  for (const path of seen) {
    const segments = path.split("/");
    for (let depth = 1; depth < segments.length; depth += 1)
      if (seen.has(segments.slice(0, depth).join("/")))
        return invalid("files", "a path is both a file and a folder");
  }
  return out;
}

export type ScanKeyResult = Readonly<{ status: "ok"; scanKey: string }> | Problem;

/**
 * The scan key of a file inventory: Git's tree hash of the folder holding exactly these
 * regular files and modes (empty folders do not exist in Git). The inventory is checked by
 * `checkTreeFiles` first. Never throws: bad input is `invalid`/`refused`, an unknown algorithm
 * is `invalid`, a realm without WebCrypto is `refused` (`crypto-unavailable`) and a WebCrypto
 * whose digest fails (for example one without SHA-1) is `refused` (`digest-failed`).
 */
export async function scanKeyOf(
  files: readonly TreeFile[],
  algorithm: GitAlgorithm = "sha1",
): Promise<ScanKeyResult> {
  if (algorithm !== "sha1" && algorithm !== "sha256")
    return invalid("algorithm", "algorithm must be sha1 or sha256");
  const checked = checkTreeFiles(files);
  if (!Array.isArray(checked)) return checked;
  if (!hasWebCrypto()) return refused("crypto-unavailable", "WebCrypto is unavailable");
  try {
    return Object.freeze({ status: "ok" as const, scanKey: await treeKeyOf(checked, algorithm) });
  } catch {
    return refused("digest-failed", "the scan key could not be computed");
  }
}

/** True when this realm exposes `crypto.subtle` (the only case `crypto-unavailable` names). */
export function hasWebCrypto(): boolean {
  try {
    webCryptoSubtle();
    return true;
  } catch {
    return false;
  }
}

export function algorithmOfKey(key: string): GitAlgorithm | undefined {
  if (!SCAN_KEY_PATTERN.test(key)) return undefined;
  return key.startsWith("git-sha1:") ? "sha1" : "sha256";
}

/** A storage folder name for a key: the colon written as a hyphen. */
export function keyFolderName(key: string): string {
  return key.replace(":", "-");
}
