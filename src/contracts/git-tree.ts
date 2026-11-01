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
const subtle = () => {
  const value = (globalThis as { crypto?: Crypto }).crypto?.subtle;
  if (value === undefined) throw new TypeError("WebCrypto is unavailable");
  return value;
};

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
  return new Uint8Array(await subtle().digest(algorithm, bytes as Uint8Array<ArrayBuffer>));
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
 * The scan key of a file inventory: Git's tree hash of the folder holding exactly these
 * regular files and modes (empty folders do not exist in Git). Paths are validated
 * item-relative POSIX paths; a path that is both a file and a folder is refused by the caller.
 */
export async function scanKeyOf(
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

export function algorithmOfKey(key: string): GitAlgorithm | undefined {
  if (!SCAN_KEY_PATTERN.test(key)) return undefined;
  return key.startsWith("git-sha1:") ? "sha1" : "sha256";
}

/** A storage folder name for a key: the colon written as a hyphen. */
export function keyFolderName(key: string): string {
  return key.replace(":", "-");
}
