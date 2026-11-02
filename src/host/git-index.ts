import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from "node:fs";
import { join } from "node:path";
import type { FileMode } from "../contracts/git-tree.js";

/** The largest `.git/index` read for modes; a bigger index is ignored (modes fall back). */
const MAX_INDEX_BYTES = 64 * 1024 * 1024;

function readBounded(path: string, maximum: number): Uint8Array | undefined {
  let descriptor: number | undefined;
  try {
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.size > maximum) return undefined;
    descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const size = fstatSync(descriptor).size;
    if (size > maximum) return undefined;
    const bytes = new Uint8Array(size);
    let offset = 0;
    while (offset < size) {
      const count = readSync(descriptor, bytes, offset, size - offset, offset);
      if (count <= 0) return undefined;
      offset += count;
    }
    return bytes;
  } catch {
    return undefined;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

/** The object id length of a clone: 32 bytes when its config selects SHA-256, else 20. */
function hashLength(git: string): number {
  const config = readBounded(join(git, "config"), 1024 * 1024);
  if (config === undefined) return 20;
  const text = new TextDecoder().decode(config);
  return /^\s*objectformat\s*=\s*sha256\s*$/im.test(text) ? 32 : 20;
}

const decoder = new TextDecoder("utf-8", { fatal: true });

/**
 * Parses a Git index (versions 2, 3 and 4) as data, without running Git, into the mode Git
 * records for each regular file at stage 0. Symbolic links, submodules and conflict stages are
 * left out. Undefined when the bytes are not a well-formed index.
 */
export function parseGitIndex(
  bytes: Uint8Array,
  idLength = 20,
): ReadonlyMap<string, FileMode> | undefined {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes.length < 12 + idLength) return undefined;
  if (view.getUint32(0) !== 0x44495243) return undefined; // "DIRC"
  const version = view.getUint32(4);
  if (version < 2 || version > 4) return undefined;
  const count = view.getUint32(8);
  const end = bytes.length - idLength;
  const modes = new Map<string, FileMode>();
  let offset = 12;
  let previous: Uint8Array = new Uint8Array(0);
  try {
    for (let index = 0; index < count; index += 1) {
      const start = offset;
      const fixed = 40 + idLength + 2;
      if (offset + fixed > end) return undefined;
      const mode = view.getUint32(offset + 24);
      const flags = view.getUint16(offset + 40 + idLength);
      offset += fixed;
      if (version >= 3 && (flags & 0x4000) !== 0) offset += 2;
      let name: Uint8Array;
      if (version === 4) {
        let strip = 0;
        let byte: number;
        let first = true;
        do {
          if (offset >= end) return undefined;
          byte = bytes[offset] as number;
          offset += 1;
          strip = first ? byte & 0x7f : ((strip + 1) << 7) | (byte & 0x7f);
          first = false;
        } while ((byte & 0x80) !== 0);
        if (strip > previous.length) return undefined;
        const nul = bytes.indexOf(0, offset);
        if (nul < 0 || nul >= end) return undefined;
        const suffix = bytes.subarray(offset, nul);
        name = new Uint8Array(previous.length - strip + suffix.length);
        name.set(previous.subarray(0, previous.length - strip));
        name.set(suffix, previous.length - strip);
        offset = nul + 1;
      } else {
        const nul = bytes.indexOf(0, offset);
        if (nul < 0 || nul >= end) return undefined;
        name = bytes.subarray(offset, nul);
        // Entries are NUL-padded to a multiple of eight bytes (one to eight NULs).
        offset = start + Math.ceil((nul - start + 1) / 8) * 8;
      }
      previous = name;
      const stage = (flags >> 12) & 0x3;
      if (stage !== 0 || (mode & 0o170000) !== 0o100000) continue;
      modes.set(decoder.decode(name), (mode & 0o111) !== 0 ? "100755" : "100644");
    }
  } catch {
    return undefined;
  }
  return modes;
}

/**
 * The modes Git's index records for a clone at `folder` (a `.git` folder directly inside it),
 * keyed by folder-relative path; undefined when the folder is not such a clone or its index
 * cannot be read. Used only where the disk cannot say whether a file is executable.
 */
export function cloneIndexModes(folder: string): ReadonlyMap<string, FileMode> | undefined {
  const git = join(folder, ".git");
  try {
    if (!lstatSync(git).isDirectory()) return undefined;
  } catch {
    return undefined;
  }
  const bytes = readBounded(join(git, "index"), MAX_INDEX_BYTES);
  return bytes === undefined ? undefined : parseGitIndex(bytes, hashLength(git));
}
