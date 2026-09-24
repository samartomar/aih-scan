import { isUtf8 } from "node:buffer";
import { opendirSync } from "node:fs";

/**
 * S2h (review of S2g): a source entry whose name the source-relative form cannot carry
 * exactly. `path` is the root-relative path with the name decoded for display only; the
 * message names it JSON-escaped, so a backslash or a control character stays visible.
 */
export class UnrepresentableSourcePathErrorV1 extends TypeError {
  readonly path: string;
  constructor(path: string, reason: string) {
    super(
      `source path ${JSON.stringify(path)} is not representable as a source-relative path: ${reason}`,
    );
    this.name = "UnrepresentableSourcePathErrorV1";
    this.path = path;
  }
}

/**
 * Why one directory entry name, as the file system returned its bytes, cannot be a segment
 * of a source-relative path, or `undefined`. On POSIX a name is any byte string without `/`
 * and NUL, so a name is refused when it holds a backslash (which Windows-minded readers and
 * the former inventory rewrite read as a separator), a control character (U+0000–U+001F or
 * U+007F), or bytes that are not well-formed UTF-8 (which a string decode would repair to
 * U+FFFD, merging distinct names). Windows returns UTF-16 names that already exclude these,
 * and its behaviour is unchanged: nothing is refused there.
 */
export function representableSourceNameProblemV1(
  name: Uint8Array,
  platform: NodeJS.Platform = process.platform,
): string | undefined {
  if (platform === "win32") return undefined;
  if (!isUtf8(name)) return "its name is not UTF-8";
  for (const byte of name) {
    if (byte === 0x5c) return "its name holds a backslash, which is not a path separator here";
    if (byte <= 0x1f || byte === 0x7f) return "its name holds a control character";
  }
  return undefined;
}

/**
 * The names of one directory's entries, each refused with
 * {@link UnrepresentableSourcePathErrorV1} unless {@link representableSourceNameProblemV1}
 * accepts it; `parent` is the directory's root-relative path (`""` for the root). Reading
 * stops with `onBound` once more than `maximum` entries are seen. Names are returned in
 * read order.
 */
export function readSourceEntryNamesV1(
  directory: string,
  parent: string,
  options: Readonly<{ maximum?: number; onBound?: () => never }> = {},
): string[] {
  // Windows keeps its string names exactly as before; POSIX names are read as their bytes.
  const windows = process.platform === "win32";
  const handle = windows
    ? opendirSync(directory)
    : // Node reads raw names with the "buffer" encoding, which its typings omit for opendir.
      opendirSync(directory, { encoding: "buffer" as BufferEncoding });
  try {
    const names: string[] = [];
    for (let entry = handle.readSync(); entry !== null; entry = handle.readSync()) {
      if (options.maximum !== undefined && names.length >= options.maximum) options.onBound?.();
      if (windows) {
        names.push(entry.name);
        continue;
      }
      const raw = entry.name as unknown as Buffer;
      const name = raw.toString("utf8");
      const problem = representableSourceNameProblemV1(raw);
      if (problem !== undefined)
        throw new UnrepresentableSourcePathErrorV1(parent ? `${parent}/${name}` : name, problem);
      names.push(name);
    }
    return names;
  } finally {
    handle.closeSync();
  }
}
