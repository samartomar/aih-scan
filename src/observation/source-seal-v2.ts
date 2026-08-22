import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, type Stats } from "node:fs";
import { relative, resolve, sep } from "node:path";
import {
  assertSafeRelativePosixPathV1,
  canonicalStrictJsonBytesV1,
  codeUnitCompare,
  deepFreezeStrictJsonV1,
} from "../contract/strict-json-v1.js";

const maxFileBytes = 16 * 1024 * 1024;
type Entry = Readonly<{ path: string; sha256: string; byteLength: number }>;
export interface SourceSealV2 {
  readonly protocol: "SourceSealV2";
  readonly algorithm: "code-unit-canonical-json-v1";
  readonly sourceTreeSha256: string;
  readonly selectedClosureSha256: string;
  readonly sealedSnapshotSha256: string;
  readonly files: readonly Entry[];
}
function fail(reason: string): never {
  throw new TypeError(`invalid SourceSealV2: ${reason}`);
}
function hash(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}
function regular(stat: Stats, label: string): void {
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.nlink > 1 ||
    stat.size < 0 ||
    stat.size > maxFileBytes
  )
    fail(`${label} must be a bounded non-linked regular file`);
}
function inside(root: string, path: string): string {
  const resolved = resolve(path);
  const relativePath = relative(root, resolved);
  if (
    !relativePath ||
    relativePath.startsWith(`..${sep}`) ||
    relativePath === ".." ||
    /^[A-Za-z]:/.test(relativePath)
  )
    fail("path escapes source root");
  return resolved;
}
function readEntry(root: string, absolute: string): Entry {
  const before = lstatSync(absolute);
  regular(before, "source entry");
  const bytes = readFileSync(absolute);
  const after = lstatSync(absolute);
  regular(after, "source entry");
  if (
    before.size !== after.size ||
    before.mtimeMs !== after.mtimeMs ||
    bytes.byteLength !== before.size
  )
    fail("source entry changed while reading");
  const path = relative(root, absolute).split(sep).join("/");
  assertSafeRelativePosixPathV1(path, "source entry path");
  return { path, sha256: hash(bytes), byteLength: bytes.byteLength };
}
function allFiles(root: string, directory = root): Entry[] {
  const dir = lstatSync(directory);
  if (!dir.isDirectory() || dir.isSymbolicLink()) fail("source directory link or type");
  const entries: Entry[] = [];
  for (const name of readdirSync(directory).sort(codeUnitCompare)) {
    const absolute = resolve(directory, name);
    inside(root, absolute);
    const stat = lstatSync(absolute);
    if (stat.isDirectory()) entries.push(...allFiles(root, absolute));
    else entries.push(readEntry(root, absolute));
  }
  return entries;
}
/**
 * V2 seal algorithm: code-unit ordered relative POSIX entries encoded by
 * canonicalStrictJsonBytesV1; links, reparse/symlink entries, and hard-linked
 * files are refused before hashing.
 */
export function sealSourceV2(value: unknown): SourceSealV2 {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail("input object");
  const input = value as Record<string, unknown>;
  if (
    Object.getPrototypeOf(input) !== Object.prototype ||
    Object.keys(input).length !== 2 ||
    !Object.hasOwn(input, "sourceRoot") ||
    !Object.hasOwn(input, "selectedClosurePaths")
  )
    fail("input fields");
  if (
    typeof input.sourceRoot !== "string" ||
    !input.sourceRoot ||
    !Array.isArray(input.selectedClosurePaths) ||
    input.selectedClosurePaths.length === 0 ||
    input.selectedClosurePaths.length > 100_000
  )
    fail("input values");
  const root = resolve(input.sourceRoot);
  if (!lstatSync(root).isDirectory() || lstatSync(root).isSymbolicLink()) fail("source root");
  const selected = input.selectedClosurePaths.map((value) => {
    if (typeof value !== "string") fail("selected path");
    assertSafeRelativePosixPathV1(value, "selected path");
    return value;
  });
  if (new Set(selected).size !== selected.length) fail("duplicate selected path");
  const files = allFiles(root).sort((left, right) => codeUnitCompare(left.path, right.path));
  const byPath = new Map(files.map((file) => [file.path, file]));
  const closure = [...selected]
    .sort(codeUnitCompare)
    .map((path) => byPath.get(path) ?? fail("selected path missing or nonregular"));
  const sourceTreeSha256 = hash(canonicalStrictJsonBytesV1({ protocol: "SourceTreeV2", files }));
  const selectedClosureSha256 = hash(
    canonicalStrictJsonBytesV1({ protocol: "SelectedClosureV2", files: closure }),
  );
  const sealedSnapshotSha256 = hash(
    canonicalStrictJsonBytesV1({
      protocol: "SealedSnapshotV2",
      sourceTreeSha256,
      selectedClosureSha256,
    }),
  );
  return deepFreezeStrictJsonV1({
    protocol: "SourceSealV2" as const,
    algorithm: "code-unit-canonical-json-v1" as const,
    sourceTreeSha256,
    selectedClosureSha256,
    sealedSnapshotSha256,
    files,
  });
}
