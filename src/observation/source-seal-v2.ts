import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  opendirSync,
  openSync,
  readSync,
  realpathSync,
  type Stats,
} from "node:fs";
import { relative, resolve, sep } from "node:path";
import { z } from "zod";
import {
  assertSafeRelativePosixPathV1,
  assertStrictJsonValueV1,
  canonicalStrictJsonBytesV1,
  codeUnitCompare,
  deepFreezeStrictJsonV1,
} from "../contract/strict-json-v1.js";

const maxEntries = 4_096,
  maxFileBytes = 16 * 1024 * 1024,
  maxTotalBytes = 256 * 1024 * 1024,
  maxSealBytes = 512 * 1024;
const sha256 = z.string().regex(/^[0-9a-f]{64}$/);
const file = z
  .object({
    kind: z.literal("file"),
    path: z.string(),
    sha256,
    byteLength: z.number().int().nonnegative().max(maxFileBytes),
  })
  .strict();
const directory = z.object({ kind: z.literal("directory"), path: z.string() }).strict();
const entry = z.union([file, directory]);
export const sourceSealV2Schema = z
  .object({
    protocol: z.literal("SourceSealV2"),
    algorithm: z.literal("code-unit-canonical-json-v1"),
    entries: z.array(entry).min(1).max(maxEntries),
    selectedClosurePaths: z.array(z.string()).min(1).max(maxEntries),
    selectedFiles: z.array(file).min(1).max(maxEntries),
    sourceTreeSha256: sha256,
    selectedClosureSha256: sha256,
    sealedSnapshotSha256: sha256,
  })
  .strict();
export type SourceSealV2 = Readonly<z.infer<typeof sourceSealV2Schema>>;
type FileEntry = z.infer<typeof file>;
type Entry = z.infer<typeof entry>;
type TraverseBudget = { entries: number; totalBytes: number };
const fail = (reason: string): never => {
  throw new TypeError(`invalid SourceSealV2: ${reason}`);
};
const hash = (value: Uint8Array): string => createHash("sha256").update(value).digest("hex");
const equalFile = (left: FileEntry, right: FileEntry) =>
  left.path === right.path && left.sha256 === right.sha256 && left.byteLength === right.byteLength;
function sortedUnique(entries: readonly Entry[], label: string): void {
  let previous: string | undefined;
  const seen = new Set<string>();
  for (const value of entries) {
    assertSafeRelativePosixPathV1(value.path, `${label} path`);
    if (previous !== undefined && codeUnitCompare(previous, value.path) >= 0)
      fail(`${label} ordering`);
    if (seen.has(value.path)) fail(`${label} duplicate`);
    previous = value.path;
    seen.add(value.path);
  }
}
function calculated(value: { entries: readonly Entry[]; selectedFiles: readonly FileEntry[] }) {
  const sourceTreeSha256 = hash(
    canonicalStrictJsonBytesV1({ protocol: "SourceTreeV2", entries: value.entries }),
  );
  const selectedClosureSha256 = hash(
    canonicalStrictJsonBytesV1({ protocol: "SelectedClosureV2", files: value.selectedFiles }),
  );
  return {
    sourceTreeSha256,
    selectedClosureSha256,
    sealedSnapshotSha256: hash(
      canonicalStrictJsonBytesV1({
        protocol: "SealedSnapshotV2",
        sourceTreeSha256,
        selectedClosureSha256,
      }),
    ),
  };
}
/** Strict portable parser which recomputes every V2 source-seal digest. */
export function validateSourceSealV2(value: unknown): SourceSealV2 {
  assertStrictJsonValueV1(value, "SourceSealV2");
  const parsed = sourceSealV2Schema.parse(structuredClone(value));
  sortedUnique(parsed.entries, "source entries");
  if (
    parsed.entries.reduce(
      (total, item) => total + (item.kind === "file" ? item.byteLength : 0),
      0,
    ) > maxTotalBytes
  )
    fail("source byte bound");
  const selected = parsed.selectedClosurePaths;
  for (const path of selected) assertSafeRelativePosixPathV1(path, "selected closure path");
  if (
    new Set(selected).size !== selected.length ||
    selected.some(
      (path, index) => index > 0 && codeUnitCompare(selected[index - 1] ?? "", path) >= 0,
    )
  )
    fail("selected closure ordering");
  sortedUnique(parsed.selectedFiles, "selected file");
  if (
    parsed.selectedFiles.length !== selected.length ||
    parsed.selectedFiles.some((item, index) => item.path !== selected[index])
  )
    fail("selected file paths");
  const files = new Map(
    parsed.entries
      .filter((item): item is FileEntry => item.kind === "file")
      .map((item) => [item.path, item]),
  );
  for (const item of parsed.selectedFiles) {
    const expected = files.get(item.path);
    if (expected === undefined || !equalFile(expected, item)) fail("selected file binding");
  }
  const expected = calculated(parsed);
  if (
    parsed.sourceTreeSha256 !== expected.sourceTreeSha256 ||
    parsed.selectedClosureSha256 !== expected.selectedClosureSha256 ||
    parsed.sealedSnapshotSha256 !== expected.sealedSnapshotSha256
  )
    fail("digest binding");
  if (canonicalStrictJsonBytesV1(parsed).byteLength > maxSealBytes)
    fail("canonical seal byte bound");
  return deepFreezeStrictJsonV1(parsed);
}
function inside(root: string, target: string): void {
  const child = relative(root, target);
  if (!child || child === ".." || child.startsWith(`..${sep}`) || /^[A-Za-z]:/.test(child))
    fail("path escapes source root");
}
const sameIdentity = (left: Stats, right: Stats) =>
  left.dev === right.dev &&
  left.ino === right.ino &&
  left.size === right.size &&
  left.mtimeMs === right.mtimeMs &&
  left.ctimeMs === right.ctimeMs;
function requireDirectory(path: string, realRoot: string): void {
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail("directory link or reparse");
  const real = realpathSync.native(path);
  if (real !== realRoot) inside(realRoot, real);
}
function reserveEntry(budget: TraverseBudget): void {
  if (budget.entries >= maxEntries) fail("source entry bound");
  budget.entries += 1;
}
function reserveFileBytes(stat: Stats, budget: TraverseBudget): void {
  if (stat.size > maxTotalBytes - budget.totalBytes) fail("source byte bound");
  budget.totalBytes += stat.size;
}
function readFileEntry(
  root: string,
  path: string,
  beforePath: Stats,
  budget: TraverseBudget,
): FileEntry {
  if (
    !beforePath.isFile() ||
    beforePath.isSymbolicLink() ||
    beforePath.nlink !== 1 ||
    beforePath.size > maxFileBytes
  )
    fail("file link, reparse, hardlink, or bounds");
  reserveFileBytes(beforePath, budget);
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const before = fstatSync(descriptor);
    if (!sameIdentity(beforePath, before) || !before.isFile() || before.nlink !== 1)
      fail("file replacement before read");
    const bytes = Buffer.allocUnsafe(before.size);
    let offset = 0;
    while (offset < bytes.byteLength) {
      const count = readSync(descriptor, bytes, offset, bytes.byteLength - offset, offset);
      if (count <= 0) fail("short file read");
      offset += count;
    }
    const after = fstatSync(descriptor),
      afterPath = lstatSync(path);
    if (!sameIdentity(before, after) || !sameIdentity(before, afterPath) || after.nlink !== 1)
      fail("file replacement during read");
    return {
      kind: "file",
      path: relative(root, path).split(sep).join("/"),
      sha256: hash(bytes),
      byteLength: bytes.byteLength,
    };
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}
function directoryNames(directoryPath: string, maximum: number): string[] {
  const handle = opendirSync(directoryPath);
  try {
    const names: string[] = [];
    for (let entry = handle.readSync(); entry !== null; entry = handle.readSync()) {
      if (names.length >= maximum) fail("source entry bound");
      names.push(entry.name);
    }
    return names.sort(codeUnitCompare);
  } finally {
    handle.closeSync();
  }
}
function traverse(
  root: string,
  realRoot: string,
  directoryPath: string,
  entries: Entry[],
  budget: TraverseBudget,
): void {
  requireDirectory(directoryPath, realRoot);
  const names = directoryNames(directoryPath, maxEntries - budget.entries);
  for (const name of names) {
    const absolute = resolve(directoryPath, name);
    inside(root, absolute);
    const stat = lstatSync(absolute),
      path = relative(root, absolute).split(sep).join("/");
    assertSafeRelativePosixPathV1(path, "source entry path");
    reserveEntry(budget);
    if (stat.isDirectory()) {
      if (stat.isSymbolicLink()) fail("directory link or reparse");
      entries.push({ kind: "directory", path });
      traverse(root, realRoot, absolute, entries, budget);
    } else entries.push(readFileEntry(root, absolute, stat, budget));
  }
}
/** Seals files and directories, including empty directories, by canonical code-unit path order. */
export function sealSourceV2(value: unknown): SourceSealV2 {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail("input object");
  const input = value as Record<string, unknown>;
  if (
    Object.getPrototypeOf(input) !== Object.prototype ||
    Object.getOwnPropertySymbols(input).length > 0 ||
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
    input.selectedClosurePaths.length > maxEntries
  )
    fail("input values");
  const sourceRoot = input.sourceRoot as string;
  const rawSelected = input.selectedClosurePaths as unknown[];
  const root = resolve(sourceRoot),
    realRoot = realpathSync.native(root);
  requireDirectory(root, realRoot);
  const selectedClosurePaths: string[] = [];
  for (const item of rawSelected) {
    const path = typeof item === "string" ? item : fail("selected closure path");
    assertSafeRelativePosixPathV1(path, "selected closure path");
    selectedClosurePaths.push(path);
  }
  selectedClosurePaths.sort(codeUnitCompare);
  if (new Set(selectedClosurePaths).size !== selectedClosurePaths.length)
    fail("selected closure duplicate");
  const entries: Entry[] = [];
  traverse(root, realRoot, root, entries, { entries: 0, totalBytes: 0 });
  entries.sort((left, right) => codeUnitCompare(left.path, right.path));
  const files = new Map(
    entries
      .filter((item): item is FileEntry => item.kind === "file")
      .map((item) => [item.path, item]),
  );
  const selectedFiles = selectedClosurePaths.map(
    (path) => files.get(path) ?? fail("selected closure file missing"),
  );
  const digests = calculated({ entries, selectedFiles });
  return validateSourceSealV2({
    protocol: "SourceSealV2",
    algorithm: "code-unit-canonical-json-v1",
    entries,
    selectedClosurePaths,
    selectedFiles,
    ...digests,
  });
}
