import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  realpathSync,
  type Stats,
  statSync,
} from "node:fs";
import { relative, resolve, sep } from "node:path";
import {
  assertSafeRelativePosixPathV1,
  canonicalStrictJsonBytesV1,
  codeUnitCompare,
  deepFreezeStrictJsonV1,
} from "../contract/strict-json-v1.js";
import { readSourceEntryNamesV1 } from "./source-entry-name-v1.js";

/**
 * The source seal a `runDetectorV1` observation run takes before and after the analyzer
 * (every profile except the OCI capture profile, whose `ScanCandidateV2` keeps
 * `SourceSealV2`). It accepts every tree Core's `assertTrustTreeSafe` accepts, up to the
 * declared bounds:
 *
 * - an empty root, and an empty selection over a non-empty tree;
 * - a symbolic link whose real path stays inside the root: to a file, recorded by its link
 *   path with the target's bytes (`file-link`); to a directory, recorded and never
 *   traversed (`directory-link`), as Core's trust inventory does;
 * - at most 100,000 entries and 256 MiB of file bytes (a single file may use the whole
 *   byte budget). A larger tree is refused, never partly sealed.
 *
 * It refuses what Core refuses (a hard-linked file, a link whose real path leaves the
 * root, a broken link) and, failing closed, anything that is neither a file, a directory
 * nor such a link. Entries are in code-unit path order; the digests are over canonical
 * JSON, so the same tree always seals the same way.
 */

export const SOURCE_OBSERVATION_SEAL_LIMITS_V1 = Object.freeze({
  maxEntries: 100_000,
  maxTotalBytes: 256 * 1024 * 1024,
  maxFileBytes: 256 * 1024 * 1024,
});

export type SourceObservationEntryV1 =
  | Readonly<{ kind: "file"; path: string; sha256: string; byteLength: number }>
  | Readonly<{ kind: "directory"; path: string }>
  | Readonly<{
      kind: "file-link";
      path: string;
      /** The link's real target, relative to the source root. */
      target: string;
      sha256: string;
      byteLength: number;
    }>
  | Readonly<{ kind: "directory-link"; path: string; target: string }>;

export type SourceObservationSealV1 = Readonly<{
  protocol: "SourceObservationSealV1";
  algorithm: "code-unit-canonical-json-v1";
  entries: readonly SourceObservationEntryV1[];
  /** The declared selection in code-unit order; every path is a `file` or `file-link`. */
  selectedClosurePaths: readonly string[];
  sourceTreeSha256: string;
  selectedClosureSha256: string;
  sealedSnapshotSha256: string;
}>;

type FileLike = Extract<SourceObservationEntryV1, { sha256: string }>;
type Budget = { entries: number; bytes: number };

const fail = (reason: string): never => {
  throw new TypeError(`invalid SourceObservationSealV1: ${reason}`);
};
const hash = (value: Uint8Array): string => createHash("sha256").update(value).digest("hex");
const posix = (root: string, path: string) => relative(root, path).split(sep).join("/");
const sameIdentity = (left: Stats, right: Stats) =>
  left.dev === right.dev &&
  left.ino === right.ino &&
  left.size === right.size &&
  left.mtimeMs === right.mtimeMs &&
  left.ctimeMs === right.ctimeMs;

function contained(realRoot: string, real: string): string {
  const child = relative(realRoot, real);
  if (child === "") return "";
  if (child === ".." || child.startsWith(`..${sep}`) || /^[A-Za-z]:/.test(child))
    fail("a symbolic link escapes the source root");
  return child.split(sep).join("/");
}

/** Reads a regular file whose identity must not change while it is read. */
function readStable(path: string, expected: Stats, maxFileBytes: number, budget: Budget) {
  if (expected.size > maxFileBytes) fail("file byte bound");
  if (expected.size > SOURCE_OBSERVATION_SEAL_LIMITS_V1.maxTotalBytes - budget.bytes)
    fail("source byte bound");
  budget.bytes += expected.size;
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const before = fstatSync(descriptor);
    if (!before.isFile() || before.nlink !== 1 || !sameIdentity(expected, before))
      fail("file replacement before read");
    const bytes = Buffer.allocUnsafe(before.size);
    let offset = 0;
    while (offset < bytes.byteLength) {
      const count = readSync(descriptor, bytes, offset, bytes.byteLength - offset, offset);
      if (count <= 0) fail("short file read");
      offset += count;
    }
    const after = fstatSync(descriptor);
    if (!sameIdentity(before, after) || !sameIdentity(before, lstatSync(path)))
      fail("file replacement during read");
    return { sha256: hash(bytes), byteLength: bytes.byteLength };
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

/** S2h: a name the source-relative form cannot carry is refused before the seal exists. */
function sortedNames(directory: string, parent: string, remaining: number): string[] {
  return readSourceEntryNamesV1(directory, parent, {
    maximum: remaining,
    onBound: () => fail("source entry bound"),
  }).sort(codeUnitCompare);
}

export type SealSourceObservationInputV1 = Readonly<{
  sourceRoot: string;
  selectedClosurePaths: readonly string[];
  /** A tighter entry bound than the declared one; never a looser one. */
  maxEntries?: number;
}>;

/** Seals a source tree for an observation run; throws a `TypeError` naming the reason. */
export function sealSourceObservationV1(
  input: SealSourceObservationInputV1,
): SourceObservationSealV1 {
  const limits = SOURCE_OBSERVATION_SEAL_LIMITS_V1;
  const maxEntries = input.maxEntries ?? limits.maxEntries;
  if (!Number.isSafeInteger(maxEntries) || maxEntries < 0 || maxEntries > limits.maxEntries)
    fail("entry bound override");
  if (typeof input.sourceRoot !== "string" || input.sourceRoot.length === 0) fail("source root");
  if (!Array.isArray(input.selectedClosurePaths)) fail("selected closure paths");
  const selected = [...input.selectedClosurePaths];
  for (const path of selected) {
    if (typeof path !== "string") fail("selected closure path");
    assertSafeRelativePosixPathV1(path, "selected closure path");
  }
  selected.sort(codeUnitCompare);
  if (new Set(selected).size !== selected.length) fail("selected closure duplicate");

  const root = resolve(input.sourceRoot);
  const rootStat = lstatSync(root);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink())
    fail("the source root is not a real directory");
  const realRoot = realpathSync.native(root);
  const entries: SourceObservationEntryV1[] = [];
  const budget: Budget = { entries: 0, bytes: 0 };

  const visit = (directory: string): void => {
    const before = lstatSync(directory);
    for (const name of sortedNames(
      directory,
      posix(root, directory),
      maxEntries - budget.entries,
    )) {
      const absolute = resolve(directory, name);
      const path = posix(root, absolute);
      assertSafeRelativePosixPathV1(path, "source entry path");
      if (budget.entries >= maxEntries) fail("source entry bound");
      budget.entries += 1;
      const stat = lstatSync(absolute);
      if (stat.isSymbolicLink()) {
        const real = (() => {
          try {
            return realpathSync.native(absolute);
          } catch {
            return fail(`symbolic link ${path} is broken`);
          }
        })();
        const target = contained(realRoot, real);
        const targetStat = statSync(real);
        if (targetStat.isFile()) {
          if (targetStat.nlink !== 1) fail(`file ${target} is a hard link`);
          entries.push({
            kind: "file-link",
            path,
            target,
            ...readStable(real, targetStat, limits.maxFileBytes, budget),
          });
        } else if (targetStat.isDirectory()) entries.push({ kind: "directory-link", path, target });
        else fail(`symbolic link ${path} names neither a file nor a directory`);
        if (!sameIdentity(stat, lstatSync(absolute))) fail("symbolic link replacement");
        continue;
      }
      if (stat.isDirectory()) {
        entries.push({ kind: "directory", path });
        visit(absolute);
        continue;
      }
      if (!stat.isFile()) fail(`${path} is neither a file, a directory nor a symbolic link`);
      if (stat.nlink !== 1) fail(`file ${path} is a hard link`);
      entries.push({
        kind: "file",
        path,
        ...readStable(absolute, stat, limits.maxFileBytes, budget),
      });
    }
    const after = lstatSync(directory);
    if (!after.isDirectory() || after.isSymbolicLink() || !sameIdentity(before, after))
      fail("directory replacement");
  };
  visit(root);
  entries.sort((left, right) => codeUnitCompare(left.path, right.path));

  const byPath = new Map(entries.map((entry) => [entry.path, entry]));
  const selectedFiles: FileLike[] = selected.map((path) => {
    const entry = byPath.get(path);
    if (entry === undefined || (entry.kind !== "file" && entry.kind !== "file-link"))
      fail(`selected closure path ${path} is not a file or a file link in the source tree`);
    return entry as FileLike;
  });
  const sourceTreeSha256 = hash(
    canonicalStrictJsonBytesV1({ protocol: "SourceObservationTreeV1", entries }),
  );
  const selectedClosureSha256 = hash(
    canonicalStrictJsonBytesV1({ protocol: "SourceObservationSelectionV1", files: selectedFiles }),
  );
  return deepFreezeStrictJsonV1({
    protocol: "SourceObservationSealV1" as const,
    algorithm: "code-unit-canonical-json-v1" as const,
    entries,
    selectedClosurePaths: selected,
    sourceTreeSha256,
    selectedClosureSha256,
    sealedSnapshotSha256: hash(
      canonicalStrictJsonBytesV1({
        protocol: "SourceObservationSnapshotV1",
        sourceTreeSha256,
        selectedClosureSha256,
      }),
    ),
  });
}
