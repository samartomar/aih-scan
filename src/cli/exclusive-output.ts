import {
  closeSync,
  fstatSync,
  lstatSync,
  openSync,
  realpathSync,
  type Stats,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";

/**
 * An exclusive file writer for CLI outputs: it creates a new file, never replaces one,
 * and fails closed when a parent directory is a link or reparse point or when the file
 * or a parent changes while the file is written. `project-core-evidence` and
 * `scan --artifact` both write through it.
 */

/** Why an exclusive write was refused. `message` is the bare reason; callers add context. */
export type ExclusiveOutputProblem = "bounds" | "exists" | "linked-parent" | "replaced";

export class ExclusiveOutputError extends Error {
  readonly problem: ExclusiveOutputProblem;
  constructor(problem: ExclusiveOutputProblem, message: string) {
    super(message);
    this.problem = problem;
  }
}

export interface ExclusiveOutputPolicy {
  /** Names the output in refusals, as in `${label} already exists`. */
  readonly label: string;
  /** Largest accepted size in bytes (inclusive); an empty output is refused too. */
  readonly maximumBytes: number;
}

type DirectorySnapshot = Readonly<{ path: string; realPath: string; stat: Stats }>;

function sameFileReference(left: Stats, right: Stats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function sameIdentity(left: Stats, right: Stats): boolean {
  return (
    sameFileReference(left, right) &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}

/**
 * Every ancestor of an output path must be a real directory: no link or reparse point.
 * A parent that cannot be inspected, such as a missing one, raises the file system error.
 */
export function safeOutputParents(path: string): readonly DirectorySnapshot[] {
  const parents: DirectorySnapshot[] = [];
  for (let current = dirname(path); ; current = dirname(current)) {
    const stat = lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink())
      throw new ExclusiveOutputError("linked-parent", "output parent link or reparse");
    parents.push({ path: current, realPath: realpathSync.native(current), stat });
    const next = dirname(current);
    if (next === current) return parents;
  }
}

function sameParents(
  left: readonly DirectorySnapshot[],
  right: readonly DirectorySnapshot[],
): boolean {
  return (
    left.length === right.length &&
    left.every(
      (entry, index) =>
        entry.path === right[index]?.path &&
        entry.realPath === right[index]?.realPath &&
        sameFileReference(entry.stat, right[index]?.stat ?? entry.stat),
    )
  );
}

/**
 * Must-not-exist is the only acceptable pre-write output state. A path that cannot be
 * inspected for a reason other than being absent raises the file system error.
 */
export function assertOutputAbsent(path: string, label: string): void {
  try {
    lstatSync(path);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return;
    throw error;
  }
  throw new ExclusiveOutputError("exists", `${label} already exists`);
}

/** Creates `path` exclusively with `bytes`, refusing as {@link ExclusiveOutputError} describes. */
export function writeNewSafeOutput(
  path: string,
  bytes: Uint8Array,
  policy: ExclusiveOutputPolicy,
): void {
  const output = resolve(path);
  if (!bytes.byteLength || bytes.byteLength > policy.maximumBytes)
    throw new ExclusiveOutputError("bounds", `${policy.label} bounds`);
  assertOutputAbsent(output, policy.label);
  const beforeParents = safeOutputParents(output);
  const descriptor = openSync(output, "wx", 0o600);
  try {
    const before = fstatSync(descriptor);
    const outputStat = lstatSync(output);
    if (
      !before.isFile() ||
      before.nlink !== 1 ||
      !outputStat.isFile() ||
      outputStat.isSymbolicLink() ||
      outputStat.nlink !== 1 ||
      !sameIdentity(before, outputStat)
    )
      throw new ExclusiveOutputError("replaced", `${policy.label} replacement`);
    writeFileSync(descriptor, bytes);
    const after = fstatSync(descriptor);
    const afterOutput = lstatSync(output);
    if (
      after.nlink !== 1 ||
      !sameFileReference(before, after) ||
      !sameFileReference(after, afterOutput) ||
      !sameParents(beforeParents, safeOutputParents(output))
    )
      throw new ExclusiveOutputError("replaced", `${policy.label} replacement`);
  } finally {
    closeSync(descriptor);
  }
}
