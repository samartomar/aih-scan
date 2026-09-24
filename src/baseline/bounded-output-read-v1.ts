import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  type Stats,
} from "node:fs";

/**
 * U1j: the one bounded read for a JSON or SARIF report an analyzer wrote to a file (Cisco
 * source-tree and shard jobs, the OCI capture, the host and namespace `scan-all` runs, the
 * linux-amd64 probe). Nothing on those paths reads analyzer output with an unbounded
 * `readFileSync`.
 */

/** The one analyzer-output cap: every analyzer report file Scan reads is at most 16 MiB. */
export const ANALYZER_OUTPUT_MAX_BYTES_V1 = 16 * 1024 * 1024;

/** How every refusal of {@link readBoundedAnalyzerOutputV1} starts; the runner types it `output`. */
export const ANALYZER_OUTPUT_READ_PREFIX_V1 = "aih-scan analyzer output: ";

/** Why a report file was refused. */
export type AnalyzerOutputReadReasonV1 = "missing" | "shape" | "size" | "changed";

/** A refused analyzer report file; its message starts with {@link ANALYZER_OUTPUT_READ_PREFIX_V1}. */
export class AnalyzerOutputReadErrorV1 extends TypeError {
  readonly reason: AnalyzerOutputReadReasonV1;
  constructor(reason: AnalyzerOutputReadReasonV1, message: string) {
    super(`${ANALYZER_OUTPUT_READ_PREFIX_V1}${message}`);
    this.name = "AnalyzerOutputReadErrorV1";
    this.reason = reason;
  }
}

function sameFile(left: Stats, right: Stats): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}

/**
 * Reads one analyzer report file: a regular file with one link, not a symbolic link, of 1 to
 * `maximum` bytes (default {@link ANALYZER_OUTPUT_MAX_BYTES_V1}). It is opened without
 * following links and without blocking, must still be the file that was checked, and is read
 * into a buffer one byte larger than its size, so a file that grows, shrinks or is replaced
 * while it is read is refused and never read past the cap. `label` names the file in every
 * refusal ({@link AnalyzerOutputReadErrorV1}).
 */
export function readBoundedAnalyzerOutputV1(
  path: string,
  label: string,
  maximum: number = ANALYZER_OUTPUT_MAX_BYTES_V1,
): Buffer {
  let before: Stats;
  try {
    before = lstatSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT")
      throw new AnalyzerOutputReadErrorV1("missing", `${label} is missing`);
    throw new AnalyzerOutputReadErrorV1("shape", `${label} cannot be inspected`);
  }
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1)
    throw new AnalyzerOutputReadErrorV1("shape", `${label} is not one regular file`);
  if (before.size === 0) throw new AnalyzerOutputReadErrorV1("size", `${label} is empty`);
  if (before.size > maximum)
    throw new AnalyzerOutputReadErrorV1("size", `${label} exceeds ${maximum} bytes`);
  const changed = () =>
    new AnalyzerOutputReadErrorV1("changed", `${label} changed while it was read`);
  let descriptor: number | undefined;
  try {
    try {
      descriptor = openSync(
        path,
        constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0),
      );
    } catch {
      throw changed();
    }
    const opened = fstatSync(descriptor);
    if (!opened.isFile() || opened.nlink !== 1 || !sameFile(before, opened)) throw changed();
    const buffer = Buffer.allocUnsafe(before.size + 1);
    let total = 0;
    while (total < buffer.length) {
      const read = readSync(descriptor, buffer, total, buffer.length - total, null);
      if (read === 0) break;
      total += read;
    }
    if (total !== before.size) throw changed();
    const after = fstatSync(descriptor);
    let afterPath: Stats;
    try {
      afterPath = lstatSync(path);
    } catch {
      throw changed();
    }
    if (after.nlink !== 1 || !sameFile(before, after) || !sameFile(before, afterPath))
      throw changed();
    return buffer.subarray(0, total);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}
