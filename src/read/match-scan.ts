import type { Problem } from "../contracts/formats.js";
import { algorithmOfKey, type FileMode, scanKeyOf, sha256Hex } from "../contracts/git-tree.js";
import { limits } from "../contracts/limits.js";
import type { Coverage } from "../contracts/risk.js";
import { isBytes, pathProblem } from "../contracts/text.js";
import { type Summary, validateSummary } from "../contracts/validate.js";

export interface MatchFile {
  readonly path: string;
  readonly mode: FileMode;
  readonly bytes: Uint8Array;
}

/** The signer as established by `verifySummary`; a summary alone has none. */
export interface MatchSigner {
  readonly identity: string;
  readonly trusted: boolean;
}

/** The fields of a `verifySummary` result that matching reads. */
export interface VerifiedSummaryInput {
  readonly status: string;
  readonly summary?: Summary | null;
  readonly signer?: MatchSigner | null;
}

export interface MatchDifferences {
  readonly missing: readonly string[];
  readonly extra: readonly string[];
  readonly changed: readonly string[];
  readonly modeChanged: readonly string[];
}

export type MatchScanResult =
  | Readonly<{
      status: "ok";
      matches: boolean;
      coverage: Coverage;
      signer: MatchSigner | null;
      scanKey: string;
      differences: MatchDifferences;
    }>
  | Problem;

const invalid = (reason: string, detail: string): Problem =>
  Object.freeze({ status: "invalid", reason, detail });
const refused = (reason: string, detail: string): Problem =>
  Object.freeze({ status: "refused", reason, detail });

function resolveSummary(
  input: unknown,
): { summary: Summary; signer: MatchSigner | null } | Problem {
  if (typeof input !== "object" || input === null)
    return invalid("summary", "expected a summary or a verifySummary result");
  const value = input as Record<string, unknown>;
  if (Object.hasOwn(value, "format")) {
    const checked = validateSummary(value);
    return checked.status === "ok" ? { summary: checked.summary, signer: null } : checked;
  }
  if (Object.hasOwn(value, "status") && Object.hasOwn(value, "summary")) {
    if (value.status !== "ok" || value.summary === null || value.summary === undefined)
      return refused("not-verified", "the verifySummary result did not verify");
    const checked = validateSummary(value.summary);
    if (checked.status !== "ok") return checked;
    const signer = value.signer as MatchSigner | null | undefined;
    const ok =
      signer === null ||
      signer === undefined ||
      (typeof signer === "object" &&
        typeof signer.identity === "string" &&
        typeof signer.trusted === "boolean");
    if (!ok) return invalid("signer", "the verifySummary result has a malformed signer");
    return {
      summary: checked.summary,
      signer:
        signer === null || signer === undefined
          ? null
          : Object.freeze({ identity: signer.identity, trusted: signer.trusted }),
    };
  }
  return invalid("summary", "expected a summary or a verifySummary result");
}

function checkFiles(files: unknown): MatchFile[] | Problem {
  if (!Array.isArray(files))
    return invalid("files", "files must be an array of { path, mode, bytes }");
  if (files.length > limits.input.files)
    return refused("files", `more than ${limits.input.files} files`);
  const seen = new Set<string>();
  let total = 0;
  const out: MatchFile[] = [];
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

/**
 * Matches a summary (or a `verifySummary` result) to exact content in one call: the supplied
 * inventory must reproduce the scan key AND every file's sha256 and mode. A summary alone gives
 * `signer: null`. When the recomputed key equals the summary's key but a listed sha256 or mode
 * differs, the summary is refused as `collision-or-tampering`. Resolves asynchronously (WebCrypto).
 */
export async function matchScan(
  summaryOrVerified: Summary | VerifiedSummaryInput,
  files: readonly MatchFile[],
): Promise<MatchScanResult> {
  const resolved = resolveSummary(summaryOrVerified);
  if ("status" in resolved) return resolved;
  const checked = checkFiles(files);
  if (!Array.isArray(checked)) return checked;
  const { summary, signer } = resolved;
  const algorithm = algorithmOfKey(summary.scanKey);
  if (algorithm === undefined) return invalid("scanKey", "unsupported scan key algorithm");
  const scanKey = await scanKeyOf(checked, algorithm);
  const listed = new Map(summary.files.map((file) => [file.path, file]));
  const supplied = new Set(checked.map((file) => file.path));
  const missing = summary.files.map((file) => file.path).filter((path) => !supplied.has(path));
  const extra: string[] = [];
  const changed: string[] = [];
  const modeChanged: string[] = [];
  for (const file of checked) {
    const expected = listed.get(file.path);
    if (expected === undefined) {
      extra.push(file.path);
      continue;
    }
    if ((await sha256Hex(file.bytes)) !== expected.sha256) changed.push(file.path);
    if (file.mode !== expected.mode) modeChanged.push(file.path);
  }
  const sort = (list: string[]) => Object.freeze(list.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)));
  const differences = Object.freeze({
    missing: sort(missing),
    extra: sort(extra),
    changed: sort(changed),
    modeChanged: sort(modeChanged),
  });
  const differs = missing.length + extra.length + changed.length + modeChanged.length > 0;
  if (scanKey === summary.scanKey && differs)
    return refused(
      "collision-or-tampering",
      "the content reproduces the scan key but not the summary's file list; the summary or content was tampered with",
    );
  return Object.freeze({
    status: "ok" as const,
    matches: scanKey === summary.scanKey && !differs,
    coverage: summary.coverage,
    signer,
    scanKey,
    differences,
  });
}
