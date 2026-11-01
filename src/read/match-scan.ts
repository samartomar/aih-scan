import type { Problem } from "../contracts/formats.js";
import {
  algorithmOfKey,
  checkTreeFiles,
  type FileMode,
  type GitAlgorithm,
  sha256Hex,
  treeKeyOf,
} from "../contracts/git-tree.js";
import type { Coverage } from "../contracts/risk.js";
import { type Summary, validateSummary } from "../contracts/validate.js";
import { isVerifySummaryResult } from "./verify-summary.js";

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
    // The signer counts only on an object verifySummary itself returned; anything else is a
    // summary without a signer.
    const signer = isVerifySummaryResult(value)
      ? (value.signer as MatchSigner | null | undefined)
      : null;
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

/**
 * Matches a summary (or a `verifySummary` result) to exact content in one call: the supplied
 * inventory must reproduce the scan key AND every file's sha256 and mode. A summary alone gives
 * `signer: null`; so does any object other than the exact `verifySummary` result (signers
 * cannot be supplied by hand). When the recomputed key equals the summary's key but a listed sha256 or mode
 * differs, the summary is refused as `collision-or-tampering`. Resolves asynchronously (WebCrypto).
 */
export async function matchScan(
  summaryOrVerified: Summary | VerifiedSummaryInput,
  files: readonly MatchFile[],
): Promise<MatchScanResult> {
  const resolved = resolveSummary(summaryOrVerified);
  if ("status" in resolved) return resolved;
  const checked = checkTreeFiles(files);
  if (!Array.isArray(checked)) return checked;
  const { summary, signer } = resolved;
  const algorithm = algorithmOfKey(summary.scanKey);
  if (algorithm === undefined) return invalid("scanKey", "unsupported scan key algorithm");
  try {
    return await compare(summary, signer, checked, algorithm);
  } catch {
    return refused("crypto-unavailable", "WebCrypto is unavailable");
  }
}

async function compare(
  summary: Summary,
  signer: MatchSigner | null,
  checked: readonly MatchFile[],
  algorithm: GitAlgorithm,
): Promise<MatchScanResult> {
  const scanKey = await treeKeyOf(checked, algorithm);
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
