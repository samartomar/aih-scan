import type { Summary } from "../contracts/validate.js";
import {
  type MatchScanResult,
  matchScan as matchFiles,
  type VerifiedSummaryInput,
} from "../read/match-scan.js";
import { readFolder } from "./snapshot.js";

/**
 * Host matching: reads `folderPath` by the scan identity rules (links, hard links, special files
 * and invalid names are refused; `.git` is omitted; disk executable bits, else `executable`)
 * and matches it exactly like the portable `matchScan` over the same path/mode/bytes records.
 */
export async function matchScan(
  summaryOrVerified: Summary | VerifiedSummaryInput,
  folderPath: string,
  options: Readonly<{ executable?: readonly string[] }> = {},
): Promise<MatchScanResult> {
  if (typeof folderPath !== "string" || folderPath.length === 0)
    return Object.freeze({
      status: "invalid" as const,
      reason: "folder",
      detail: "folderPath must be a folder path",
    });
  const read = readFolder(
    folderPath,
    options.executable === undefined ? {} : { executable: options.executable },
  );
  if (read.status !== "ok")
    return Object.freeze({ status: read.status, reason: read.reason, detail: read.detail });
  return matchFiles(summaryOrVerified, read.files);
}
