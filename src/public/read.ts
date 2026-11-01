/**
 * `@aihq/scan/read` — portable readers (browser-safe: no Node globals or built-ins).
 * `readSummary` is synchronous; `readFindings` and `matchScan` resolve asynchronously
 * because they hash with WebCrypto.
 */
export {
  type MatchDifferences,
  type MatchFile,
  type MatchScanResult,
  type MatchSigner,
  matchScan,
  type VerifiedSummaryInput,
} from "../read/match-scan.js";
export {
  FINDINGS_MISMATCH_MESSAGE,
  type Finding,
  type ReadFindingsResult,
  readFindings,
} from "../read/read-findings.js";
export { type ReadSummaryResult, readSummary } from "../read/read-summary.js";
