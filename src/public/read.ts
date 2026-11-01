/**
 * `@aihq/scan/read` — portable readers (browser-safe: no Node globals or built-ins).
 * `readSummary` is synchronous; `readFindings`, `matchScan` and `verifySummary` resolve
 * asynchronously because they use WebCrypto. `checkAdvisories` asks a live advisory service
 * (OSV) through `fetch`; it is separate from every scan and never signed.
 */
export {
  type Advisory,
  type AdvisoryDependency,
  type AdvisoryFetch,
  type AdvisoryResult,
  type CheckAdvisoriesOptions,
  type CheckAdvisoriesResult,
  checkAdvisories,
  type NotCheckedReason,
} from "../read/check-advisories.js";
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
export {
  type JsonInput,
  type VerifiedSignerInfo,
  type VerifySummaryOptions,
  type VerifySummaryResult,
  verifySummary,
  type WithdrawalOutcome,
} from "../read/verify-summary.js";
