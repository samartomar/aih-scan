/**
 * `@aihq/scan/contracts` — portable published contract data and validators: formats,
 * schemas, routing (`aih-scan-routing/1`), scoring (`aih-risk/1`), codes (`aih-codes/1`)
 * and limits. Importing it performs no host operations.
 */
export {
  type AdvisoryCode,
  advisoryCodes,
  type Code,
  codeForRule,
  codes,
  isScanCode,
  type ScanCode,
  scanCodes,
  toolRuleCodes,
} from "../contracts/codes.js";
export { formats, type Problem, type ResultStatus } from "../contracts/formats.js";
export {
  algorithmOfKey,
  type FileMode as TreeFileMode,
  type GitAlgorithm,
  keyFolderName,
  SCAN_KEY_PATTERN,
  scanKeyOf,
  sha256Hex,
  type TreeFile,
} from "../contracts/git-tree.js";
export { type Limits, limits } from "../contracts/limits.js";
export {
  type CountedFinding,
  type Coverage,
  displayLabel,
  type FindingPart,
  failAtReached,
  type RiskLabel,
  riskLabelForScore,
  type SarifLevel,
  type ScoredFinding,
  type Severity,
  type SummaryLabel,
  scoreFindings,
  scoring,
  severityOf,
  storedLabel,
} from "../contracts/risk.js";
export {
  type Dependency,
  type InlineCommand,
  type Kind,
  kinds,
  optionalTools,
  type Part,
  type RoutedFile,
  routeFile,
  routing,
  type ToolId,
  toolsForPart,
} from "../contracts/routing.js";
export { schemas } from "../contracts/schemas.js";
export { pathProblem, sanitizeText } from "../contracts/text.js";
export {
  type FileMode,
  type Origin,
  type RequestItem,
  type ScanMode,
  type ScanRequest,
  type SourceDescriptor,
  type Summary,
  type SummaryDependency,
  type SummaryFile,
  type SummaryTool,
  type ToolResult,
  validateRequest,
  validateSource,
  validateSummary,
  validateWithdrawn,
  type Withdrawal,
} from "../contracts/validate.js";
export { packageIdentity } from "./package-identity.js";
