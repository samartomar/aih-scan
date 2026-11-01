/**
 * `@aihq/scan/host` — Node host operations: `scan` reads supplied folders into Scan-owned
 * read-only snapshots and writes summaries and SARIF into a new output folder; `matchScan`
 * matches a summary to a folder on disk. Supplied content is never executed.
 */
export { matchScan } from "../host/match-folder.js";
export {
  type ScanItemResult,
  type ScanOptions,
  type ScanResult,
  type SourcePin,
  scan,
} from "../host/scan.js";
