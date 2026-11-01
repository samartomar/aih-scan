/**
 * `@aihq/scan/host` — Node host operations: `scan` reads supplied folders or acquires a source
 * (folder, public Git repository or item, npm package or tarball, remote MCP configuration),
 * discovers its items, snapshots each read-only and writes summaries and SARIF into a new output
 * folder; `matchScan` matches a summary to a folder on disk. Supplied content is never executed.
 */
export { matchScan } from "../host/match-folder.js";
export {
  type Acquisition,
  type ResultKind,
  type Rollup,
  type ScanItemResult,
  type ScanOptions,
  type ScanResult,
  type SourcePin,
  scan,
} from "../host/scan.js";
