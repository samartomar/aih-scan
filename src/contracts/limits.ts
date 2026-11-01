import { formats } from "./formats.js";

const MiB = 1024 * 1024;

/**
 * Published limits (`aih-scan-limits/1`). Input limits refuse the whole request before
 * anything is scanned; the tool limit marks only that tool `not-run` (`timeout`); output
 * limits bound what readers return from untrusted summaries and SARIF.
 *
 * Units: bytes for sizes; path length in Unicode code points of the item-relative POSIX
 * path; depth as the number of folders above a file inside an item or source; milliseconds
 * for time.
 */
export const limits = Object.freeze({
  format: formats.limits,
  input: Object.freeze({
    /** Total bytes of every regular file in one source or one request. */
    sourceBytes: 500 * MiB,
    /** Regular files in one source or one request. */
    files: 50_000,
    /** Bytes of one file. */
    fileBytes: 50 * MiB,
    /** Code points of one relative path. */
    pathLength: 1024,
    /** Folders above one file. */
    depth: 64,
    /** Items in one request or found in one source. */
    items: 20_000,
  }),
  tool: Object.freeze({
    /** One tool on one item; over it the tool is `not-run` with reason `timeout`. */
    timeoutMs: 10 * 60 * 1000,
  }),
  output: Object.freeze({
    /** Code points kept of one finding's text (`readFindings`); longer text is cut. */
    findingText: 500,
    /** Code points of one finding path; longer paths cannot match a scanned file. */
    findingPath: 1024,
    /** Code points kept of a rule id or tool name. */
    ruleId: 256,
    /** Findings read from one SARIF document; more is refused. */
    findingsPerSarif: 100_000,
    /** Bytes of one summary document accepted by `readSummary`. */
    summaryBytes: 128 * MiB,
    /** Bytes of one SARIF document accepted by `readFindings`. */
    sarifBytes: 256 * MiB,
    /** Code points of a tool or summary reason. */
    reason: 500,
    /** Code points of a request label echoed in a scan result. */
    label: 256,
  }),
});

export type Limits = typeof limits;
