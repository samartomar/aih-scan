import { createHash } from "node:crypto";
import type { SourceObservationEntryV1 } from "../observation/source-observation-seal-v1.js";

/**
 * Completion evidence v1 (C2a §1.6 [Scan: S2g]). Core cannot see an analyzer's own output, so
 * every run of a succeeded SARIF log names the subject Scan proved was analyzed:
 * `invocations[0].executionSuccessful: true` and
 * `invocations[0].properties.aihScanCompletionV1 = {detectorId, subjectTreeSha256,
 * analyzedFileCount, analyzer: {version, lockSha256}}`. Scan writes it only after the
 * analyzer's own completion proof, the location rules and the equal re-seal have passed, and
 * never on a failed result.
 *
 * `subjectTreeSha256` (subject-files-v1) is the sha256 over, for the subject files sorted by
 * root-relative POSIX path in UTF-16 code-unit order, `UTF-8(path) 0x00 sha256-hex 0x0A`;
 * `analyzedFileCount` is the number of those files.
 */

export const SCAN_COMPLETION_PROPERTY_V1 = "aihScanCompletionV1";

export interface ScanCompletionEvidenceV1 {
  readonly detectorId: string;
  readonly subjectTreeSha256: string;
  readonly analyzedFileCount: number;
  readonly analyzer: Readonly<{ version: string; lockSha256: string | null }>;
}

export interface SubjectFileV1 {
  readonly path: string;
  readonly sha256: string;
}

/**
 * The engine or analyzer whose subject rule applies: the name `runDetectorV1` dispatches on
 * (`cisco` is the skill-directory analyzer, `cisco-source-tree` the multi-skill engine).
 */
export type ScanCompletionSubjectEngineV1 =
  | "semgrep"
  | "skillspector"
  | "cisco"
  | "snyk-agent-scan"
  | "cisco-source-tree"
  | "cisco-mcp-scanner"
  | "aih-trust-lint"
  | "aih-binding-gate";

const SHA256 = /^[0-9a-f]{64}$/u;

const fail = (detail: string): never => {
  throw new TypeError(`completion evidence: ${detail}`);
};
const codeUnitCompare = (left: string, right: string): number =>
  left < right ? -1 : left > right ? 1 : 0;
const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** subject-files-v1 over a file set; a duplicate or malformed entry is refused. */
export function subjectFilesDigestV1(
  files: readonly SubjectFileV1[],
): Readonly<{ subjectTreeSha256: string; analyzedFileCount: number }> {
  const ordered = [...files].sort((left, right) => codeUnitCompare(left.path, right.path));
  const hash = createHash("sha256");
  for (const [index, file] of ordered.entries()) {
    if (typeof file.path !== "string" || file.path.length === 0 || file.path.includes("\u0000"))
      fail(`subject file path ${JSON.stringify(file.path)} is not a sealed path`);
    if (typeof file.sha256 !== "string" || !SHA256.test(file.sha256))
      fail(`subject file ${file.path} has no lowercase sha256 hex digest`);
    if (index > 0 && ordered[index - 1]?.path === file.path)
      fail(`subject file ${file.path} is listed twice`);
    hash.update(`${file.path}\u0000${file.sha256}\n`, "utf8");
  }
  return Object.freeze({
    subjectTreeSha256: hash.digest("hex"),
    analyzedFileCount: ordered.length,
  });
}

/**
 * The evidence for one detector run or shard job. A zero count is allowed only where the
 * detector completes on an empty source (capability `emptySource: "completes"`).
 */
export function scanCompletionEvidenceV1(input: {
  readonly detectorId: string;
  readonly files: readonly SubjectFileV1[];
  readonly emptyAllowed: boolean;
  readonly analyzer: Readonly<{ version: string; lockSha256: string | null }>;
}): ScanCompletionEvidenceV1 {
  const { version, lockSha256 } = input.analyzer;
  if (typeof version !== "string" || version.length === 0) fail("the analyzer version is empty");
  if (lockSha256 !== null && (typeof lockSha256 !== "string" || !SHA256.test(lockSha256)))
    fail("the analyzer lock digest is not a lowercase sha256 hex digest");
  const digest = subjectFilesDigestV1(input.files);
  if (digest.analyzedFileCount === 0 && !input.emptyAllowed)
    fail(`${input.detectorId} analyzed no file, and it does not complete on an empty source`);
  return Object.freeze({
    detectorId: input.detectorId,
    ...digest,
    analyzer: Object.freeze({ version, lockSha256 }),
  });
}

/** Whether a root-relative path lies in the top-level `.git`, which a snapshot leaves out. */
const inGitDirectory = (path: string) => path === ".git" || path.startsWith(".git/");

/**
 * The files an engine received, from the before-run seal's `file` and `file-link` entries
 * (C2a §1.6 table). Paths come back in code-unit order.
 */
export function scanCompletionSubjectFilesV1(input: {
  readonly engine: ScanCompletionSubjectEngineV1;
  readonly entries: readonly SourceObservationEntryV1[];
  readonly selectedClosurePaths: readonly string[];
  readonly detectorOptions?: unknown;
}): SubjectFileV1[] {
  const sealed = new Map<string, SubjectFileV1>();
  for (const entry of input.entries)
    if (entry.kind === "file" || entry.kind === "file-link")
      sealed.set(entry.path, { path: entry.path, sha256: entry.sha256 });
  const all = [...sealed.values()];
  const named = (paths: readonly string[], label: string, required: boolean) => {
    const files: SubjectFileV1[] = [];
    for (const path of new Set(paths)) {
      const file = sealed.get(path);
      if (file !== undefined) files.push(file);
      else if (required || !input.entries.some((entry) => entry.path === path))
        fail(`${label} ${JSON.stringify(path)} is not a sealed file`);
    }
    return files;
  };
  let files: SubjectFileV1[];
  switch (input.engine) {
    case "semgrep":
    case "skillspector":
      files = all;
      break;
    case "cisco":
    case "snyk-agent-scan":
      files = all.filter((file) => !inGitDirectory(file.path));
      break;
    case "cisco-source-tree": {
      // C2a §3.1: a job is the directory of every selected SKILL.md, the root included.
      const jobs = input.selectedClosurePaths.flatMap((path) =>
        path === "SKILL.md"
          ? [""]
          : path.endsWith("/SKILL.md")
            ? [path.slice(0, -"SKILL.md".length)]
            : [],
      );
      files = all.filter(
        (file) =>
          !inGitDirectory(file.path) && jobs.some((job) => job === "" || file.path.startsWith(job)),
      );
      break;
    }
    case "cisco-mcp-scanner": {
      const options = input.detectorOptions;
      const paths = isRecord(options) ? options.mcpConfigPaths : undefined;
      if (!Array.isArray(paths) || !paths.every((path) => typeof path === "string"))
        fail("mcpConfigPaths is not a list of paths");
      files = named(paths as string[], "MCP config path", false);
      break;
    }
    case "aih-trust-lint":
    case "aih-binding-gate":
      files = named(input.selectedClosurePaths, "selected path", true);
      break;
    default:
      return fail(`no subject rule for ${JSON.stringify(input.engine)}`);
  }
  return files.sort((left, right) => codeUnitCompare(left.path, right.path));
}

/**
 * Writes the evidence into every run of a freshly parsed SARIF log, in place, and returns it.
 * Analyzer SARIF keeps its own invocations and gains the key in `invocations[0].properties`;
 * a Scan-built run without invocations gains one successful invocation. Anything else, and
 * an incoming completion key anywhere (a forgery), throws.
 */
export function attachScanCompletionV1(
  log: unknown,
  evidence: ScanCompletionEvidenceV1,
  options: { readonly scanBuilt: boolean },
): Record<string, unknown> & { runs: Record<string, unknown>[] } {
  if (!isRecord(log) || !Array.isArray(log.runs) || log.runs.length === 0)
    return fail("the SARIF log has no runs to carry it");
  const runs: unknown[] = log.runs;
  // Every run is checked for a forged key before any run is written.
  for (const [index, run] of runs.entries()) {
    if (!isRecord(run)) return fail(`SARIF run ${index} is not an object`);
    const invocations: unknown = run.invocations;
    if (!Array.isArray(invocations)) continue;
    for (const invocation of invocations)
      if (
        isRecord(invocation) &&
        isRecord(invocation.properties) &&
        Object.hasOwn(invocation.properties, SCAN_COMPLETION_PROPERTY_V1)
      )
        return fail(
          `SARIF run ${index} already carries ${SCAN_COMPLETION_PROPERTY_V1}; it is forged`,
        );
  }
  for (const [index, value] of runs.entries()) {
    const run = value as Record<string, unknown>;
    if (run.invocations === undefined && options.scanBuilt) {
      run.invocations = [
        { executionSuccessful: true, properties: { [SCAN_COMPLETION_PROPERTY_V1]: evidence } },
      ];
      continue;
    }
    const invocations: unknown = run.invocations;
    if (!Array.isArray(invocations) || invocations.length === 0)
      return fail(`SARIF run ${index} reports no invocation to carry it`);
    const first: unknown = invocations[0];
    if (!isRecord(first) || first.executionSuccessful !== true)
      return fail(`SARIF run ${index} does not report a successful first invocation`);
    // S2h: only an absent `properties` is created; a present non-object (null included) fails.
    const properties = first.properties === undefined ? {} : first.properties;
    if (!isRecord(properties))
      return fail(`SARIF run ${index} has invocation properties that are not an object`);
    first.properties = { ...properties, [SCAN_COMPLETION_PROPERTY_V1]: evidence };
  }
  return log as Record<string, unknown> & { runs: Record<string, unknown>[] };
}
