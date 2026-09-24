import { realpathSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { deepFreezeStrictJsonV1, parseStrictJsonObjectV1 } from "../../contract/strict-json-v1.js";

/**
 * The `snyk-agent-scan` detector engine (detector id `detector.snyk-agent-scan`), ported
 * from Core's `src/trust/detectors.ts` with identical planning and parsing behaviour:
 *
 * - planning: one pinned `uv run` argv (`--locked --isolated --offline
 *   --no-python-downloads --no-env-file`) against the bundled uv lock project, with the
 *   scan flags `scan <tree> --json --no-bootstrap --suppress-mcpserver-io=true` and never
 *   `--dangerously-run-mcp-servers`;
 * - environment: the caller environment is reduced to a fixed allow-list with every
 *   secret-looking key removed; `SNYK_TOKEN` (trimmed) is added only to the scan call,
 *   never to the help probe, and never to any other argv, env, log or diagnostic;
 * - parsing: the scanner's JSON is accepted in Core's report shapes (top-level finding
 *   array, `{findings|issues|results|vulnerabilities: [...]}`, and a scan-path map whose
 *   issues recover their artifact path from the server `reference` index) and converted
 *   to SARIF 2.1.0 with the line defaulting to 1. Unlike Core it fails closed (S2e, the
 *   owner principle): zero findings completes only when a scan-path entry proves the root
 *   was analyzed; an empty object or empty finding array, any failure ScanError at report,
 *   entry or server level, an agent-scan X-code issue, and any malformed entry or finding
 *   fail at stage `output`. The pinned 0.6.x analyzer prints a ScanResponse
 *   (`{scan_path_responses: [...]}`) instead; it is held to the same rules (every response
 *   names the root by an existing path, no failure ScanError anywhere, every record and
 *   risk validated) and every present risk becomes one result. The 0.5.17 shapes stay
 *   because the recorded parity outputs replayed against Core use them;
 * - classification (C2a §5.3): a spawn failure or an exit code outside `{0, 1}` is a
 *   failure at stage `execution`; empty stdout, unparseable stdout, a missing findings
 *   array and an exit 1 without findings are failures at stage `output`; exit 1 with
 *   findings completes, exactly as Core's `runSnykAgentScan` decides. A failure detail
 *   is fixed engine text plus the exit status and output byte counts: the analyzer's
 *   stdout and stderr never reach a diagnostic, and every SARIF field whose decoded
 *   comparison form carries the token is replaced whole.
 *
 * C2a §5.1 environment seam: the request-scoped entry points
 * ({@link planSnykAgentScanRequestV1}, {@link runSnykAgentScanRequestV1},
 * {@link probeSnykAgentScanAvailabilityV1}) accept a caller `env` carrying only
 * `SNYK_TOKEN` — any other key is a typed refusal (`detector-options-invalid`) — and a
 * missing or blank token is a typed refusal (`prerequisite-missing`) naming the
 * variable, before anything spawns. The validated, trimmed token reaches only the scan
 * invocation's environment; never the help probe, acquisition, logs or diagnostics.
 *
 * The engine spawns nothing itself; every process runs through the injected
 * `SnykAgentScanRunnerV1` seam the runtime supplies. Grading, posture, policy and
 * evidence acceptance stay in Core and are deliberately not here.
 */

export const SNYK_AGENT_SCAN_VERSION = "0.6.4";
export const SNYK_AGENT_SCAN_ANALYZER = `snyk-agent-scan@uv:${SNYK_AGENT_SCAN_VERSION}`;
export const SNYK_AGENT_SCAN_UV_PYTHON = "3.12";
export const SNYK_AGENT_SCAN_SCAN_TIMEOUT_MS = 120_000;
export const SNYK_AGENT_SCAN_HELP_TIMEOUT_MS = 120_000;

const moduleDirectory = dirname(fileURLToPath(import.meta.url));
/** The bundled exact-pinned uv project; the same relative location in `src` and `dist`. */
export const SNYK_AGENT_SCAN_PROJECT = resolve(
  moduleDirectory,
  "..",
  "..",
  "..",
  "tools",
  "baseline-analyzers",
  "snyk-agent-scan",
);

const MAX_OUTPUT_BYTES = 16 * 1024 * 1024;
const MAX_FINDINGS = 4096;

export type SnykAgentScanPlatformV1 = "windows" | "darwin" | "linux";

export interface SnykAgentScanProcessResultV1 {
  readonly stdout: string;
  readonly stderr: string;
  readonly code: number | null;
  readonly spawnError?: boolean;
}

/** The runtime-supplied process seam; the engine never spawns directly. */
export type SnykAgentScanRunnerV1 = (
  argv: readonly string[],
  options: Readonly<{ env: NodeJS.ProcessEnv; timeoutMs: number }>,
) => Promise<SnykAgentScanProcessResultV1>;

export interface SnykAgentScanPlanV1 {
  readonly argv: readonly string[];
  readonly env: NodeJS.ProcessEnv;
  readonly timeoutMs: number;
}

export interface SnykAgentScanSarifResultV1 {
  readonly ruleId: string;
  readonly message: Readonly<{ text: string }>;
  readonly locations: readonly [
    Readonly<{
      physicalLocation: Readonly<{
        artifactLocation: Readonly<{ uri: string }>;
        region: Readonly<{ startLine: number }>;
      }>;
    }>,
  ];
}

export interface SnykAgentScanSarifV1 {
  readonly version: "2.1.0";
  readonly runs: readonly [Readonly<{ results: readonly SnykAgentScanSarifResultV1[] }>];
}

/** C2a §5.3 failure stages: `execution` for spawn/exit shortfalls, `output` for stdout ones. */
export type SnykAgentScanFailureStageV1 = "execution" | "output";

export type SnykAgentScanRunOutcomeV1 = Readonly<
  | { kind: "completed"; sarif: SnykAgentScanSarifV1; sarifText: string }
  | { kind: "failed"; stage: SnykAgentScanFailureStageV1; detail: string }
>;

// The environment allow-list and secret-key rule are Core's `scrubFetchEnv`, verbatim:
// only named, non-secret variables reach the analyzer process.
const SAFE_ENV_KEYS = new Set([
  "ALLUSERSPROFILE",
  "APPDATA",
  "COMSPEC",
  "HOME",
  "HOMEDRIVE",
  "HOMEPATH",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "LANG",
  "LOCALAPPDATA",
  "NO_PROXY",
  "NODE_EXTRA_CA_CERTS",
  "PATH",
  "PATHEXT",
  "PROGRAMDATA",
  "PROGRAMFILES",
  "PROGRAMFILES(X86)",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE",
  "SYSTEMDRIVE",
  "SYSTEMROOT",
  "TEMP",
  "TMP",
  "TMPDIR",
  "USERPROFILE",
  "UV_CACHE_DIR",
  "WINDIR",
  "XDG_DATA_HOME",
  "XDG_CACHE_HOME",
]);

function isSecretEnvKey(key: string): boolean {
  const upper = key.toUpperCase();
  return (
    upper.includes("TOKEN") ||
    upper.includes("SECRET") ||
    upper.includes("PASSWORD") ||
    upper.endsWith("_KEY") ||
    upper.endsWith("_CREDENTIALS") ||
    upper.startsWith("AWS_") ||
    upper.startsWith("GITHUB_") ||
    upper.startsWith("ANTHROPIC_") ||
    upper.startsWith("OPENAI_")
  );
}

function scrubEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined || isSecretEnvKey(key)) continue;
    if (SAFE_ENV_KEYS.has(key.toUpperCase())) out[key] = value;
  }
  return out;
}

function snykToken(env: NodeJS.ProcessEnv): string | undefined {
  const raw = env.SNYK_TOKEN;
  if (typeof raw !== "string") return undefined;
  const trimmed = raw.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

/** The scrubbed scan environment: allow-listed, plus `SNYK_TOKEN` only for this call. */
export function snykAgentScanEnvV1(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const out = scrubEnv(env);
  const token = snykToken(env);
  if (token !== undefined) out.SNYK_TOKEN = token;
  return Object.freeze(out);
}

function execArgv(platform: SnykAgentScanPlatformV1, argv: readonly string[]): string[] {
  // Core routes npm-style `.cmd` shims through `cmd /c` on Windows; `uv` is a real
  // executable on every platform, so Core returns this argv unchanged everywhere.
  void platform;
  return [...argv];
}

function baseArgv(platform: SnykAgentScanPlatformV1): string[] {
  return execArgv(platform, [
    "uv",
    "run",
    "--project",
    SNYK_AGENT_SCAN_PROJECT,
    "--locked",
    "--isolated",
    "--python",
    SNYK_AGENT_SCAN_UV_PYTHON,
    "--offline",
    "--no-python-downloads",
    "--no-env-file",
    "snyk-agent-scan",
  ]);
}

/** The availability probe: `snyk-agent-scan help` with the scrubbed, token-free env. */
export function planSnykAgentScanHelpV1(input: {
  readonly platform: SnykAgentScanPlatformV1;
  readonly env: NodeJS.ProcessEnv;
}): SnykAgentScanPlanV1 {
  return Object.freeze({
    argv: Object.freeze([...baseArgv(input.platform), "help"]),
    env: Object.freeze(scrubEnv(input.env)),
    timeoutMs: SNYK_AGENT_SCAN_HELP_TIMEOUT_MS,
  });
}

/** The scan plan: pinned argv plus the scrubbed env with `SNYK_TOKEN` forwarded. */
export function planSnykAgentScanV1(input: {
  readonly platform: SnykAgentScanPlatformV1;
  readonly tree: string;
  readonly env: NodeJS.ProcessEnv;
}): SnykAgentScanPlanV1 {
  if (typeof input.tree !== "string" || input.tree.length === 0)
    throw new TypeError("snyk-agent-scan plan requires a non-empty tree path");
  return Object.freeze({
    argv: Object.freeze([
      ...baseArgv(input.platform),
      "scan",
      input.tree,
      "--json",
      "--no-bootstrap",
      "--suppress-mcpserver-io=true",
    ]),
    env: snykAgentScanEnvV1(input.env),
    timeoutMs: SNYK_AGENT_SCAN_SCAN_TIMEOUT_MS,
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function firstString(record: object, keys: readonly string[]): string | undefined {
  for (const key of keys) {
    const value = (record as Record<string, unknown>)[key];
    if (typeof value === "string" && value.trim().length > 0) return value;
  }
  return undefined;
}

function toPosix(path: string): string {
  return path.replace(/\\/g, "/");
}

function realpathIfExists(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return path;
  }
}

function isSafeRelativeSarifUri(uri: string): boolean {
  if (uri.length === 0 || isAbsolute(uri) || /^[A-Za-z]:/.test(uri)) return false;
  return !uri.split("/").some((part) => part === "..");
}

function snykIssueReference(issue: Record<string, unknown>): number | undefined {
  const reference = issue.reference;
  if (!Array.isArray(reference)) return undefined;
  const serverIndex = reference[0];
  return typeof serverIndex === "number" && Number.isInteger(serverIndex) && serverIndex >= 0
    ? serverIndex
    : undefined;
}

function snykServerUri(server: Record<string, unknown>): string | undefined {
  const configPath = firstString(server, ["config_path", "configPath", "path"]);
  if (configPath !== undefined) return configPath;
  if (isRecord(server.server)) {
    return firstString(server.server, ["path", "config_path", "configPath"]);
  }
  return undefined;
}

function snykScanPathIssueUri(
  scanPath: string,
  pathResult: Record<string, unknown>,
  issue: Record<string, unknown>,
): string {
  const direct = firstString(issue, ["file", "path"]);
  if (direct !== undefined) return direct;
  const reference = snykIssueReference(issue);
  if (reference !== undefined && Array.isArray(pathResult.servers)) {
    const server = pathResult.servers[reference];
    if (isRecord(server)) {
      const serverUri = snykServerUri(server);
      if (serverUri !== undefined) return serverUri;
    }
  }
  return firstString(pathResult, ["path"]) ?? scanPath;
}

const ANALYZER_ERROR = "snyk-agent-scan JSON reported an analyzer error";
const NO_ANALYSIS = "snyk-agent-scan JSON shows no analysis of the scanned root";
const MALFORMED_FINDING = "snyk-agent-scan JSON carries a malformed finding";
const MALFORMED_ENTRY = "snyk-agent-scan JSON carries a malformed scan-path entry";
const NO_FINDINGS_ARRAY = "snyk-agent-scan JSON did not include a findings array";

/** agent-scan's own failure codes (`FAILURE_CATEGORY_TO_CODE`), never an analysis finding. */
const FAILURE_CODE = /^X\d{3}$/;

/**
 * A ScanError-style `error` value: absent or null is no error, an object whose `is_failure`
 * is exactly `false` is agent-scan's non-failure note (a missing candidate config), and
 * anything else — a failure ScanError, a bare string, an object without the flag — is an
 * analyzer error.
 */
function errorKind(value: unknown): "none" | "note" | "failure" {
  if (value === undefined || value === null) return "none";
  return isRecord(value) && value.is_failure === false ? "note" : "failure";
}

/** An object carrying an analyzer error or failure marker of its own. */
function carriesFailure(record: Record<string, unknown>): boolean {
  if (errorKind(record.error) === "failure") return true;
  if (record.errors !== undefined && record.errors !== null) {
    if (!Array.isArray(record.errors) || record.errors.length > 0) return true;
  }
  if (record.is_failure !== undefined && record.is_failure !== false) return true;
  return record.isFailure !== undefined && record.isFailure !== false;
}

/** A path inside the tree, or the tree itself; relative or scheme-less text never counts. */
function namesTreePath(raw: unknown, tree: string): boolean {
  if (typeof raw !== "string") return false;
  const stripped = raw.replace(/^file:\/\//, "");
  if (!isAbsolute(stripped)) return false;
  const rel = relative(realpathIfExists(tree), realpathIfExists(stripped));
  return rel === "" || (!isAbsolute(rel) && !toPosix(rel).split("/").includes(".."));
}

function serverNamesTree(server: Record<string, unknown>, tree: string): boolean {
  const nested = isRecord(server.server) ? server.server : {};
  return [
    server.config_path,
    server.configPath,
    server.path,
    nested.path,
    nested.config_path,
    nested.configPath,
  ].some((value) => namesTreePath(value, tree));
}

/**
 * A generic finding (top-level array or finding-key report): an object carrying no error or
 * failure marker and no agent-scan failure code. The rule id, message, URI and line keep
 * C2a §5.3's documented defaults.
 */
function validatedFinding(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) throw new TypeError(MALFORMED_FINDING);
  if (carriesFailure(value) || FAILURE_CODE.test(snykFindingRuleId(value)))
    throw new TypeError(ANALYZER_ERROR);
  return value;
}

/**
 * The findings of a `{<scanPath>: ScanPathResult}` report (snyk-agent-scan 0.5.17's
 * `--json` output, keyed by `ScanPathResult.path`). Every entry, server and issue is
 * validated, never skipped: a failure ScanError anywhere or an X-code issue is an analyzer
 * error; `servers: null`, or a non-failure ScanError with nothing discovered, means that
 * entry was not analyzed. The scanned root must be named by an entry key or a server path
 * (a root holding SKILL.md is reported under its parent, with the root as the skill's
 * path), or nothing proves the root was analyzed.
 */
function scanPathFindings(
  report: Record<string, unknown>,
  tree: string,
): Record<string, unknown>[] {
  const findings: Record<string, unknown>[] = [];
  let namesRoot = false;
  for (const [scanPath, entry] of Object.entries(report)) {
    if (!isRecord(entry) || !Array.isArray(entry.issues)) throw new TypeError(MALFORMED_ENTRY);
    const error = errorKind(entry.error);
    if (error === "failure" || carriesFailure(entry)) throw new TypeError(ANALYZER_ERROR);
    if (!Array.isArray(entry.servers)) throw new TypeError(NO_ANALYSIS);
    if (error === "note" && entry.servers.length === 0) throw new TypeError(NO_ANALYSIS);
    if (namesTreePath(scanPath, tree)) namesRoot = true;
    for (const server of entry.servers) {
      if (!isRecord(server)) throw new TypeError(MALFORMED_ENTRY);
      if (carriesFailure(server)) throw new TypeError(ANALYZER_ERROR);
      if (serverNamesTree(server, tree)) namesRoot = true;
    }
    for (const issue of entry.issues) {
      if (!isRecord(issue)) throw new TypeError(MALFORMED_FINDING);
      const code = issue.code;
      if (typeof code !== "string" || code.trim().length === 0 || typeof issue.message !== "string")
        throw new TypeError(MALFORMED_FINDING);
      if (FAILURE_CODE.test(code.trim()) || carriesFailure(issue))
        throw new TypeError(ANALYZER_ERROR);
      findings.push({ ...issue, path: snykScanPathIssueUri(scanPath, entry, issue) });
    }
  }
  if (!namesRoot) throw new TypeError(NO_ANALYSIS);
  return findings;
}

/**
 * The report shapes of C2a §5.3, validated whole. A finding array must be non-empty to prove
 * analysis (an empty one, like `{}`, says nothing about the root); a report-level error or
 * failure marker beside it is an analyzer error; every finding is validated, none filtered.
 */
function snykFindingArray(report: unknown, tree: string): Record<string, unknown>[] {
  const findingList = (value: unknown[]): Record<string, unknown>[] => {
    const findings = value.map(validatedFinding);
    if (findings.length === 0) throw new TypeError(NO_ANALYSIS);
    return findings;
  };
  if (Array.isArray(report)) return findingList(report);
  if (!isRecord(report)) throw new TypeError(NO_FINDINGS_ARRAY);
  for (const key of ["findings", "issues", "results", "vulnerabilities"] as const) {
    const value = report[key];
    if (!Array.isArray(value)) continue;
    if (carriesFailure(report)) throw new TypeError(ANALYZER_ERROR);
    return findingList(value);
  }
  const entries = Object.values(report);
  if (entries.length === 0) throw new TypeError(NO_ANALYSIS);
  // A map in which no value is a ScanPathResult is no report shape at all (Core's message);
  // once one is, every other value must be one too.
  if (!entries.some((entry) => isRecord(entry) && Array.isArray(entry.issues))) {
    if (carriesFailure(report) || entries.some((entry) => isRecord(entry) && carriesFailure(entry)))
      throw new TypeError(ANALYZER_ERROR);
    throw new TypeError(NO_FINDINGS_ARRAY);
  }
  return scanPathFindings(report, tree);
}

function snykFindingRuleId(finding: Record<string, unknown>): string {
  return firstString(finding, ["id", "code", "issueCode", "ruleId"]) ?? "snyk-agent-scan.finding";
}

function snykFindingMessage(finding: Record<string, unknown>): string {
  const title = firstString(finding, ["title", "message", "description"]);
  const description = firstString(finding, ["description", "message"]);
  if (title !== undefined && description !== undefined && title !== description) {
    return `${title}: ${description}`;
  }
  return title ?? description ?? "Snyk Agent Scan finding";
}

function snykSafeSarifUri(raw: string, tree: string): string {
  const stripped = raw.replace(/^file:\/\//, "");
  const posix = toPosix(stripped);
  if (isAbsolute(stripped) || isAbsolute(posix) || /^[A-Za-z]:/.test(posix)) {
    const relativeUri = toPosix(relative(realpathIfExists(tree), realpathIfExists(stripped)));
    if (relativeUri.length === 0) return ".";
    return isSafeRelativeSarifUri(relativeUri) ? relativeUri : ".";
  }
  return isSafeRelativeSarifUri(posix) ? posix : ".";
}

function snykFindingUri(finding: Record<string, unknown>, tree: string): string {
  let raw: string | undefined;
  if (isRecord(finding.location)) {
    const locationFile = firstString(finding.location, ["file", "path"]);
    if (locationFile !== undefined) raw = locationFile;
  }
  raw ??= firstString(finding, ["file", "path"]);
  return raw === undefined ? "." : snykSafeSarifUri(raw, tree);
}

function snykFindingLine(finding: Record<string, unknown>): number {
  const raw = isRecord(finding.location) ? (finding.location.line ?? finding.line) : finding.line;
  return typeof raw === "number" && Number.isInteger(raw) && raw > 0 ? raw : 1;
}

// ---------------------------------------------------------------------------
// snyk-agent-scan 0.6.x `scan --json`: the ScanResponse (models/api/v20260710.py)
// ---------------------------------------------------------------------------

const RISK_SCORE_MAX = 1000;
const RISK_NAME = /^[a-z][a-z0-9_]{0,63}$/;
const RESPONSE_KEYS = new Set(["client", "path", "server_risks", "skill_risks", "error"]);
const SERVER_KEYS = new Set(["name", "entities", "risk_indexes", "error"]);
const SKILL_KEYS = new Set(["name", "files", "risk_indexes", "error"]);
const SERVER_RISK_KEYS = new Set(["score", "evidence", "affected_tools"]);
const SKILL_RISK_KEYS = new Set([
  "score",
  "evidence",
  "locations",
  "malicious_urls",
  "unverifiable_urls",
]);
const ENTITY_TYPES = new Set(["tool", "resource", "resource_template", "prompt"]);
const FILE_TYPES = new Set(["instruction", "script", "asset"]);

function hasOnlyKeys(record: Record<string, unknown>, keys: ReadonlySet<string>): boolean {
  return Object.keys(record).every((key) => keys.has(key));
}

function isNonBlankString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isCount(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

function malformedEntry(): never {
  throw new TypeError(MALFORMED_ENTRY);
}

function malformedFinding(): never {
  throw new TypeError(MALFORMED_FINDING);
}

/** A list of `{name, type}` summaries (`McpEntitySummary`, `SkillFileSummary`). */
function namedSummaries(value: unknown, types: ReadonlySet<string>): Record<string, unknown>[] {
  if (!Array.isArray(value)) return malformedEntry();
  return value.map((item) =>
    isRecord(item) &&
    Object.keys(item).length === 2 &&
    isNonBlankString(item.name) &&
    typeof item.type === "string" &&
    types.has(item.type)
      ? item
      : malformedEntry(),
  );
}

/** An existing path whose realpath is the scanned root's; nothing else names the root. */
function isScannedRoot(raw: unknown, tree: string): boolean {
  if (typeof raw !== "string" || !isAbsolute(raw)) return false;
  try {
    return realpathSync(raw) === realpathSync(tree);
  } catch {
    return false;
  }
}

interface SnykRiskV1 {
  readonly name: string;
  readonly score: number;
  readonly evidence: string;
  readonly value: Record<string, unknown>;
}

/** Every present risk of a record's `risk_indexes`, validated against the 0.6.4 models. */
function riskEntries(indexes: unknown, keys: ReadonlySet<string>): SnykRiskV1[] {
  if (!isRecord(indexes)) return malformedEntry();
  return Object.entries(indexes).map(([name, value]): SnykRiskV1 => {
    if (!RISK_NAME.test(name) || !isRecord(value) || !hasOnlyKeys(value, keys))
      return malformedFinding();
    const { score, evidence } = value;
    if (!isCount(score) || score > RISK_SCORE_MAX || typeof evidence !== "string")
      return malformedFinding();
    for (const key of ["malicious_urls", "unverifiable_urls"] as const) {
      const urls = value[key];
      if (urls !== undefined && (!Array.isArray(urls) || !urls.every((u) => typeof u === "string")))
        malformedFinding();
    }
    return { name, score, evidence, value };
  });
}

function riskText(risk: SnykRiskV1, subject: string, detail: string): string {
  const evidence = risk.evidence.trim().length > 0 ? risk.evidence : "Snyk Agent Scan finding";
  return `${evidence} (${subject}; score ${risk.score}/${RISK_SCORE_MAX}${detail})`;
}

function affectedToolsText(risk: SnykRiskV1, entities: readonly Record<string, unknown>[]): string {
  const affected = risk.value.affected_tools;
  if (affected === undefined) return "";
  if (!Array.isArray(affected)) return malformedFinding();
  const names = affected.map((index) =>
    isCount(index) && index < entities.length
      ? (entities[index]?.name as string)
      : malformedFinding(),
  );
  return names.length > 0 ? `; affected tools: ${names.join(", ")}` : "";
}

/** The first skill-relative location (`Region.start`), as `; at path[:line] in the skill`. */
function skillLocationText(risk: SnykRiskV1): string {
  const locations = risk.value.locations;
  if (locations === undefined) return "";
  if (!Array.isArray(locations)) return malformedFinding();
  const occurrence = (value: unknown): Record<string, unknown> => {
    if (!isRecord(value) || !hasOnlyKeys(value, new Set(["path", "line", "offset"])))
      return malformedFinding();
    if (typeof value.path !== "string") return malformedFinding();
    if (value.line !== undefined && !isCount(value.line)) return malformedFinding();
    if (value.offset !== undefined && !isCount(value.offset)) return malformedFinding();
    return value;
  };
  const starts = locations.map((region) => {
    if (!isRecord(region) || !hasOnlyKeys(region, new Set(["start", "end"])))
      return malformedFinding();
    if (region.end !== undefined) occurrence(region.end);
    return occurrence(region.start);
  });
  const first = starts[0];
  if (first === undefined) return "";
  const path = toPosix(first.path as string);
  return `; at ${typeof first.line === "number" && first.line > 0 ? `${path}:${first.line}` : path} in the skill`;
}

function scanResponseResult(ruleId: string, text: string): SnykAgentScanSarifResultV1 {
  // Risk locations are relative to a skill directory the response does not name, so a
  // result points at the scanned root (line 1) and carries the location in its message.
  return {
    ruleId,
    message: { text },
    locations: [{ physicalLocation: { artifactLocation: { uri: "." }, region: { startLine: 1 } } }],
  };
}

/**
 * A 0.6.x server or skill record: its keys, name and summaries are validated, a failure
 * ScanError is an analyzer error, and a non-failure one means the record was not
 * analyzed. Returns the record's `risk_indexes`.
 */
function analyzedRecord(
  value: unknown,
  keys: ReadonlySet<string>,
  summaryKey: "entities" | "files",
  summaryTypes: ReadonlySet<string>,
): { name: string; summaries: Record<string, unknown>[]; indexes: unknown } {
  if (!isRecord(value) || !hasOnlyKeys(value, keys) || !isNonBlankString(value.name))
    return malformedEntry();
  const summaries =
    value[summaryKey] === undefined ? [] : namedSummaries(value[summaryKey], summaryTypes);
  if (!Object.hasOwn(value, "risk_indexes")) malformedEntry();
  const error = errorKind(value.error);
  if (error === "failure") throw new TypeError(ANALYZER_ERROR);
  if (error === "note") throw new TypeError(NO_ANALYSIS);
  return { name: value.name, summaries, indexes: value.risk_indexes };
}

/**
 * The results of a 0.6.x ScanResponse, under the S2e rules: every response must name the
 * scanned root by `client` or an absolute `path` that exists and is the root (a home
 * display path `~/…` never does); any failure ScanError on the report, a response, a
 * server or a skill is an analyzer error; a non-failure note on a record, or on a response
 * with nothing analyzed, is no analysis; every record and risk is validated, none skipped.
 * Every present risk becomes one result named by its risk key.
 */
function scanResponseResults(
  report: Record<string, unknown>,
  tree: string,
): SnykAgentScanSarifResultV1[] {
  if (carriesFailure(report)) throw new TypeError(ANALYZER_ERROR);
  if (!hasOnlyKeys(report, new Set(["scan_path_responses"]))) malformedEntry();
  const responses = report.scan_path_responses;
  if (!Array.isArray(responses)) return malformedEntry();
  if (responses.length === 0) throw new TypeError(NO_ANALYSIS);
  const results: SnykAgentScanSarifResultV1[] = [];
  for (const response of responses) {
    if (!isRecord(response) || !hasOnlyKeys(response, RESPONSE_KEYS)) return malformedEntry();
    const { client, path } = response;
    if (!isNonBlankString(path)) malformedEntry();
    if (client !== undefined && typeof client !== "string") malformedEntry();
    if (!Array.isArray(response.server_risks) || !Array.isArray(response.skill_risks))
      malformedEntry();
    const error = errorKind(response.error);
    if (error === "failure") throw new TypeError(ANALYZER_ERROR);
    const servers = (response.server_risks as unknown[]).map((value) =>
      analyzedRecord(value, SERVER_KEYS, "entities", ENTITY_TYPES),
    );
    const skills = (response.skill_risks as unknown[]).map((value) =>
      analyzedRecord(value, SKILL_KEYS, "files", FILE_TYPES),
    );
    for (const server of servers) {
      for (const risk of riskEntries(server.indexes, SERVER_RISK_KEYS)) {
        const tools = affectedToolsText(risk, server.summaries);
        results.push(
          scanResponseResult(risk.name, riskText(risk, `MCP server "${server.name}"`, tools)),
        );
      }
    }
    for (const skill of skills) {
      for (const risk of riskEntries(skill.indexes, SKILL_RISK_KEYS)) {
        const location = skillLocationText(risk);
        results.push(
          scanResponseResult(risk.name, riskText(risk, `skill "${skill.name}"`, location)),
        );
      }
    }
    if (results.length > MAX_FINDINGS)
      throw new TypeError("snyk-agent-scan JSON exceeds the bounded finding count");
    if (!isScannedRoot(client, tree) && !isScannedRoot(path, tree))
      throw new TypeError(NO_ANALYSIS);
    if (error === "note" && servers.length + skills.length === 0) throw new TypeError(NO_ANALYSIS);
  }
  return results;
}

function parseReportJson(raw: string): unknown {
  if (Buffer.byteLength(raw, "utf8") > MAX_OUTPUT_BYTES)
    throw new TypeError("snyk-agent-scan output exceeds the bounded size");
  try {
    // The wrapper object lets the strict contract parser validate every root shape,
    // including the top-level finding array, with duplicate keys rejected.
    return parseStrictJsonObjectV1(`{"report":${raw}}`, "snyk-agent-scan").report;
  } catch {
    throw new TypeError("snyk-agent-scan did not emit parseable JSON");
  }
}

/**
 * Converts the scanner's JSON stdout to the SARIF 2.1.0 projection Core emits, frozen.
 * Throws `TypeError` with Core's exact messages when the output is not parseable JSON or
 * holds no findings array, and with the engine's fixed messages when the report carries an
 * analyzer error, a malformed entry or finding, or no evidence that the root was analyzed.
 */
export function parseSnykAgentScanSarifV1(raw: string, tree: string): SnykAgentScanSarifV1 {
  const parsed = parseReportJson(raw);
  if (isRecord(parsed) && Object.hasOwn(parsed, "scan_path_responses"))
    return deepFreezeStrictJsonV1({
      version: "2.1.0" as const,
      runs: [{ results: scanResponseResults(parsed, tree) }],
    });
  const findings = snykFindingArray(parsed, tree);
  if (findings.length > MAX_FINDINGS)
    throw new TypeError("snyk-agent-scan JSON exceeds the bounded finding count");
  const results = findings.map((finding): SnykAgentScanSarifResultV1 => {
    return {
      ruleId: snykFindingRuleId(finding),
      message: { text: snykFindingMessage(finding) },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: snykFindingUri(finding, tree) },
            region: { startLine: snykFindingLine(finding) },
          },
        },
      ],
    };
  });
  return deepFreezeStrictJsonV1({
    version: "2.1.0" as const,
    runs: [{ results }],
  });
}

/** The fixed marker that replaces a SARIF field carrying the request token. */
export const SNYK_TOKEN_REDACTION_V1 = "[redacted SNYK_TOKEN]";

const MAX_DECODE_ROUNDS = 8;

/** Decodes each valid run of percent-encoded UTF-8 octets; invalid runs stay as they are. */
function percentDecodeValid(value: string): string {
  return value.replace(/(?:%[0-9A-Fa-f]{2})+/g, (run) => {
    try {
      return decodeURIComponent(run);
    } catch {
      return run;
    }
  });
}

/** Decodes literal `\uXXXX` escapes, the form a JSON string escape takes once echoed as text. */
function unicodeEscapeDecode(value: string): string {
  return value.replace(/\\u([0-9A-Fa-f]{4})/g, (_escape, hex: string) =>
    String.fromCharCode(Number.parseInt(hex, 16)),
  );
}

/**
 * The comparison form of a string: valid percent-encoding and `\u` escapes decoded
 * (repeatedly, so a double encoding is seen through), then all whitespace removed,
 * so encoded and line-wrapped echoes of the token are recognized.
 */
function tokenComparisonForm(value: string): string {
  let current = value;
  for (let round = 0; round < MAX_DECODE_ROUNDS; round += 1) {
    const next = unicodeEscapeDecode(percentDecodeValid(current));
    if (next === current) break;
    current = next;
  }
  return current.replace(/\s+/gu, "");
}

/**
 * The SARIF projection with every field that carries the request token replaced
 * whole: rule ids and messages by the marker, a URI by Snyk's C2a §1.4 fallback
 * `.`, since a redacted path would name no real file. Each decoded field is
 * compared on its own comparison form; nothing relies on the serialized SARIF.
 */
function redactSarif(sarif: SnykAgentScanSarifV1, token: string | undefined): SnykAgentScanSarifV1 {
  if (token === undefined) return sarif;
  const normalizedToken = tokenComparisonForm(token);
  const carriesToken = (value: string): boolean =>
    tokenComparisonForm(value).includes(normalizedToken);
  const results = sarif.runs[0].results.map((result): SnykAgentScanSarifResultV1 => {
    const location = result.locations[0].physicalLocation;
    return {
      ruleId: carriesToken(result.ruleId) ? SNYK_TOKEN_REDACTION_V1 : result.ruleId,
      message: {
        text: carriesToken(result.message.text) ? SNYK_TOKEN_REDACTION_V1 : result.message.text,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: carriesToken(location.artifactLocation.uri)
                ? "."
                : location.artifactLocation.uri,
            },
            region: { startLine: location.region.startLine },
          },
        },
      ],
    };
  });
  return deepFreezeStrictJsonV1({ version: "2.1.0" as const, runs: [{ results }] });
}

/**
 * A failure detail: fixed engine text plus the exit status and output byte
 * counts. The analyzer's stdout and stderr never reach an outward diagnostic,
 * because an echoed request token cannot be reliably recognized in free text.
 */
function processDetail(message: string, result: SnykAgentScanProcessResultV1): string {
  const stdoutBytes = Buffer.byteLength(result.stdout, "utf8");
  const stderrBytes = Buffer.byteLength(result.stderr, "utf8");
  return `${message}; exit ${result.code ?? "signal"}, stdout ${stdoutBytes} bytes, stderr ${stderrBytes} bytes`;
}

/** The engine's own parse messages; any other thrown text is replaced by fixed text. */
const SNYK_OUTPUT_MESSAGES: ReadonlySet<string> = new Set([
  "snyk-agent-scan output exceeds the bounded size",
  "snyk-agent-scan did not emit parseable JSON",
  "snyk-agent-scan JSON did not include a findings array",
  "snyk-agent-scan JSON exceeds the bounded finding count",
  ANALYZER_ERROR,
  NO_ANALYSIS,
  MALFORMED_FINDING,
  MALFORMED_ENTRY,
]);

const RUNNER_FAILED = "runner failed before an exit status was available";

/**
 * Executes one scan plan through the injected runner and classifies the outcome with
 * Core's exact rules and messages, staged per C2a §5.3: spawn error or an exit outside
 * `{0, 1}` fails at `execution`; empty stdout, unparseable JSON, a missing findings
 * array and an exit 1 without findings fail at `output`; exit 1 with findings
 * completes.
 */
async function executeSnykAgentScanPlanV1(
  run: SnykAgentScanRunnerV1,
  plan: SnykAgentScanPlanV1,
  tree: string,
): Promise<SnykAgentScanRunOutcomeV1> {
  // The analyzer's output never reaches a diagnostic (fixed text, exit status and
  // byte counts only), and every SARIF field is checked for the request token.
  const token = plan.env.SNYK_TOKEN;
  let scan: SnykAgentScanProcessResultV1;
  try {
    scan = await run(plan.argv, { env: plan.env, timeoutMs: plan.timeoutMs });
  } catch {
    return Object.freeze({
      kind: "failed" as const,
      stage: "execution" as const,
      detail: `snyk-agent-scan ${RUNNER_FAILED}`,
    });
  }
  if (scan.spawnError)
    return Object.freeze({
      kind: "failed" as const,
      stage: "execution" as const,
      detail: processDetail("snyk-agent-scan could not start", scan),
    });
  if (scan.stdout.trim().length === 0)
    return Object.freeze({
      kind: "failed" as const,
      stage: "output" as const,
      detail: processDetail("snyk-agent-scan emitted no JSON on stdout", scan),
    });
  // Snyk Agent Scan documents --ci as the mode that exits non-zero for findings, but
  // --ci requires --dangerously-run-mcp-servers, which never appears in the planned
  // argv. Exit 1 is accepted only when the JSON payload contains findings.
  if (scan.code !== 0 && scan.code !== 1)
    return Object.freeze({
      kind: "failed" as const,
      stage: "execution" as const,
      detail: processDetail("snyk-agent-scan exited outside {0, 1}", scan),
    });
  let sarif: SnykAgentScanSarifV1;
  try {
    sarif = redactSarif(parseSnykAgentScanSarifV1(scan.stdout, tree), token);
  } catch (error) {
    // An exit 1 whose report proves nothing keeps Core's exit-1 message (§5.3).
    const message =
      error instanceof TypeError && SNYK_OUTPUT_MESSAGES.has(error.message)
        ? scan.code === 1 && error.message === NO_ANALYSIS
          ? "snyk-agent-scan exited 1 without findings"
          : error.message
        : "invalid snyk-agent-scan JSON";
    return Object.freeze({
      kind: "failed" as const,
      stage: "output" as const,
      detail: processDetail(message, scan),
    });
  }
  if (scan.code === 1 && !sarif.runs.some((run0) => run0.results.length > 0))
    return Object.freeze({
      kind: "failed" as const,
      stage: "output" as const,
      detail: processDetail("snyk-agent-scan exited 1 without findings", scan),
    });
  return Object.freeze({ kind: "completed" as const, sarif, sarifText: JSON.stringify(sarif) });
}

// ---------------------------------------------------------------------------
// C2a §5.1: the request environment seam (SNYK_TOKEN only, typed refusals)
// ---------------------------------------------------------------------------

/** The only caller environment variable this detector accepts (C2a §5.1). */
export const SNYK_TOKEN_ENV_VAR_V1 = "SNYK_TOKEN";

/**
 * Why a `detector.snyk-agent-scan` request was refused before anything spawned.
 * The B2 wiring maps both reasons to Core's refusal reasons of the same names
 * (`prerequisite-missing` for the absent token, `detector-options-invalid` for
 * a malformed environment seam).
 */
export type SnykAgentScanRefusalReasonV1 = "detector-options-invalid" | "prerequisite-missing";

export interface SnykAgentScanRefusalV1 {
  readonly reason: SnykAgentScanRefusalReasonV1;
  /** One actionable sentence; never carries the token value. */
  readonly detail: string;
}

export type SnykAgentScanRequestEnvOutcomeV1 =
  | Readonly<{ ok: true; token: string }>
  | Readonly<{ ok: false; refusal: SnykAgentScanRefusalV1 }>;

/**
 * Validates the caller's request `env` (C2a §5.1): it must be a plain object
 * whose only key is `SNYK_TOKEN`, holding a string that is non-blank once
 * trimmed. A missing or blank token is a `prerequisite-missing` refusal naming
 * the variable (Core's exact "SNYK_TOKEN is not set"); any other key or a
 * non-string value is a `detector-options-invalid` refusal. Never throws, and
 * the token value never appears in a refusal detail.
 */
export function validateSnykAgentScanRequestEnvV1(env: unknown): SnykAgentScanRequestEnvOutcomeV1 {
  const invalid = (detail: string): SnykAgentScanRequestEnvOutcomeV1 =>
    Object.freeze({
      ok: false as const,
      refusal: Object.freeze({ reason: "detector-options-invalid" as const, detail }),
    });
  const missingToken = (): SnykAgentScanRequestEnvOutcomeV1 =>
    Object.freeze({
      ok: false as const,
      refusal: Object.freeze({
        reason: "prerequisite-missing" as const,
        detail: "SNYK_TOKEN is not set",
      }),
    });
  if (env === undefined) return missingToken();
  if (!isRecord(env))
    return invalid(`env must be an object with exactly the key ${SNYK_TOKEN_ENV_VAR_V1}.`);
  for (const key of Object.keys(env)) {
    if (key !== SNYK_TOKEN_ENV_VAR_V1)
      return invalid(
        `env may carry only ${SNYK_TOKEN_ENV_VAR_V1}; unexpected key ${JSON.stringify(key)}.`,
      );
  }
  const raw: unknown = env[SNYK_TOKEN_ENV_VAR_V1];
  if (raw === undefined) return missingToken();
  if (typeof raw !== "string")
    return invalid(`env.${SNYK_TOKEN_ENV_VAR_V1} must be a string when present.`);
  const token = raw.trim();
  if (token.length === 0) return missingToken();
  return Object.freeze({ ok: true as const, token });
}

/** The C2a §5 request inputs: subject root, host environment, caller token env. */
export interface SnykAgentScanRequestInputV1 {
  readonly platform: SnykAgentScanPlatformV1;
  /** `subject.sourceRoot`: the absolute realpath of the scanned root. */
  readonly tree: string;
  /** Host environment; scrubbed to the safe-key allow list before any spawn. */
  readonly hostEnv: NodeJS.ProcessEnv;
  /** The caller's `env` field; only `SNYK_TOKEN` is accepted (§5.1). */
  readonly requestEnv?: unknown;
}

export type SnykAgentScanRequestPlanOutcomeV1 =
  | Readonly<{ status: "planned"; plan: SnykAgentScanPlanV1 }>
  | Readonly<{ status: "refused"; refusal: SnykAgentScanRefusalV1 }>;

/**
 * Plans the scan from a C2a request: validates the env seam (§5.1), then plans
 * the §5.2 argv. The validated token is added to the scan environment only,
 * alongside the scrubbed host environment; a token in the host environment is
 * scrubbed away like any other secret-shaped key.
 */
export function planSnykAgentScanRequestV1(
  input: SnykAgentScanRequestInputV1,
): SnykAgentScanRequestPlanOutcomeV1 {
  const env = validateSnykAgentScanRequestEnvV1(input.requestEnv);
  if (!env.ok) return Object.freeze({ status: "refused" as const, refusal: env.refusal });
  if (typeof input.tree !== "string" || input.tree.length === 0)
    return Object.freeze({
      status: "refused" as const,
      refusal: Object.freeze({
        reason: "detector-options-invalid" as const,
        detail: "snyk-agent-scan requires a non-empty source root path.",
      }),
    });
  return Object.freeze({
    status: "planned" as const,
    plan: planSnykAgentScanV1({
      platform: input.platform,
      tree: input.tree,
      env: { ...input.hostEnv, [SNYK_TOKEN_ENV_VAR_V1]: env.token },
    }),
  });
}

export type SnykAgentScanRequestRunOutcomeV1 =
  | Readonly<{ kind: "refused"; refusal: SnykAgentScanRefusalV1 }>
  | SnykAgentScanRunOutcomeV1;

/**
 * The full C2a §5 run: validate the env seam (a refusal spawns nothing), then
 * execute the plan and classify per §5.3.
 */
export async function runSnykAgentScanRequestV1(
  run: SnykAgentScanRunnerV1,
  input: SnykAgentScanRequestInputV1,
): Promise<SnykAgentScanRequestRunOutcomeV1> {
  const planned = planSnykAgentScanRequestV1(input);
  if (planned.status === "refused")
    return Object.freeze({ kind: "refused" as const, refusal: planned.refusal });
  return executeSnykAgentScanPlanV1(run, planned.plan, input.tree);
}

/**
 * Typed availability probe (C2a §5.1/§5.2): a refused env seam spawns nothing;
 * otherwise `snyk-agent-scan help` runs with the scrubbed, token-free host
 * environment and must exit 0 with non-empty output.
 */
export type SnykAgentScanAvailabilityOutcomeV1 =
  | Readonly<{ status: "available" }>
  | Readonly<{ status: "refused"; refusal: SnykAgentScanRefusalV1 }>
  | Readonly<{ status: "unavailable"; detail: string }>;

export async function probeSnykAgentScanAvailabilityV1(
  run: SnykAgentScanRunnerV1,
  input: Readonly<{
    platform: SnykAgentScanPlatformV1;
    hostEnv: NodeJS.ProcessEnv;
    requestEnv?: unknown;
  }>,
): Promise<SnykAgentScanAvailabilityOutcomeV1> {
  const env = validateSnykAgentScanRequestEnvV1(input.requestEnv);
  if (!env.ok) return Object.freeze({ status: "refused" as const, refusal: env.refusal });
  const plan = planSnykAgentScanHelpV1({ platform: input.platform, env: input.hostEnv });
  // The help call never receives the token, and its output never reaches a
  // diagnostic all the same: fixed text, exit status and byte counts only.
  let help: SnykAgentScanProcessResultV1;
  try {
    help = await run(plan.argv, { env: plan.env, timeoutMs: plan.timeoutMs });
  } catch {
    return Object.freeze({
      status: "unavailable" as const,
      detail: `snyk-agent-scan help check ${RUNNER_FAILED}`,
    });
  }
  if (help.spawnError || help.code !== 0)
    return Object.freeze({
      status: "unavailable" as const,
      detail: processDetail("snyk-agent-scan help check failed", help),
    });
  if (`${help.stdout}${help.stderr}`.trim().length === 0)
    return Object.freeze({
      status: "unavailable" as const,
      detail: "snyk-agent-scan help check emitted no output",
    });
  return Object.freeze({ status: "available" as const });
}
