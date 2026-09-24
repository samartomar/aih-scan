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
 * - parsing: the scanner's JSON is accepted in the four report shapes Core accepts
 *   (top-level finding array, `{findings|issues|results|vulnerabilities: [...]}`, a
 *   scan-path map whose issues recover their artifact path from the server `reference`
 *   index, and the empty object) and converted to SARIF 2.1.0 with the line defaulting
 *   to 1;
 * - classification: a spawn failure or an exit code outside `{0, 1}` is a failure, empty
 *   stdout is unavailable, exit 1 with no findings is unavailable, and exit 1 with
 *   findings completes, exactly as Core's `runSnykAgentScan` decides.
 *
 * The engine spawns nothing itself; every process runs through the injected
 * `SnykAgentScanRunnerV1` seam the runtime supplies. Grading, posture, policy and
 * evidence acceptance stay in Core and are deliberately not here.
 */

export const SNYK_AGENT_SCAN_VERSION = "0.5.17";
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
const MAX_DETAIL_CHARACTERS = 1024;

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

export type SnykAgentScanRunOutcomeV1 = Readonly<
  | { kind: "completed"; sarif: SnykAgentScanSarifV1; sarifText: string }
  | { kind: "unavailable"; detail: string }
  | { kind: "failed"; detail: string }
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

/** The four report shapes Core accepts, or `undefined` for anything else. */
function snykFindingArray(report: unknown): Record<string, unknown>[] | undefined {
  if (Array.isArray(report)) return report.filter(isRecord);
  if (!isRecord(report)) return undefined;
  for (const key of ["findings", "issues", "results", "vulnerabilities"] as const) {
    const value = report[key];
    if (Array.isArray(value)) return value.filter(isRecord);
  }
  const pathFindings: Record<string, unknown>[] = [];
  let sawScanPathResult = false;
  for (const [scanPath, rawPathResult] of Object.entries(report)) {
    if (!isRecord(rawPathResult)) continue;
    if (!Array.isArray(rawPathResult.issues)) continue;
    sawScanPathResult = true;
    for (const rawIssue of rawPathResult.issues) {
      if (!isRecord(rawIssue)) continue;
      pathFindings.push({
        ...rawIssue,
        path: snykScanPathIssueUri(scanPath, rawPathResult, rawIssue),
      });
    }
  }
  if (sawScanPathResult || Object.keys(report).length === 0) return pathFindings;
  return undefined;
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
 * holds no findings array.
 */
export function parseSnykAgentScanSarifV1(raw: string, tree: string): SnykAgentScanSarifV1 {
  const parsed = parseReportJson(raw);
  const findings = snykFindingArray(parsed);
  if (findings === undefined)
    throw new TypeError("snyk-agent-scan JSON did not include a findings array");
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

/** Bounded, control-character-encoded diagnostic text; engine messages pass through as-is. */
function boundedDetail(value: string): string {
  const encoded = JSON.stringify(value).slice(1, -1);
  if (encoded.length <= MAX_DETAIL_CHARACTERS) return encoded;
  const marker = "… middle omitted …";
  const retained = MAX_DETAIL_CHARACTERS - marker.length;
  const headLength = Math.ceil(retained / 2);
  return `${encoded.slice(0, headLength)}${marker}${encoded.slice(-(retained - headLength))}`;
}

function exitLabel(code: number | null): string {
  return `detector exit ${code ?? "signal"}`;
}

/**
 * Core's availability probe: a missing `SNYK_TOKEN` is reported before anything runs,
 * then the help argv runs with the scrubbed, token-free environment. Returns the reason
 * the detector is unavailable, or `undefined` when it answered.
 */
export async function checkSnykAgentScanAvailableV1(
  run: SnykAgentScanRunnerV1,
  input: {
    readonly platform: SnykAgentScanPlatformV1;
    readonly env: NodeJS.ProcessEnv;
  },
): Promise<string | undefined> {
  if (snykToken(input.env) === undefined) return "SNYK_TOKEN is not set";
  const plan = planSnykAgentScanHelpV1(input);
  let help: SnykAgentScanProcessResultV1;
  try {
    help = await run(plan.argv, { env: plan.env, timeoutMs: plan.timeoutMs });
  } catch (error) {
    return boundedDetail(error instanceof Error ? error.message : "snyk-agent-scan runner failed");
  }
  if (help.spawnError || help.code !== 0)
    return boundedDetail(help.stderr || help.stdout || `uvx exit ${help.code ?? "signal"}`);
  if (`${help.stdout}${help.stderr}`.trim().length === 0)
    return "snyk-agent-scan help check emitted no output";
  return undefined;
}

/**
 * Runs the scan through the injected runner and classifies the outcome with Core's exact
 * rules and messages: spawn error or an exit outside `{0, 1}` fails, empty stdout is
 * unavailable, exit 1 without findings is unavailable, exit 1 with findings completes.
 */
export async function runSnykAgentScanV1(
  run: SnykAgentScanRunnerV1,
  input: {
    readonly platform: SnykAgentScanPlatformV1;
    readonly tree: string;
    readonly env: NodeJS.ProcessEnv;
  },
): Promise<SnykAgentScanRunOutcomeV1> {
  const plan = planSnykAgentScanV1(input);
  let scan: SnykAgentScanProcessResultV1;
  try {
    scan = await run(plan.argv, { env: plan.env, timeoutMs: plan.timeoutMs });
  } catch (error) {
    return Object.freeze({
      kind: "failed" as const,
      detail: boundedDetail(
        error instanceof Error ? error.message : "snyk-agent-scan runner failed",
      ),
    });
  }
  if (scan.spawnError)
    return Object.freeze({
      kind: "failed" as const,
      detail: boundedDetail(scan.stderr || scan.stdout || exitLabel(scan.code)),
    });
  if (scan.stdout.trim().length === 0)
    return Object.freeze({
      kind: "unavailable" as const,
      detail: boundedDetail(scan.stderr || "snyk-agent-scan emitted no JSON on stdout"),
    });
  // Snyk Agent Scan documents --ci as the mode that exits non-zero for findings, but
  // --ci requires --dangerously-run-mcp-servers, which never appears in the planned
  // argv. Exit 1 is accepted only when the JSON payload contains findings.
  if (scan.code !== 0 && scan.code !== 1)
    return Object.freeze({
      kind: "failed" as const,
      detail: boundedDetail(scan.stderr || scan.stdout || exitLabel(scan.code)),
    });
  let sarif: SnykAgentScanSarifV1;
  try {
    sarif = parseSnykAgentScanSarifV1(scan.stdout, input.tree);
  } catch (error) {
    return Object.freeze({
      kind: "failed" as const,
      detail: boundedDetail(
        error instanceof Error ? error.message : "invalid snyk-agent-scan JSON",
      ),
    });
  }
  if (scan.code === 1 && !sarif.runs.some((run0) => run0.results.length > 0))
    return Object.freeze({
      kind: "unavailable" as const,
      detail: boundedDetail(scan.stderr || "snyk-agent-scan exited 1 without findings"),
    });
  return Object.freeze({ kind: "completed" as const, sarif, sarifText: JSON.stringify(sarif) });
}
