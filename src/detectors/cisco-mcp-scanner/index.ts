import { existsSync, lstatSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { type Node as JsonNode, type ParseError, parse, parseTree } from "jsonc-parser";
import {
  assertStrictJsonValueV1,
  assertWellFormedNfcV1,
  deepFreezeStrictJsonV1,
} from "../../contract/strict-json-v1.js";
import {
  MAX_MCP_CONFIG_PATHS_V1,
  mcpConfigPathsProblemV1,
  visibleOptionsDetailV1,
} from "../mcp-config-paths-v1.js";

/**
 * Scan detector engine `detector.cisco-mcp-scanner`: the Cisco AI Defense
 * `mcp-scanner` (uv-pinned 4.8.2) run over the MCP tool manifest derived from a
 * subject tree's MCP config files.
 *
 * Ported from Core (`src/trust/detectors.ts` and `src/trust/scan.ts`) with
 * identical behaviour: the same derived tool names and manifest bytes, the same
 * argv, the same environment scrub, the same strict JSON-to-SARIF conversion
 * with the same failure messages, and the same fail-closed rules (exactly one
 * completed result per submitted tool, required YARA analyzer coverage, integer
 * totals, one SARIF result per threat pointing at the config file on line 1).
 *
 * C2a §4 interface (what Core consumes):
 *
 * - §4.1: Core declares the MCP config files as
 *   `detectorOptions: { mcpConfigPaths: string[] }`; applicability is Core's
 *   decision (Core sends no request when the list is empty), but the engine
 *   still validates. {@link planCiscoMcpScannerRequestV1} validates the options
 *   with the one C2a §2.1 validator shared with trust-lint (safe unique
 *   source-relative POSIX paths from Core's config-name set in Core's
 *   discovery order, a nonexistent path refused, a directory or symlink
 *   accepted) and returns a typed refusal
 *   (`detector-options-invalid`) instead of throwing.
 * - §4.2: {@link deriveCiscoMcpToolsV1} derives tools from the declared paths
 *   in declared order, verbatim from Core's `mcpStaticTools`: a read/parse
 *   failure contributes one `<path>:malformed` placeholder tool, non-object
 *   maps and documents are ignored, and zero tools or a duplicate derived name
 *   are typed refusals (`subject-requirement-unmet`) before anything spawns.
 * - §4.3: argv `mcp-scanner --raw --analyzers yara static --tools <file>`,
 *   120 000 ms, exit 0 with non-empty stdout, strict output parsing and SARIF
 *   conversion unchanged from the phase-A port.
 *
 * The engine never spawns a process: execution goes through the injected
 * {@link CiscoMcpScannerRunnerV1} seam. Grading, posture, policy and evidence
 * acceptance stay in Core and are deliberately not part of this module.
 */

export const CISCO_MCP_SCANNER_DETECTOR_ID_V1 = "detector.cisco-mcp-scanner";
export const CISCO_MCP_SCANNER_VERSION_V1 = "4.8.2";
export const CISCO_MCP_SCANNER_ANALYZER_V1 = `mcp-scanner@uv:${CISCO_MCP_SCANNER_VERSION_V1}`;
export const CISCO_MCP_SCANNER_PYTHON_V1 = "3.12";
export const CISCO_MCP_SCANNER_TIMEOUT_MS_V1 = 120_000;

const moduleDir = dirname(fileURLToPath(import.meta.url));
const projectCandidates = [
  resolve(moduleDir, "..", "..", "..", "tools", "baseline-analyzers", "cisco-mcp-scanner"),
  resolve(moduleDir, "..", "..", "..", "..", "tools", "baseline-analyzers", "cisco-mcp-scanner"),
] as const;
/** Absolute path of the bundled, exact-pinned uv project (`pyproject.toml` + `uv.lock`). */
export const CISCO_MCP_SCANNER_PROJECT_V1 =
  projectCandidates.find((candidate) => existsSync(join(candidate, "uv.lock"))) ??
  projectCandidates[0];

/**
 * Repo-relative MCP config files submitted to the scanner, in Core's fixed
 * iteration order (Core `MCP_CONFIG_FILES` plus `mcp.json`).
 */
export const MCP_CONFIG_FILE_NAMES_V1: readonly string[] = Object.freeze([
  ".mcp.json",
  ".cursor/mcp.json",
  ".kiro/settings/mcp.json",
  "mcp-configs/mcp-servers.json",
  ".vscode/mcp.json",
  "opencode.json",
  "mcp.json",
]);

/** C2a §2.1: at most this many caller-declared MCP config paths per request. */
export const MCP_DECLARED_CONFIG_PATHS_MAX_V1 = MAX_MCP_CONFIG_PATHS_V1;
const MAX_TOOLS = 4096;
const MAX_STDOUT_BYTES = 16 * 1024 * 1024;
const MAX_THREATS_PER_ANALYZER = 4096;
const MAX_ANALYZERS_PER_RESULT = 64;
const MAX_DESCRIPTION_LENGTH = 400;
const MAX_TOOL_NAME_LENGTH = 120;
const FALLBACK_SARIF_URI = "mcp-scanner.json";

function fail(message: string): never {
  throw new Error(message);
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

// ---------------------------------------------------------------------------
// Tools manifest: the scanner input derived from the declared config files
// ---------------------------------------------------------------------------

export interface CiscoMcpScannerToolV1 {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: Readonly<{ type: "object"; properties: Record<string, never> }>;
}

export interface CiscoMcpToolsManifestV1 {
  readonly tools: readonly CiscoMcpScannerToolV1[];
  /** Derived tool name -> subject-relative POSIX path of its declaring config file. */
  readonly sourceUriByToolName: ReadonlyMap<string, string>;
}

function safeToolName(raw: string): string {
  const safe = raw.replace(/[^A-Za-z0-9._:-]/g, "_").replace(/^_+|_+$/g, "");
  return safe.length > 0 ? safe.slice(0, MAX_TOOL_NAME_LENGTH) : "mcp-server";
}

function toolsFromConfig(rel: string, parsed: unknown): CiscoMcpScannerToolV1[] {
  if (!isRecord(parsed)) return [];
  const maps: Array<Record<string, unknown>> = [];
  for (const key of ["mcpServers", "servers", "mcp"]) {
    const value = parsed[key];
    if (isRecord(value)) maps.push(value);
  }
  return maps.flatMap((servers) =>
    Object.entries(servers)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([name, rawServer]) => ({
        name: safeToolName(`${rel}:${name}`),
        description:
          isRecord(rawServer) && typeof rawServer.description === "string"
            ? rawServer.description.slice(0, MAX_DESCRIPTION_LENGTH)
            : `MCP server declared in ${rel}`,
        inputSchema: { type: "object" as const, properties: {} },
      })),
  );
}

/** The exact bytes Core writes to the `--tools` input file. */
export function serializeMcpToolsManifestV1(manifest: CiscoMcpToolsManifestV1): string {
  return `${JSON.stringify({ tools: manifest.tools }, null, 2)}\n`;
}

// ---------------------------------------------------------------------------
// Planning: argv and environment for one scanner invocation
// ---------------------------------------------------------------------------

export type CiscoMcpScannerPlatformV1 = "windows" | "darwin" | "linux";

const CMD_INJECTION = /[&|<>^%!\r\n"]/;
const WIN_CMD_SHIMS = new Set(["claude", "npm", "npx", "pnpm", "scoop", "yarn"]);

/** Core's `execArgv`: `cmd /c` wrapping applies only to known .cmd shims; `uv` is not one. */
function execArgv(platform: CiscoMcpScannerPlatformV1, argv: string[]): string[] {
  if (platform !== "windows" || argv[0] === undefined || !WIN_CMD_SHIMS.has(argv[0])) return argv;
  for (const [index, arg] of argv.entries()) {
    if (CMD_INJECTION.test(arg))
      throw new TypeError(
        `Windows ${argv[0]} shim argv[${index}] contains a shell metacharacter ` +
          `(one of & | < > ^ % ! " or a newline) that is unsafe for a Windows cmd launcher: ` +
          JSON.stringify(arg),
      );
  }
  return ["cmd", "/c", ...argv];
}

function baseArgv(): string[] {
  return [
    "uv",
    "run",
    "--project",
    CISCO_MCP_SCANNER_PROJECT_V1,
    "--locked",
    "--isolated",
    "--python",
    CISCO_MCP_SCANNER_PYTHON_V1,
    "--offline",
    "--no-python-downloads",
    "--no-env-file",
    "mcp-scanner",
  ];
}

/** The scan argv: `mcp-scanner --raw --analyzers yara static --tools <inputJson>`. */
export function ciscoMcpScannerArgvV1(
  platform: CiscoMcpScannerPlatformV1,
  inputJson: string,
): readonly string[] {
  return Object.freeze(
    execArgv(platform, [
      ...baseArgv(),
      "--raw",
      "--analyzers",
      "yara",
      "static",
      "--tools",
      inputJson,
    ]),
  );
}

/** The availability probe argv (`mcp-scanner --help`) a runtime may use before planning. */
export function ciscoMcpScannerHelpArgvV1(platform: CiscoMcpScannerPlatformV1): readonly string[] {
  return Object.freeze(execArgv(platform, [...baseArgv(), "--help"]));
}

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

/**
 * Core's `scrubFetchEnv`: the caller environment reduced to a safe-key allow
 * list with every secret-shaped key removed. The scanner never sees credentials.
 */
export function scrubCiscoMcpScannerEnvV1(
  env: Readonly<Record<string, string | undefined>>,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined || isSecretEnvKey(key)) continue;
    if (SAFE_ENV_KEYS.has(key.toUpperCase())) out[key] = value;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Output parsing: strict scanner JSON to SARIF 2.1.0
// ---------------------------------------------------------------------------

export interface CiscoMcpScannerSarifResultV1 {
  readonly ruleId: string;
  readonly message: Readonly<{ text: string }>;
  readonly locations: readonly [
    Readonly<{
      physicalLocation: Readonly<{
        artifactLocation: Readonly<{ uri: string }>;
        region: Readonly<{ startLine: 1 }>;
      }>;
    }>,
  ];
}

export interface CiscoMcpScannerSarifV1 {
  readonly version: "2.1.0";
  readonly runs: readonly [Readonly<{ results: readonly CiscoMcpScannerSarifResultV1[] }>];
}

function duplicateKeys(node: JsonNode): void {
  if (node.type === "object") {
    const keys = new Set<string>();
    for (const property of node.children ?? []) {
      const key = property.children?.[0]?.value;
      if (typeof key === "string") {
        if (keys.has(key)) fail(`duplicate JSON object key: ${key}`);
        keys.add(key);
      }
      const child = property.children?.[1];
      if (child !== undefined) duplicateKeys(child);
    }
  } else if (node.type === "array") for (const child of node.children ?? []) duplicateKeys(child);
}

function parseScannerJson(text: string): unknown[] {
  if (Buffer.byteLength(text, "utf8") > MAX_STDOUT_BYTES)
    fail("mcp-scanner emitted output beyond the bounded size");
  try {
    assertWellFormedNfcV1(text, "mcp-scanner JSON text");
  } catch {
    fail("mcp-scanner did not emit parseable JSON");
  }
  const options = { allowTrailingComma: false, disallowComments: true } as const;
  const errors: ParseError[] = [];
  const tree = parseTree(text, errors, options);
  if (errors.length > 0 || tree === undefined || tree.type !== "array") {
    if (tree !== undefined && errors.length === 0 && tree.type !== "array")
      fail("mcp-scanner JSON did not include a result array");
    fail("mcp-scanner did not emit parseable JSON");
  }
  duplicateKeys(tree);
  const parseErrors: ParseError[] = [];
  const parsed: unknown = parse(text, parseErrors, options);
  if (parseErrors.length > 0 || !Array.isArray(parsed))
    fail("mcp-scanner did not emit parseable JSON");
  try {
    assertStrictJsonValueV1(parsed, "mcp-scanner JSON");
  } catch {
    fail("mcp-scanner did not emit parseable JSON");
  }
  return parsed;
}

function mcpScannerRuleId(analyzer: string, threat: string): string {
  const normalized = threat
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return normalized.length > 0 ? normalized : analyzer;
}

function isSafeRelativeSarifUri(uri: string): boolean {
  if (uri.length === 0 || isAbsolute(uri) || /^[A-Za-z]:/.test(uri)) return false;
  return !uri.split("/").some((part) => part === "..");
}

function toolUri(raw: unknown, sourceUriByToolName: ReadonlyMap<string, string>): string {
  if (typeof raw !== "string") return FALLBACK_SARIF_URI;
  const candidate = sourceUriByToolName.get(raw);
  return candidate !== undefined && isSafeRelativeSarifUri(candidate)
    ? candidate
    : FALLBACK_SARIF_URI;
}

/**
 * Convert raw mcp-scanner stdout into SARIF 2.1.0, exactly as Core does:
 * exactly one completed result per submitted tool, required `yara_analyzer`
 * coverage in every result, integer `total_findings` per analyzer, and one
 * SARIF result per threat pointing at the declaring config file on line 1.
 * Anything malformed, incomplete or inconsistent fails closed with Core's
 * message. Beyond Core (S2f): every summary field is validated before a zero
 * total is skipped; a zero total naming threats, a positive total naming none
 * or more than it counts, and a result marked safe that reports a finding are
 * contradictions and fail.
 */
export function parseCiscoMcpScannerSarifV1(
  stdout: string,
  sourceUriByToolName: ReadonlyMap<string, string>,
): CiscoMcpScannerSarifV1 {
  const parsed = parseScannerJson(stdout);
  if (parsed.length !== sourceUriByToolName.size)
    fail(
      `mcp-scanner returned ${parsed.length} result(s) for ${sourceUriByToolName.size} submitted tool(s)`,
    );

  const remainingToolNames = new Set(sourceUriByToolName.keys());

  const results: CiscoMcpScannerSarifResultV1[] = [];
  for (const rawResult of parsed) {
    if (!isRecord(rawResult)) fail("mcp-scanner JSON included a malformed result");
    if (rawResult.status !== "completed" || typeof rawResult.is_safe !== "boolean")
      fail("mcp-scanner JSON included an incomplete result");
    if (typeof rawResult.tool_name !== "string")
      fail("mcp-scanner JSON result omitted its submitted tool name");
    if (!remainingToolNames.delete(rawResult.tool_name))
      fail(`mcp-scanner JSON included an unexpected tool result: ${rawResult.tool_name}`);
    if (!isRecord(rawResult.findings)) fail("mcp-scanner JSON result omitted analyzer findings");
    if (!isRecord(rawResult.findings.yara_analyzer))
      fail("mcp-scanner JSON result omitted required YARA analyzer coverage");

    const analyzers = Object.entries(rawResult.findings);
    if (analyzers.length > MAX_ANALYZERS_PER_RESULT)
      fail("mcp-scanner JSON result exceeds the analyzer bound");

    let emitted = 0;
    for (const [analyzer, rawSummary] of analyzers) {
      if (!isRecord(rawSummary)) fail("mcp-scanner JSON included a malformed analyzer finding");
      const total =
        typeof rawSummary.total_findings === "number" &&
        Number.isInteger(rawSummary.total_findings) &&
        rawSummary.total_findings >= 0
          ? rawSummary.total_findings
          : undefined;
      if (total === undefined) fail("mcp-scanner JSON analyzer finding omitted a valid total");

      // Malformed threat fields fail rather than being filtered or ignored (S2e), a zero
      // total included (S2f).
      const rawThreats = rawSummary.threat_names;
      if (
        rawThreats !== undefined &&
        rawThreats !== null &&
        (!Array.isArray(rawThreats) || rawThreats.some((threat) => typeof threat !== "string"))
      )
        fail("mcp-scanner JSON analyzer finding carries malformed threat names");
      for (const key of ["threat_summary", "severity"] as const) {
        const value = rawSummary[key];
        if (value !== undefined && value !== null && typeof value !== "string")
          fail("mcp-scanner JSON included a malformed analyzer finding");
      }
      const threats: string[] = Array.isArray(rawThreats) ? rawThreats : [];
      if (threats.length > MAX_THREATS_PER_ANALYZER)
        fail("mcp-scanner JSON analyzer finding exceeds the threat bound");
      // mcp-scanner's report generator names one threat type per distinct finding type: a
      // zero total names none, a positive total names at least one and never more than it
      // counts (S2f). Anything else contradicts the analyzer's own total.
      if (total === 0 ? threats.length > 0 : threats.length === 0 || threats.length > total)
        fail("mcp-scanner JSON analyzer finding contradicts its total");
      if (total === 0) continue;
      if (rawResult.is_safe === true)
        fail("mcp-scanner marked a result safe while reporting a finding");
      const findingNames = threats;
      const detail =
        typeof rawSummary.threat_summary === "string" && rawSummary.threat_summary.length > 0
          ? rawSummary.threat_summary
          : `${total} finding(s) from ${analyzer}`;
      const severity =
        typeof rawSummary.severity === "string" ? `; severity ${rawSummary.severity}` : "";
      for (const threat of findingNames) {
        results.push({
          ruleId: mcpScannerRuleId(analyzer, threat),
          message: { text: `${detail}${severity}; analyzer ${analyzer}; count ${total}` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: toolUri(rawResult.tool_name, sourceUriByToolName) },
                region: { startLine: 1 as const },
              },
            },
          ],
        });
        emitted += 1;
      }
    }
    if (rawResult.is_safe === false && emitted === 0)
      fail("mcp-scanner marked a result unsafe without reporting a finding");
  }

  return deepFreezeStrictJsonV1({ version: "2.1.0" as const, runs: [{ results }] });
}

// ---------------------------------------------------------------------------
// Runner seam, planning and error classification
// ---------------------------------------------------------------------------

/** Result of one spawned process, supplied by the runtime's runner. */
export interface CiscoMcpScannerRunResultV1 {
  readonly stdout: string;
  readonly stderr: string;
  /** Process exit code; `null` when terminated by a signal. */
  readonly exitCode: number | null;
  /** True when the executable could not be spawned (ENOENT, timeout, abort). */
  readonly spawnError?: boolean;
}

/** The only process-spawning seam: the runtime injects this; the engine never spawns. */
export type CiscoMcpScannerRunnerV1 = (
  argv: readonly string[],
  options: Readonly<{ env: Record<string, string>; timeoutMs: number }>,
) => Promise<CiscoMcpScannerRunResultV1>;

export interface CiscoMcpScannerPlanV1 {
  readonly detectorId: typeof CISCO_MCP_SCANNER_DETECTOR_ID_V1;
  readonly analyzerIdentity: typeof CISCO_MCP_SCANNER_ANALYZER_V1;
  /** `uv run --locked --offline ... mcp-scanner --raw --analyzers yara static --tools <inputPath>`. */
  readonly argv: readonly string[];
  /** Scrubbed environment for the spawn; never carries secret-shaped caller variables. */
  readonly env: Record<string, string>;
  readonly timeoutMs: number;
  /** Where the runtime must write {@link inputBytes} before spawning. */
  readonly inputPath: string;
  /** The exact tools manifest bytes the scanner reads. */
  readonly inputBytes: string;
  readonly toolCount: number;
  readonly sourceUriByToolName: ReadonlyMap<string, string>;
}

export type CiscoMcpScannerFailureKindV1 = "runner-failed" | "empty-output" | "invalid-output";

export type CiscoMcpScannerRunOutcomeV1 =
  | Readonly<{ status: "completed"; sarif: CiscoMcpScannerSarifV1 }>
  | Readonly<{ status: "failed"; kind: CiscoMcpScannerFailureKindV1; detail: string }>;

function planFromManifestV1(
  request: Readonly<{
    platform: CiscoMcpScannerPlatformV1;
    env: Readonly<Record<string, string | undefined>>;
    inputPath: string;
    timeoutMs?: number;
  }>,
  manifest: CiscoMcpToolsManifestV1,
): CiscoMcpScannerPlanV1 {
  return deepFreezeStrictJsonV1({
    detectorId: CISCO_MCP_SCANNER_DETECTOR_ID_V1,
    analyzerIdentity: CISCO_MCP_SCANNER_ANALYZER_V1,
    argv: ciscoMcpScannerArgvV1(request.platform, request.inputPath),
    env: scrubCiscoMcpScannerEnvV1(request.env),
    timeoutMs: request.timeoutMs ?? CISCO_MCP_SCANNER_TIMEOUT_MS_V1,
    inputPath: request.inputPath,
    inputBytes: serializeMcpToolsManifestV1(manifest),
    toolCount: manifest.tools.length,
    sourceUriByToolName: new Map(manifest.sourceUriByToolName),
  });
}

/**
 * Execute a plan through the injected runner and classify the result. Exit
 * failure reports Core's reason (stderr, else stdout, else `detector exit N`);
 * empty stdout and unparseable or inconsistent scanner JSON fail closed.
 */
export async function runCiscoMcpScannerPlanV1(
  plan: CiscoMcpScannerPlanV1,
  run: CiscoMcpScannerRunnerV1,
): Promise<CiscoMcpScannerRunOutcomeV1> {
  const result = await run(plan.argv, { env: plan.env, timeoutMs: plan.timeoutMs });
  if (result.spawnError === true || result.exitCode !== 0) {
    return {
      status: "failed",
      kind: "runner-failed",
      detail:
        result.stderr ||
        result.stdout ||
        `detector exit ${result.exitCode === null ? "signal" : result.exitCode}`,
    };
  }
  if (result.stdout.trim().length === 0)
    return { status: "failed", kind: "empty-output", detail: "mcp-scanner emitted no JSON" };
  try {
    return {
      status: "completed",
      sarif: parseCiscoMcpScannerSarifV1(result.stdout, plan.sourceUriByToolName),
    };
  } catch (error) {
    return {
      status: "failed",
      kind: "invalid-output",
      detail: error instanceof Error ? error.message : String(error),
    };
  }
}

// ---------------------------------------------------------------------------
// C2a §4: Core-declared config paths (options validation and tool derivation)
// ---------------------------------------------------------------------------

/**
 * Why a `detector.cisco-mcp-scanner` request was refused before anything
 * spawned. The B2 wiring maps `detector-options-invalid` and
 * `subject-requirement-unmet` to Core's refusal reasons of the same names.
 */
export type CiscoMcpScannerRefusalReasonV1 =
  | "detector-options-invalid"
  | "subject-requirement-unmet";

export interface CiscoMcpScannerRefusalV1 {
  readonly reason: CiscoMcpScannerRefusalReasonV1;
  /** One actionable sentence. */
  readonly detail: string;
}

/**
 * C2a §4.1 options validation, exactly as §2.1: `detectorOptions` must be a
 * plain object with exactly the key `mcpConfigPaths`, whose value passes the
 * one §2.1 path validator shared with `detector.aih-trust-lint`
 * ({@link mcpConfigPathsProblemV1}: 0-1024 unique paths with
 * `assertSafeRelativePosixPathV1` semantics, from Core's incoming config-name
 * set at the root or under a selected SKILL.md directory, in Core's discovery
 * order, present in the sealed tree — a directory or symlink is accepted).
 * The accepted order is preserved verbatim. Never throws.
 */
export function validateCiscoMcpScannerDetectorOptionsV1(
  detectorOptions: unknown,
  request: Readonly<{ root: string; selectedClosurePaths: readonly string[] }>,
):
  | Readonly<{ ok: true; mcpConfigPaths: readonly string[] }>
  | Readonly<{ ok: false; refusal: CiscoMcpScannerRefusalV1 }> {
  const invalid = (detail: string) =>
    Object.freeze({
      ok: false as const,
      refusal: Object.freeze({
        reason: "detector-options-invalid" as const,
        detail: visibleOptionsDetailV1(detail),
      }),
    });
  if (!isRecord(detectorOptions))
    return invalid("detectorOptions must be an object with exactly the key mcpConfigPaths.");
  const keys = Object.keys(detectorOptions);
  if (keys.length !== 1 || keys[0] !== "mcpConfigPaths")
    return invalid(
      `detectorOptions must have exactly the key mcpConfigPaths; got ${JSON.stringify(keys)}.`,
    );
  const value: unknown = detectorOptions.mcpConfigPaths;
  const problem = mcpConfigPathsProblemV1(
    value,
    request.selectedClosurePaths,
    (path) =>
      lstatSync(join(request.root, ...path.split("/")), { throwIfNoEntry: false }) !== undefined,
  );
  if (problem !== undefined) return invalid(problem);
  return Object.freeze({
    ok: true as const,
    mcpConfigPaths: Object.freeze([...(value as readonly string[])]),
  });
}

export type CiscoMcpToolsDerivationV1 =
  | Readonly<{ status: "derived"; manifest: CiscoMcpToolsManifestV1 }>
  | Readonly<{ status: "refused"; refusal: CiscoMcpScannerRefusalV1 }>;

/**
 * C2a §4.2 tool derivation over Core-declared config paths, in declared order,
 * verbatim from Core's `mcpStaticTools`: a read or `JSON.parse` failure yields
 * one `<path>:malformed` placeholder tool, non-object maps and non-object
 * documents contribute nothing, and servers sort by name with `localeCompare`.
 * Zero derived tools or a duplicate derived name is a typed refusal
 * (`subject-requirement-unmet`) with Core's exact detail, before anything
 * spawns. Never throws.
 */
export function deriveCiscoMcpToolsV1(
  root: string,
  mcpConfigPaths: readonly string[],
): CiscoMcpToolsDerivationV1 {
  const refused = (detail: string): CiscoMcpToolsDerivationV1 =>
    Object.freeze({
      status: "refused" as const,
      refusal: Object.freeze({ reason: "subject-requirement-unmet" as const, detail }),
    });
  const tools: CiscoMcpScannerToolV1[] = [];
  const sourceUriByToolName = new Map<string, string>();
  for (const rel of mcpConfigPaths) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(join(root, ...rel.split("/")), "utf8"));
    } catch {
      parsed = undefined;
    }
    const derived =
      parsed === undefined
        ? [
            {
              name: safeToolName(`${rel}:malformed`),
              description: `Malformed MCP config declared in ${rel}`,
              inputSchema: { type: "object" as const, properties: {} },
            },
          ]
        : toolsFromConfig(rel, parsed);
    for (const tool of derived) {
      if (sourceUriByToolName.has(tool.name))
        return refused(`derived duplicate MCP tool name: ${tool.name}`);
      sourceUriByToolName.set(tool.name, rel);
      tools.push(tool);
      if (tools.length > MAX_TOOLS) return refused("derived MCP tool count exceeds bound");
    }
  }
  if (tools.length === 0)
    return refused("mcp-scanner received an MCP config with no scannable tools");
  return Object.freeze({
    status: "derived" as const,
    manifest: deepFreezeStrictJsonV1({
      tools: structuredClone(tools),
      sourceUriByToolName: new Map(sourceUriByToolName),
    }),
  });
}

/** The C2a §4 request as Core sends it (subject and options plus planning fields). */
export interface CiscoMcpScannerRequestV1 {
  /** `subject.sourceRoot`: the absolute realpath of the scanned root. */
  readonly root: string;
  /** `subject.selectedClosurePaths`: Core's trust inventory (may be empty). */
  readonly selectedClosurePaths: readonly string[];
  /** `detectorOptions`: required, exactly `{ mcpConfigPaths: string[] }` (§4.1). */
  readonly detectorOptions: unknown;
  readonly platform: CiscoMcpScannerPlatformV1;
  /** Host environment; scrubbed to the safe-key allow list before the spawn. */
  readonly env: Readonly<Record<string, string | undefined>>;
  /** Private path the runtime writes the tools manifest bytes to. */
  readonly inputPath: string;
  readonly timeoutMs?: number;
}

export type CiscoMcpScannerRequestOutcomeV1 =
  | Readonly<{ status: "planned"; plan: CiscoMcpScannerPlanV1 }>
  | Readonly<{ status: "refused"; refusal: CiscoMcpScannerRefusalV1 }>;

/**
 * The C2a §4 flow: validate the declared options (§4.1), derive the tools
 * manifest from exactly the declared paths (§4.2), then plan the §4.3 argv.
 * Every shortfall is a typed refusal; this function never throws on bad input.
 */
export function planCiscoMcpScannerRequestV1(
  request: CiscoMcpScannerRequestV1,
): CiscoMcpScannerRequestOutcomeV1 {
  const options = validateCiscoMcpScannerDetectorOptionsV1(request.detectorOptions, request);
  if (!options.ok) return Object.freeze({ status: "refused" as const, refusal: options.refusal });
  const derived = deriveCiscoMcpToolsV1(request.root, options.mcpConfigPaths);
  if (derived.status === "refused")
    return Object.freeze({ status: "refused" as const, refusal: derived.refusal });
  return Object.freeze({
    status: "planned" as const,
    plan: planFromManifestV1(request, derived.manifest),
  });
}
