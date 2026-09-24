import { existsSync, lstatSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { type Node as JsonNode, type ParseError, parse, parseTree } from "jsonc-parser";
import {
  assertStrictJsonValueV1,
  assertWellFormedNfcV1,
  deepFreezeStrictJsonV1,
} from "../../contract/strict-json-v1.js";

/**
 * Scan detector engine `detector.cisco-mcp-scanner`: the Cisco AI Defense
 * `mcp-scanner` (uv-pinned 4.8.2) run over the MCP tool manifest derived from a
 * subject tree's MCP config files.
 *
 * Ported from Core (`src/trust/detectors.ts` and `src/trust/scan.ts`) with
 * identical behaviour: the same config discovery surface, the same derived tool
 * names and manifest bytes, the same argv, the same environment scrub, the same
 * strict JSON-to-SARIF conversion with the same failure messages, and the same
 * fail-closed rules (exactly one completed result per submitted tool, required
 * YARA analyzer coverage, integer totals, one SARIF result per threat pointing
 * at the config file on line 1).
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

/** Directory names never descended into while discovering config files (Core's trust skip dirs). */
export const MCP_CONFIG_SKIP_DIRS_V1: ReadonlySet<string> = new Set([
  ".git",
  ".hg",
  ".svn",
  ".aih",
  "coverage",
  "dist",
  "node_modules",
  "vendor",
]);

const MAX_CONFIG_FILES = 1024;
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

function toPosix(path: string): string {
  return path.replace(/\\/g, "/");
}

// ---------------------------------------------------------------------------
// Discovery: which MCP config files of a subject tree build the tools manifest
// ---------------------------------------------------------------------------

export interface CiscoMcpConfigFileV1 {
  /** Subject-root-relative POSIX path, for example `.mcp.json`. */
  readonly relativePath: string;
  readonly absolutePath: string;
}

function skillDirs(root: string): string[] {
  const dirs: string[] = [];
  const visit = (absolutePath: string): void => {
    const stats = lstatSync(absolutePath);
    if (stats.isSymbolicLink()) return;
    if (!stats.isDirectory()) return;
    if (absolutePath !== root && MCP_CONFIG_SKIP_DIRS_V1.has(basename(absolutePath))) return;
    for (const entry of readdirSync(absolutePath).sort()) {
      const child = join(absolutePath, entry);
      if (entry === "SKILL.md" && statSync(child).isFile()) dirs.push(absolutePath);
      visit(child);
    }
  };
  visit(root);
  return dirs;
}

/**
 * The MCP config files Core would submit for this subject tree: the fixed
 * config file names at the root and at every directory holding a `SKILL.md`
 * (skip dirs excluded), deduplicated, in Core's discovery order. An empty
 * result means the scanner does not run for this subject.
 */
export function discoverMcpConfigFilesV1(root: string): readonly CiscoMcpConfigFileV1[] {
  const absoluteRoot = resolve(root);
  const rootStats = statSync(absoluteRoot, { throwIfNoEntry: false });
  if (rootStats === undefined || !rootStats.isDirectory())
    throw new TypeError("Cisco mcp-scanner subject root must be an existing directory");
  const roots = [
    absoluteRoot,
    ...skillDirs(absoluteRoot).sort((left, right) =>
      toPosix(relative(absoluteRoot, left)).localeCompare(toPosix(relative(absoluteRoot, right))),
    ),
  ];
  const seen = new Set<string>();
  const files: CiscoMcpConfigFileV1[] = [];
  for (const dir of new Set(roots)) {
    for (const name of MCP_CONFIG_FILE_NAMES_V1) {
      const absolutePath = join(dir, ...name.split("/"));
      if (!existsSync(absolutePath) || seen.has(absolutePath)) continue;
      seen.add(absolutePath);
      files.push({
        relativePath: toPosix(relative(absoluteRoot, absolutePath)),
        absolutePath,
      });
      if (files.length > MAX_CONFIG_FILES) fail("mcp-scanner config file count exceeds bound");
    }
  }
  return Object.freeze(files);
}

// ---------------------------------------------------------------------------
// Tools manifest: the scanner input derived from the discovered config files
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

/**
 * Derive the tools manifest from a subject's discovered MCP config files.
 * A config file that does not parse contributes exactly one placeholder tool,
 * matching Core. Fails closed when the tree yields no scannable tools or when
 * two derived tools collide on a name.
 */
export function buildMcpToolsManifestV1(root: string): CiscoMcpToolsManifestV1 {
  const absoluteRoot = resolve(root);
  const tools: CiscoMcpScannerToolV1[] = [];
  const sourceUriByToolName = new Map<string, string>();
  for (const config of discoverMcpConfigFilesV1(absoluteRoot)) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(config.absolutePath, "utf8"));
    } catch {
      parsed = undefined;
    }
    const derived =
      parsed === undefined
        ? [
            {
              name: safeToolName(`${config.relativePath}:malformed`),
              description: `Malformed MCP config declared in ${config.relativePath}`,
              inputSchema: { type: "object" as const, properties: {} },
            },
          ]
        : toolsFromConfig(config.relativePath, parsed);
    for (const tool of derived) {
      if (sourceUriByToolName.has(tool.name)) fail(`derived duplicate MCP tool name: ${tool.name}`);
      sourceUriByToolName.set(tool.name, config.relativePath);
      tools.push(tool);
      if (tools.length > MAX_TOOLS) fail("derived MCP tool count exceeds bound");
    }
  }
  if (tools.length === 0) fail("mcp-scanner received an MCP config with no scannable tools");
  return deepFreezeStrictJsonV1({
    tools: structuredClone(tools),
    sourceUriByToolName: new Map(sourceUriByToolName),
  });
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
 * message.
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
      if (total === 0) continue;

      const threats = Array.isArray(rawSummary.threat_names)
        ? rawSummary.threat_names.filter((threat): threat is string => typeof threat === "string")
        : [];
      if (threats.length > MAX_THREATS_PER_ANALYZER)
        fail("mcp-scanner JSON analyzer finding exceeds the threat bound");
      const findingNames = threats.length > 0 ? threats : [analyzer];
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

export type CiscoMcpScannerFailureKindV1 =
  | "no-scannable-tools"
  | "invalid-manifest"
  | "runner-failed"
  | "empty-output"
  | "invalid-output";

export type CiscoMcpScannerPlanOutcomeV1 =
  | Readonly<{ status: "planned"; plan: CiscoMcpScannerPlanV1 }>
  /** No MCP config files: Core does not run the scanner for this subject at all. */
  | Readonly<{ status: "no-config" }>
  | Readonly<{ status: "failed"; kind: CiscoMcpScannerFailureKindV1; detail: string }>;

export type CiscoMcpScannerRunOutcomeV1 =
  | Readonly<{ status: "completed"; sarif: CiscoMcpScannerSarifV1 }>
  | Readonly<{ status: "failed"; kind: CiscoMcpScannerFailureKindV1; detail: string }>;

/**
 * Plan one scanner run for a subject tree: discover config files, derive the
 * tools manifest, and produce argv/env. The runtime writes `plan.inputBytes` to
 * `plan.inputPath` and then spawns `plan.argv` through its own runner.
 */
export function planCiscoMcpScannerV1(
  request: Readonly<{
    root: string;
    platform: CiscoMcpScannerPlatformV1;
    env: Readonly<Record<string, string | undefined>>;
    inputPath: string;
    timeoutMs?: number;
  }>,
): CiscoMcpScannerPlanOutcomeV1 {
  if (discoverMcpConfigFilesV1(request.root).length === 0) return { status: "no-config" };
  let manifest: CiscoMcpToolsManifestV1;
  try {
    manifest = buildMcpToolsManifestV1(request.root);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return {
      status: "failed",
      kind:
        detail === "mcp-scanner received an MCP config with no scannable tools"
          ? "no-scannable-tools"
          : "invalid-manifest",
      detail,
    };
  }
  return {
    status: "planned",
    plan: deepFreezeStrictJsonV1({
      detectorId: CISCO_MCP_SCANNER_DETECTOR_ID_V1,
      analyzerIdentity: CISCO_MCP_SCANNER_ANALYZER_V1,
      argv: ciscoMcpScannerArgvV1(request.platform, request.inputPath),
      env: scrubCiscoMcpScannerEnvV1(request.env),
      timeoutMs: request.timeoutMs ?? CISCO_MCP_SCANNER_TIMEOUT_MS_V1,
      inputPath: request.inputPath,
      inputBytes: serializeMcpToolsManifestV1(manifest),
      toolCount: manifest.tools.length,
      sourceUriByToolName: new Map(manifest.sourceUriByToolName),
    }),
  };
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
