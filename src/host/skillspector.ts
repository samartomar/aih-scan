import { statSync } from "node:fs";
import { posix, win32 } from "node:path";
import type { HostExecutableV1 } from "../cli/host-executable.js";
import type { ScanMode } from "../contracts/validate.js";
import {
  type HostEnv,
  PYTHON_LOADER_VARIABLES,
  probeVersion,
  readJsonReport,
  runAnalyzer,
  scratchFolder,
  selectAnalyzer,
  staticAnalyzerEnv,
} from "./analyzer-process.js";
import { analyzerFinding, notRun, objectOf } from "./analyzer-report.js";
import type { AssessItem, ToolAdapter, ToolContext, ToolFinding, ToolRun } from "./tools.js";

/** The SkillSpector release Scan runs (NVIDIA/SkillSpector tag v2.13.2). */
export const SKILLSPECTOR_VERSION = "2.13.2";
/** Selects an exact SkillSpector executable, or `none` to disable it. */
export const SKILLSPECTOR_VARIABLE = "AIH_SCAN_SKILLSPECTOR";

/** How SkillSpector's AI pass would run: `cli` a signed-in AI CLI, `local` a local model, `provider` a hosted API. */
export type AiVia = "cli" | "local" | "provider";

/**
 * Whether the caller's existing SkillSpector AI settings are usable here. Scan only reads
 * which settings are present; it never stores, prints or records a credential value.
 */
export type AiSetup =
  | Readonly<{ available: true; provider: string; via: AiVia; model?: string }>
  | Readonly<{ available: false; reason: string }>;

type Requirement = Readonly<{
  via: AiVia;
  /** Every group needs one of its variables set. */
  variables?: readonly (readonly string[])[];
  /** An AI CLI SkillSpector starts itself. */
  cli?: string;
}>;

/** The SkillSpector 2.13.2 providers Scan passes through, and what each needs to be set up. */
const PROVIDERS: Readonly<Record<string, Requirement>> = Object.freeze({
  openai: { via: "provider", variables: [["OPENAI_API_KEY"]] },
  anthropic: { via: "provider", variables: [["ANTHROPIC_API_KEY"]] },
  anthropic_proxy: {
    via: "provider",
    variables: [["ANTHROPIC_PROXY_API_KEY"], ["ANTHROPIC_PROXY_ENDPOINT_URL"]],
  },
  bedrock: { via: "provider", variables: [["AWS_PROFILE", "AWS_ACCESS_KEY_ID"]] },
  nv_build: { via: "provider", variables: [["NVIDIA_INFERENCE_KEY"]] },
  nv_inference: { via: "provider", variables: [["NVIDIA_INFERENCE_KEY"]] },
  azure_openai: {
    via: "provider",
    variables: [["AZURE_OPENAI_API_KEY"], ["AZURE_OPENAI_ENDPOINT"]],
  },
  openai_compatible: { via: "provider", variables: [["SKILLSPECTOR_COMPAT_BASE_URL"]] },
  ollama: { via: "local" },
  claude_cli: { via: "cli", cli: "claude" },
  gemini_cli: { via: "cli", cli: "gemini" },
  opencode_cli: { via: "cli", cli: "opencode" },
});
const DISABLED_UPSTREAM = new Set(["codex_cli", "antigravity_cli"]);

const isSet = (env: HostEnv, name: string) => {
  const value = env[name];
  return typeof value === "string" && value.trim().length > 0;
};

function isLoopbackUrl(value: string | undefined): boolean {
  if (value === undefined) return false;
  try {
    const host = new URL(value).hostname.toLowerCase();
    return host === "localhost" || host === "[::1]" || /^127(\.\d{1,3}){3}$/u.test(host);
  } catch {
    return false;
  }
}

/** Whether `name` is an executable on the caller's PATH (no search beyond it, nothing run). */
export function onPath(name: string, env: HostEnv, platform: NodeJS.Platform): boolean {
  const value = platform === "win32" ? (env.Path ?? env.PATH ?? env.path) : env.PATH;
  if (typeof value !== "string") return false;
  const path = platform === "win32" ? win32 : posix;
  const extensions =
    platform === "win32"
      ? (env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";").filter((entry) => entry.length > 0)
      : [""];
  for (const directory of value.split(platform === "win32" ? ";" : ":")) {
    if (!path.isAbsolute(directory)) continue;
    for (const extension of extensions) {
      try {
        const stat = statSync(path.join(directory, `${name}${extension}`));
        if (stat.isFile() && (platform === "win32" || (stat.mode & 0o111) !== 0)) return true;
      } catch {
        // Not here.
      }
    }
  }
  return false;
}

/**
 * Reads the caller's SkillSpector AI settings (`SKILLSPECTOR_PROVIDER`, `SKILLSPECTOR_MODEL` and
 * the provider's own variables) without changing them. AI is "set up" when a supported provider
 * is named and its required variables are present (a CLI provider: its CLI is on PATH). Scan never
 * picks a provider for the caller: an unset `SKILLSPECTOR_PROVIDER` is not set up.
 */
export function skillSpectorAiSetup(
  env: HostEnv,
  platform: NodeJS.Platform = process.platform,
): AiSetup {
  const named = env.SKILLSPECTOR_PROVIDER?.trim().toLowerCase() ?? "";
  if (named === "")
    return Object.freeze({ available: false as const, reason: "SKILLSPECTOR_PROVIDER is not set" });
  if (DISABLED_UPSTREAM.has(named))
    return Object.freeze({
      available: false as const,
      reason: `SkillSpector ${SKILLSPECTOR_VERSION} disables the ${named} provider`,
    });
  const requirement = Object.hasOwn(PROVIDERS, named) ? PROVIDERS[named] : undefined;
  if (requirement === undefined)
    return Object.freeze({
      available: false as const,
      reason: "SKILLSPECTOR_PROVIDER names a provider SkillSpector does not support",
    });
  for (const group of requirement.variables ?? [])
    if (!group.some((name) => isSet(env, name)))
      return Object.freeze({
        available: false as const,
        reason: `${group.join(" or ")} is not set for provider ${named}`,
      });
  if (requirement.cli !== undefined && !onPath(requirement.cli, env, platform))
    return Object.freeze({
      available: false as const,
      reason: `the ${requirement.cli} CLI for provider ${named} is not on PATH`,
    });
  const via =
    named === "openai_compatible" && isLoopbackUrl(env.SKILLSPECTOR_COMPAT_BASE_URL)
      ? ("local" as const)
      : requirement.via;
  const model = env.SKILLSPECTOR_MODEL?.trim();
  return Object.freeze({
    available: true as const,
    provider: named,
    via,
    ...(model ? { model } : {}),
  });
}

/** The command line, environment and folder of one SkillSpector run. */
export interface SkillSpectorInvocation {
  readonly argv: readonly string[];
  readonly env: Readonly<Record<string, string>>;
  readonly cwd: string;
}

/**
 * Builds one native, shell-free SkillSpector run over Scan's working copy `input`, writing its
 * JSON report to `report`. Static mode adds `--no-llm` and a scrubbed environment (no provider,
 * credential or proxy variables; a private HOME). AI mode passes the caller's environment through
 * unchanged except Python loader variables. Both disable SkillSpector's live OSV lookup
 * (`SKILLSPECTOR_OSV_TIMEOUT=0`): known vulnerabilities come only from `checkAdvisories`.
 * Never passes `--transitive*`, `--mcp-registry`, `--use-shipped-baseline` or a URL input.
 */
export function skillSpectorInvocation(
  input: Readonly<{
    executable: string;
    mode: ScanMode;
    folder: string;
    report: string;
    scratch: string;
    env: HostEnv;
    platform: NodeJS.Platform;
  }>,
): SkillSpectorInvocation {
  const argv = [
    input.executable,
    "scan",
    input.folder,
    "--format",
    "json",
    "--output",
    input.report,
    ...(input.mode === "static" ? ["--no-llm"] : []),
  ];
  const fixed = {
    SKILLSPECTOR_OSV_TIMEOUT: "0",
    PYTHONUTF8: "1",
    PYTHONIOENCODING: "utf-8",
    PYTHONDONTWRITEBYTECODE: "1",
    NO_COLOR: "1",
  };
  let env: Record<string, string>;
  if (input.mode === "static")
    env = staticAnalyzerEnv(input.env, input.scratch, input.platform, fixed);
  else {
    env = {};
    for (const [key, value] of Object.entries(input.env)) {
      if (value === undefined) continue;
      const name = input.platform === "win32" ? key.toUpperCase() : key;
      if (PYTHON_LOADER_VARIABLES.includes(name) || name === "SKILLSPECTOR_OSV_TIMEOUT") continue;
      env[key] = value;
    }
    Object.assign(env, fixed);
  }
  return Object.freeze({ argv: Object.freeze(argv), env: Object.freeze(env), cwd: input.scratch });
}

const SEVERITIES = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);
const OK_ANALYZER = new Set(["completed", "not_applicable", "disabled"]);
/** SkillSpector's own OSV lookup, which Scan switches off: advisories are a separate call. */
const OSV_ANALYZER = "static_patterns_supply_chain";
const OSV_EXCEPTION = "static_patterns_supply_chain_dependencies_runtime_limit";
const ANALYZED_PARTS = new Set(["text", "code", "config"]);

/**
 * What SkillSpector itself reported it did not fully inspect, as one unsigned note, and whether
 * its AI pass (the analyzers its LLM provenance names) failed to complete. Gaps on files Scan does
 * not route to SkillSpector (binaries, dependency manifests) and the disabled OSV lookup are not
 * gaps. A static gap is a note only: SkillSpector ran, so coverage follows `aih-risk/1`. In AI
 * mode an incomplete AI pass is a failure of required analysis.
 */
function completenessOf(
  completeness: Record<string, unknown>,
  metadata: Record<string, unknown>,
  item: AssessItem,
  mode: ScanMode,
): Readonly<{ note?: string; aiFailure?: string }> {
  const list = (value: unknown) => (Array.isArray(value) ? value : []);
  const ignorable = new Set<string>([OSV_ANALYZER]);
  const gaps = new Set<string>();
  for (const raw of list(completeness.ledger_exceptions)) {
    const exception = objectOf(raw);
    if (exception === undefined) continue;
    const analyzers = list(exception.analyzers).map(String);
    const osvOnly =
      exception.fatal !== true &&
      exception.reason_code === "runtime_limit" &&
      analyzers.length > 0 &&
      analyzers.every((name) => name === OSV_EXCEPTION);
    const path = typeof exception.path === "string" ? exception.path : undefined;
    const part = path === undefined ? undefined : item.routed.get(path)?.part;
    const unrouted =
      exception.fatal !== true &&
      path !== undefined &&
      (part === undefined || part === null || !ANALYZED_PARTS.has(part));
    if (osvOnly || unrouted) {
      for (const name of analyzers) ignorable.add(name);
      continue;
    }
    gaps.add(`${String(exception.reason_code)}${path === undefined ? "" : ` ${path}`}`);
  }
  const aiAnalyzers = new Set(
    list(objectOf(metadata.llm_provenance)?.analyzers).map((entry) =>
      String(objectOf(entry)?.analyzer_id),
    ),
  );
  const aiGaps: string[] = [];
  for (const raw of list(completeness.analyzer_statuses)) {
    const status = objectOf(raw);
    if (status === undefined) continue;
    const id = String(status.analyzer_id);
    const state = String(status.status);
    if (mode === "ai" && aiAnalyzers.has(id) && state !== "completed" && state !== "not_applicable")
      aiGaps.push(`${id} ${state}`);
    if (OK_ANALYZER.has(state)) continue;
    if (state !== "failed" && ignorable.has(id)) continue;
    gaps.add(`${id} ${state}`);
  }
  const shown = (values: Iterable<string>) => [...new Set(values)].sort().slice(0, 8).join(", ");
  return Object.freeze({
    ...(gaps.size === 0
      ? {}
      : { note: `SkillSpector reported partial inspection: ${shown(gaps)}` }),
    ...(aiGaps.length === 0
      ? {}
      : { aiFailure: `SkillSpector's AI pass did not complete: ${shown(aiGaps)}` }),
  });
}

function aiProvenance(
  metadata: Record<string, unknown>,
  setup: Extract<AiSetup, { available: true }>,
): Readonly<{ via: AiVia; provider: string; model: string }> {
  const provenance = objectOf(metadata.llm_provenance);
  const provider = objectOf(provenance?.provider);
  const effective = provider?.effective_adapter;
  const models = new Set<string>();
  for (const raw of Array.isArray(provenance?.analyzers) ? provenance.analyzers : []) {
    const model = objectOf(raw)?.model;
    if (typeof model === "string" && model.length > 0 && model !== "redacted") models.add(model);
  }
  const model =
    setup.model ?? (models.size > 0 ? [...models].sort().join(", ") : "provider default");
  return Object.freeze({
    via: setup.via,
    provider:
      typeof effective === "string" && /^[a-z0-9_]{1,64}$/u.test(effective)
        ? effective
        : setup.provider,
    model: model.slice(0, 256),
  });
}

/**
 * Turns one SkillSpector 2.13.2 JSON report into Scan's tool run. Findings keep SkillSpector's
 * rule id, severity and confidence; each is placed at its primary location's file and line,
 * which must be an item file routed to SkillSpector (Text, Code or Config). SC4 (known
 * vulnerable dependency) is dropped: advisories are a separate call. SkillSpector's own risk
 * score is ignored; `aih-risk/1` scores the findings.
 */
export function skillSpectorRun(
  report: unknown,
  item: AssessItem,
  mode: ScanMode,
  setup: AiSetup | undefined,
): ToolRun {
  const document = objectOf(report);
  const metadata = objectOf(document?.metadata);
  if (document === undefined || metadata === undefined || !Array.isArray(document.issues))
    return notRun("failed", mode, SKILLSPECTOR_VERSION, "SkillSpector wrote no readable report");
  if (metadata.skillspector_version !== SKILLSPECTOR_VERSION)
    return notRun("failed", mode, SKILLSPECTOR_VERSION, "SkillSpector reported another version");
  const completeness = objectOf(document.analysis_completeness);
  if (
    document.execution_successful !== true ||
    completeness === undefined ||
    completeness.status === "failed"
  )
    return notRun("failed", mode, SKILLSPECTOR_VERSION, "SkillSpector reported a failed analysis");
  if (mode === "ai" && (metadata.llm_requested !== true || metadata.llm_available !== true))
    return notRun("failed", mode, SKILLSPECTOR_VERSION, "SkillSpector's AI pass did not run");
  const findings: ToolFinding[] = [];
  const rules: Record<string, string> = {};
  for (const raw of document.issues) {
    const issue = objectOf(raw);
    if (issue === undefined || typeof issue.id !== "string" || issue.id === "SC4") continue;
    const location = objectOf(issue.location);
    const severity =
      typeof issue.severity === "string" && SEVERITIES.has(issue.severity.toUpperCase())
        ? (issue.severity.toUpperCase() as ToolFinding["severity"])
        : undefined;
    const description =
      typeof issue.pattern === "string" && issue.pattern.length > 0
        ? issue.pattern
        : typeof issue.category === "string"
          ? issue.category
          : issue.id;
    const finding = analyzerFinding(item, {
      ruleId: issue.id,
      message: description,
      file: location?.file,
      line: location?.start_line,
      severity,
      confidence: issue.confidence,
      fingerprint:
        typeof issue.match_fingerprint === "string" &&
        /^[0-9a-f]{16,128}$/u.test(issue.match_fingerprint)
          ? issue.match_fingerprint
          : undefined,
    });
    if (finding === undefined) continue;
    findings.push(finding);
    rules[issue.id] ??= description;
  }
  const suppressedCount =
    typeof document.suppressed_count === "number" ? document.suppressed_count : 0;
  const inspected = completenessOf(completeness, metadata, item, mode);
  return Object.freeze({
    status: "ran" as const,
    version: SKILLSPECTOR_VERSION,
    mode,
    ...(mode === "ai" && setup?.available === true ? { ai: aiProvenance(metadata, setup) } : {}),
    findings: Object.freeze(findings),
    rules: Object.freeze(rules),
    ...(Number.isSafeInteger(suppressedCount) && suppressedCount > 0
      ? { suppressed: Object.freeze([{ count: suppressedCount, reason: "SkillSpector baseline" }]) }
      : {}),
    ...(inspected.aiFailure === undefined ? {} : { failedPart: inspected.aiFailure }),
    ...(inspected.note === undefined ? {} : { notes: Object.freeze([inspected.note]) }),
  });
}

export interface SkillSpectorOptions {
  readonly env?: HostEnv;
  readonly platform?: NodeJS.Platform;
  /** The AI setup for `mode: ai` (computed once per scan); static runs ignore it. */
  readonly ai?: AiSetup;
}

/**
 * The SkillSpector adapter: runs the installed SkillSpector 2.13.2 CLI natively (Windows
 * included) over Scan's read-only working copy, under the tool time limit and the caller's
 * cancellation, with its whole process tree contained and removed.
 */
export function skillSpectorAdapter(options: SkillSpectorOptions = {}): ToolAdapter {
  const env = options.env ?? process.env;
  const platform = options.platform ?? process.platform;
  return Object.freeze({
    id: "skillspector" as const,
    version: SKILLSPECTOR_VERSION,
    async run(item: AssessItem, context: ToolContext): Promise<ToolRun> {
      const notes: string[] = [];
      let mode: ScanMode = "static";
      if (context.mode === "ai") {
        const setup = options.ai ?? skillSpectorAiSetup(env, platform);
        if (setup.available) mode = "ai";
        else
          notes.push(`AI not available here: ${setup.reason}; SkillSpector ran static checks only`);
      }
      const withNotes = (run: ToolRun): ToolRun =>
        notes.length === 0
          ? run
          : Object.freeze({ ...run, notes: Object.freeze([...notes, ...(run.notes ?? [])]) });
      if (context.signal.aborted) return withNotes(notRun("cancelled", mode, SKILLSPECTOR_VERSION));
      const selection = selectAnalyzer("skillspector", SKILLSPECTOR_VARIABLE, env, platform);
      if (selection.status === "missing")
        return withNotes(notRun("unavailable", mode, SKILLSPECTOR_VERSION, selection.detail));
      const scratch = scratchFolder("aih-scan-skillspector-");
      try {
        return withNotes(
          await runInstalled(selection.executable, item, context, mode, {
            env,
            platform,
            scratch: scratch.path,
            ai: options.ai ?? (mode === "ai" ? skillSpectorAiSetup(env, platform) : undefined),
          }),
        );
      } finally {
        scratch.dispose();
      }
    },
  });
}

async function runInstalled(
  executable: HostExecutableV1,
  item: AssessItem,
  context: ToolContext,
  mode: ScanMode,
  settings: Readonly<{
    env: HostEnv;
    platform: NodeJS.Platform;
    scratch: string;
    ai: AiSetup | undefined;
  }>,
): Promise<ToolRun> {
  const probeEnv = staticAnalyzerEnv(settings.env, settings.scratch, settings.platform);
  const version = await probeVersion(
    executable,
    probeEnv,
    settings.scratch,
    /SkillSpector v?(\d+\.\d+\.\d+)/u,
    context.signal,
  );
  if (context.signal.aborted) return notRun("cancelled", mode, SKILLSPECTOR_VERSION);
  if (version !== SKILLSPECTOR_VERSION)
    return notRun(
      "unavailable",
      mode,
      SKILLSPECTOR_VERSION,
      version === undefined
        ? "the installed SkillSpector did not report its version"
        : `the installed SkillSpector is ${version}; Scan runs ${SKILLSPECTOR_VERSION}`,
    );
  const path = settings.platform === "win32" ? win32 : posix;
  const report = path.join(settings.scratch, "skillspector-report.json");
  const invocation = skillSpectorInvocation({
    executable: executable.path,
    mode,
    folder: item.snapshotRoot,
    report,
    scratch: settings.scratch,
    env: settings.env,
    platform: settings.platform,
  });
  const result = await runAnalyzer(invocation.argv, {
    cwd: invocation.cwd,
    env: invocation.env,
    signal: context.signal,
  });
  if (result.termination === "timeout") return notRun("timeout", mode, SKILLSPECTOR_VERSION);
  if (result.termination === "abort")
    return notRun(context.signal.aborted ? "cancelled" : "timeout", mode, SKILLSPECTOR_VERSION);
  if (result.termination !== undefined)
    return notRun("failed", mode, SKILLSPECTOR_VERSION, `SkillSpector ${result.termination}`);
  // Exit 1 means SkillSpector's own risk threshold was crossed: a finished run.
  if (result.code !== 0 && result.code !== 1)
    return notRun("failed", mode, SKILLSPECTOR_VERSION, `SkillSpector exited ${result.code}`);
  return skillSpectorRun(readJsonReport(report, "SkillSpector report"), item, mode, settings.ai);
}
