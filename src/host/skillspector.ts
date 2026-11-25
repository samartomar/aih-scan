import { existsSync, mkdirSync, statSync, writeFileSync } from "node:fs";
import { posix, win32 } from "node:path";
import { fileURLToPath } from "node:url";
import { type HostExecutableV1, resolveHostExecutableV1 } from "../cli/host-executable.js";
import type { AiProvenance, ScanMode } from "../contracts/validate.js";
import {
  ANALYZER_REPORT_MAX_BYTES,
  type HostEnv,
  PYTHON_LOADER_VARIABLES,
  probeVersion,
  readJsonReport,
  readJsonStdout,
  runAnalyzer,
  scratchFolder,
  selectAnalyzer,
  staticAnalyzerEnv,
} from "./analyzer-process.js";
import { analyzerFinding, notRun, objectOf } from "./analyzer-report.js";
import { KIMI_EFFORTS, KIMI_MODEL, KIMI_QUOTA_RECEIPT, KIMI_VERSION } from "./kimi-inference.js";
import type { AssessItem, ToolAdapter, ToolContext, ToolFinding, ToolRun } from "./tools.js";

/** The SkillSpector release Scan runs (NVIDIA/SkillSpector tag v2.13.6). */
export const SKILLSPECTOR_VERSION = "2.13.6";
/** Exact source/archive/patch/runtime-lock/build-lock/builder-recipe maintenance identity. */
export const SKILLSPECTOR_MAINTENANCE_VERSION =
  "2.13.6+aih.1.06fc3defc5b6f792396162f5f3678f7f07c32adf1f440194637392bfadac9e81";
/** Selects an exact SkillSpector executable, or `none` to disable it. */
export const SKILLSPECTOR_VARIABLE = "AIH_SCAN_SKILLSPECTOR";

/** How SkillSpector's AI pass would run: `cli` a signed-in AI CLI, `local` a local model, `provider` a hosted API. */
export type AiVia = "cli" | "local" | "provider";

/**
 * Whether the caller's existing SkillSpector AI settings are usable here. Scan only reads
 * which settings are present; it never stores, prints or records a credential value.
 */
export type AiSetup =
  | Readonly<{
      available: true;
      provider: string;
      via: AiVia;
      model?: string;
      /** An effort Scan applies to the agent CLI (`AIH_SCAN_AI_EFFORT`); absent means the CLI's own. */
      effort?: string;
      /** The agent CLI and the version it reported, filled in when Scan runs it. */
      client?: Readonly<{ name: string; version: string }>;
    }>
  | Readonly<{ available: false; reason: string }>;

/** Scan's own control for the effort of a signed-in Claude CLI pass. */
export const AI_EFFORT_VARIABLE = "AIH_SCAN_AI_EFFORT";
/** Effort levels the Claude CLI accepts for `--effort`. */
export const AI_EFFORT_LEVELS = Object.freeze(["low", "medium", "high", "xhigh", "max"] as const);
/** Providers whose CLI Scan can start with an explicit effort. */
const EFFORT_PROVIDERS = new Set(["claude_cli", "kimi_cli"]);

type Requirement = Readonly<{
  via: AiVia;
  /** Every group needs one of its variables set. */
  variables?: readonly (readonly string[])[];
  /** An AI CLI SkillSpector starts itself. */
  cli?: string;
}>;

/** The SkillSpector 2.13.6 providers Scan passes through, and what each needs to be set up. */
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
  openai_compatible: {
    via: "provider",
    variables: [["SKILLSPECTOR_COMPAT_BASE_URL"], ["SKILLSPECTOR_COMPAT_API_KEY"]],
  },
  ollama: { via: "local" },
  claude_cli: { via: "cli", cli: "claude" },
  kimi_cli: { via: "cli", cli: "kimi" },
  gemini_cli: { via: "cli", cli: "gemini" },
  opencode_cli: { via: "cli", cli: "opencode" },
});
const DISABLED_UPSTREAM = new Set(["antigravity_cli"]);
/** Providers SkillSpector 2.13.6 offers that Scan does not pass through yet. */
const UNSUPPORTED_BY_SCAN = new Set(["gemini"]);

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
  return pathOf(name, env, platform) !== undefined;
}

/** The first executable named `name` on the caller's PATH, or `undefined` (nothing run). */
export function pathOf(name: string, env: HostEnv, platform: NodeJS.Platform): string | undefined {
  const value = platform === "win32" ? (env.Path ?? env.PATH ?? env.path) : env.PATH;
  if (typeof value !== "string") return undefined;
  const path = platform === "win32" ? win32 : posix;
  const extensions =
    platform === "win32"
      ? (env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";").filter((entry) => entry.length > 0)
      : [""];
  for (const directory of value.split(platform === "win32" ? ";" : ":")) {
    if (!path.isAbsolute(directory)) continue;
    for (const extension of extensions) {
      const candidate = path.join(directory, `${name}${extension}`);
      try {
        const stat = statSync(candidate);
        if (stat.isFile() && (platform === "win32" || (stat.mode & 0o111) !== 0)) return candidate;
      } catch {
        // Not here.
      }
    }
  }
  return undefined;
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
  if (named === "codex_cli")
    return Object.freeze({
      available: false as const,
      reason: "Codex CLI has no verified tool-free inference configuration",
    });
  if (DISABLED_UPSTREAM.has(named))
    return Object.freeze({
      available: false as const,
      reason: `SkillSpector ${SKILLSPECTOR_VERSION} disables the ${named} provider`,
    });
  if (UNSUPPORTED_BY_SCAN.has(named))
    return Object.freeze({
      available: false as const,
      reason: `Scan does not yet support the ${named} provider`,
    });
  const requirement = Object.hasOwn(PROVIDERS, named) ? PROVIDERS[named] : undefined;
  if (requirement === undefined)
    return Object.freeze({
      available: false as const,
      reason: "SKILLSPECTOR_PROVIDER names a provider SkillSpector does not support",
    });
  const effort = env[AI_EFFORT_VARIABLE]?.trim().toLowerCase() ?? "";
  if (
    named === "kimi_cli" &&
    (env.SKILLSPECTOR_MODEL?.trim() !== KIMI_MODEL ||
      !KIMI_EFFORTS.some((level) => level === effort))
  )
    return Object.freeze({
      available: false as const,
      reason: `Kimi CLI requires model ${KIMI_MODEL} and explicit effort: ${KIMI_EFFORTS.join(", ")}`,
    });
  if (effort !== "") {
    if (!EFFORT_PROVIDERS.has(named))
      return Object.freeze({
        available: false as const,
        reason: `${AI_EFFORT_VARIABLE} applies only to provider ${[...EFFORT_PROVIDERS].join(", ")}`,
      });
    if (!(AI_EFFORT_LEVELS as readonly string[]).includes(effort))
      return Object.freeze({
        available: false as const,
        reason: `${AI_EFFORT_VARIABLE} must be one of ${AI_EFFORT_LEVELS.join(", ")}`,
      });
    if (platform === "win32")
      return Object.freeze({
        available: false as const,
        reason: `${AI_EFFORT_VARIABLE} needs a POSIX host; Scan cannot apply it on Windows`,
      });
  }
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
    ...(effort ? { effort } : {}),
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
 * JSON report to `report` (stdout on Windows). Static mode adds `--no-llm` and a scrubbed environment (no provider,
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
    // Upstream safe file output is unavailable on Windows; its supported JSON stdout
    // path stays inside the same bounded, hidden Job Object process transport.
    ...(input.platform === "win32" ? [] : ["--output", input.report]),
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
const COMPLETENESS_AGGREGATES = [
  "total_components",
  "scanned_components",
  "fully_inspected_files",
  "partially_inspected_files",
  "entirely_uninspected_files",
] as const;

function recognizedCompleteness(completeness: Record<string, unknown>): boolean {
  const status = completeness.status;
  if (status !== "complete" && status !== "complete_with_caveats" && status !== "partial")
    return false;
  if (completeness.is_complete !== (status !== "partial")) return false;
  if (completeness.execution_successful !== true) return false;
  const counts = COMPLETENESS_AGGREGATES.map((name) => completeness[name]);
  if (counts.some((value) => !Number.isSafeInteger(value) || (value as number) < 0)) return false;
  const [total, scanned, fully, partially, entirely] = counts as [
    number,
    number,
    number,
    number,
    number,
  ];
  if (total !== fully + partially + entirely || scanned !== fully) return false;
  if (
    !Array.isArray(completeness.limitations) ||
    completeness.limitations.some((value) => typeof value !== "string" || value.length === 0)
  )
    return false;
  for (const name of ["ledger_exceptions", "analyzer_statuses"]) {
    const value = completeness[name];
    if (!Array.isArray(value) || value.some((entry) => objectOf(entry) === undefined)) return false;
  }
  for (const name of ["warnings", "notices"]) {
    const value = completeness[name];
    if (
      value !== undefined &&
      (!Array.isArray(value) || value.some((entry) => objectOf(entry) === undefined))
    )
      return false;
  }
  const patterns = completeness.exclude_patterns;
  if (
    patterns !== undefined &&
    (!Array.isArray(patterns) || patterns.some((value) => typeof value !== "string"))
  )
    return false;
  const excluded = completeness.excluded_file_count;
  if (excluded !== undefined && (!Number.isSafeInteger(excluded) || (excluded as number) < 0))
    return false;
  if (
    completeness.dependency_inspection !== undefined &&
    objectOf(completeness.dependency_inspection) === undefined
  )
    return false;
  return true;
}

/**
 * What SkillSpector itself reported it did not fully inspect, as one unsigned note, and whether
 * its AI pass (the analyzers its LLM provenance names) failed to complete. Gaps on files Scan does
 * not route to SkillSpector (binaries, dependency manifests) and the disabled OSV lookup are not
 * gaps. Their derived limitations and aggregates are excluded only up to the positively excluded
 * component count and only when no other gap exists. Reference-only caveats do not make inspection
 * incomplete; every other relevant gap does.
 */
function completenessOf(
  completeness: Record<string, unknown>,
  metadata: Record<string, unknown>,
  item: AssessItem,
  mode: ScanMode,
): Readonly<{ note?: string; incomplete: boolean; aiFailure?: string }> {
  const list = (value: unknown) => (Array.isArray(value) ? value : []);
  const ignorable = new Set<string>([OSV_ANALYZER]);
  const caveats = new Set<string>();
  const gaps = new Set<string>();
  const excludedLimitations = new Map<string, number>();
  const excludedPaths = new Set<string>();
  let positiveExclusion = false;
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
    const outer = path?.split("!/")[0];
    const nested =
      path !== undefined &&
      outer !== undefined &&
      (path.includes("!/") || exception.phase === "nested_artifact_inspection") &&
      item.routed.has(outer);
    const unrouted =
      !nested &&
      exception.fatal !== true &&
      path !== undefined &&
      (part === undefined || part === null || !ANALYZED_PARTS.has(part));
    if (osvOnly || unrouted) {
      positiveExclusion = true;
      if (path !== undefined) excludedPaths.add(path);
      for (const name of analyzers) ignorable.add(name);
      continue;
    }
    const detail = `${String(exception.reason_code)}${path === undefined ? "" : ` ${path}`}`;
    if (exception.reason_code === "reference_missing") caveats.add(detail);
    else gaps.add(detail);
  }
  for (const raw of list(completeness.warnings)) {
    const warning = objectOf(raw);
    if (warning === undefined) continue;
    const path = typeof warning.path === "string" ? ` ${warning.path}` : "";
    gaps.add(`${String(warning.reason_code)}${path}`);
  }
  // 2.13.5+ reports documentation notices (prose command notation it did not inspect as a
  // command), caller exclusions and opt-in dependency-content inspection outside the status.
  // Scan requests none of them and has not established that any leaves inspection complete.
  for (const raw of list(completeness.notices)) {
    const notice = objectOf(raw);
    if (notice === undefined) continue;
    const path = typeof notice.path === "string" ? ` ${notice.path}` : "";
    gaps.add(`notice ${String(notice.reason_code)}${path}`);
  }
  const excludedFiles = completeness.excluded_file_count;
  if (
    list(completeness.exclude_patterns).length > 0 ||
    (typeof excludedFiles === "number" && excludedFiles > 0)
  )
    gaps.add(`user_exclusion: ${String(excludedFiles ?? 0)}`);
  // 2.13.5+ always reports this summary; only the untouched default is complete.
  const dependencies = objectOf(completeness.dependency_inspection);
  if (dependencies === undefined) gaps.add("dependency_inspection missing");
  else if (
    dependencies.enabled !== false ||
    dependencies.status !== "not_requested" ||
    dependencies.inspected_artifacts !== 0 ||
    !Array.isArray(dependencies.artifacts) ||
    dependencies.artifacts.length > 0
  )
    gaps.add(`dependency_inspection ${String(dependencies.status)}`);
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
    const limitation =
      typeof status.message === "string" && status.message.length > 0
        ? status.message
        : `Analyzer ${id} status: ${state}.`;
    if (state !== "failed" && ignorable.has(id)) {
      excludedLimitations.set(limitation, (excludedLimitations.get(limitation) ?? 0) + 1);
      continue;
    }
    gaps.add(`${id} ${state}`);
  }
  if (mode === "ai" && metadata.llm_assessment_complete === false && aiGaps.length === 0)
    aiGaps.push("reported assessment incomplete");
  for (const limitation of list(completeness.limitations)) {
    if (typeof limitation !== "string") continue;
    const excluded = excludedLimitations.get(limitation) ?? 0;
    if (excluded > 1) excludedLimitations.set(limitation, excluded - 1);
    else excludedLimitations.delete(limitation);
    if (excluded === 0) gaps.add(limitation);
  }
  const omitted =
    (completeness.partially_inspected_files as number) +
    (completeness.entirely_uninspected_files as number);
  const aggregatesExplained = positiveExclusion && gaps.size === 0 && omitted <= excludedPaths.size;
  if (!aggregatesExplained)
    for (const name of ["partially_inspected_files", "entirely_uninspected_files"]) {
      const count = completeness[name];
      if (typeof count === "number" && count > 0) gaps.add(`${name}: ${count}`);
    }
  const shown = (values: Iterable<string>) => [...new Set(values)].sort().slice(0, 8).join(", ");
  const caveatOnly =
    gaps.size === 0 &&
    caveats.size > 0 &&
    completeness.status === "complete_with_caveats" &&
    completeness.is_complete === true;
  const unexplained =
    gaps.size === 0 &&
    caveats.size === 0 &&
    ((completeness.status === "partial" && !positiveExclusion) ||
      (completeness.status === "complete_with_caveats" && !caveatOnly));
  if (unexplained)
    gaps.add(
      `unexplained completeness state: ${String(completeness.status)}/is_complete=${String(completeness.is_complete)}`,
    );
  const incomplete = gaps.size > 0 || (caveats.size > 0 && !caveatOnly);
  return Object.freeze({
    incomplete,
    ...(caveatOnly
      ? { note: `SkillSpector reported inspection caveats: ${shown(caveats)}` }
      : incomplete
        ? {
            note: `SkillSpector reported partial inspection: ${shown([...gaps, ...caveats])}`,
          }
        : {}),
    ...(aiGaps.length === 0
      ? {}
      : { aiFailure: `SkillSpector's AI pass did not complete: ${shown(aiGaps)}` }),
  });
}

function aiProvenance(
  metadata: Record<string, unknown>,
  setup: Extract<AiSetup, { available: true }>,
): AiProvenance {
  const provenance = objectOf(metadata.llm_provenance);
  const provider = objectOf(provenance?.provider);
  const effective = provider?.effective_adapter;
  const models = new Set<string>();
  for (const raw of Array.isArray(provenance?.analyzers) ? provenance.analyzers : []) {
    const model = objectOf(raw)?.model;
    if (typeof model === "string" && model.length > 0 && model !== "redacted") models.add(model);
  }
  // Record what SkillSpector reports it used when that differs from the request, so a slot
  // override or substitution can never be signed as the requested model.
  const reported = [...models].sort().join(", ");
  const kimiTransport = setup.provider === "kimi_cli" && effective === "claude_cli";
  const model =
    setup.model === undefined
      ? models.size > 0
        ? reported
        : "provider default"
      : models.size === 0 || (models.size === 1 && models.has(setup.model))
        ? setup.model
        : reported;
  return Object.freeze({
    via: setup.via,
    provider:
      !kimiTransport && typeof effective === "string" && /^[a-z0-9_]{1,64}$/u.test(effective)
        ? effective
        : setup.provider,
    model: model.slice(0, 256),
    ...(setup.effort === undefined ? {} : { effort: setup.effort }),
    ...(setup.client === undefined ? {} : { client: setup.client }),
  });
}

/**
 * Turns one SkillSpector 2.13.6 JSON report into Scan's tool run. Findings keep SkillSpector's
 * rule id, severity and confidence; ordinary findings are placed at their primary location's
 * file and line, which must be an item file routed to SkillSpector (Text, Code or Config).
 * Archive findings use the exact outer file with `part: none` and retain member details in text.
 * SC4 (known vulnerable dependency) is dropped: advisories are a separate call. SkillSpector's
 * own risk score is ignored; `aih-risk/1` scores the findings.
 */
export function skillSpectorRun(
  report: unknown,
  item: AssessItem,
  mode: ScanMode,
  setup: AiSetup | undefined,
): ToolRun {
  const document = objectOf(report);
  const metadata = objectOf(document?.metadata);
  const acceptedVersion = [SKILLSPECTOR_VERSION, SKILLSPECTOR_MAINTENANCE_VERSION].includes(
    String(metadata?.skillspector_version),
  )
    ? String(metadata?.skillspector_version)
    : SKILLSPECTOR_VERSION;
  if (document === undefined || metadata === undefined || !Array.isArray(document.issues))
    return notRun("failed", mode, acceptedVersion, "SkillSpector wrote no readable report");
  if (
    ![SKILLSPECTOR_VERSION, SKILLSPECTOR_MAINTENANCE_VERSION].includes(
      String(metadata.skillspector_version),
    )
  )
    return notRun("failed", mode, SKILLSPECTOR_VERSION, "SkillSpector reported another version");
  const completeness = objectOf(document.analysis_completeness);
  if (
    document.execution_successful !== true ||
    completeness === undefined ||
    completeness.status === "failed"
  )
    return notRun(
      "failed",
      mode,
      String(metadata.skillspector_version),
      `SkillSpector reported a failed analysis${failureDiagnostic(document)}`,
    );
  if (!recognizedCompleteness(completeness))
    return notRun(
      "failed",
      mode,
      String(metadata.skillspector_version),
      "SkillSpector reported unrecognized or inconsistent completeness metadata",
    );
  const findings: ToolFinding[] = [];
  const rules: Record<string, string> = {};
  const archiveRoots = new Set<string>();
  for (const raw of document.issues) {
    const file = objectOf(objectOf(raw)?.location)?.file;
    if (typeof file !== "string" || !file.includes("!/")) continue;
    const outer = file.split("!/")[0];
    if (outer !== undefined) archiveRoots.add(outer);
  }
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
    const input = {
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
    };
    let finding = analyzerFinding(item, input);
    const file =
      typeof location?.file === "string"
        ? location.file.startsWith("./")
          ? location.file.slice(2)
          : location.file
        : undefined;
    const outer = file?.split("!/")[0];
    if (
      finding === undefined &&
      file !== undefined &&
      outer !== undefined &&
      (file.includes("!/") || archiveRoots.has(outer)) &&
      item.routed.get(outer)?.part === null
    ) {
      const nested = file !== outer;
      const memberLine =
        typeof location?.start_line === "number" &&
        Number.isSafeInteger(location.start_line) &&
        location.start_line >= 1
          ? location.start_line
          : 1;
      finding = analyzerFinding(item, {
        ...input,
        file: outer,
        line: nested ? 1 : location?.start_line,
        message: nested ? `${file}:${memberLine}: ${description}` : description,
        allowUnrouted: true,
      });
    }
    if (finding === undefined) continue;
    findings.push(finding);
    rules[issue.id] ??= description;
  }
  const suppressedCount =
    typeof document.suppressed_count === "number" ? document.suppressed_count : 0;
  const inspected = completenessOf(completeness, metadata, item, mode);
  // A usable report keeps its findings and counts; an incomplete AI pass or another relevant
  // inspection gap is a failed part (the item is partial with reason `failed`).
  const aiFailure =
    mode === "ai" && (metadata.llm_requested !== true || metadata.llm_available !== true)
      ? "SkillSpector's AI pass did not run"
      : inspected.aiFailure;
  const failedPart =
    aiFailure ?? (inspected.incomplete ? "SkillSpector's inspection is incomplete" : undefined);
  return Object.freeze({
    status: "ran" as const,
    version: String(metadata.skillspector_version),
    mode,
    ...(mode === "ai" && setup?.available === true ? { ai: aiProvenance(metadata, setup) } : {}),
    findings: Object.freeze(findings),
    rules: Object.freeze(rules),
    ...(Number.isSafeInteger(suppressedCount) && suppressedCount > 0
      ? { suppressed: Object.freeze([{ count: suppressedCount, reason: "SkillSpector baseline" }]) }
      : {}),
    ...(failedPart === undefined ? {} : { failedPart }),
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
 * The SkillSpector adapter: runs the installed SkillSpector 2.13.6 CLI natively (Windows
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
      if (context.mode !== "ai" && (env[AI_EFFORT_VARIABLE]?.trim() ?? "") !== "")
        notes.push(`${AI_EFFORT_VARIABLE} has no effect in static mode`);
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

function failureDiagnostic(report: unknown): string {
  const completeness = objectOf(objectOf(report)?.analysis_completeness);
  if (completeness === undefined || !Array.isArray(completeness.ledger_exceptions)) return "";
  const reasons = new Set<string>();
  for (const raw of completeness.ledger_exceptions) {
    const exception = objectOf(raw);
    if (exception?.fatal !== true) continue;
    const reason =
      typeof exception.reason_code === "string" ? exception.reason_code : "unknown_failure";
    const path = typeof exception.path === "string" ? ` ${exception.path}` : "";
    reasons.add(`${reason}${path}`);
  }
  return reasons.size === 0 ? "" : `; report: ${[...reasons].sort().slice(0, 8).join(", ")}`;
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
    /SkillSpector v?(\d+\.\d+\.\d+(?:\+[0-9a-z.]+)?)(?:\s|$)/u,
    context.signal,
  );
  if (context.signal.aborted) return notRun("cancelled", mode, version ?? SKILLSPECTOR_VERSION);
  if (version !== SKILLSPECTOR_VERSION && version !== SKILLSPECTOR_MAINTENANCE_VERSION)
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
  let ai = settings.ai;
  let runEnv = invocation.env;
  if (mode === "ai" && ai?.available === true && ai.via === "cli") {
    const agent = await agentCli(ai, invocation.env, settings, context.signal);
    if (typeof agent === "string") return notRun("failed", mode, version, agent);
    ai = agent.ai;
    runEnv = agent.env;
  }
  const result = await runAnalyzer(invocation.argv, {
    cwd: invocation.cwd,
    env: runEnv,
    signal: context.signal,
    ...(settings.platform === "win32" ? { maxStdoutBytes: ANALYZER_REPORT_MAX_BYTES } : {}),
  });
  if (result.termination === "timeout") return notRun("timeout", mode, version);
  if (result.termination === "abort")
    return notRun(context.signal.aborted ? "cancelled" : "timeout", mode, version);
  if (result.termination !== undefined)
    return notRun("failed", mode, version, `SkillSpector ${result.termination}`);
  // Exit 1 means SkillSpector's own risk threshold was crossed: a finished run.
  if (![0, 1, 2].includes(result.code ?? -1))
    return notRun("failed", mode, version, `SkillSpector exited ${result.code}`);
  const document =
    settings.platform === "win32"
      ? readJsonStdout(result)
      : readJsonReport(report, "SkillSpector report");
  const metadata = objectOf(objectOf(document)?.metadata);
  if (metadata?.skillspector_version !== version)
    return notRun("failed", mode, version, "SkillSpector probe/report identity mismatch");
  const kimiQuota =
    ai?.available === true &&
    ai.provider === "kimi_cli" &&
    existsSync(path.join(settings.scratch, KIMI_QUOTA_RECEIPT));
  if (result.code === 2)
    return notRun(
      "failed",
      mode,
      version,
      `SkillSpector exited 2${failureDiagnostic(document)}${kimiQuota ? "; Kimi rate or quota limit refused the request" : ""}`,
    );
  if (version === SKILLSPECTOR_MAINTENANCE_VERSION) {
    const actual = objectOf(metadata?.aih_scan_tp4_limits);
    const expected = {
      maxFiles: invocation.env.SKILLSPECTOR_TP4_MAX_FILES ?? "128",
      maxFindings: invocation.env.SKILLSPECTOR_TP4_MAX_FINDINGS ?? "64",
      maxBatches: invocation.env.SKILLSPECTOR_TP4_MAX_BATCHES ?? "256",
    };
    if (
      actual === undefined ||
      Object.entries(expected).some(([key, value]) => actual[key] !== Number(value))
    )
      return notRun("failed", mode, version, "SkillSpector effective TP4 limits mismatch");
  } else if (
    ["SKILLSPECTOR_TP4_MAX_FILES", "SKILLSPECTOR_TP4_MAX_FINDINGS"].some(
      (key) => invocation.env[key] !== undefined,
    )
  )
    return notRun(
      "failed",
      mode,
      version,
      "Configured TP4 capacity requires the maintenance build",
    );
  if (ai?.available && ai.provider === "kimi_cli") {
    const provider = objectOf(objectOf(metadata.llm_provenance)?.provider);
    if (
      provider?.effective_adapter !== "claude_cli" ||
      !existsSync(path.join(settings.scratch, "kimi-inference-completed"))
    ) {
      const run = skillSpectorRun(document, item, mode, undefined);
      if (run.status !== "ran") return run;
      return Object.freeze({
        ...run,
        failedPart: kimiQuota
          ? "Kimi rate or quota limit refused the request"
          : (run.failedPart ?? "Kimi inference did not complete"),
      });
    }
  }
  const run = skillSpectorRun(document, item, mode, ai);
  if (kimiQuota && run.status === "ran")
    return Object.freeze({ ...run, failedPart: "Kimi rate or quota limit refused the request" });
  return run;
}

/**
 * Prepares the signed-in Claude CLI SkillSpector will start. Scan resolves the real binary on
 * PATH and records the version it reports (running only that binary's `--version`; nothing from
 * the scanned content runs). On a POSIX host it puts a private launcher first on SkillSpector's
 * PATH that execs exactly that binary with the CLI's auto-updater disabled, so the recorded
 * version is the one that runs, and adds `--effort <level>` to each `-p` call when an effort was
 * selected. An explicit effort requires both the launcher and a reported version.
 */
async function agentCli(
  setup: Extract<AiSetup, { available: true }>,
  env: Readonly<Record<string, string>>,
  settings: Readonly<{ platform: NodeJS.Platform; scratch: string }>,
  signal: AbortSignal,
): Promise<
  | string
  | Readonly<{ ai: Extract<AiSetup, { available: true }>; env: Readonly<Record<string, string>> }>
> {
  const name = PROVIDERS[setup.provider]?.cli;
  if (name !== "claude" && name !== "kimi") return Object.freeze({ ai: setup, env });
  // SkillSpector finds the CLI on PATH; Scan resolves the same PATH entry through its runner.
  const found = resolveHostExecutableV1(name, env, settings.platform);
  if (found === undefined || found.foundIn !== "PATH") return `the ${name} CLI is not on PATH`;
  const real = found.path;
  const reported = await probeVersion(
    found,
    env,
    settings.scratch,
    /(?:^|\s)v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)(?:\s|$)/u,
    signal,
  );
  if (name === "kimi") {
    if (reported !== KIMI_VERSION)
      return `Kimi Code CLI ${KIMI_VERSION} is required for verified tool-free inference`;
    return kimiTransport(real, setup, env, settings.scratch);
  }
  if (setup.effort !== undefined && reported === undefined)
    return `the ${name} CLI did not report its version; Scan cannot record which client applies ${AI_EFFORT_VARIABLE}`;
  const ai = Object.freeze({
    ...setup,
    ...(reported === undefined ? {} : { client: Object.freeze({ name, version: reported }) }),
  });
  const pinnable = settings.platform !== "win32" && !/['\n]/u.test(real);
  if (!pinnable) {
    if (setup.effort !== undefined)
      return `Scan cannot apply ${AI_EFFORT_VARIABLE} to this ${name} CLI`;
    return Object.freeze({ ai, env });
  }
  const effort = setup.effort === undefined ? "" : ` --effort '${setup.effort}'`;
  const bin = posix.join(settings.scratch, "agent-cli");
  mkdirSync(bin, { mode: 0o700 });
  writeFileSync(
    posix.join(bin, name),
    `#!/bin/sh\nDISABLE_AUTOUPDATER=1\nexport DISABLE_AUTOUPDATER\nif [ "$1" = "-p" ]; then exec '${real}' "$@"${effort}; fi\nexec '${real}' "$@"\n`,
    { mode: 0o700, flag: "wx" },
  );
  return Object.freeze({ ai, env: Object.freeze({ ...env, PATH: `${bin}:${env.PATH ?? ""}` }) });
}

/** Reuse the analyzer's bounded, tool-free text transport with a Scan-owned Kimi client. */
function kimiTransport(
  binary: string,
  setup: Extract<AiSetup, { available: true }>,
  env: Readonly<Record<string, string>>,
  scratch: string,
) {
  const home = env.KIMI_CODE_HOME ?? (env.HOME ? posix.join(env.HOME, ".kimi-code") : "");
  if (!posix.isAbsolute(home)) return "Kimi Code requires an absolute login directory";
  const moduleUrl = new URL(import.meta.url);
  const launcher = fileURLToPath(
    new URL(
      moduleUrl.pathname.endsWith(".ts") ? "./kimi-inference.ts" : "./kimi-inference.js",
      moduleUrl,
    ),
  );
  const region = env.AIH_SCAN_KIMI_REGION ?? "global";
  if (region !== "global" && region !== "mainland-cn")
    return "AIH_SCAN_KIMI_REGION must be global or mainland-cn";
  const argv = [process.execPath, launcher, binary, home, scratch, setup.effort ?? "", region];
  if (argv.some((part) => /['\n]/u.test(part)))
    return "Kimi Code launcher paths cannot be quoted safely";
  const bin = posix.join(scratch, "agent-cli");
  mkdirSync(bin, { mode: 0o700 });
  writeFileSync(
    posix.join(bin, "claude"),
    `#!/bin/sh\nexec ${argv.map((part) => `'${part}'`).join(" ")} "$@"\n`,
    { mode: 0o700, flag: "wx" },
  );
  const ai = Object.freeze({
    ...setup,
    client: Object.freeze({ name: "kimi", version: KIMI_VERSION }),
  });
  return Object.freeze({
    ai,
    env: Object.freeze({
      ...env,
      SKILLSPECTOR_PROVIDER: "claude_cli",
      PATH: `${bin}:${env.PATH ?? ""}`,
    }),
  });
}
