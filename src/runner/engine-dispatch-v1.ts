import { realpathSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  AnalyzerRunFailureV1,
  type BaselineProcessRunnerV1,
  CISCO_SKILL_SCANNER_HOST_PROJECT_V1,
  CISCO_SKILL_SCANNER_VERSION_V1,
  type HostProcessRuntimeV1,
  runHostUvEngineV1,
} from "../baseline/runtime-v1.js";
import { parseStrictJsonObjectV1 } from "../contract/strict-json-v1.js";
import { runBindingGateV1 } from "../detectors/binding-gate/index.js";
import {
  CISCO_MCP_SCANNER_PROJECT_V1,
  CISCO_MCP_SCANNER_VERSION_V1,
  type CiscoMcpScannerPlatformV1,
  deriveCiscoMcpToolsV1,
  planCiscoMcpScannerRequestV1,
  runCiscoMcpScannerPlanV1,
  validateCiscoMcpScannerDetectorOptionsV1,
} from "../detectors/cisco-mcp-scanner/index.js";
import {
  planCiscoSourceTreeJobsV1,
  runCiscoSourceTreeScanV1,
} from "../detectors/cisco-multi-skill/index.js";
import {
  ciscoJobDirectoryProblemTextV1,
  resolveContainedCiscoJobDirectoryV1,
} from "../detectors/cisco-multi-skill/job-dir-v1.js";
import {
  runSnykAgentScanRequestV1,
  SNYK_AGENT_SCAN_PROJECT,
  SNYK_AGENT_SCAN_VERSION,
  SNYK_TOKEN_ENV_VAR_V1,
  validateSnykAgentScanRequestEnvV1,
} from "../detectors/snyk-agent-scan/index.js";
import { runTrustLintV1 } from "../detectors/trust-lint/index.js";

/**
 * Phase B2 dispatch for the engine-backed detectors (C2a §2, §4, §5, §8.1). Each engine keeps
 * Core's behaviour and spawns nothing itself: the in-process engines run over the declared
 * source root inside this process, and the uv engines run through `runHostUvEngineV1`, which
 * supplies host-process-uv-v1's containment, sweep and cleanup. The runner around this module
 * owns the seal before and after, the snapshot, the annex and the findings projection.
 */

export type EngineAnalyzerV1 =
  | "aih-trust-lint"
  | "aih-binding-gate"
  | "cisco-mcp-scanner"
  | "snyk-agent-scan";

/** An engine: one of the B2 analyzers, or Cisco's per-directory source-tree scan (C2a §3). */
export type EngineV1 = EngineAnalyzerV1 | "cisco-source-tree";

const ENGINE_BY_DETECTOR: Readonly<Record<string, EngineAnalyzerV1>> = Object.freeze({
  "detector.aih-trust-lint": "aih-trust-lint",
  "detector.aih-binding-gate": "aih-binding-gate",
  "detector.cisco-mcp-scanner": "cisco-mcp-scanner",
  "detector.snyk-agent-scan": "snyk-agent-scan",
});

/** The engine a request runs, or `undefined` for the baseline analyzers. */
export function engineForV1(detectorId: string, subjectKind: string): EngineV1 | undefined {
  if (detectorId === "detector.cisco")
    return subjectKind === "source-tree" ? "cisco-source-tree" : undefined;
  return ENGINE_BY_DETECTOR[detectorId];
}

/** The analyzer an engine's observation names; Cisco's jobs are still the `cisco` analyzer. */
export function engineObservationAnalyzerV1(engine: EngineV1): EngineAnalyzerV1 | "cisco" {
  return engine === "cisco-source-tree" ? "cisco" : engine;
}

/** In-process engines read the declared source root; uv engines scan a private snapshot. */
export function engineRunsInProcessV1(engine: EngineV1): boolean {
  return engine === "aih-trust-lint" || engine === "aih-binding-gate";
}

/** The most SARIF results an engine may report (C2a §2.8: the binding gate's bound). */
export const ENGINE_MAX_RESULTS_V1 = 100_000;

export type EngineRefusalV1 = Readonly<{
  reason: "prerequisite-missing" | "detector-options-invalid" | "subject-requirement-unmet";
  detail: string;
}>;

/**
 * The request env a detector's environment-variable prerequisites are read from. Only
 * `detector.snyk-agent-scan` takes a request env of its own (exactly `SNYK_TOKEN`); for it the
 * host environment uv is resolved from is the process environment, never the request env.
 */
export function engineEnvironmentsV1(
  detectorId: string,
  requestEnv: Readonly<NodeJS.ProcessEnv> | undefined,
): Readonly<{ host: Readonly<NodeJS.ProcessEnv>; prerequisites: Readonly<NodeJS.ProcessEnv> }> {
  if (detectorId === "detector.snyk-agent-scan")
    return { host: process.env, prerequisites: requestEnv ?? {} };
  const env = requestEnv ?? process.env;
  return { host: env, prerequisites: env };
}

/**
 * Refusals an engine owns, settled before anything spawns: the Snyk token seam (C2a §5.1:
 * absent or blank is `prerequisite-missing` naming the variable, never its value) and the
 * MCP tool derivation (C2a §4.2: no scannable tool is `subject-requirement-unmet`).
 */
export function enginePreflightRefusalV1(
  analyzer: EngineV1,
  input: Readonly<{
    sourceRoot: string;
    selectedClosurePaths: readonly string[];
    detectorOptions: unknown;
    requestEnv: unknown;
  }>,
): EngineRefusalV1 | undefined {
  if (analyzer === "snyk-agent-scan") {
    const env = validateSnykAgentScanRequestEnvV1(input.requestEnv);
    return env.ok ? undefined : env.refusal;
  }
  if (analyzer === "cisco-mcp-scanner") {
    const options = validateCiscoMcpScannerDetectorOptionsV1(input.detectorOptions, {
      root: input.sourceRoot,
      selectedClosurePaths: input.selectedClosurePaths,
    });
    if (!options.ok) return options.refusal;
    const derived = deriveCiscoMcpToolsV1(input.sourceRoot, options.mcpConfigPaths);
    return derived.status === "refused" ? derived.refusal : undefined;
  }
  if (analyzer === "cisco-source-tree") {
    // C2a §3.1, §3.5: the jobs come from the selection, and a selection holding no SKILL.md,
    // or a job directory reached through a link, is refused before any runner call.
    const jobs = planCiscoSourceTreeJobsV1(input.sourceRoot, input.selectedClosurePaths);
    if (jobs.length === 0)
      return {
        reason: "subject-requirement-unmet",
        detail: "no SKILL.md directories found for Cisco scan",
      };
    for (const job of jobs) {
      const resolved = resolveContainedCiscoJobDirectoryV1(input.sourceRoot, job.path);
      if (!resolved.ok)
        return {
          reason: "subject-requirement-unmet",
          detail: `Cisco job path ${ciscoJobDirectoryProblemTextV1(resolved.problem)}: ${job.path}`,
        };
    }
  }
  return undefined;
}

export type EngineOutcomeV1 =
  | Readonly<{
      kind: "sarif";
      analyzerVersion: string;
      sarif: unknown;
      hostRuntime?: HostProcessRuntimeV1;
    }>
  | Readonly<{ kind: "refused"; refusal: EngineRefusalV1 }>
  | Readonly<{
      kind: "failed";
      stage: "availability" | "acquisition" | "execution" | "output";
      error: unknown;
    }>;

export interface EngineRunInputV1 {
  readonly analyzer: EngineV1;
  /** The declared source root (in-process) or the private snapshot (uv engines). */
  readonly root: string;
  readonly selectedClosurePaths: readonly string[];
  readonly detectorOptions: unknown;
  readonly requestEnv: unknown;
  readonly hostEnv: Readonly<NodeJS.ProcessEnv>;
  readonly runner?: BaselineProcessRunnerV1;
  readonly signal?: AbortSignal;
  readonly deadline?: number;
}

function platformName(): CiscoMcpScannerPlatformV1 {
  return process.platform === "win32"
    ? "windows"
    : process.platform === "darwin"
      ? "darwin"
      : "linux";
}

function failed(stage: "execution" | "output", detail: string): EngineOutcomeV1 {
  return Object.freeze({ kind: "failed" as const, stage, error: new TypeError(detail) });
}

/**
 * Why an in-process result may not be kept: the analysis is synchronous, so the signal and
 * the time budget are read before it starts and again once it returns.
 */
function lateness(input: EngineRunInputV1, when: "started" | "kept"): unknown {
  const verb = when === "started" ? "was not started" : "result was discarded";
  if (input.signal?.aborted)
    return new AnalyzerRunFailureV1(
      "cancelled",
      `${input.analyzer} ${verb}: the run was cancelled`,
    );
  if (input.deadline !== undefined && Date.now() >= input.deadline)
    return new AnalyzerRunFailureV1(
      "timed-out",
      `${input.analyzer} ${verb}: the run's time budget is spent`,
    );
  return undefined;
}

function inProcess(input: EngineRunInputV1): EngineOutcomeV1 {
  const early = lateness(input, "started");
  if (early !== undefined) return { kind: "failed", stage: "execution", error: early };
  const request = {
    sourceRoot: input.root,
    selectedClosurePaths: input.selectedClosurePaths,
    detectorOptions: input.detectorOptions,
  };
  const outcome =
    input.analyzer === "aih-trust-lint" ? runTrustLintV1(request) : runBindingGateV1(request);
  const late = lateness(input, "kept");
  if (late !== undefined) return { kind: "failed", stage: "execution", error: late };
  if (outcome.kind === "refused")
    return { kind: "refused", refusal: { reason: outcome.reason, detail: outcome.detail } };
  if (outcome.kind === "failed") return failed("execution", outcome.detail);
  // The engine's serialized text is what Core reads; an undefined-valued key in the frozen
  // object (the binding gate's typography.contextClass) is absent from it, as it is for Core.
  return {
    kind: "sarif",
    analyzerVersion: "1.0.0",
    sarif: parseStrictJsonObjectV1(outcome.sarifText, `${input.analyzer} SARIF`),
  };
}

/** Runs one engine-backed detector. Never throws; every shortfall is a typed outcome. */
export async function runEngineDetectorV1(input: EngineRunInputV1): Promise<EngineOutcomeV1> {
  if (engineRunsInProcessV1(input.analyzer)) {
    try {
      return inProcess(input);
    } catch (error) {
      return { kind: "failed", stage: "execution", error };
    }
  }
  const platform = platformName();
  const common = {
    sourceRoot: input.root,
    ...(input.runner === undefined ? {} : { runner: input.runner }),
    callerEnv: input.hostEnv,
    ...(input.signal === undefined ? {} : { signal: input.signal }),
    ...(input.deadline === undefined ? {} : { deadline: input.deadline }),
  };
  try {
    if (input.analyzer === "cisco-source-tree") {
      const ran = await runHostUvEngineV1({
        ...common,
        project: CISCO_SKILL_SCANNER_HOST_PROJECT_V1,
        version: CISCO_SKILL_SCANNER_VERSION_V1,
        tools: ["skill-scanner"],
        body: ({ run }) =>
          runCiscoSourceTreeScanV1({
            run: (argv, options) => run(argv, options ?? {}),
            platform,
            env: {},
            sourceRoot: input.root,
            selectedClosurePaths: input.selectedClosurePaths,
            ...(input.detectorOptions === undefined
              ? {}
              : { detectorOptions: input.detectorOptions }),
            // The host profile installs its own lock, so the engine names that project.
            analyzerProject: CISCO_SKILL_SCANNER_HOST_PROJECT_V1,
          }),
      });
      const outcome = ran.value;
      if (outcome.kind === "refused")
        return { kind: "refused", refusal: { reason: outcome.reason, detail: outcome.detail } };
      if (outcome.kind === "failed")
        return { kind: "failed", stage: outcome.stage, error: new TypeError(outcome.detail) };
      return {
        kind: "sarif",
        analyzerVersion: ran.analyzerVersion,
        sarif: parseStrictJsonObjectV1(outcome.sarifText, "Cisco merged SARIF"),
        hostRuntime: ran.hostRuntime,
      };
    }
    if (input.analyzer === "snyk-agent-scan") {
      const tree = realpathSync.native(input.root);
      const ran = await runHostUvEngineV1({
        ...common,
        project: SNYK_AGENT_SCAN_PROJECT,
        version: SNYK_AGENT_SCAN_VERSION,
        tools: ["snyk-agent-scan"],
        passEnv: [SNYK_TOKEN_ENV_VAR_V1],
        body: ({ run }) =>
          runSnykAgentScanRequestV1(run, {
            platform,
            tree,
            // Only the token crosses, through passEnv; the engine's scrubbed host env is unused.
            hostEnv: {},
            requestEnv: input.requestEnv,
          }),
      });
      const outcome = ran.value;
      if (outcome.kind === "refused") return { kind: "refused", refusal: outcome.refusal };
      if (outcome.kind === "failed") return failed(outcome.stage, outcome.detail);
      return {
        kind: "sarif",
        analyzerVersion: ran.analyzerVersion,
        sarif: parseStrictJsonObjectV1(outcome.sarifText, "snyk-agent-scan SARIF"),
        hostRuntime: ran.hostRuntime,
      };
    }
    const ran = await runHostUvEngineV1({
      ...common,
      project: CISCO_MCP_SCANNER_PROJECT_V1,
      version: CISCO_MCP_SCANNER_VERSION_V1,
      tools: ["mcp-scanner"],
      body: async ({ run, work }) => {
        const inputPath = join(work, "tools.json");
        const planned = planCiscoMcpScannerRequestV1({
          root: input.root,
          selectedClosurePaths: input.selectedClosurePaths,
          detectorOptions: input.detectorOptions,
          platform,
          env: {},
          inputPath,
        });
        if (planned.status === "refused") return planned;
        writeFileSync(inputPath, planned.plan.inputBytes, { flag: "wx", mode: 0o600 });
        return runCiscoMcpScannerPlanV1(planned.plan, async (argv, options) => {
          const result = await run(argv, options);
          return {
            stdout: result.stdout,
            stderr: result.stderr,
            exitCode: result.code,
            ...(result.spawnError === true ? { spawnError: true } : {}),
          };
        });
      },
    });
    const outcome = ran.value;
    if (outcome.status === "refused") return { kind: "refused", refusal: outcome.refusal };
    if (outcome.status === "failed")
      return failed(
        outcome.kind === "runner-failed" ? "execution" : "output",
        `mcp-scanner ${outcome.kind}: ${outcome.detail}`,
      );
    return {
      kind: "sarif",
      analyzerVersion: ran.analyzerVersion,
      sarif: outcome.sarif,
      hostRuntime: ran.hostRuntime,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    return {
      kind: "failed",
      stage: message.includes("environment acquisition")
        ? "acquisition"
        : message.includes("availability") || message.includes("analyzer lock")
          ? "availability"
          : "execution",
      error,
    };
  }
}
