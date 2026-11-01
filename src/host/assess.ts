import { createHash } from "node:crypto";
import { codeForRule } from "../contracts/codes.js";
import { formats } from "../contracts/formats.js";
import { limits } from "../contracts/limits.js";
import {
  type FindingPart,
  type ScoredFinding,
  scoreFindings,
  severityOf,
  storedLabel,
} from "../contracts/risk.js";
import { type RoutedFile, routeFile, type ToolId, toolsForPart } from "../contracts/routing.js";
import { sanitizeText } from "../contracts/text.js";
import type {
  Origin,
  ScanMode,
  Summary,
  SummaryDependency,
  SummaryTool,
} from "../contracts/validate.js";
import { packageIdentity } from "../public/package-identity.js";
import type { SnapshotFile } from "./snapshot.js";
import type { AssessItem, ToolAdapter, ToolContext, ToolFinding, ToolRun } from "./tools.js";

export interface AssessSettings {
  readonly origin: Origin;
  readonly mode: ScanMode;
  /** The caller's tool selection; undefined selects every routed tool. aih-trust-lint always runs. */
  readonly tools: readonly ToolId[] | undefined;
  readonly internalScopes: readonly string[];
  readonly signal: AbortSignal;
  readonly now: () => Date;
  readonly timeoutMs: number;
}

export interface SarifDocument {
  readonly tool: string;
  readonly path: string;
  readonly bytes: Uint8Array;
  readonly sha256: string;
}

export interface Assessment {
  readonly summary: Summary;
  /** Unsigned notes for the caller (tool details, AI availability); never in the summary or SARIF. */
  readonly notes: readonly string[];
  readonly summaryBytes: Uint8Array;
  readonly sarif: readonly SarifDocument[];
}

export function routeFiles(files: readonly SnapshotFile[]): ReadonlyMap<string, RoutedFile> {
  return new Map(files.map((file) => [file.path, routeFile(file.path, file.bytes)]));
}

const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const codeUnit = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
const encoder = new TextEncoder();

/** How long (at most; never longer than the tool limit) a stopped adapter may take to end its processes. */
const SETTLE_GRACE_MS = 10_000;

async function runWithLimit(
  adapter: ToolAdapter,
  item: AssessItem,
  context: ToolContext,
  timeoutMs: number,
): Promise<ToolRun> {
  const timeout = new AbortController();
  const signal = AbortSignal.any([context.signal, timeout.signal]);
  const ended = (reason: "timeout" | "cancelled" | "failed"): ToolRun =>
    Object.freeze({
      status: "not-run" as const,
      version: adapter.version,
      mode: context.mode,
      reason,
    });
  let timer: ReturnType<typeof setTimeout> | undefined;
  let timedOut = false;
  const running = adapter.run(item, { ...context, signal }).catch(() => ended("failed"));
  const stopped = new Promise<"stopped">((resolve) => {
    timer = setTimeout(() => {
      timedOut = true;
      timeout.abort();
      resolve("stopped");
    }, timeoutMs);
    if (context.signal.aborted) resolve("stopped");
    else context.signal.addEventListener("abort", () => resolve("stopped"), { once: true });
  });
  try {
    const first = await Promise.race([running, stopped]);
    if (first !== "stopped") {
      if (context.signal.aborted && first.status !== "not-run") return ended("cancelled");
      return first;
    }
    // Let the adapter end its process tree (bounded) before the working copy is removed.
    let grace: ReturnType<typeof setTimeout> | undefined;
    const run = await Promise.race([
      running,
      new Promise<undefined>((resolve) => {
        grace = setTimeout(() => resolve(undefined), Math.min(SETTLE_GRACE_MS, timeoutMs));
      }),
    ]);
    if (grace !== undefined) clearTimeout(grace);
    const notes = run?.notes;
    const outcome = ended(timedOut && !context.signal.aborted ? "timeout" : "cancelled");
    return notes === undefined ? outcome : Object.freeze({ ...outcome, notes });
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function toolResult(findings: readonly ToolFinding[]): SummaryTool["result"] {
  if (findings.length === 0) return "pass";
  return findings.some((finding) => ["CRITICAL", "HIGH"].includes(severityOf(finding)))
    ? "fail"
    : "warn";
}

function sarifOf(
  scanKey: string,
  tool: string,
  run: Extract<ToolRun, { status: "ran" }>,
  item: AssessItem,
  codes: (f: ToolFinding) => string,
): Uint8Array {
  const usedRules = [...new Set(run.findings.map((finding) => finding.ruleId))].sort(codeUnit);
  const findings = [...run.findings].sort(
    (a, b) =>
      codeUnit(a.path, b.path) ||
      a.line - b.line ||
      codeUnit(a.ruleId, b.ruleId) ||
      codeUnit(a.message, b.message),
  );
  const document = {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: tool,
            version: run.version,
            rules: usedRules.map((id) => ({
              id,
              shortDescription: { text: run.rules?.[id] ?? id },
            })),
          },
        },
        invocations: [{ executionSuccessful: true }],
        artifacts: item.files.map((file) => ({
          location: { uri: file.path },
          hashes: { "sha-256": file.sha256 },
        })),
        results: findings.map((finding) => ({
          ruleId: finding.ruleId,
          ...(finding.level === undefined ? {} : { level: finding.level }),
          message: { text: sanitizeText(finding.message, limits.output.findingText) },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: finding.path },
                region: { startLine: finding.line },
              },
            },
          ],
          ...(finding.fingerprint === undefined
            ? {}
            : { partialFingerprints: { "aih-scan/v1": finding.fingerprint } }),
          properties: {
            scanKey,
            part: finding.part,
            code: codes(finding),
            ...(finding.severity === undefined ? {} : { severity: finding.severity }),
            ...(finding.confidence === undefined ? {} : { confidence: finding.confidence }),
          },
        })),
      },
    ],
  };
  return encoder.encode(`${JSON.stringify(document)}\n`);
}

/**
 * Assesses one item's exact inventory: routes every file, runs the routed tools (aih-trust-lint
 * always), measures coverage against the routed tools only, scores with `aih-risk/1` and returns
 * the summary and one SARIF document per tool that ran. Cisco never counts for coverage.
 */
export async function assessItem(
  item: AssessItem,
  adapters: ReadonlyMap<ToolId, ToolAdapter>,
  settings: AssessSettings,
): Promise<Assessment> {
  const routed = item.routed;
  const parts = new Set<FindingPart>();
  for (const file of item.files) parts.add(routed.get(file.path)?.part ?? "none");
  const routable = [...parts].some((part) => part !== "none");
  const required = new Set<ToolId>();
  for (const part of parts)
    if (part !== "none") for (const tool of toolsForPart(part)) required.add(tool);
  const explicit = new Set<ToolId>(settings.tools ?? []);
  const selected = new Set<ToolId>(settings.tools ?? [...required]);
  const context: ToolContext = {
    mode: settings.mode,
    signal: settings.signal,
    internalScopes: settings.internalScopes,
  };
  const findings: ScoredFinding[] = [];
  const sarif: SarifDocument[] = [];
  const tools: SummaryTool[] = [];
  const notRunReasons = new Set<string>();
  const notes: string[] = [];
  /** Files whose secret check ran in this assessment (only a completed trust-lint run). */
  const secretsChecked = new Set<string>();
  for (const tool of ["aih-trust-lint", "skillspector", "cisco"] as const) {
    const adapter = adapters.get(tool);
    const version = adapter?.version ?? "unknown";
    const counts =
      tool !== "cisco" && (required.has(tool) || (tool === "aih-trust-lint" && routable));
    let run: ToolRun;
    if (
      tool === "aih-trust-lint" ||
      (tool === "cisco" ? explicit.has(tool) : required.has(tool) && selected.has(tool))
    ) {
      run =
        adapter === undefined
          ? Object.freeze({
              status: "not-run" as const,
              version,
              mode: settings.mode,
              reason: "unavailable" as const,
            })
          : await runWithLimit(adapter, item, context, settings.timeoutMs);
    } else if (required.has(tool) && tool !== "cisco") {
      run = Object.freeze({
        status: "not-run" as const,
        version,
        mode: settings.mode,
        reason: "not selected" as const,
      });
    } else {
      if (explicit.has(tool))
        tools.push(
          Object.freeze({
            tool,
            version,
            mode: settings.mode,
            result: "not-applicable" as const,
            counts: {},
          }),
        );
      continue;
    }
    for (const note of run.notes ?? []) notes.push(note);
    if (run.status === "not-applicable") {
      if (run.detail !== undefined) notes.push(`${tool}: ${run.detail}`);
      tools.push(
        Object.freeze({
          tool,
          version: run.version,
          mode: run.mode,
          result: "not-applicable" as const,
          counts: {},
        }),
      );
      continue;
    }
    if (run.status === "not-run") {
      if (counts) notRunReasons.add(run.reason);
      if (run.detail !== undefined) notes.push(`${tool}: ${run.reason}: ${run.detail}`);
      tools.push(
        Object.freeze({
          tool,
          version: run.version,
          mode: run.mode,
          result: "not-run" as const,
          reason: run.reason,
          counts: {},
        }),
      );
      continue;
    }
    if (tool === "aih-trust-lint")
      for (const path of run.secretsChecked ?? []) secretsChecked.add(path);
    if (run.failedPart !== undefined) {
      if (counts) notRunReasons.add("failed");
      notes.push(`${tool}: ${run.failedPart}`);
    }
    const codeOf = (finding: ToolFinding) => codeForRule(tool, finding.ruleId, finding.category);
    const bytes = sarifOf(item.scanKey, tool, run, item, codeOf);
    const digest = sha256(bytes);
    sarif.push(Object.freeze({ tool, path: `sarif/${digest}.sarif`, bytes, sha256: digest }));
    const severityCounts: Record<string, number> = {};
    for (const finding of run.findings) {
      const key = severityOf(finding).toLowerCase();
      severityCounts[key] = (severityCounts[key] ?? 0) + 1;
      // Cisco findings are scored like any tool's (cross-tool deduplication applies);
      // only coverage ignores Cisco.
      findings.push({
        tool,
        ruleId: finding.ruleId,
        code: codeOf(finding),
        severity: finding.severity,
        level: finding.level,
        confidence: finding.confidence,
        part: finding.part,
        path: finding.path,
        line: finding.line,
      });
    }
    tools.push(
      Object.freeze({
        tool,
        version: run.version,
        mode: run.mode,
        ...(run.ai === undefined ? {} : { ai: run.ai }),
        result: toolResult(run.findings),
        counts: Object.freeze(severityCounts),
        ...(run.suppressed === undefined || run.suppressed.length === 0
          ? {}
          : { suppressed: run.suppressed }),
      }),
    );
  }
  const coverage = notRunReasons.size > 0 ? ("partial" as const) : ("complete" as const);
  const { score } = scoreFindings(findings);
  const dependencies: SummaryDependency[] = [];
  for (const file of item.files)
    for (const dependency of routed.get(file.path)?.dependencies ?? [])
      dependencies.push(dependency);
  const summary: Summary = Object.freeze({
    format: formats.summary,
    scanKey: item.scanKey,
    revision: 1,
    origin: settings.origin,
    scannedAt: `${settings.now().toISOString().slice(0, 19)}Z`,
    scanner: `${packageIdentity.name} ${packageIdentity.version}`,
    routing: formats.routing,
    scoring: formats.scoring,
    score,
    label: storedLabel({ score, coverage, routable }),
    coverage,
    ...(coverage === "partial" ? { reason: [...notRunReasons].sort(codeUnit).join(", ") } : {}),
    files: Object.freeze(
      item.files.map((file) =>
        Object.freeze({
          path: file.path,
          mode: file.mode,
          part: routed.get(file.path)?.part ?? "none",
          sha256: file.sha256,
        }),
      ),
    ),
    tools: Object.freeze(tools),
    notAnalysed: Object.freeze(
      item.files
        .filter((file) => (routed.get(file.path)?.part ?? null) === null)
        .map((file) =>
          Object.freeze({ path: file.path, secretsChecked: secretsChecked.has(file.path) }),
        ),
    ),
    sarif: Object.freeze(
      [...sarif]
        .sort((a, b) => codeUnit(a.path, b.path))
        .map((entry) => Object.freeze({ path: entry.path, sha256: entry.sha256 })),
    ),
    dependencies: Object.freeze(dependencies),
  });
  return Object.freeze({
    summary,
    summaryBytes: encoder.encode(`${JSON.stringify(summary, null, 2)}\n`),
    notes: Object.freeze([...new Set(notes)]),
    sarif: Object.freeze(sarif),
  });
}
