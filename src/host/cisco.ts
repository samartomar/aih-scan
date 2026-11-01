import { posix, win32 } from "node:path";
import {
  type HostEnv,
  probeVersion,
  readJsonReport,
  runAnalyzer,
  scratchFolder,
  selectAnalyzer,
  staticAnalyzerEnv,
} from "./analyzer-process.js";
import { analyzerFinding, notRun, objectOf } from "./analyzer-report.js";
import type { AssessItem, ToolAdapter, ToolContext, ToolFinding, ToolRun } from "./tools.js";

/** The Cisco skill-scanner release Scan runs (PyPI `cisco-ai-skill-scanner==2.3.2`). */
export const CISCO_VERSION = "2.3.2";
/** Selects an exact `skill-scanner` executable, or `none` to disable it. */
export const CISCO_VARIABLE = "AIH_SCAN_SKILL_SCANNER";

/**
 * The command line of one Cisco run: `skill-scanner scan . --use-behavioral` from inside Scan's
 * working copy (Cisco reports paths relative to its working folder), JSON written to `report`.
 * No LLM, VirusTotal, AI Defense, OSV, meta or remote-repository option is ever passed, and the
 * environment is scrubbed, so the run is static and offline. Behavioral analysis parses code
 * (AST and dataflow) and never executes it.
 */
export function ciscoInvocation(
  input: Readonly<{
    executable: string;
    folder: string;
    report: string;
    scratch: string;
    env: HostEnv;
    platform: NodeJS.Platform;
  }>,
): Readonly<{ argv: readonly string[]; env: Readonly<Record<string, string>>; cwd: string }> {
  return Object.freeze({
    argv: Object.freeze([
      input.executable,
      "scan",
      ".",
      "--use-behavioral",
      "--format",
      "json",
      "--output-json",
      input.report,
    ]),
    env: Object.freeze(staticAnalyzerEnv(input.env, input.scratch, input.platform)),
    cwd: input.folder,
  });
}

const SEVERITIES = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);

/** Turns one Cisco skill-scanner 2.3.2 JSON report into Scan's tool run (no confidence field upstream). */
export function ciscoRun(report: unknown, item: AssessItem): ToolRun {
  const document = objectOf(report);
  if (document === undefined || !Array.isArray(document.findings))
    return notRun(
      "failed",
      "static",
      CISCO_VERSION,
      "Cisco skill-scanner wrote no readable report",
    );
  const findings: ToolFinding[] = [];
  const rules: Record<string, string> = {};
  for (const raw of document.findings) {
    const entry = objectOf(raw);
    if (entry === undefined || typeof entry.rule_id !== "string" || entry.rule_id.length === 0)
      continue;
    const severity =
      typeof entry.severity === "string" && SEVERITIES.has(entry.severity.toUpperCase())
        ? (entry.severity.toUpperCase() as ToolFinding["severity"])
        : undefined;
    const title =
      typeof entry.title === "string" && entry.title.length > 0 ? entry.title : entry.rule_id;
    const finding = analyzerFinding(item, {
      ruleId: entry.rule_id,
      message: title,
      file: entry.file_path,
      line: entry.line_number,
      severity,
      confidence: undefined,
      category:
        typeof entry.category === "string" && /^[a-z_]{1,64}$/u.test(entry.category)
          ? entry.category
          : undefined,
    });
    if (finding === undefined) continue;
    findings.push(finding);
    rules[finding.ruleId] ??= title;
  }
  return Object.freeze({
    status: "ran" as const,
    version: CISCO_VERSION,
    mode: "static" as const,
    findings: Object.freeze(findings),
    rules: Object.freeze(rules),
  });
}

export interface CiscoOptions {
  readonly env?: HostEnv;
  readonly platform?: NodeJS.Platform;
}

/**
 * The optional Cisco skill-scanner adapter, run only when the caller names `cisco`. It is a
 * skill scanner: an item without a root `SKILL.md` is `not-applicable` (Cisco's lenient fallback
 * would report findings against a `SKILL.md` that does not exist). Its outcomes never change
 * required coverage. Always static, even in AI mode.
 */
export function ciscoAdapter(options: CiscoOptions = {}): ToolAdapter {
  const env = options.env ?? process.env;
  const platform = options.platform ?? process.platform;
  return Object.freeze({
    id: "cisco" as const,
    version: CISCO_VERSION,
    async run(item: AssessItem, context: ToolContext): Promise<ToolRun> {
      if (context.signal.aborted) return notRun("cancelled", "static", CISCO_VERSION);
      if (!item.files.some((file) => file.path === "SKILL.md"))
        return Object.freeze({
          status: "not-applicable" as const,
          version: CISCO_VERSION,
          mode: "static" as const,
          detail: "Cisco skill-scanner reads skills; this item has no SKILL.md",
        });
      const selection = selectAnalyzer("skill-scanner", CISCO_VARIABLE, env, platform);
      if (selection.status === "missing")
        return notRun("unavailable", "static", CISCO_VERSION, selection.detail);
      const scratch = scratchFolder("aih-scan-cisco-");
      try {
        const probeEnv = staticAnalyzerEnv(env, scratch.path, platform);
        const version = await probeVersion(
          selection.executable,
          probeEnv,
          scratch.path,
          /skill-scanner,? (?:version )?v?(\d+\.\d+\.\d+)/u,
          context.signal,
        );
        if (context.signal.aborted) return notRun("cancelled", "static", CISCO_VERSION);
        if (version !== CISCO_VERSION)
          return notRun(
            "unavailable",
            "static",
            CISCO_VERSION,
            version === undefined
              ? "the installed skill-scanner did not report its version"
              : `the installed skill-scanner is ${version}; Scan runs ${CISCO_VERSION}`,
          );
        const report = (platform === "win32" ? win32 : posix).join(scratch.path, "cisco.json");
        const invocation = ciscoInvocation({
          executable: selection.executable.path,
          folder: item.snapshotRoot,
          report,
          scratch: scratch.path,
          env,
          platform,
        });
        const result = await runAnalyzer(invocation.argv, {
          cwd: invocation.cwd,
          env: invocation.env,
          signal: context.signal,
        });
        if (result.termination === "timeout") return notRun("timeout", "static", CISCO_VERSION);
        if (result.termination === "abort") return notRun("cancelled", "static", CISCO_VERSION);
        if (result.termination !== undefined)
          return notRun("failed", "static", CISCO_VERSION, `skill-scanner ${result.termination}`);
        if (result.code !== 0)
          return notRun("failed", "static", CISCO_VERSION, `skill-scanner exited ${result.code}`);
        return ciscoRun(readJsonReport(report, "Cisco report"), item);
      } finally {
        scratch.dispose();
      }
    },
  });
}
