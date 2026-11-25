import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { nativeNodeCli } from "./native-node-cli.js";

/**
 * A controlled analyzer CLI: a small Node program installed as an executable named like the
 * real analyzer. It is NOT SkillSpector or Cisco and never contacts an AI provider. It records
 * every call (argv, cwd, environment, the files it can see in the folder it was given) and
 * answers with the configured version text and report.
 */
export interface FakeAnalyzerBehaviour {
  readonly versionText: string;
  /** The flag naming the report path (`--output` for SkillSpector, `--output-json` for Cisco). */
  readonly outputFlag: string;
  /** The report to write; `null` writes nothing. */
  readonly report: unknown;
  readonly exit?: number;
  /** Start a long-lived child process, record both pids, and never exit. */
  readonly hang?: boolean;
  /** With `hang`: both processes ignore SIGTERM, so only a forced stop ends them. */
  readonly ignoreTerm?: boolean;
  /**
   * On `scan`, start this agent CLI by name from the analyzer's PATH, as SkillSpector's CLI
   * providers do (`<name> -p --output-format text`), and record its stdout as `agentStdout`.
   */
  readonly agentCli?: string;
  readonly agentModel?: string;
}

export interface FakeCall {
  readonly args: string[];
  readonly cwd: string;
  readonly env: Record<string, string>;
  /** Files visible in the scanned folder (argv folder, or the cwd for `.`). */
  readonly listing: string[];
  readonly writable: boolean;
  /** Windows attributes protect copied files even though directory creation is allowed. */
  readonly filesWritable: boolean;
  /** Stdout of the agent CLI started on `scan` when `agentCli` is configured. */
  readonly agentStdout?: string;
}

export interface FakeAnalyzer {
  readonly path: string;
  readonly dir: string;
  calls(): FakeCall[];
  pids(): { self: number; child: number } | undefined;
}

const program = `
const fs = require("node:fs");
const path = require("node:path");
const dir = __dirname;
const b = JSON.parse(fs.readFileSync(path.join(dir, "behaviour.json"), "utf8"));
const args = process.argv.slice(2);
const list = (root, prefix = "") => {
  const out = [];
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const rel = prefix ? prefix + "/" + entry.name : entry.name;
    if (entry.isDirectory()) out.push(...list(path.join(root, entry.name), rel));
    else out.push(rel);
  }
  return out.sort();
};
let listing = [];
let writable = false;
let filesWritable = false;
if (args[0] === "scan") {
  const folder = path.resolve(process.cwd(), args[1]);
  listing = list(folder);
  try {
    fs.writeFileSync(path.join(folder, "probe-write"), "x");
    writable = true;
  } catch (error) {
    writable = error.code !== "EACCES" && error.code !== "EROFS" && error.code !== "EPERM";
  }
  if (writable) fs.unlinkSync(path.join(folder, "probe-write"));
  for (const file of listing) {
    const target = path.join(folder, file);
    const original = fs.readFileSync(target);
    try { fs.writeFileSync(target, original); filesWritable = true; }
    catch (error) { if (!["EACCES", "EROFS", "EPERM"].includes(error.code)) throw error; }
  }
}
let agentStdout;
if (args[0] === "scan" && b.agentCli) {
  const agent = require("node:child_process").spawnSync(b.agentCli, ["-p", "--output-format", "text", ...(b.agentModel ? ["--model", b.agentModel] : [])], { input: "prompt", env: process.env, encoding: "utf8" });
  agentStdout = agent.stdout;
}
fs.appendFileSync(
  path.join(dir, "calls.jsonl"),
  JSON.stringify({ args, cwd: process.cwd(), env: process.env, listing, writable, filesWritable, agentStdout }) + "\\n",
);
if (args[0] === "--version") {
  process.stdout.write(b.versionText + "\\n");
  process.exit(0);
}
if (b.hang) {
  const keep = b.ignoreTerm ? "process.on('SIGTERM', () => {}); " : "";
  if (b.ignoreTerm) process.on("SIGTERM", () => {});
  const child = require("node:child_process").spawn(process.execPath, ["-e", keep + "setInterval(() => {}, 1000)"], { stdio: "ignore", windowsHide: true });
  fs.writeFileSync(path.join(dir, "pids.json"), JSON.stringify({ self: process.pid, child: child.pid }));
  setInterval(() => {}, 1000);
} else {
  const out = args.includes(b.outputFlag) ? args[args.indexOf(b.outputFlag) + 1] : undefined;
  if (b.report !== null) {
    if (out === undefined) process.stdout.write(JSON.stringify(b.report));
    else fs.writeFileSync(out, JSON.stringify(b.report));
  }
  if (out !== undefined) process.stdout.write("Report saved to: " + out + "\\n");
  process.exit(b.exit ?? 0);
}
`;

let installed = 0;

export function fakeAnalyzer(
  root: string,
  name: "skillspector" | "skill-scanner",
  behaviour: FakeAnalyzerBehaviour,
): FakeAnalyzer {
  installed += 1;
  const dir = join(root, `${name}-cli-${installed}`);
  mkdirSync(dir, { recursive: true });
  const path = nativeNodeCli(dir, name, program);
  writeFileSync(join(dir, "behaviour.json"), JSON.stringify(behaviour));
  return {
    path,
    dir,
    calls() {
      const file = join(dir, "calls.jsonl");
      if (!existsSync(file)) return [];
      return readFileSync(file, "utf8")
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as FakeCall);
    },
    pids() {
      const file = join(dir, "pids.json");
      return existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : undefined;
    },
  };
}

/** `true` while a process with this pid can still run. Linux zombies have already exited. */
export function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
  if (process.platform === "linux") {
    try {
      const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
      const close = stat.lastIndexOf(")");
      if (close > 0 && /^\s+Z(?:\s|$)/u.test(stat.slice(close + 1))) return false;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
      // A state we cannot read is not evidence that the process has exited.
    }
  }
  return true;
}

/** A SkillSpector 2.13.6 JSON report in the upstream shape (fields as the real CLI writes them). */
export function skillSpectorReport(
  issues: readonly Record<string, unknown>[],
  overrides: Readonly<{
    llm?: boolean;
    status?: string;
    analyzerStatuses?: readonly Record<string, unknown>[];
    ledgerExceptions?: readonly Record<string, unknown>[];
    executionSuccessful?: boolean;
    version?: string;
    provenance?: Record<string, unknown>;
    completeness?: Record<string, unknown>;
  }> = {},
): Record<string, unknown> {
  return {
    skill: { name: "fixture", source: "/scan/item", scanned_at: "2026-11-01T00:00:00+00:00" },
    risk_assessment: { score: 100, severity: "CRITICAL", recommendation: "DO_NOT_INSTALL" },
    components: [],
    structured_summaries: [],
    issues,
    suppressed_count: 0,
    suppressed: [],
    metadata: {
      skillspector_version: overrides.version ?? "2.13.6",
      llm_requested: overrides.llm ?? false,
      llm_available: overrides.llm ?? false,
      llm_provenance: overrides.provenance ?? {
        schema_version: 1,
        provider: { configured_adapter: "unknown", effective_adapter: "not_applicable" },
        analyzers: [],
      },
    },
    execution_successful: overrides.executionSuccessful ?? true,
    analysis_completeness: {
      total_components: 0,
      scanned_components: 0,
      coverage_percent: 100,
      status: overrides.status ?? "complete",
      is_complete: ["complete", "complete_with_caveats"].includes(overrides.status ?? "complete"),
      execution_successful: overrides.executionSuccessful ?? true,
      fully_inspected_files: 0,
      partially_inspected_files: 0,
      entirely_uninspected_files: 0,
      analyzer_statuses: overrides.analyzerStatuses ?? [
        { analyzer_id: "artifact_integrity", status: "completed" },
        { analyzer_id: "semantic_security_discovery", status: "disabled" },
      ],
      ledger_exceptions: overrides.ledgerExceptions ?? [],
      scope_exclusions: [],
      limitations: [],
      dependency_inspection: {
        enabled: false,
        status: "not_requested",
        mode: "static_local",
        locked_entries: 0,
        inspected_artifacts: 0,
        artifacts: [],
      },
      ...overrides.completeness,
    },
  };
}

export function skillSpectorIssue(
  id: string,
  file: string,
  line: number,
  severity: string,
  confidence: number,
  pattern: string | null = id,
): Record<string, unknown> {
  return {
    id,
    finding_id: `finding-${Math.random().toString(16).slice(2)}`,
    category: "Category",
    pattern,
    severity,
    confidence,
    location: { file, start_line: line, end_line: null, start_column: 0 },
    finding: "matched supplied text",
    explanation: "why",
    remediation: "fix",
    code_snippet: "snippet",
    match_fingerprint: `${id.toLowerCase().padEnd(8, "0")}${"ab".repeat(28)}`,
    occurrences: [{ file, start_line: line }],
    surface: "instructions",
  };
}

/** A Cisco skill-scanner 2.3.2 JSON report in the upstream shape. */
export function ciscoReport(findings: readonly Record<string, unknown>[]): Record<string, unknown> {
  return {
    skill_name: "fixture",
    skill_path: "/scan/item",
    is_safe: findings.length === 0,
    max_severity: "HIGH",
    findings_count: findings.length,
    findings,
    analyzers_used: [
      "static_analyzer",
      "bytecode",
      "pipeline",
      "correlation",
      "behavioral_analyzer",
    ],
  };
}

export function ciscoFinding(
  ruleId: string,
  category: string,
  severity: string,
  file: string,
  line: number | null,
): Record<string, unknown> {
  return {
    id: `${ruleId}_0123456789`,
    rule_id: ruleId,
    category,
    severity,
    title: `${ruleId} title`,
    description: "supplied text",
    file_path: file,
    line_number: line,
    snippet: null,
    analyzer: "static",
  };
}
