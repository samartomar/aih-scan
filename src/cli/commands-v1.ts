import { lstatSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { formats } from "../contracts/formats.js";
import { limits } from "../contracts/limits.js";
import {
  displayLabel,
  failAtReached,
  type RiskLabel,
  type SummaryLabel,
} from "../contracts/risk.js";
import { kinds, optionalTools } from "../contracts/routing.js";
import { pathProblem, sanitizeText } from "../contracts/text.js";
import type { Summary } from "../contracts/validate.js";
import {
  type Rollup,
  type ScanInternals,
  type ScanItemResult,
  type ScanResult,
  type SharedOutput,
  scanWith,
} from "../host/scan.js";
import { skillSpectorAiSetup } from "../host/skillspector.js";
import { FINDINGS_MISMATCH_MESSAGE, type Finding, readFindings } from "../read/read-findings.js";
import { readSummary } from "../read/read-summary.js";
import { TargetError, targetSource } from "./targets-v1.js";

/** 0 finished (complete or partial); 1 only with --fail-at; 2 could not scan or read; 130 cancelled. */
export const exitCodes = Object.freeze({ ok: 0, failAt: 1, input: 2, cancelled: 130 });

export interface CommandIo {
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
  readonly cancellation?: AbortSignal;
  readonly cwd?: string;
  /** Internal seams passed to the host scan (an npm registry stub, a fixed clock, adapters). */
  readonly internals?: Omit<ScanInternals, "sharedOutput">;
}

export const scanUsage = `${[
  "Usage: aih-scan scan <target> [<target>...] --out <new-folder> [options]",
  "",
  "Targets:",
  "  <folder>                    a folder or a local clone (private repositories stay local)",
  "  <owner/repo | https-url>    a public Git repository, with --ref <name>",
  "  <github item link>          https://github.com/<owner>/<repo>/tree/<ref>/<path>",
  "  npm:<package>@<version>     a public npm MCP package (exact version)",
  "  npm-file:<package.tgz>      a downloaded npm package tarball",
  "  mcp-url:<url>               remote MCP configuration only; the endpoint is never contacted",
  "",
  "Finds skills, agents, commands, rules, hooks and MCP configs: one result per item, one for",
  "the remaining files and a roll-up. Each item is keyed by its Git tree hash. Git and npm",
  "sources are fetched before scanning; supplied content is never executed and static mode",
  "makes no network calls.",
  "",
  "Options:",
  "  --out <new-folder>          required; must not exist",
  "  --ref <name>                branch, tag or full commit of a Git target",
  "  --tools <list>              skillspector,aih-trust-lint[,cisco]; aih-trust-lint always runs",
  "  --mode static|ai            default static; ai adds SkillSpector's AI pass using your",
  "                              existing SKILLSPECTOR_PROVIDER settings and sends the scanned",
  "                              content to that AI",
  "  --origin published|local    default local",
  "  --kinds <list>              skill,agent,command,rule,hook,mcp",
  "  --internal-scope <@scope>   repeatable",
  "  --fail-at CAUTION|DO_NOT_INSTALL   exit 1 when a stored label reaches it",
  "  --json | --quiet",
  "",
  "Exit: 0 finished (complete or partial), 1 only with --fail-at, 2 could not scan, 130 cancelled.",
].join("\n")}\n`;

const readUsage =
  "Usage: aih-scan read <summary.json> [--json] [--fail-at CAUTION|DO_NOT_INSTALL]\n";
const findingsUsage = "Usage: aih-scan findings <summary.json> --key <scanKey> [--json]\n";

export class UsageError extends Error {}

export interface Parsed {
  readonly positional: string[];
  readonly values: Map<string, string[]>;
  readonly flags: Set<string>;
}

export function parse(
  args: readonly string[],
  valued: readonly string[],
  booleans: readonly string[],
): Parsed {
  const positional: string[] = [];
  const values = new Map<string, string[]>();
  const flags = new Set<string>();
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index] as string;
    if (arg === "--") {
      positional.push(...args.slice(index + 1));
      break;
    }
    if (arg.startsWith("--")) {
      const [name, inline] = arg.includes("=")
        ? [arg.slice(0, arg.indexOf("=")), arg.slice(arg.indexOf("=") + 1)]
        : [arg, undefined];
      if (booleans.includes(name)) {
        if (inline !== undefined) throw new UsageError(`${name} takes no value`);
        flags.add(name);
        continue;
      }
      if (!valued.includes(name)) throw new UsageError(`unknown option ${sanitizeText(name, 64)}`);
      if (inline === undefined) index += 1;
      const value = inline ?? args[index];
      if (value === undefined || value.length === 0) throw new UsageError(`${name} needs a value`);
      values.set(name, [...(values.get(name) ?? []), value]);
      continue;
    }
    positional.push(arg);
  }
  return { positional, values, flags };
}

export function single(parsed: Parsed, name: string): string | undefined {
  const list = parsed.values.get(name);
  if (list !== undefined && list.length > 1) throw new UsageError(`${name} may be given once`);
  return list?.[0];
}

function list(
  value: string | undefined,
  allowed: readonly string[],
  name: string,
): string[] | undefined {
  if (value === undefined) return undefined;
  const entries = value.split(",").map((entry) => entry.trim());
  for (const entry of entries)
    if (!allowed.includes(entry)) throw new UsageError(`${name} accepts ${allowed.join(", ")}`);
  return entries;
}

function failAtOf(value: string | undefined): RiskLabel | undefined {
  if (value === undefined) return undefined;
  if (value === "CAUTION") return "CAUTION";
  if (value === "DO_NOT_INSTALL" || value === "DO NOT INSTALL") return "DO NOT INSTALL";
  throw new UsageError("--fail-at accepts CAUTION or DO_NOT_INSTALL");
}

const safe = (value: string, max: number = limits.output.findingPath) => sanitizeText(value, max);

export function readSummaryFile(path: string): { summary: Summary } | { problem: string } {
  try {
    const stat = lstatSync(path);
    if (!stat.isFile()) return { problem: "summary is not a regular file" };
    if (stat.size > limits.output.summaryBytes)
      return { problem: "summary exceeds the size limit" };
    const read = readSummary(new Uint8Array(readFileSync(path)));
    if (read.status !== "ok")
      return {
        problem: `summary ${read.status}${read.detail ? `: ${safe(read.detail, 300)}` : ""}`,
      };
    return { summary: read.summary };
  } catch {
    return { problem: "summary could not be read" };
  }
}

function summaryLines(summary: Summary): string {
  const lines = [
    `${displayLabel(summary)}  score ${summary.score}  ${summary.scanKey}`,
    `  coverage ${summary.coverage}${summary.reason ? ` (${safe(summary.reason, 200)})` : ""}; routing ${summary.routing}; scoring ${summary.scoring}`,
    `  scanned ${summary.scannedAt} by ${safe(summary.scanner, 128)}; origin ${summary.origin}; revision ${summary.revision}`,
    ...summary.tools.map(
      (tool) =>
        `  ${safe(tool.tool, 64)} ${safe(tool.version, 64)} ${tool.mode}: ${tool.result}${tool.reason ? ` (${safe(tool.reason, 200)})` : ""}${
          Object.keys(tool.counts).length > 0
            ? ` ${Object.entries(tool.counts)
                .map(([key, count]) => `${key} ${count}`)
                .join(", ")}`
            : ""
        }`,
    ),
    `  files ${summary.files.length}; not analysed ${summary.notAnalysed.length}${
      summary.notAnalysed.length > 0
        ? ` (${summary.notAnalysed.map((entry) => `${safe(entry.path)}${entry.secretsChecked ? " secrets checked" : " binary"}`).join("; ")})`
        : ""
    }`,
  ];
  if (summary.dependencies.length > 0)
    lines.push(
      `  dependencies ${summary.dependencies.map((d) => `${safe(d.name, 214)}@${d.version === null ? "?" : safe(d.version, 64)}`).join(", ")}`,
    );
  return `${lines.join("\n")}\n`;
}

function resultLine(entry: ScanItemResult, summary: Summary | undefined): string {
  const name = `${entry.kind === undefined ? "" : `${entry.kind} `}${safe(entry.path)}`;
  if (entry.status !== "ok")
    return `${name}: ${entry.status} (${safe(entry.reason, 200)})${entry.detail ? ` ${safe(entry.detail, 300)}` : ""}\n`;
  if (summary === undefined) return `${name}: summary unreadable\n`;
  const notes = (entry.notes ?? []).map((note) => `  note: ${safe(note, 300)}\n`).join("");
  return `${name}\n  ${summaryLines(summary).trimEnd().split("\n").join("\n  ")}\n${notes}  summary ${safe(entry.summaryPath, 4096)}\n`;
}

function rollupLine(rollup: Rollup): string {
  const counts = (record: Readonly<Record<string, number | undefined>>) =>
    Object.entries(record)
      .map(([kind, count]) => `${kind} ${count}`)
      .join(", ");
  const parts = [
    `${displayLabel(rollup)}${rollup.reason ? ` (${safe(rollup.reason, 200)})` : ""}`,
    `${rollup.items} scanned, ${rollup.partial} partial, ${rollup.notAssessed} NOT ASSESSED`,
    `found ${counts(rollup.found) || "no items"}`,
    `remaining files ${rollup.remainingFiles}`,
  ];
  if (Object.keys(rollup.notSelected).length > 0)
    parts.push(`not selected ${counts(rollup.notSelected)}`);
  return `Roll-up: ${parts.join("; ")}\n`;
}

/**
 * `aih-scan scan <target...> --out <new-folder>`: each target is a source (folder, Git
 * repository or item link, npm package or tarball, remote MCP configuration) scanned by
 * discovery into one shared new output folder.
 */
export async function runScanCommandV1(args: readonly string[], io: CommandIo): Promise<number> {
  if (args.length === 1 && (args[0] === "--help" || args[0] === "-h")) {
    io.stdout(scanUsage);
    return exitCodes.ok;
  }
  const outcomes: { target: string; result: ScanResult }[] = [];
  let failAt: RiskLabel | undefined;
  let json = false;
  let quiet = false;
  try {
    const parsed = parse(
      args,
      [
        "--out",
        "--ref",
        "--tools",
        "--mode",
        "--origin",
        "--kinds",
        "--internal-scope",
        "--fail-at",
      ],
      ["--json", "--quiet"],
    );
    if (parsed.positional.length === 0) throw new UsageError("name at least one target");
    const out = single(parsed, "--out");
    if (out === undefined) throw new UsageError("--out <new-folder> is required");
    json = parsed.flags.has("--json");
    quiet = parsed.flags.has("--quiet");
    if (json && quiet) throw new UsageError("--json and --quiet cannot be combined");
    failAt = failAtOf(single(parsed, "--fail-at"));
    const tools = list(single(parsed, "--tools"), optionalTools, "--tools");
    const selectedKinds = list(single(parsed, "--kinds"), kinds, "--kinds");
    const mode = single(parsed, "--mode");
    const origin = single(parsed, "--origin") ?? "local";
    const ref = single(parsed, "--ref");
    const scopes = parsed.values.get("--internal-scope") ?? [];
    for (const scope of scopes)
      if (!/^@[a-z0-9][a-z0-9._~-]*$/.test(scope))
        throw new UsageError("--internal-scope takes @scope");
    const cwd = io.cwd ?? process.cwd();
    const sources = parsed.positional.map((target) => {
      try {
        return targetSource(target, cwd, ref);
      } catch (error) {
        throw new UsageError(error instanceof TargetError ? error.message : "unreadable target");
      }
    });
    if (mode === "ai") {
      // Said before anything is scanned, on stderr, whatever the output format.
      const setup = skillSpectorAiSetup(io.internals?.env ?? process.env);
      io.stderr(
        setup.available
          ? `aih-scan: AI mode: SkillSpector sends the content it scans to the AI you set up (provider ${setup.provider}, via ${setup.via}); static checks run too.\n`
          : `aih-scan: AI not available here: ${safe(setup.reason, 200)}. SkillSpector runs static checks only; no content is sent to an AI.\n`,
      );
    }
    const shared: SharedOutput = { outDir: resolve(cwd, out), written: new Map() };
    for (const [index, source] of sources.entries()) {
      const request = {
        format: formats.request,
        origin,
        source,
        ...(selectedKinds === undefined ? {} : { kinds: selectedKinds }),
        ...(tools === undefined ? {} : { tools }),
        ...(mode === undefined ? {} : { mode }),
      };
      const result = await scanWith(
        request,
        {
          outDir: shared.outDir,
          ...(io.cancellation === undefined ? {} : { signal: io.cancellation }),
          internalScopes: [...new Set(scopes)].sort(),
        },
        { ...io.internals, sharedOutput: shared },
      );
      outcomes.push({ target: parsed.positional[index] as string, result });
      if (result.status === "cancelled") break;
      // An existing or unusable output folder stops every target.
      if (
        "reason" in result &&
        (result.reason === "output-exists" || result.reason === "output-unavailable")
      )
        break;
    }
  } catch (error) {
    if (error instanceof UsageError) {
      io.stderr(`aih-scan: ${error.message}\n${scanUsage}`);
      return exitCodes.input;
    }
    io.stderr("aih-scan: the scan could not complete\n");
    return exitCodes.input;
  }
  const summaries = new Map<string, Summary>();
  for (const { result } of outcomes)
    for (const entry of result.results) {
      if (entry.status !== "ok" || summaries.has(entry.summaryPath)) continue;
      const read = readSummaryFile(entry.summaryPath);
      if ("summary" in read) summaries.set(entry.summaryPath, read.summary);
    }
  const cancelled = outcomes.some(({ result }) => result.status === "cancelled");
  const failed = outcomes.some(
    ({ result }) => result.status !== "ok" && result.status !== "cancelled",
  );
  if (json)
    io.stdout(
      `${JSON.stringify(
        {
          status: cancelled ? "cancelled" : failed ? "refused" : "ok",
          targets: outcomes.map(({ target, result }) => ({ target, ...result })),
        },
        null,
        2,
      )}\n`,
    );
  else if (!quiet)
    for (const { target, result } of outcomes) {
      if (outcomes.length > 1) io.stdout(`== ${safe(target)}\n`);
      if (result.acquisition?.fetched)
        io.stdout(
          `Fetched the ${result.acquisition.type} source before scanning; the scan itself is offline in static mode.\n`,
        );
      for (const entry of result.results)
        io.stdout(
          resultLine(entry, entry.status === "ok" ? summaries.get(entry.summaryPath) : undefined),
        );
      if (result.rollup !== undefined && result.status !== "invalid")
        io.stdout(rollupLine(result.rollup));
      if (result.results.length === 0 && "detail" in result)
        io.stderr(
          `aih-scan: ${safe(target)}: ${result.status} (${safe(result.reason, 200)}): ${safe(String(result.detail ?? ""), 300)}\n`,
        );
    }
  if (cancelled) {
    io.stderr("aih-scan: cancelled; finished results were kept\n");
    return exitCodes.cancelled;
  }
  if (failed) return exitCodes.input;
  if (
    failAt !== undefined &&
    [...summaries.values()].some((summary) => failAtReached(summary.label as SummaryLabel, failAt))
  )
    return exitCodes.failAt;
  return exitCodes.ok;
}

/** `aih-scan read <summary.json>`: prints the summary. */
export function runReadCommand(args: readonly string[], io: CommandIo): number {
  try {
    const parsed = parse(args, ["--fail-at"], ["--json"]);
    if (parsed.positional.length !== 1) throw new UsageError("name one summary file");
    const failAt = failAtOf(single(parsed, "--fail-at"));
    const read = readSummaryFile(resolve(io.cwd ?? process.cwd(), parsed.positional[0] as string));
    if ("problem" in read) {
      io.stderr(`aih-scan: ${read.problem}\n`);
      return exitCodes.input;
    }
    io.stdout(
      parsed.flags.has("--json")
        ? `${JSON.stringify(read.summary, null, 2)}\n`
        : summaryLines(read.summary),
    );
    return failAt !== undefined && failAtReached(read.summary.label, failAt)
      ? exitCodes.failAt
      : exitCodes.ok;
  } catch (error) {
    io.stderr(
      `aih-scan: ${error instanceof UsageError ? error.message : "the summary could not be read"}\n${readUsage}`,
    );
    return exitCodes.input;
  }
}

function findingLine(finding: Finding): string {
  return `${finding.severity.padEnd(8)} ${finding.code}  ${safe(finding.path)}:${finding.line}  [${finding.tool} ${finding.ruleId}] ${finding.text}\n`;
}

/** `aih-scan findings <summary.json> --key <scanKey>`: one line per finding from every pinned SARIF. */
export async function runFindingsCommand(args: readonly string[], io: CommandIo): Promise<number> {
  try {
    const parsed = parse(args, ["--key"], ["--json"]);
    if (parsed.positional.length !== 1) throw new UsageError("name one summary file");
    const key = single(parsed, "--key");
    if (key === undefined) throw new UsageError("--key <scanKey> is required");
    const path = resolve(io.cwd ?? process.cwd(), parsed.positional[0] as string);
    const read = readSummaryFile(path);
    if ("problem" in read) {
      io.stderr(`aih-scan: ${read.problem}\n`);
      return exitCodes.input;
    }
    const findings: Finding[] = [];
    for (const entry of read.summary.sarif) {
      if (pathProblem(entry.path, limits.input.pathLength, limits.input.depth) !== undefined) {
        io.stderr(`aih-scan: ${FINDINGS_MISMATCH_MESSAGE}\n`);
        return exitCodes.input;
      }
      let bytes: Uint8Array;
      try {
        const file = join(dirname(path), ...entry.path.split("/"));
        const stat = lstatSync(file);
        if (!stat.isFile() || stat.size > limits.output.sarifBytes) throw new Error("not a file");
        bytes = new Uint8Array(readFileSync(file));
      } catch {
        io.stderr("aih-scan: a pinned SARIF file could not be read\n");
        return exitCodes.input;
      }
      const result = await readFindings(read.summary, bytes, key);
      if (result.status !== "ok") {
        io.stderr(`aih-scan: ${"message" in result ? result.message : `SARIF ${result.status}`}\n`);
        return exitCodes.input;
      }
      findings.push(...result.findings);
    }
    if (parsed.flags.has("--json"))
      io.stdout(`${JSON.stringify({ status: "ok", findings }, null, 2)}\n`);
    else if (findings.length === 0) io.stdout("No findings.\n");
    else for (const finding of findings) io.stdout(findingLine(finding));
    return exitCodes.ok;
  } catch (error) {
    io.stderr(
      `aih-scan: ${error instanceof UsageError ? error.message : "the findings could not be read"}\n${findingsUsage}`,
    );
    return exitCodes.input;
  }
}
