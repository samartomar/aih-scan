import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { resolve } from "node:path";
import { prepareArtifact } from "../artifact/host.js";
import { readArtifact } from "../artifact/read.js";
import { base64Decode, canonicalBytes } from "../assessment/json.js";
import { type RunScanOptions, runScan } from "../assessment/run.js";
import {
  type DetectorResult,
  type Diagnostic,
  defaultLimits,
  type Finding,
  type ReportBody,
  type ScanRequest,
  type ScanRunResult,
  schemas,
} from "../assessment/types.js";
import { resolveDetectorCapabilityV1 } from "../capability/detector-capability-v1.js";
import { TRUST_LINT_DETECTOR_ID_V1 } from "../detectors/trust-lint/findings.js";
import {
  assertOutputAbsent,
  ExclusiveOutputError,
  type ExclusiveOutputPolicy,
  type ExclusiveOutputProblem,
  safeOutputParents,
  writeNewSafeOutput,
} from "./exclusive-output.js";
import {
  classifyScanTarget,
  type GitRefRequest,
  GitSourceRefusal,
  parseGitRef,
  type ResolvedGitSource,
  resolveGitSource,
} from "./git-source.js";
import { resolveGitScanInputs, resolveScanInputs, type ScanInputs } from "./scan-inputs.js";

export const scanExitCodes = {
  complete: 0,
  incomplete: 1,
  findings: 1,
  invalid: 2,
  cancelled: 130,
} as const;

export const scanUsage = `${[
  "Usage: aih-scan scan <directory> [options]",
  "       aih-scan scan <https-url | owner/repo> [--ref <name>] [options]",
  "",
  "Assesses one local directory, or one exact commit of a Git repository, and reports",
  "what each detector observed and covered.",
  "",
  "Git sources:",
  "  An https:// URL, or a GitHub owner/repo, is resolved to one full commit before the",
  "  assessment; the summary shows that commit and the ref it came from. owner/repo",
  "  names a local directory instead when one exists with that spelling; use",
  "  https://github.com/owner/repo to force Git. Credentials, queries and fragments in",
  "  the URL and other schemes (http, ssh, git, file, user@host:path) are refused.",
  "  Only repositories that need no credentials can be assessed.",
  "",
  "Options:",
  "  --ref <name>           Assess this branch, tag, refs/heads/<name>, refs/tags/<name>",
  "                         or full 40-character commit of a Git source instead of its",
  "                         default HEAD. A name that is both a branch and a tag is",
  "                         refused; qualify it.",
  "  --detector <id>        Run exactly the named detector; repeat for several.",
  "                         Default: detector.aih-native and detector.aih-trust-lint.",
  "                         A detector that cannot run is reported as refused or failed",
  "                         and leaves the assessment incomplete.",
  "  --mcp-config <path>    Use this MCP configuration instead of the ones discovered",
  "                         inside the target (at its root and in directories holding a",
  "                         SKILL.md); repeat for several. A relative path resolves",
  "                         against the target; an absolute path must lead into it, and",
  "                         may be spelled through a link in an ancestor of the target",
  "                         or a link to the target itself.",
  "                         A path outside the target, through a link inside it, missing",
  "                         or duplicated is refused.",
  "                         Requires a selected detector that reads MCP configuration",
  "                         (detector.aih-trust-lint or detector.cisco-mcp-scanner).",
  "                         Local directories only: MCP configuration is not read from",
  "                         Git sources.",
  "  --internal-scope <@scope>",
  "                         Declare an internal package scope for detector.aih-trust-lint;",
  "                         repeat for several. Values are trimmed, lowercased,",
  "                         @-prefixed, deduplicated and sorted before validation.",
  "  --json                 Write the complete run result as canonical JSON to stdout.",
  "  --artifact <new-file>  Also save an unsigned portable artifact to a file that does",
  "                         not exist yet; it is read back before the command succeeds.",
  "                         Every parent directory must be a real directory: a linked",
  "                         parent (macOS /tmp is one) is refused, so use a real path.",
  "  --fail-on-findings     Exit 1 when the assessment reports any finding.",
  "  -h, --help             Print this help.",
  "",
  "Exit codes:",
  "  0    complete assessment",
  "  1    incomplete assessment, or findings with --fail-on-findings",
  "  2    invalid input, no assessment, or the artifact could not be saved",
  "  130  cancelled; finished results are still reported and saved",
].join("\n")}\n`;

export interface ScanCommandIo {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  /** Aborted when the user cancels. */
  cancellation?: AbortSignal;
  /** Defaults to the assessment host's `runScan`. */
  runScan?: (request: unknown, options: RunScanOptions) => Promise<ScanRunResult>;
  /** Relative targets resolve against this directory. Defaults to `process.cwd()`. */
  cwd?: string;
}

const defaultDetectors = ["detector.aih-native", TRUST_LINT_DETECTOR_ID_V1];

/** An invalid command: reported as `aih-scan: <message>` with exit 2 before any work. */
class InvalidCommand extends Error {}
function invalid(message: string): never {
  throw new InvalidCommand(message);
}

interface ParsedArguments {
  positionals: string[];
  detectors: string[];
  mcpConfigPaths: string[];
  internalScopes: string[];
  failOnFindings: boolean;
  json: boolean;
  artifact?: string;
  ref?: string;
}

function optionValue(args: readonly string[], index: number, name: string): string {
  const value = args[index];
  if (value === undefined || value.startsWith("-")) invalid(`${name} requires a value`);
  return value;
}

function parseArguments(args: readonly string[]): ParsedArguments {
  const parsed: ParsedArguments = {
    positionals: [],
    detectors: [],
    mcpConfigPaths: [],
    internalScopes: [],
    failOnFindings: false,
    json: false,
  };
  const single = new Set<string>();
  const repeatable = new Set(["--detector", "--mcp-config", "--internal-scope"]);
  for (let index = 0; index < args.length; index++) {
    const arg = args[index] as string;
    if (!repeatable.has(arg) && arg.startsWith("--")) {
      if (single.has(arg)) invalid(`duplicate option ${arg}`);
      single.add(arg);
    }
    if (arg === "--detector") {
      const value = optionValue(args, ++index, arg);
      if (!resolveDetectorCapabilityV1(value)) invalid(`unknown detector ${value}`);
      if (parsed.detectors.includes(value)) invalid(`duplicate detector ${value}`);
      parsed.detectors.push(value);
    } else if (arg === "--mcp-config") parsed.mcpConfigPaths.push(optionValue(args, ++index, arg));
    else if (arg === "--internal-scope")
      parsed.internalScopes.push(optionValue(args, ++index, arg));
    else if (arg === "--fail-on-findings") parsed.failOnFindings = true;
    else if (arg === "--json") parsed.json = true;
    else if (arg === "--artifact") parsed.artifact = optionValue(args, ++index, arg);
    else if (arg === "--ref") parsed.ref = optionValue(args, ++index, arg);
    else if (arg.startsWith("-")) invalid(`unknown option ${arg}`);
    else parsed.positionals.push(arg);
  }
  return parsed;
}

function resolveTarget(spelling: string, cwd: string): string {
  const path = resolve(cwd, spelling);
  let stat: ReturnType<typeof lstatSync>;
  try {
    stat = lstatSync(path);
  } catch {
    invalid("the target does not exist or cannot be inspected");
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) invalid("the target is not a real directory");
  return realpathSync.native(path);
}

const replacementCharacter = String.fromCodePoint(0xfffd);

/**
 * Detector and report text is data, never terminal input. Line breaks and tabs become
 * spaces so a value cannot start a forged line; every other control or format character
 * (escape sequences, bidirectional overrides, ...) becomes U+FFFD.
 */
function neutralizeTerminalText(text: string): string {
  return text.replace(/[\n\r\t\p{Zl}\p{Zp}]/gu, " ").replace(/\p{C}/gu, replacementCharacter);
}

function diagnosticLine(
  diagnostic: Diagnostic,
  indent: string,
  options: { showDetector: boolean },
): string {
  const detector =
    options.showDetector && diagnostic.detectorId !== undefined
      ? ` [${neutralizeTerminalText(diagnostic.detectorId)}]`
      : "";
  return `${indent}${neutralizeTerminalText(diagnostic.code)}: ${neutralizeTerminalText(diagnostic.detail)}${detector}`;
}

function detectorLines(result: DetectorResult): string[] {
  const origins = [...new Set(result.observations.map((observation) => observation.origin))];
  const findings = result.observations.reduce(
    (sum, observation) => sum + observation.body.findings.length,
    0,
  );
  const covered = result.coverage.coveredPaths.length;
  const selected = covered + result.coverage.uncoveredPaths.length;
  return [
    `  ${neutralizeTerminalText(result.detectorId)}: ${neutralizeTerminalText(result.outcome)}; origin ${neutralizeTerminalText(origins.join(", ") || "none")}; ` +
      `${findings} ${findings === 1 ? "finding" : "findings"}; coverage ${covered}/${selected} ` +
      (result.coverage.complete ? "complete" : "incomplete"),
    ...result.diagnostics.map((diagnostic) =>
      diagnosticLine(diagnostic, "    ", { showDetector: false }),
    ),
  ];
}

const findingListCap = 20;

function findingLine(detectorId: string, finding: Finding): string {
  const severity = finding.severity.state === "present" ? finding.severity.value.level : "unknown";
  const rule = finding.rule.state === "present" ? finding.rule.value.nativeRuleId : "unknown-rule";
  const location =
    finding.location.state === "present"
      ? `${finding.location.value.path}${
          finding.location.value.startLine === undefined
            ? ""
            : `:${finding.location.value.startLine}`
        }`
      : "unknown-location";
  const message = finding.message.state === "present" ? finding.message.value : "(no message)";
  return `  [${neutralizeTerminalText(severity)}] ${neutralizeTerminalText(rule)} ${neutralizeTerminalText(location)} (${neutralizeTerminalText(detectorId)}) ${neutralizeTerminalText(message)}`;
}

function findingCount(report: ReportBody): number {
  return report.results
    .flatMap((result) => result.observations)
    .reduce((sum, observation) => sum + observation.body.findings.length, 0);
}

function findingLines(report: ReportBody): string[] {
  const lines = report.results.flatMap((result) =>
    result.observations.flatMap((observation) =>
      observation.body.findings.map((finding) => findingLine(result.detectorId, finding)),
    ),
  );
  if (lines.length === 0) return ["Findings: none"];
  const hidden = lines.length - findingListCap;
  return [
    `Findings (${lines.length}):`,
    ...lines.slice(0, findingListCap),
    ...(hidden > 0
      ? [
          `  ... ${hidden} more ${hidden === 1 ? "finding" : "findings"} not shown; use --json or --artifact for the complete list`,
        ]
      : []),
  ];
}

function annexLines(report: ReportBody): string[] {
  if (report.annexes.length === 0) return ["Annexes: none"];
  return [
    `Annexes (${report.annexes.length}): per-detector evidence, never combined`,
    ...report.annexes.map((annex) => {
      const producer = report.results.find((result) =>
        result.observations.some((observation) => observation.body.annexIds.includes(annex.id)),
      );
      return `  ${neutralizeTerminalText(annex.id)} ${neutralizeTerminalText(annex.mediaType)} ${annex.byteLength} bytes, from ${neutralizeTerminalText(producer?.detectorId ?? "an unknown detector")}`;
    }),
  ];
}

/** Specialized detector inputs the command resolved, reported as one note per line. */
function inputLines(notes: readonly string[]): string[] {
  if (notes.length === 0) return ["Inputs: none"];
  return [`Inputs (${notes.length}):`, ...notes.map((note) => `  ${neutralizeTerminalText(note)}`)];
}

function diagnosticLines(result: Assessment): string[] {
  const unique = new Map<string, Diagnostic>();
  for (const diagnostic of [...result.report.diagnostics, ...result.diagnostics])
    unique.set(JSON.stringify(diagnostic), diagnostic);
  if (unique.size === 0) return ["Diagnostics: none"];
  return [
    `Diagnostics (${unique.size}):`,
    ...[...unique.values()].map((diagnostic) =>
      diagnosticLine(diagnostic, "  ", { showDetector: true }),
    ),
  ];
}

function targetLines(target: Target, report: ReportBody): string[] {
  const entries = report.source.capture.entries;
  const files = entries.filter((entry) => entry.kind === "file" || entry.kind === "file-link");
  return [
    `Target: ${neutralizeTerminalText(target.name)} (${files.length} ${files.length === 1 ? "file" : "files"}, ${entries.length} ${entries.length === 1 ? "entry" : "entries"})`,
    ...(target.git === undefined ? [] : [`Commit: ${commitText(target.git)}`]),
  ];
}

/** `<commit>` or `<commit> (<ref>)`: the exact commit and the ref it was resolved from. */
function commitText(git: ResolvedGitSource): string {
  return `${neutralizeTerminalText(git.commit)}${git.ref === undefined ? "" : ` (${neutralizeTerminalText(git.ref)})`}`;
}

function humanSummary(result: ScanRunResult, target: Target, notes: readonly string[]): string {
  if (result.status !== "assessment")
    return [
      `No assessment (${neutralizeTerminalText(result.phase)} diagnostic)`,
      ...result.diagnostics.map((diagnostic) =>
        diagnosticLine(diagnostic, "  ", { showDetector: false }),
      ),
      "",
    ].join("\n");
  return [
    `Scan ID: ${neutralizeTerminalText(result.scanId)}`,
    ...targetLines(target, result.report),
    `Completion: ${neutralizeTerminalText(result.report.completion)}`,
    "Detectors:",
    ...result.report.results.flatMap(detectorLines),
    ...findingLines(result.report),
    ...annexLines(result.report),
    ...inputLines(notes),
    ...diagnosticLines(result),
    "",
  ].join("\n");
}

/** One exclusive writer for the artifact, the same one `project-core-evidence` writes through. */
const artifactOutput: ExclusiveOutputPolicy = {
  label: "artifact output",
  maximumBytes: defaultLimits.maxArtifactBytes,
};

const artifactRefusals: Record<ExclusiveOutputProblem, string> = {
  bounds: "the artifact is empty or larger than the artifact size limit",
  exists: "the artifact path already exists",
  "linked-parent":
    "the artifact path has a linked or non-directory parent; use a real path (a link such as macOS /tmp is refused)",
  replaced: "the artifact file or its directory was replaced while the file was written",
};

function artifactFailure(error: unknown): string {
  if (error instanceof ExclusiveOutputError) return artifactRefusals[error.problem];
  return error instanceof Error ? error.message : "unknown failure";
}

function refuseArtifact(error: unknown, uninspectable: string): never {
  return invalid(error instanceof ExclusiveOutputError ? artifactFailure(error) : uninspectable);
}

/** The artifact must be a new file in real directories: refused before any scan work. */
function assertNewArtifactPath(path: string): void {
  try {
    assertOutputAbsent(path, artifactOutput.label);
  } catch (error) {
    refuseArtifact(error, "the artifact path cannot be inspected");
  }
  try {
    safeOutputParents(path);
  } catch (error) {
    refuseArtifact(error, "the artifact directory does not exist or cannot be inspected");
  }
}

type Assessment = Extract<ScanRunResult, { status: "assessment" }>;

/** Writes the unsigned artifact, then proves it by reading the saved bytes back. */
async function saveArtifact(result: Assessment, path: string): Promise<void> {
  const limit = result.report.effectiveLimits.maxAnnexBytes;
  const prepared = await prepareArtifact({
    report: result.report,
    annexes: result.annexes.map(({ id, bytesBase64 }) => ({
      id,
      bytes: base64Decode(bytesBase64, limit),
    })),
  });
  writeNewSafeOutput(path, prepared.bytes, artifactOutput);
  const saved = readFileSync(path);
  if (!saved.equals(prepared.bytes))
    throw new Error("the saved artifact differs from the bytes that were written");
  const read = await readArtifact(new Uint8Array(saved));
  if (read.status !== "read" || read.scanId !== result.scanId)
    throw new Error("the saved artifact did not read back as this assessment");
}

/** What the summary names: a local directory, or a repository and its resolved commit. */
interface Target {
  readonly name: string;
  readonly git?: ResolvedGitSource;
}

/** The validated source before any network: a local directory or an unresolved Git source. */
type PlannedSource =
  | { readonly kind: "local"; readonly path: string }
  | {
      readonly kind: "git";
      readonly repository: string;
      /** The --ref spelling as given, or HEAD. */
      readonly requested: string;
      readonly request: GitRefRequest;
    };

function planSource(parsed: ParsedArguments, cwd: string): PlannedSource {
  if (parsed.positionals.length !== 1) invalid("scan requires exactly one target directory");
  const spelling = parsed.positionals[0] as string;
  const classified = classifyScanTarget(spelling, cwd);
  if (classified.kind === "local") {
    if (parsed.ref !== undefined) invalid("--ref applies only to Git sources");
    return { kind: "local", path: resolveTarget(spelling, cwd) };
  }
  const ref = parseGitRef(parsed.ref);
  if (!ref.ok) invalid(ref.detail);
  return {
    kind: "git",
    repository: classified.repository,
    requested: parsed.ref ?? "HEAD",
    request: ref.request,
  };
}

export async function runScanCommand(args: readonly string[], io: ScanCommandIo): Promise<number> {
  if (args.length === 1 && (args[0] === "--help" || args[0] === "-h")) {
    io.stdout(scanUsage);
    return scanExitCodes.complete;
  }
  const cwd = io.cwd ?? process.cwd();
  let source: PlannedSource;
  let parsed: ParsedArguments;
  let artifactPath: string | undefined;
  let detectorIds: readonly string[];
  let inputs: ScanInputs;
  try {
    parsed = parseArguments(args);
    source = planSource(parsed, cwd);
    if (parsed.artifact !== undefined) {
      artifactPath = resolve(cwd, parsed.artifact);
      assertNewArtifactPath(artifactPath);
    }
    detectorIds = parsed.detectors.length ? parsed.detectors : defaultDetectors;
    const explicit = {
      mcpConfigPaths: parsed.mcpConfigPaths,
      internalScopes: parsed.internalScopes,
    };
    const resolved =
      source.kind === "local"
        ? resolveScanInputs(source.path, detectorIds, explicit)
        : resolveGitScanInputs(detectorIds, explicit);
    if (!resolved.ok) invalid(resolved.detail);
    inputs = resolved.inputs;
  } catch (error) {
    if (!(error instanceof InvalidCommand || error instanceof GitSourceRefusal)) throw error;
    io.stderr(`aih-scan: ${neutralizeTerminalText(error.message)}\n`);
    return scanExitCodes.invalid;
  }
  const cancellation = new AbortController();
  const forwardCancellation = () => cancellation.abort();
  if (io.cancellation?.aborted) cancellation.abort();
  else io.cancellation?.addEventListener("abort", forwardCancellation, { once: true });
  try {
    let target: Target;
    let requestSource: ScanRequest["source"];
    if (source.kind === "local") {
      target = { name: source.path };
      requestSource = { kind: "local", path: source.path };
    } else {
      const resolution = await resolveGit(source, io, cancellation.signal);
      if (!resolution.ok) return resolution.exitCode;
      const { git } = resolution;
      target = { name: git.repository, git };
      requestSource = { kind: "git", repository: git.repository, commit: git.commit };
    }
    const request: ScanRequest = {
      schema: schemas.request,
      source: requestSource,
      selection: { paths: "all", excludedPaths: [] },
      detectors: detectorIds.map((detectorId) => ({
        detectorId,
        configuration: inputs.configurations.get(detectorId) ?? {},
      })),
    };
    return await assess(
      parsed,
      request,
      target,
      artifactPath,
      io,
      cancellation.signal,
      inputs.notes,
    );
  } finally {
    io.cancellation?.removeEventListener("abort", forwardCancellation);
  }
}

/** A Git source resolved to one commit, or the exit code of a reported refusal. */
type GitResolution =
  | { readonly ok: true; readonly git: ResolvedGitSource }
  | { readonly ok: false; readonly exitCode: number };

/** Resolves the Git source to one commit before any assessment. */
async function resolveGit(
  source: Extract<PlannedSource, { kind: "git" }>,
  io: ScanCommandIo,
  signal: AbortSignal,
): Promise<GitResolution> {
  const cancelled = (): GitResolution => {
    io.stderr("aih-scan: cancelled; no assessment was produced\n");
    return { ok: false, exitCode: scanExitCodes.cancelled };
  };
  if (signal.aborted) return cancelled();
  const requested = neutralizeTerminalText(source.requested);
  io.stderr(`aih-scan: resolving ${requested} of ${neutralizeTerminalText(source.repository)}\n`);
  let git: ResolvedGitSource;
  try {
    git = await resolveGitSource(source.repository, source.request, signal);
  } catch (error) {
    if (signal.aborted) return cancelled();
    if (!(error instanceof GitSourceRefusal)) throw error;
    io.stderr(`aih-scan: ${neutralizeTerminalText(error.message)}\n`);
    return { ok: false, exitCode: scanExitCodes.invalid };
  }
  io.stderr(`aih-scan: resolved ${requested} to ${commitText(git)}\n`);
  return { ok: true, git };
}

async function assess(
  parsed: ParsedArguments,
  request: ScanRequest,
  target: Target,
  artifactPath: string | undefined,
  io: ScanCommandIo,
  signal: AbortSignal,
  notes: readonly string[],
): Promise<number> {
  io.stderr(
    `aih-scan: assessing ${neutralizeTerminalText(target.name)}${
      target.git === undefined ? "" : ` at ${neutralizeTerminalText(target.git.commit)}`
    }\n`,
  );
  if (parsed.json)
    for (const note of notes) io.stderr(`aih-scan: note: ${neutralizeTerminalText(note)}\n`);
  const result = await (io.runScan ?? runScan)(request, { signal });
  if (parsed.json) {
    io.stdout(`${new TextDecoder().decode(canonicalBytes(result))}\n`);
    io.stderr(
      result.status === "assessment"
        ? `aih-scan: ${neutralizeTerminalText(result.scanId)} is ${neutralizeTerminalText(result.report.completion)}\n`
        : `aih-scan: no assessment (${neutralizeTerminalText(result.phase)} diagnostic)\n`,
    );
  } else io.stdout(humanSummary(result, target, notes));
  let artifactSaved = true;
  if (result.status === "assessment" && artifactPath !== undefined) {
    try {
      await saveArtifact(result, artifactPath);
      (parsed.json ? io.stderr : io.stdout)(
        `Artifact: ${neutralizeTerminalText(artifactPath)}\n` +
          `  unsigned; authenticity unchecked; read back through the portable reader as ${neutralizeTerminalText(result.scanId)}\n`,
      );
    } catch (error) {
      artifactSaved = false;
      io.stderr(
        `aih-scan: artifact not saved: ${neutralizeTerminalText(artifactFailure(error))}\n`,
      );
    }
  }
  if (signal.aborted) {
    io.stderr(
      result.status === "assessment"
        ? "aih-scan: cancelled; finished results are preserved\n"
        : "aih-scan: cancelled; no assessment was produced\n",
    );
    return scanExitCodes.cancelled;
  }
  if (result.status !== "assessment" || !artifactSaved) return scanExitCodes.invalid;
  if (result.report.completion === "partial") return scanExitCodes.incomplete;
  if (parsed.failOnFindings && findingCount(result.report) > 0) return scanExitCodes.findings;
  return scanExitCodes.complete;
}
