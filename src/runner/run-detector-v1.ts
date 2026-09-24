import { createHash } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertBaselineAnalyzerSnapshotUnchangedV1,
  type BaselineAnalyzerV1,
  createBaselineAnalyzerSnapshotV1,
  normalizedObservation,
} from "../baseline/batch-v1.js";
import { bindCiscoSarifToSealedFilesV1 } from "../baseline/cisco-sealed-case-binding-v1.js";
import {
  type AnalyzerFailureCauseV1,
  AnalyzerRunFailureV1,
  type BaselineExecutionProfileIdV1,
  type BaselineProcessRunnerV1,
  boundedDiagnosticDetailV1,
  createBaselineAnalyzerRunV1,
  type HostDockerRuntimeV1,
  type HostProcessRuntimeV1,
  type SkillspectorImageMatchV1,
  skillspectorAcceptedImageDigestsRefusalV1,
} from "../baseline/runtime-v1.js";
import {
  type DetectorCapabilityV1,
  type DetectorExecutionProfileV1,
  type DetectorPlatformV1,
  type DetectorPrerequisiteV1,
  type DetectorSubjectKindV1,
  listDetectorCapabilitiesV1,
  resolveDetectorCapabilityV1,
  snykAgentScanPlatformSupportV1,
} from "../capability/detector-capability-v1.js";
import { type CiscoCaptureV2, captureCiscoOciCandidateV2 } from "../cisco/capture-v2.js";
import { resolveHostExecutableV1 } from "../cli/host-executable.js";
import {
  assertSafeRelativePosixPathV1,
  canonicalStrictJsonBytesV1,
  codeUnitCompare,
  parseStrictJsonObjectV1,
} from "../contract/strict-json-v1.js";
import {
  attachScanCompletionV1,
  inGitDirectoryV1,
  type ScanCompletionSubjectEngineV1,
  scanCompletionEvidenceV1,
  scanCompletionSubjectFilesV1,
} from "../detectors/completion-evidence-v1.js";
import { validateSnykAgentScanRequestEnvV1 } from "../detectors/snyk-agent-scan/index.js";
import {
  buildScanFindingsV1,
  digestBoundAnalyzerFindingsV1,
  projectAnalyzerSarifFindingsV1,
  type ScanFindingsV1,
} from "../findings/scan-findings-v1.js";
import {
  SOURCE_OBSERVATION_SEAL_LIMITS_V1,
  type SourceObservationSealV1,
  sealSourceObservationV1,
} from "../observation/source-observation-seal-v1.js";
import { type SourceSealV2, sealSourceV2 } from "../observation/source-seal-v2.js";
import {
  concurrencyRefusalV1,
  type DetectorOptionsV1,
  detectorOptionsSealRefusalV1,
  readDetectorOptionsV1,
} from "./detector-options-v1.js";
import {
  ENGINE_MAX_RESULTS_V1,
  type EngineAnalyzerV1,
  type EngineV1,
  engineEnvironmentsV1,
  engineForV1,
  engineObservationAnalyzerV1,
  enginePreflightRefusalV1,
  engineRunsInProcessV1,
  runEngineDetectorV1,
} from "./engine-dispatch-v1.js";

/**
 * Runs one Scan-owned detector without the caller writing any execution code.
 *
 * Honesty rules enforced by construction:
 *
 * - every unsupported detector, subject, profile, platform or prerequisite is a
 *   returned refusal, produced before any process is spawned; a refusal and a failure
 *   are values, never thrown exceptions;
 * - platform and prerequisite gates are the selected profile's own. A weaker profile such
 *   as `host-process-uv-v1` runs only when named; a missing prerequisite never downgrades;
 * - the execution profile reported is the one that actually ran, and its digest is the
 *   digest of a readable document this package publishes;
 * - selection is exactly what the caller declared. Scan never discovers, widens,
 *   renames, copies or creates a `SKILL.md`, and never silently scans more than the
 *   coverage record states;
 * - coverage names what was covered, what the caller declared excluded, and what was
 *   neither, so "complete" is a computed field rather than a claim;
 * - findings come only from digest-verified annex bytes, and every SARIF artifact URI is
 *   relative to the declared source root. An empty list is never reported as "nothing is
 *   wrong"; the gaps say what it means;
 * - a caller's `signal` or `timeoutMs` ends the whole analyzer process tree and yields a
 *   failure whose `cause` says so.
 *
 * A result grants no qualification, approval, installation or adoption authority.
 */

const moduleDirectory = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(moduleDirectory, "..", "..");

const ANALYZER_BY_DETECTOR: Readonly<Record<string, BaselineAnalyzerV1>> = Object.freeze({
  "detector.aih-native": "aih-native",
  "detector.cisco": "cisco",
  "detector.semgrep": "semgrep",
  "detector.skillspector": "skillspector",
});

/**
 * Analyzers that scan the whole tree, a top-level `.git` and dependency or build
 * directories included, exactly as Core's own Semgrep and SkillSpector runs do. The other
 * analyzers are given the tree without its top-level `.git`, and their coverage says so.
 */
const WHOLE_TREE_ANALYZERS: ReadonlySet<BaselineAnalyzerV1> = new Set(["semgrep", "skillspector"]);

/**
 * Engines whose SARIF Scan builds from the analyzer's own records (C2a §1.6): their runs carry
 * no analyzer invocation, so the completion evidence brings its own successful one.
 */
const SCAN_BUILT_SARIF_ENGINES: ReadonlySet<EngineV1> = new Set([
  "aih-trust-lint",
  "aih-binding-gate",
  "cisco-mcp-scanner",
  "snyk-agent-scan",
]);

/** The shortest and longest whole-run budget a caller may set, in milliseconds. */
const MIN_TIMEOUT_MS = 100;
const MAX_TIMEOUT_MS = 3_600_000;
/**
 * The seal a run takes: `SourceSealV2` for the OCI capture profile, whose candidate protocol
 * carries it, and `SourceObservationSealV1` for every observation run.
 */
type RunSealV1 = SourceSealV2 | SourceObservationSealV1;
const isFileEntry = (entry: RunSealV1["entries"][number]) =>
  entry.kind === "file" || entry.kind === "file-link";

export type RunDetectorRefusalReasonV1 =
  | "unknown-detector"
  | "unsupported-platform"
  | "unsupported-subject-kind"
  | "subject-requirement-unmet"
  | "prerequisite-missing"
  | "execution-profile-unavailable"
  | "detector-options-invalid";

export type RunDetectorFailureStageV1 =
  | "acquisition"
  | "availability"
  | "execution"
  | "output"
  | "coverage"
  | "cleanup";

/**
 * Why a run that started failed, when the analyzer's own error is not the reason:
 * `cancelled` (the caller's signal), `timed-out` (a stage or the caller's `timeoutMs`),
 * `residual-processes` (processes outlived the analyzer and were killed) or
 * `containment-failure` (Scan could not prove the process tree was gone).
 */
export type RunDetectorFailureCauseV1 = AnalyzerFailureCauseV1;

export interface ScanCoverageV1 {
  readonly kind: "selected-closure" | "source-tree";
  readonly sha256: string;
  /** `true` only when no sealed source file is left both uncovered and undeclared. */
  readonly complete: boolean;
  /** Exactly what this run covered, in canonical code-unit order. */
  readonly coveredPaths: readonly string[];
  /** Exactly what the caller declared it was leaving out, verbatim. */
  readonly excludedPaths: readonly string[];
  /** Sealed source files that are neither covered nor declared excluded. */
  readonly uncoveredPaths: readonly string[];
}

export interface DetectorPrerequisiteStateV1 {
  readonly kind: DetectorPrerequisiteV1["kind"];
  readonly id: string;
  readonly required: boolean;
  /** `not-probed` means Scan cannot determine it without running the detector. */
  readonly state: "present" | "missing" | "not-probed";
}

export type { HostDockerRuntimeV1, HostProcessRuntimeV1, SkillspectorImageMatchV1 };

export interface BaselineAnalyzerObservationV1 {
  readonly protocol: "BaselineAnalyzerObservationV1";
  readonly analyzer: BaselineAnalyzerV1 | EngineAnalyzerV1;
  readonly analyzerVersion: string;
  readonly mediaType: "application/sarif+json" | "application/vnd.aih.baseline-native+json";
  readonly annex: Readonly<{ path: string; sha256: string; byteLength: number }>;
  /** The exact canonical bytes the digest above was taken over. */
  readonly bytes: Buffer;
  /**
   * SkillSpector only: the image that ran and whose digest admitted it. With
   * `acceptance: "caller-accepted"` Scan verified the image digest the caller named, not
   * that image's provenance or source revision.
   */
  readonly image?: SkillspectorImageMatchV1;
  /** `host-process-uv-v1` only: the uv, Python, uv cache and containment the run used. */
  readonly hostRuntime?: HostProcessRuntimeV1;
  /** `docker-host-local-skillspector-v1` only: the Docker client and context the run used. */
  readonly hostDocker?: HostDockerRuntimeV1;
}

export interface RunDetectorV1Request {
  readonly detectorId: string;
  readonly subject: {
    readonly kind: DetectorSubjectKindV1;
    readonly sourceRoot: string;
    /**
     * Exact, caller-declared selection. Never widened, never discovered. Empty only for a
     * source root with no entries, which only an `emptySource: "completes"` detector runs.
     */
    readonly selectedClosurePaths: readonly string[];
    /** Recorded verbatim so evidence can state what was deliberately left out. */
    readonly excludedPaths?: readonly string[];
  };
  /** Optional override; the capability's own default profile is used when absent. */
  readonly executionProfileId?: string;
  /**
   * The caller environment. Analyzer profiles scrub it to Scan's allow-list; the host
   * profiles read only their documented variables from it (to find uv, Python, Docker and
   * the user cache directory) and never pass it to an analyzer.
   */
  readonly env?: Readonly<NodeJS.ProcessEnv>;
  /**
   * Per-detector options (C2a §2.1, §3.3, §4.1), validated strictly and snapshotted once:
   * `detector.cisco` `{ concurrency }` (optional), `detector.aih-trust-lint`
   * `{ internalScopes, mcpConfigPaths }` and `detector.cisco-mcp-scanner` `{ mcpConfigPaths }`
   * (required). Any other detector must not carry them. A violation is refused
   * `detector-options-invalid` before the source is read.
   */
  readonly detectorOptions?: DetectorOptionsV1;
  /** Aborting ends the analyzer's whole process tree and fails the run `cancelled`. */
  readonly signal?: AbortSignal;
  /**
   * A whole-run budget in milliseconds (100 to 3,600,000). When it runs out the process tree
   * is ended and the run fails `timed-out`. Each stage also keeps its own built-in limit.
   */
  readonly timeoutMs?: number;
  /** Test and CI seam only. Absent in production; its presence is recorded in the result. */
  readonly runner?: BaselineProcessRunnerV1;
  /**
   * Test and CI seam only: decides prerequisite presence instead of Scan's own
   * filesystem and environment probe. Its presence is recorded in the result. Claiming
   * a prerequisite present does not make it so: the run still fails at execution.
   */
  readonly prerequisiteProbe?: (
    prerequisite: DetectorPrerequisiteV1,
  ) => DetectorPrerequisiteStateV1["state"];
  /**
   * SkillSpector only: image digests (`sha256:` + 64 lowercase hex) the caller also accepts.
   * `docker-hardened-skillspector-v1` consults them, in order and against local images only,
   * after Scan's own pinned pull has failed; it never replaces that acquisition nor relaxes
   * its check. `docker-host-local-skillspector-v1` admits the local tag's image when it
   * carries the pinned digest or one of these.
   */
  readonly acceptedImageDigests?: readonly string[];
  /** Material only the OCI capture profile needs; its absence refuses that profile. */
  readonly ociCapture?: {
    readonly layout: unknown;
    readonly runtime: unknown;
    readonly broker: unknown;
    readonly annexPayloads: unknown;
    /** Test and CI seam only, as above. */
    readonly runner?: (argv: readonly string[], options: never) => Promise<unknown>;
  };
}

/** Which parts of the run came from Scan and which from the caller. */
export type RunDetectorSeamsV1 = Readonly<{
  runner: "scan-owned-default" | "caller-supplied";
  prerequisiteProbe: "scan-owned-default" | "caller-supplied";
}>;

/**
 * The installed package whose code executed this run, read once from the manifest that
 * ships beside it. Only a run that started carries it; a refusal executed nothing.
 * `version` is `null` when that manifest cannot be read or does not name this package,
 * rather than a guessed value.
 */
export type RunDetectorProducerV1 = Readonly<{
  name: "@aihq/scan";
  version: string | null;
}>;

export type RunDetectorV1Result =
  | Readonly<{
      outcome: "refused";
      reason: RunDetectorRefusalReasonV1;
      /** One actionable sentence; bounded and control-character encoded. */
      detail: string;
      capability?: DetectorCapabilityV1;
      host: Readonly<{ os: NodeJS.Platform; architecture: string }>;
    }>
  | Readonly<{
      outcome: "failed";
      failure: Readonly<{
        stage: RunDetectorFailureStageV1;
        detail: string;
        /** Present when the run was cancelled, timed out, or its process tree was not clean. */
        cause?: RunDetectorFailureCauseV1;
      }>;
      capability: DetectorCapabilityV1;
      executionProfile: DetectorExecutionProfileV1;
      prerequisites: readonly DetectorPrerequisiteStateV1[];
      seams: RunDetectorSeamsV1;
      producer: RunDetectorProducerV1;
      coverage: ScanCoverageV1;
    }>
  | Readonly<{
      outcome: "succeeded";
      capability: DetectorCapabilityV1;
      /** The profile that actually ran, not the one that was asked for. */
      executionProfile: DetectorExecutionProfileV1;
      prerequisites: readonly DetectorPrerequisiteStateV1[];
      seams: RunDetectorSeamsV1;
      producer: RunDetectorProducerV1;
      evidence:
        | Readonly<{
            kind: "baseline-analyzer-observation-v1";
            observation: BaselineAnalyzerObservationV1;
          }>
        | Readonly<{ kind: "scan-candidate-v2"; capture: CiscoCaptureV2 }>;
      findings: ScanFindingsV1;
      coverage: ScanCoverageV1;
      /**
       * The source seal taken before and after the run: `SourceObservationSealV1` for an
       * observation run (an empty root included), `SourceSealV2` for the OCI capture profile.
       */
      sourceSeal:
        | Readonly<{ before: SourceObservationSealV1; after: SourceObservationSealV1 }>
        | Readonly<{ before: SourceSealV2; after: SourceSealV2 }>;
    }>;

let producerRecord: RunDetectorProducerV1 | undefined;

export function producer(): RunDetectorProducerV1 {
  if (producerRecord !== undefined) return producerRecord;
  let version: string | null = null;
  try {
    const manifest: unknown = JSON.parse(readFileSync(join(packageRoot, "package.json"), "utf8"));
    if (
      typeof manifest === "object" &&
      manifest !== null &&
      (manifest as { name?: unknown }).name === "@aihq/scan"
    ) {
      const declared = (manifest as { version?: unknown }).version;
      if (typeof declared === "string" && declared.length > 0 && declared.length <= 256)
        version = declared;
    }
  } catch {
    version = null;
  }
  producerRecord = Object.freeze({ name: "@aihq/scan" as const, version });
  return producerRecord;
}

function host(): { os: NodeJS.Platform; architecture: string } {
  return Object.freeze({ os: process.platform, architecture: process.arch });
}

export function capabilityPlatform(): DetectorPlatformV1 | undefined {
  const os =
    process.platform === "linux"
      ? "linux"
      : process.platform === "darwin"
        ? "darwin"
        : process.platform === "win32"
          ? "windows"
          : undefined;
  const architecture =
    process.arch === "x64" ? "amd64" : process.arch === "arm64" ? "arm64" : undefined;
  if (os === undefined || architecture === undefined) return undefined;
  return { os, architecture };
}

/** Why this host cannot run the selected profile; decided before any probe or spawn. */
export function platformRefusal(
  capability: DetectorCapabilityV1,
  profile: DetectorExecutionProfileV1,
): string {
  const supported = profile.supportedPlatforms
    .map((entry) => `${entry.os}/${entry.architecture}`)
    .join(", ");
  const hostPlatform = `${process.platform}/${process.arch}`;
  const reason =
    profile.id === "host-process-uv-v1"
      ? capability.detectorId === "detector.cisco-mcp-scanner"
        ? "Its lock pins litellm 1.93.0, which publishes manylinux wheels only, and Scan never builds analyzer dependencies from source."
        : capability.detectorId === "detector.snyk-agent-scan"
          ? snykAgentScanPlatformSupportV1(capability.analyzerVersion ?? "").refusal
          : "No exact-pinned binary wheel exists for every analyzer dependency on this host (macOS amd64 lacks cryptography 50.0.0, Windows arm64 lacks Semgrep), and Scan never builds analyzer dependencies from source."
      : profile.id === "docker-host-local-skillspector-v1"
        ? "Its Docker engine must run the linux/amd64 SkillSpector image, natively or emulated."
        : profile.id.startsWith("in-process-")
          ? "The in-process analyzer knows only these operating systems and architectures."
          : "Scan's hardened detector profiles are Linux amd64 only.";
  return `This host is ${hostPlatform}; ${capability.detectorId} under ${profile.id} runs only on ${supported}. ${reason}`;
}

function refuse(
  reason: RunDetectorRefusalReasonV1,
  detail: string,
  capability?: DetectorCapabilityV1,
): RunDetectorV1Result {
  return Object.freeze({
    outcome: "refused" as const,
    reason,
    detail: boundedDiagnosticDetailV1(detail),
    ...(capability === undefined ? {} : { capability }),
    host: host(),
  });
}

export function failureStage(message: string): RunDetectorFailureStageV1 {
  if (message.includes("environment acquisition") || message.includes("image acquisition"))
    return "acquisition";
  if (
    message.includes("Docker availability") ||
    message.includes("image availability") ||
    message.includes("host runtime availability")
  )
    return "availability";
  if (message.includes("run directory cleanup")) return "cleanup";
  if (message.includes("coverage")) return "coverage";
  if (
    message.includes("observation") ||
    message.includes("emitted no SARIF") ||
    message.includes("SARIF artifact URI") ||
    message.includes("Cisco SARIF")
  )
    return "output";
  return "execution";
}

function probePrerequisite(
  prerequisite: DetectorPrerequisiteV1,
  env: Readonly<NodeJS.ProcessEnv>,
  requestEnv: Readonly<NodeJS.ProcessEnv>,
): DetectorPrerequisiteStateV1["state"] {
  if (prerequisite.kind === "executable" || prerequisite.kind === "bundled-asset") {
    const path =
      prerequisite.kind === "executable"
        ? prerequisite.id
        : join(packageRoot, ...prerequisite.id.split("/"));
    try {
      return statSync(path).isFile() ? "present" : "missing";
    } catch {
      return "missing";
    }
  }
  if (prerequisite.kind === "host-executable") {
    if (prerequisite.id !== "uv" && prerequisite.id !== "docker") return "missing";
    return resolveHostExecutableV1(prerequisite.id, env) === undefined ? "missing" : "present";
  }
  if (prerequisite.kind === "environment-variable") {
    const value = requestEnv[prerequisite.id];
    return typeof value === "string" && value.length > 0 ? "present" : "missing";
  }
  // A container image, a uv-discoverable Python and a reachable index cannot be settled
  // without running the detector, so they are reported as not probed rather than guessed.
  return "not-probed";
}

function coverageRecord(input: {
  readonly seal: RunSealV1;
  readonly kind: ScanCoverageV1["kind"];
  readonly excludedPaths: readonly string[];
  /** Whether the analyzer was given the top-level `.git`; only a source-tree run asks. */
  readonly analyzesGitDirectory: boolean;
}): ScanCoverageV1 {
  const sealedFiles = input.seal.entries.filter(isFileEntry).map((entry) => entry.path);
  const coveredPaths =
    input.kind === "source-tree"
      ? sealedFiles.filter((path) => input.analyzesGitDirectory || !inGitDirectoryV1(path))
      : [...input.seal.selectedClosurePaths];
  coveredPaths.sort(codeUnitCompare);
  const covered = new Set(coveredPaths);
  const excluded = new Set(input.excludedPaths);
  const uncoveredPaths = sealedFiles
    .filter((path) => !covered.has(path) && !excluded.has(path))
    .sort(codeUnitCompare);
  return Object.freeze({
    kind: input.kind,
    sha256:
      input.kind === "source-tree" ? input.seal.sourceTreeSha256 : input.seal.selectedClosureSha256,
    complete: uncoveredPaths.length === 0,
    coveredPaths: Object.freeze(coveredPaths),
    excludedPaths: Object.freeze([...input.excludedPaths]),
    uncoveredPaths: Object.freeze(uncoveredPaths),
  });
}

function selectProfile(
  capability: DetectorCapabilityV1,
  request: RunDetectorV1Request,
): DetectorExecutionProfileV1 | { readonly refusal: string } {
  const named = request.executionProfileId;
  const available = capability.executionProfiles;
  const selected =
    named === undefined
      ? request.ociCapture === undefined
        ? capability.executionProfile
        : available.find((entry) => entry.evidence === "ScanCandidateV2")
      : available.find((entry) => entry.id === named);
  if (named === undefined && selected?.id === "host-process-uv-v1")
    return {
      refusal: `${capability.detectorId} runs only under host-process-uv-v1, which is unisolated and never a default: it runs only when named. Set executionProfileId to host-process-uv-v1 to run it.`,
    };
  if (selected === undefined)
    return {
      refusal:
        named === undefined
          ? `${capability.detectorId} has no OCI capture profile, so the supplied ociCapture material cannot be used. Available profiles: ${available
              .map((entry) => entry.id)
              .join(", ")}.`
          : `${capability.detectorId} has no execution profile ${named}. Available profiles: ${available
              .map((entry) => entry.id)
              .join(", ")}.`,
    };
  if (selected.evidence === "ScanCandidateV2" && request.ociCapture === undefined)
    return {
      refusal: `Execution profile ${selected.id} needs a caller-supplied immutable OCI layout, runtime registration, broker identity and annex payloads; supply subject.ociCapture or use ${capability.executionProfile.id}.`,
    };
  if (selected.evidence !== "ScanCandidateV2" && request.ociCapture !== undefined)
    return {
      refusal: `Execution profile ${selected.id} takes no OCI capture material; remove ociCapture or name an OCI capture profile.`,
    };
  if (
    selected.evidence === "ScanCandidateV2" &&
    (request.signal !== undefined || request.timeoutMs !== undefined)
  )
    return {
      refusal: `Execution profile ${selected.id} cannot yet be cancelled or given a time budget; remove signal and timeoutMs, or use ${capability.executionProfile.id}.`,
    };
  return selected;
}

function subjectRefusal(
  capability: DetectorCapabilityV1,
  seal: RunSealV1,
  request: RunDetectorV1Request,
  profile: DetectorExecutionProfileV1,
): string | undefined {
  const excludedPaths = request.subject.excludedPaths ?? [];
  if (excludedPaths.length > 0 && profile.evidence !== "ScanCandidateV2")
    return `Execution profile ${profile.id} analyzes the whole sealed snapshot, so it cannot honour declared excludedPaths; remove them rather than record an exclusion that did not happen.`;
  const selected = new Set(seal.selectedClosurePaths);
  for (const path of excludedPaths) {
    if (selected.has(path))
      return `Declared excluded path ${path} is also a selected closure path; a file cannot be both covered and left out.`;
  }
  if (capability.detectorId === "detector.skillspector") {
    if (
      request.subject.sourceRoot.includes(",") ||
      [...request.subject.sourceRoot].some((character) => {
        const code = character.charCodeAt(0);
        return code <= 31 || code === 127;
      })
    )
      return "The declared source root path holds a comma or a control character, which a Docker bind-mount specification cannot represent.";
  }
  if (request.subject.kind !== "skill-directory") return undefined;
  const topLevelSkill = seal.entries.some(
    (entry) => isFileEntry(entry) && entry.path === "SKILL.md",
  );
  if (!topLevelSkill) {
    // A tree of several skills is not one skill root. Say so, and how to shard it,
    // rather than only that the top-level SKILL.md is absent.
    const nested = seal.selectedClosurePaths.filter((path) => path.endsWith("/SKILL.md"));
    if (nested.length > 0) {
      const directories = nested.map((path) => path.slice(0, -"/SKILL.md".length));
      const named =
        directories.length <= 3
          ? directories.join(", ")
          : `${directories.slice(0, 3).join(", ")} and ${directories.length - 3} more`;
      return `${capability.detectorId} runs one skill root per request; this selection holds ${nested.length} SKILL.md file${nested.length === 1 ? "" : "s"} below the declared root and none at its top. Shard it: send one skill-directory request per directory that holds a SKILL.md, with that directory as sourceRoot and its own files, SKILL.md included, as selectedClosurePaths. Directories: ${named}.`;
    }
    return `${capability.detectorId} needs a top-level SKILL.md in the declared source root. Scan does not create, rename, copy or discover one, so this subject is refused unchanged.`;
  }
  if (!selected.has("SKILL.md"))
    return "The top-level SKILL.md is not one of the declared selected closure paths; declare it so the selection and the requirement agree.";
  return undefined;
}

function sameSeal(left: RunSealV1, right: RunSealV1): boolean {
  return (
    left.sourceTreeSha256 === right.sourceTreeSha256 &&
    left.selectedClosureSha256 === right.selectedClosureSha256 &&
    left.sealedSnapshotSha256 === right.sealedSnapshotSha256
  );
}

/** A thrown value's message, or `undefined`; reading it never throws. */
function thrownMessage(error: unknown): string | undefined {
  try {
    if (error instanceof Error && typeof error.message === "string") return error.message;
  } catch {
    // A hostile message accessor is reported as an unknown failure.
  }
  return undefined;
}

export function detail(error: unknown): string {
  return boundedDiagnosticDetailV1(thrownMessage(error) ?? "unknown failure");
}

const REQUEST_FIELDS = [
  "detectorId",
  "subject",
  "executionProfileId",
  "env",
  "signal",
  "timeoutMs",
  "runner",
  "prerequisiteProbe",
  "ociCapture",
  "acceptedImageDigests",
  "detectorOptions",
] as const;
const SUBJECT_FIELDS = ["kind", "sourceRoot", "selectedClosurePaths", "excludedPaths"] as const;
const OCI_CAPTURE_FIELDS = ["layout", "runtime", "broker", "annexPayloads", "runner"] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Names a value's shape without coercing it, so no caller `toString` ever runs. */
function valueKind(value: unknown): string {
  if (value === null) return "null";
  try {
    if (Array.isArray(value)) return "an array";
  } catch {
    return "a revoked proxy";
  }
  return typeof value === "object" ? "an object" : `a ${typeof value}`;
}

/**
 * Checks the snapshotted fields that select or configure the execution profile, before
 * any of them is interpolated or handed on. Malformed values are refused, never coerced.
 */
export function executionFieldRefusal(
  capability: DetectorCapabilityV1,
  input: Readonly<Record<string, unknown>>,
): string | undefined {
  const named = input.executionProfileId;
  if (named !== undefined && (typeof named !== "string" || named.length === 0))
    return `executionProfileId must be a non-empty string naming an execution profile of ${capability.detectorId}, not ${
      typeof named === "string" ? "an empty string" : valueKind(named)
    }. Available profiles: ${capability.executionProfiles
      .map((entry) => entry.id)
      .join(", ")}; omit it to use ${capability.executionProfile.id}.`;
  const env = input.env;
  if (env !== undefined) {
    if (!isRecord(env))
      return `env must be an object mapping environment variable names to strings, not ${valueKind(env)}.`;
    for (const [key, value] of Object.entries(env)) {
      if (value !== undefined && typeof value !== "string")
        return `env.${key} must be a string, not ${valueKind(value)}; Scan does not coerce environment values.`;
    }
  }
  const signal = input.signal;
  if (signal !== undefined && !(signal instanceof AbortSignal))
    return `signal must be an AbortSignal, not ${valueKind(signal)}.`;
  const timeoutMs = input.timeoutMs;
  if (
    timeoutMs !== undefined &&
    (typeof timeoutMs !== "number" ||
      !Number.isSafeInteger(timeoutMs) ||
      timeoutMs < MIN_TIMEOUT_MS ||
      timeoutMs > MAX_TIMEOUT_MS)
  )
    return `timeoutMs must be a whole number of milliseconds from ${MIN_TIMEOUT_MS} to ${MAX_TIMEOUT_MS}, not ${
      typeof timeoutMs === "number" ? String(timeoutMs) : valueKind(timeoutMs)
    }.`;
  const ociCapture = input.ociCapture;
  if (ociCapture !== undefined && !isRecord(ociCapture))
    return `ociCapture must be an object holding layout, runtime, broker and annexPayloads, not ${valueKind(ociCapture)}.`;
  return undefined;
}

type FieldSnapshot =
  | { readonly value: Record<string, unknown> }
  | { readonly field: string; readonly error: unknown };

/**
 * Reads each named field exactly once into a new plain object, copying arrays, so no
 * caller accessor runs again later outside a guard. Reports the first field that threw.
 */
function snapshotFields(
  source: Record<string, unknown>,
  fields: readonly string[],
  prefix: string,
): FieldSnapshot {
  const value: Record<string, unknown> = {};
  let field = "";
  try {
    for (field of fields) {
      const read = source[field];
      value[field] = Array.isArray(read) ? Array.from(read) : read;
    }
  } catch (error) {
    return { field: `${prefix}${field}`, error };
  }
  return { value };
}

/** The request's own fields, plus a copy of the caller environment and OCI material. */
function snapshotRequest(request: Record<string, unknown>): FieldSnapshot {
  const top = snapshotFields(request, REQUEST_FIELDS, "");
  if ("field" in top) return top;
  const env = top.value.env;
  if (isRecord(env)) {
    try {
      top.value.env = Object.freeze(Object.fromEntries(Object.entries(env)));
    } catch (error) {
      return { field: "env", error };
    }
  }
  const ociCapture = top.value.ociCapture;
  if (isRecord(ociCapture)) {
    const material = snapshotFields(ociCapture, OCI_CAPTURE_FIELDS, "ociCapture.");
    if ("field" in material) return material;
    top.value.ociCapture = material.value;
  }
  return top;
}

/**
 * Settles every prerequisite once. A caller probe that throws, is not callable or answers
 * outside the three states stops probing: that prerequisite and every later one stay
 * `not-probed`, so nothing is claimed, and the reason is returned for an availability failure.
 */
export function probeStates(
  declared: readonly DetectorPrerequisiteV1[],
  probe: unknown,
  env: Readonly<NodeJS.ProcessEnv>,
  requestEnv: Readonly<NodeJS.ProcessEnv> = env,
): { readonly states: readonly DetectorPrerequisiteStateV1[]; readonly failure?: string } {
  const states: DetectorPrerequisiteStateV1[] = [];
  let failure: string | undefined;
  for (const prerequisite of declared) {
    let state: DetectorPrerequisiteStateV1["state"] = "not-probed";
    if (failure === undefined && probe === undefined)
      state = probePrerequisite(prerequisite, env, requestEnv);
    else if (failure === undefined) {
      try {
        const reported: unknown = (probe as (entry: DetectorPrerequisiteV1) => unknown)(
          prerequisite,
        );
        if (reported === "present" || reported === "missing" || reported === "not-probed")
          state = reported;
        else
          failure = `The caller-supplied prerequisiteProbe answered ${
            typeof reported === "string" ? JSON.stringify(reported) : typeof reported
          } for ${prerequisite.kind} ${prerequisite.id}; only present, missing or not-probed is a prerequisite state.`;
      } catch (error) {
        // The thrown text leads and the prerequisite closes, so both survive bounding.
        failure = `The caller-supplied prerequisiteProbe threw: ${
          thrownMessage(error) ?? "unknown failure"
        } (while probing ${prerequisite.kind} ${prerequisite.id}).`;
      }
    }
    states.push(
      Object.freeze({
        kind: prerequisite.kind,
        id: prerequisite.id,
        required: prerequisite.required,
        state,
      }),
    );
  }
  return { states: Object.freeze(states), ...(failure === undefined ? {} : { failure }) };
}

/** Runs one detector, returning a refusal, a failure or a success. Never throws. */
export async function runDetectorV1(request: unknown): Promise<RunDetectorV1Result> {
  try {
    return await runReadableRequestV1(request);
  } catch (error) {
    // Every step after the request is read and before anything runs is guarded, and a
    // run that started reports its own failures, so what reaches here is a request that
    // could not even be inspected, such as a revoked Proxy: refused, never a rejection.
    return refuse(
      "unknown-detector",
      `The run request could not be read: ${
        thrownMessage(error) ?? "unknown failure"
      }. Pass a plain data object naming a detector.`,
    );
  }
}

async function runReadableRequestV1(request: unknown): Promise<RunDetectorV1Result> {
  if (typeof request !== "object" || request === null || Array.isArray(request))
    return refuse("unknown-detector", "A run request must be an object naming a detector.");
  // Every caller field is read once, here, inside a guard. An accessor that throws makes
  // the request unreadable, refused like one that is not an object, never a rejection.
  const top = snapshotRequest(request as Record<string, unknown>);
  if ("field" in top)
    return refuse(
      "unknown-detector",
      `The run request could not be read: reading ${top.field} threw: ${
        thrownMessage(top.error) ?? "unknown failure"
      }. Pass a plain data object naming a detector.`,
    );
  const detectorId = top.value.detectorId;
  const capability = resolveDetectorCapabilityV1(detectorId);
  if (capability === undefined)
    return refuse(
      "unknown-detector",
      `Scan owns no detector ${typeof detectorId === "string" ? detectorId : "of that shape"}. Known detectors: ${listDetectorCapabilitiesV1()
        .map((entry) => entry.detectorId)
        .join(", ")}.`,
    );

  const declaredSubject = top.value.subject;
  if (!isRecord(declaredSubject))
    return refuse(
      "subject-requirement-unmet",
      "A run request must carry a subject naming a kind, a source root and the selected closure paths.",
      capability,
    );
  const subjectSnapshot = snapshotFields(declaredSubject, SUBJECT_FIELDS, "subject.");
  if ("field" in subjectSnapshot)
    return refuse(
      "subject-requirement-unmet",
      `The declared subject could not be read: reading ${subjectSnapshot.field} threw: ${
        thrownMessage(subjectSnapshot.error) ?? "unknown failure"
      }.`,
      capability,
    );
  // From here on only the snapshot is read; the caller's objects are never touched again.
  const input = { ...top.value, subject: subjectSnapshot.value } as unknown as RunDetectorV1Request;
  const subject = input.subject;
  if (!capability.subjectKinds.includes(subject.kind))
    return refuse(
      "unsupported-subject-kind",
      `${capability.detectorId} accepts ${capability.subjectKinds.join(", ")}, not ${
        typeof subject.kind === "string" ? subject.kind : "that subject kind"
      }.${
        capability.subjectKinds.length === 1 && capability.subjectKinds[0] === "skill-directory"
          ? " Scan runs one skill root per request: shard a tree holding several skills into one skill-directory request per directory that holds a SKILL.md."
          : ""
      }`,
      capability,
    );

  const optionsRead = readDetectorOptionsV1(
    capability.detectorId,
    top.value.detectorOptions,
    Array.isArray(subject.selectedClosurePaths) ? subject.selectedClosurePaths : [],
  );
  if (!optionsRead.ok) return refuse("detector-options-invalid", optionsRead.detail, capability);
  const detectorOptions = optionsRead.options;

  const fieldRefusal = executionFieldRefusal(capability, top.value);
  if (fieldRefusal !== undefined)
    return refuse("execution-profile-unavailable", fieldRefusal, capability);
  const profileOrRefusal = selectProfile(capability, input);
  if ("refusal" in profileOrRefusal)
    return refuse("execution-profile-unavailable", profileOrRefusal.refusal, capability);
  const profile = profileOrRefusal;
  if (
    capability.detectorId === "detector.cisco" &&
    subject.kind === "source-tree" &&
    profile.id !== "host-process-uv-v1"
  )
    return refuse(
      "unsupported-subject-kind",
      `detector.cisco accepts a source-tree subject only under host-process-uv-v1, which runs one skill-scanner job per directory holding a selected SKILL.md; ${profile.id} runs one skill root per request. Name host-process-uv-v1, or shard the tree into one skill-directory request per directory that holds a SKILL.md.`,
      capability,
    );
  const concurrencyRefusal = concurrencyRefusalV1(detectorOptions, subject.kind, profile.id);
  if (concurrencyRefusal !== undefined)
    return refuse("detector-options-invalid", concurrencyRefusal, capability);
  if (input.acceptedImageDigests !== undefined) {
    if (
      profile.id !== "docker-hardened-skillspector-v1" &&
      profile.id !== "docker-host-local-skillspector-v1"
    )
      return refuse(
        "execution-profile-unavailable",
        `acceptedImageDigests applies only to the docker-hardened-skillspector-v1 and docker-host-local-skillspector-v1 profiles; ${capability.detectorId} runs ${profile.id}, so remove it.`,
        capability,
      );
    const digestRefusal = skillspectorAcceptedImageDigestsRefusalV1(input.acceptedImageDigests);
    if (digestRefusal !== undefined)
      return refuse("execution-profile-unavailable", digestRefusal, capability);
  }

  const excludedPaths = subject.excludedPaths ?? [];
  if (!Array.isArray(excludedPaths))
    return refuse(
      "subject-requirement-unmet",
      "Declared excluded paths must be an array of safe relative POSIX paths.",
      capability,
    );
  try {
    for (const path of excludedPaths) assertSafeRelativePosixPathV1(path, "excluded path");
  } catch (error) {
    return refuse("subject-requirement-unmet", detail(error), capability);
  }

  const oci = profile.evidence === "ScanCandidateV2";
  let before: RunSealV1;
  try {
    before = oci
      ? sealSourceV2({
          sourceRoot: subject.sourceRoot,
          selectedClosurePaths: subject.selectedClosurePaths,
        })
      : sealSourceObservationV1({
          sourceRoot: subject.sourceRoot,
          selectedClosurePaths: subject.selectedClosurePaths,
        });
  } catch (error) {
    return refuse(
      "subject-requirement-unmet",
      `The declared subject could not be sealed: ${detail(error)}`,
      capability,
    );
  }
  const empty = before.entries.length === 0;
  if (empty) {
    if (capability.emptySource !== "completes")
      return refuse(
        "subject-requirement-unmet",
        `The declared source root holds no entries, and ${capability.detectorId} refuses an empty source (capability emptySource: ${capability.emptySource}).`,
        capability,
      );
    if (excludedPaths.length > 0)
      return refuse(
        "subject-requirement-unmet",
        "An empty source root has nothing to exclude; remove excludedPaths.",
        capability,
      );
  }
  const optionsSealRefusal = detectorOptionsSealRefusalV1(detectorOptions, before.entries);
  if (optionsSealRefusal !== undefined)
    return refuse("detector-options-invalid", optionsSealRefusal, capability);
  const requirement = subjectRefusal(capability, before, input, profile);
  if (requirement !== undefined)
    return refuse("subject-requirement-unmet", requirement, capability);

  const platform = capabilityPlatform();
  if (
    platform === undefined ||
    !profile.supportedPlatforms.some(
      (entry) => entry.os === platform.os && entry.architecture === platform.architecture,
    )
  )
    return refuse("unsupported-platform", platformRefusal(capability, profile), capability);

  const environments = engineEnvironmentsV1(capability.detectorId, input.env);
  const env = environments.host;
  const probe = input.prerequisiteProbe;
  const engineAnalyzer = engineForV1(capability.detectorId, subject.kind);
  if (engineAnalyzer !== undefined) {
    const preflight = enginePreflightRefusalV1(engineAnalyzer, {
      sourceRoot: subject.sourceRoot,
      selectedClosurePaths: subject.selectedClosurePaths,
      detectorOptions,
      requestEnv: input.env,
    });
    if (preflight !== undefined) return refuse(preflight.reason, preflight.detail, capability);
  }
  const seams: RunDetectorSeamsV1 = Object.freeze({
    runner:
      (input.ociCapture?.runner ?? input.runner) === undefined
        ? ("scan-owned-default" as const)
        : ("caller-supplied" as const),
    prerequisiteProbe: probe === undefined ? "scan-owned-default" : "caller-supplied",
  });
  const analyzerName = ANALYZER_BY_DETECTOR[capability.detectorId];
  const wholeTree = analyzerName !== undefined && WHOLE_TREE_ANALYZERS.has(analyzerName);
  const coverage = coverageRecord({
    seal: before,
    kind: oci ? "selected-closure" : "source-tree",
    excludedPaths,
    analyzesGitDirectory: wholeTree,
  });
  // Only the selected profile's prerequisites are probed, and only they gate the run.
  const probed = probeStates(profile.prerequisites, probe, env, environments.prerequisites);
  const prerequisites = probed.states;
  const failed = (stage: RunDetectorFailureStageV1, error: unknown): RunDetectorV1Result =>
    Object.freeze({
      outcome: "failed" as const,
      failure: Object.freeze({
        stage,
        detail: detail(error),
        ...(error instanceof AnalyzerRunFailureV1 ? { cause: error.failureCause } : {}),
      }),
      capability,
      executionProfile: profile,
      prerequisites,
      seams,
      producer: producer(),
      coverage,
    });
  if (probed.failure !== undefined) return failed("availability", new TypeError(probed.failure));
  const missing = profile.prerequisites.find(
    (prerequisite, index) => prerequisite.required && prerequisites[index]?.state === "missing",
  );
  if (missing !== undefined)
    return refuse(
      "prerequisite-missing",
      `${capability.detectorId} needs ${missing.kind} ${missing.id}, which is not present. ${missing.detail}`,
      capability,
    );
  const deadline = input.timeoutMs === undefined ? undefined : Date.now() + input.timeoutMs;
  if (input.signal?.aborted)
    return failed(
      "availability",
      new AnalyzerRunFailureV1("cancelled", "the run was cancelled before anything started"),
    );

  if (oci) {
    const sealed = before as SourceSealV2;
    const material = input.ociCapture as NonNullable<RunDetectorV1Request["ociCapture"]>;
    let capture: CiscoCaptureV2;
    try {
      capture = await captureCiscoOciCandidateV2({
        layout: material.layout,
        sourceRoot: subject.sourceRoot,
        selectedClosurePaths: [...subject.selectedClosurePaths],
        runtime: material.runtime,
        annexPayloads: material.annexPayloads,
        broker: material.broker,
        ...(material.runner === undefined ? {} : { runner: material.runner }),
      });
    } catch (error) {
      return failed(failureStage(thrownMessage(error) ?? ""), error);
    }
    let after: SourceSealV2;
    try {
      after = sealSourceV2({
        sourceRoot: subject.sourceRoot,
        selectedClosurePaths: subject.selectedClosurePaths,
      });
      if (!sameSeal(sealed, after)) throw new TypeError("source changed during the run");
    } catch (error) {
      return failed("coverage", error);
    }
    const detector = capture.candidate.scanner.detector;
    let findings: ScanFindingsV1;
    try {
      findings = buildScanFindingsV1({
        detector: { id: detector.detectorId, analyzerIdentity: detector.analyzerIdentity },
        facts: detector.observation.facts,
        annexDescriptors: capture.candidate.annexes,
        annexArtifacts: capture.annexArtifacts.map((artifact) => ({
          descriptorId: artifact.descriptorId,
          bytes: artifact.bytes,
        })),
      });
    } catch (error) {
      return failed("output", error);
    }
    return Object.freeze({
      outcome: "succeeded" as const,
      capability,
      executionProfile: profile,
      prerequisites,
      seams,
      producer: producer(),
      evidence: Object.freeze({ kind: "scan-candidate-v2" as const, capture }),
      findings,
      coverage,
      sourceSeal: Object.freeze({ before: sealed, after }),
    });
  }

  const analyzer: BaselineAnalyzerV1 | EngineAnalyzerV1 | undefined =
    engineAnalyzer === undefined
      ? ANALYZER_BY_DETECTOR[capability.detectorId]
      : engineObservationAnalyzerV1(engineAnalyzer);
  if (analyzer === undefined)
    return refuse(
      "execution-profile-unavailable",
      `${capability.detectorId} has no analyzer backend in this package.`,
      capability,
    );
  // In-process engines read the declared source root, sealed before and after; every
  // other analyzer is given a private snapshot that is itself checked and removed.
  const inProcessEngine = engineAnalyzer !== undefined && engineRunsInProcessV1(engineAnalyzer);

  const snapshotOptions = {
    includeGitDirectory: wholeTree,
    maxFileBytes: SOURCE_OBSERVATION_SEAL_LIMITS_V1.maxFileBytes,
    links: "observation" as const,
  };
  let snapshotRoot: string | undefined;
  if (!inProcessEngine) {
    try {
      snapshotRoot = empty
        ? mkdtempSync(join(tmpdir(), "aih-scan-baseline-source-"))
        : createBaselineAnalyzerSnapshotV1(subject.sourceRoot, snapshotOptions);
    } catch (error) {
      return failed("availability", error);
    }
  }
  // Every path below returns a result rather than throwing, so the snapshot removal after
  // it always runs and a removal that fails is reported instead of rejecting.
  const analyzed = await (async (): Promise<RunDetectorV1Result> => {
    let normalized: {
      readonly analyzerVersion: string;
      readonly mediaType: BaselineAnalyzerObservationV1["mediaType"];
      readonly bytes: Buffer;
    };
    let extras: Pick<BaselineAnalyzerObservationV1, "image" | "hostRuntime" | "hostDocker"> = {};
    if (engineAnalyzer !== undefined) {
      const ran = await runEngineDetectorV1({
        analyzer: engineAnalyzer,
        root: snapshotRoot ?? subject.sourceRoot,
        selectedClosurePaths: subject.selectedClosurePaths,
        detectorOptions,
        requestEnv: input.env,
        hostEnv: env,
        ...(input.runner === undefined ? {} : { runner: input.runner }),
        ...(input.signal === undefined ? {} : { signal: input.signal }),
        ...(deadline === undefined ? {} : { deadline }),
      });
      if (ran.kind === "refused") return refuse(ran.refusal.reason, ran.refusal.detail, capability);
      if (ran.kind === "failed") return failed(ran.stage, ran.error);
      try {
        normalized = {
          analyzerVersion: ran.analyzerVersion,
          mediaType: "application/sarif+json",
          bytes: Buffer.from(canonicalStrictJsonBytesV1(ran.sarif)),
        };
      } catch (error) {
        return failed("output", error);
      }
      if (ran.hostRuntime !== undefined) extras = { hostRuntime: ran.hostRuntime };
    } else {
      let observed: Awaited<ReturnType<ReturnType<typeof createBaselineAnalyzerRunV1>>>;
      try {
        const run = createBaselineAnalyzerRunV1({
          ...(input.runner === undefined ? {} : { runner: input.runner }),
          ...(input.env === undefined ? {} : { env: input.env }),
          ...(input.acceptedImageDigests === undefined
            ? {}
            : { skillspectorAcceptedImageDigests: input.acceptedImageDigests }),
          executionProfileId: profile.id as BaselineExecutionProfileIdV1,
          ...(input.signal === undefined ? {} : { signal: input.signal }),
          ...(deadline === undefined ? {} : { deadline }),
        });
        observed = await run({
          analyzer: analyzer as BaselineAnalyzerV1,
          sourceRoot: snapshotRoot as string,
        });
      } catch (error) {
        return failed(failureStage(thrownMessage(error) ?? ""), error);
      }
      try {
        normalized = normalizedObservation(analyzer as BaselineAnalyzerV1, observed);
      } catch (error) {
        return failed("output", error);
      }
      extras = {
        ...(observed.image === undefined ? {} : { image: observed.image }),
        ...(observed.hostRuntime === undefined ? {} : { hostRuntime: observed.hostRuntime }),
        ...(observed.hostDocker === undefined ? {} : { hostDocker: observed.hostDocker }),
      };
    }
    let after: SourceObservationSealV1;
    try {
      if (snapshotRoot !== undefined) {
        if (empty) {
          if (readdirSync(snapshotRoot).length !== 0)
            throw new TypeError("source changed during the run");
        } else assertBaselineAnalyzerSnapshotUnchangedV1(snapshotRoot, snapshotOptions);
      }
      after = sealSourceObservationV1({
        sourceRoot: subject.sourceRoot,
        selectedClosurePaths: subject.selectedClosurePaths,
      });
      if (!sameSeal(before, after)) throw new TypeError("source changed during the run");
    } catch (error) {
      return failed("coverage", error);
    }
    const sealedFiles = new Map(
      before.entries.flatMap((entry) =>
        entry.kind === "file" || entry.kind === "file-link"
          ? [[entry.path, entry.sha256] as const]
          : [],
      ),
    );
    // Owner decision D1: Cisco 2.1.0 reports os.path.normcase paths, lowercased on Windows.
    // There, and only there, each is bound to the unique sealed file equal ignoring case and
    // carries that file's real name in the SARIF itself; no match still fails below.
    if (
      analyzer === "cisco" &&
      normalized.mediaType === "application/sarif+json" &&
      process.platform === "win32"
    ) {
      try {
        const bound = bindCiscoSarifToSealedFilesV1(
          parseStrictJsonObjectV1(normalized.bytes.toString("utf8"), "Cisco SARIF"),
          sealedFiles.keys(),
          process.platform,
        );
        if (bound.rebound > 0)
          normalized = {
            ...normalized,
            bytes: Buffer.from(canonicalStrictJsonBytesV1(bound.document)),
          };
      } catch (error) {
        return failed("output", error);
      }
    }
    // C2a §1.6: only now, with the analyzer's own completion proven and the source re-sealed
    // unchanged, does every SARIF run name the files the analyzer received.
    if (normalized.mediaType === "application/sarif+json") {
      try {
        const sealed = before as SourceObservationSealV1;
        const evidence = scanCompletionEvidenceV1({
          detectorId: capability.detectorId,
          files: scanCompletionSubjectFilesV1({
            engine: (engineAnalyzer ?? analyzer) as ScanCompletionSubjectEngineV1,
            entries: sealed.entries,
            selectedClosurePaths: sealed.selectedClosurePaths,
            detectorOptions,
          }),
          emptyAllowed: capability.emptySource === "completes",
          analyzer: {
            version: normalized.analyzerVersion,
            lockSha256: profile.analyzerLock?.sha256 ?? null,
          },
        });
        const log = attachScanCompletionV1(
          parseStrictJsonObjectV1(normalized.bytes.toString("utf8"), `${analyzer} SARIF`),
          evidence,
          {
            scanBuilt: engineAnalyzer !== undefined && SCAN_BUILT_SARIF_ENGINES.has(engineAnalyzer),
          },
        );
        normalized = { ...normalized, bytes: Buffer.from(canonicalStrictJsonBytesV1(log)) };
      } catch (error) {
        return failed("output", error);
      }
    }
    const annex = Object.freeze({
      path: `annex/${analyzer}.json`,
      sha256: createHash("sha256").update(normalized.bytes).digest("hex"),
      byteLength: normalized.bytes.byteLength,
    });
    let findings: ScanFindingsV1;
    try {
      findings =
        normalized.mediaType === "application/sarif+json"
          ? projectAnalyzerSarifFindingsV1({
              detectorId: capability.detectorId,
              analyzer,
              analyzerIdentity: `${analyzer}@${normalized.analyzerVersion}`,
              annex: {
                descriptorId: annex.path,
                sha256: annex.sha256,
                byteLength: annex.byteLength,
              },
              bytes: normalized.bytes,
              sealedFiles,
              // Engine SARIF may name no file (a whole-tree finding, a fallback URI). Cisco's
              // source-tree jobs are skill-scanner SARIF and stay bound like its directory run.
              ...(engineAnalyzer === undefined || engineAnalyzer === "cisco-source-tree"
                ? {}
                : { unboundLocations: "unavailable" as const, maxResults: ENGINE_MAX_RESULTS_V1 }),
            })
          : digestBoundAnalyzerFindingsV1(
              `The ${analyzer} output is a source identity observation, not a findings report, so no rule, severity, message or location is derived from it.`,
            );
    } catch (error) {
      return failed("output", error);
    }
    return Object.freeze({
      outcome: "succeeded" as const,
      capability,
      executionProfile: profile,
      prerequisites,
      seams,
      producer: producer(),
      evidence: Object.freeze({
        kind: "baseline-analyzer-observation-v1" as const,
        observation: Object.freeze({
          protocol: "BaselineAnalyzerObservationV1" as const,
          analyzer,
          analyzerVersion: normalized.analyzerVersion,
          mediaType: normalized.mediaType,
          annex,
          bytes: normalized.bytes,
          ...extras,
        }),
      }),
      findings,
      coverage,
      sourceSeal: Object.freeze({ before: before as SourceObservationSealV1, after }),
    });
  })();
  if (snapshotRoot === undefined) return analyzed;
  try {
    rmSync(snapshotRoot, { recursive: true, force: true });
  } catch (error) {
    // The detector already ran, so this is never a refusal. A run that already failed
    // keeps its own, earlier failure; one that succeeded must not claim success while
    // leaving its private snapshot behind.
    return analyzed.outcome === "succeeded" ? failed("cleanup", error) : analyzed;
  }
  return analyzed;
}

const PROBE_FIELDS = [
  "detectorId",
  "executionProfileId",
  "env",
  "signal",
  "prerequisiteProbe",
  "acceptedImageDigests",
] as const;

export type DetectorAvailabilityV1Result =
  | Readonly<{
      available: true;
      detectorId: string;
      /** The pinned analyzer version the capability targets; nothing was executed. */
      analyzerVersion: string;
      /** Exactly the profile that was named. */
      executionProfile: DetectorExecutionProfileV1;
      /**
       * Every prerequisite of that profile. `not-probed` ones (a container image, a
       * uv-discoverable Python, a reachable index) are settled only by a run.
       */
      prerequisites: readonly DetectorPrerequisiteStateV1[];
      seams: Readonly<{ prerequisiteProbe: RunDetectorSeamsV1["prerequisiteProbe"] }>;
    }>
  | Readonly<{
      available: false;
      reason: RunDetectorRefusalReasonV1 | "availability-failed";
      /** One actionable sentence; bounded and control-character encoded. */
      detail: string;
    }>;

function unavailable(
  reason: RunDetectorRefusalReasonV1 | "availability-failed",
  detail: string,
): DetectorAvailabilityV1Result {
  return Object.freeze({
    available: false as const,
    reason,
    detail: boundedDiagnosticDetailV1(detail),
  });
}

/**
 * Probes whether a detector could run under the named profile on this host, without a
 * subject and without spawning, pulling or executing anything (C2a §3.8). It applies the
 * same request-field, profile, platform and prerequisite gates as `runDetectorV1` and
 * answers with the same refusal reasons, or `availability-failed` when the caller's signal
 * is already aborted or its `prerequisiteProbe` misbehaves. `available: true` means no
 * required prerequisite is known to be missing. Never throws.
 */
export async function probeDetectorAvailabilityV1(
  request: unknown,
): Promise<DetectorAvailabilityV1Result> {
  try {
    if (typeof request !== "object" || request === null || Array.isArray(request))
      return unavailable(
        "unknown-detector",
        "A probe request must be an object naming a detector.",
      );
    const read = snapshotFields(request as Record<string, unknown>, PROBE_FIELDS, "");
    if ("field" in read)
      return unavailable(
        "unknown-detector",
        `The probe request could not be read: reading ${read.field} threw: ${
          thrownMessage(read.error) ?? "unknown failure"
        }.`,
      );
    const input = read.value;
    const capability = resolveDetectorCapabilityV1(input.detectorId);
    if (capability === undefined)
      return unavailable(
        "unknown-detector",
        `Scan owns no detector ${
          typeof input.detectorId === "string" ? input.detectorId : "of that shape"
        }. Known detectors: ${listDetectorCapabilitiesV1()
          .map((entry) => entry.detectorId)
          .join(", ")}.`,
      );
    const available = capability.executionProfiles.map((entry) => entry.id).join(", ");
    if (input.executionProfileId === undefined)
      return unavailable(
        "execution-profile-unavailable",
        `A probe names the execution profile it asks about; ${capability.detectorId} has ${available}.`,
      );
    const fieldRefusal = executionFieldRefusal(capability, input);
    if (fieldRefusal !== undefined)
      return unavailable("execution-profile-unavailable", fieldRefusal);
    const profile = capability.executionProfiles.find(
      (entry) => entry.id === input.executionProfileId,
    );
    if (profile === undefined)
      return unavailable(
        "execution-profile-unavailable",
        `${capability.detectorId} has no execution profile ${String(
          input.executionProfileId,
        )}. Available profiles: ${available}.`,
      );
    if (input.acceptedImageDigests !== undefined) {
      if (
        profile.id !== "docker-hardened-skillspector-v1" &&
        profile.id !== "docker-host-local-skillspector-v1"
      )
        return unavailable(
          "execution-profile-unavailable",
          `acceptedImageDigests applies only to the docker-hardened-skillspector-v1 and docker-host-local-skillspector-v1 profiles; ${capability.detectorId} runs ${profile.id}, so remove it.`,
        );
      const digestRefusal = skillspectorAcceptedImageDigestsRefusalV1(input.acceptedImageDigests);
      if (digestRefusal !== undefined)
        return unavailable("execution-profile-unavailable", digestRefusal);
    }
    const platform = capabilityPlatform();
    if (
      platform === undefined ||
      !profile.supportedPlatforms.some(
        (entry) => entry.os === platform.os && entry.architecture === platform.architecture,
      )
    )
      return unavailable("unsupported-platform", platformRefusal(capability, profile));
    const signal = input.signal as AbortSignal | undefined;
    if (signal?.aborted)
      return unavailable("availability-failed", "The probe was cancelled before it started.");
    // As for a run: Snyk's env is the request env of SNYK_TOKEN alone, and its uv is found
    // on the host environment; every other detector's env is the host environment.
    if (capability.detectorId === "detector.snyk-agent-scan") {
      const snyk = validateSnykAgentScanRequestEnvV1(input.env);
      if (!snyk.ok) return unavailable(snyk.refusal.reason, snyk.refusal.detail);
    }
    const environments = engineEnvironmentsV1(
      capability.detectorId,
      input.env as Readonly<NodeJS.ProcessEnv> | undefined,
    );
    const probed = probeStates(
      profile.prerequisites,
      input.prerequisiteProbe,
      environments.host,
      environments.prerequisites,
    );
    if (probed.failure !== undefined) return unavailable("availability-failed", probed.failure);
    const missing = profile.prerequisites.find(
      (prerequisite, index) => prerequisite.required && probed.states[index]?.state === "missing",
    );
    if (missing !== undefined)
      return unavailable(
        "prerequisite-missing",
        `${capability.detectorId} needs ${missing.kind} ${missing.id}, which is not present. ${missing.detail}`,
      );
    return Object.freeze({
      available: true as const,
      detectorId: capability.detectorId,
      analyzerVersion: capability.analyzerVersion,
      executionProfile: profile,
      prerequisites: probed.states,
      seams: Object.freeze({
        prerequisiteProbe:
          input.prerequisiteProbe === undefined
            ? ("scan-owned-default" as const)
            : ("caller-supplied" as const),
      }),
    });
  } catch (error) {
    return unavailable(
      "unknown-detector",
      `The probe request could not be read: ${thrownMessage(error) ?? "unknown failure"}.`,
    );
  }
}
