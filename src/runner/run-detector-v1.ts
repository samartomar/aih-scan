import { createHash } from "node:crypto";
import { rmSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertBaselineAnalyzerSnapshotUnchangedV1,
  type BaselineAnalyzerV1,
  createBaselineAnalyzerSnapshotV1,
  normalizedObservation,
} from "../baseline/batch-v1.js";
import {
  type BaselineProcessRunnerV1,
  boundedDiagnosticDetailV1,
  createBaselineAnalyzerRunV1,
} from "../baseline/runtime-v1.js";
import {
  type DetectorCapabilityV1,
  type DetectorExecutionProfileV1,
  type DetectorPlatformV1,
  type DetectorPrerequisiteV1,
  type DetectorSubjectKindV1,
  listDetectorCapabilitiesV1,
  resolveDetectorCapabilityV1,
} from "../capability/detector-capability-v1.js";
import { type CiscoCaptureV2, captureCiscoOciCandidateV2 } from "../cisco/capture-v2.js";
import { assertSafeRelativePosixPathV1, codeUnitCompare } from "../contract/strict-json-v1.js";
import {
  buildScanFindingsV1,
  digestBoundAnalyzerFindingsV1,
  type ScanFindingsV1,
} from "../findings/scan-findings-v1.js";
import { type SourceSealV2, sealSourceV2 } from "../observation/source-seal-v2.js";

/**
 * Runs one Scan-owned detector without the caller writing any execution code.
 *
 * Honesty rules enforced by construction:
 *
 * - every unsupported detector, subject, profile, platform or prerequisite is a
 *   returned refusal, produced before any process is spawned; a refusal and a failure
 *   are values, never thrown exceptions;
 * - the execution profile reported is the one that actually ran, and its digest is the
 *   digest of a readable document this package publishes;
 * - selection is exactly what the caller declared. Scan never discovers, widens,
 *   renames, copies or creates a `SKILL.md`, and never silently scans more than the
 *   coverage record states;
 * - coverage names what was covered, what the caller declared excluded, and what was
 *   neither, so "complete" is a computed field rather than a claim;
 * - findings come only from digest-verified annex bytes. An empty list is never
 *   reported as "nothing was found"; the gaps say why it is empty.
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

export type RunDetectorRefusalReasonV1 =
  | "unknown-detector"
  | "unsupported-platform"
  | "unsupported-subject-kind"
  | "subject-requirement-unmet"
  | "prerequisite-missing"
  | "execution-profile-unavailable";

export type RunDetectorFailureStageV1 =
  | "acquisition"
  | "availability"
  | "execution"
  | "output"
  | "coverage"
  | "cleanup";

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

export interface BaselineAnalyzerObservationV1 {
  readonly protocol: "BaselineAnalyzerObservationV1";
  readonly analyzer: BaselineAnalyzerV1;
  readonly analyzerVersion: string;
  readonly mediaType: "application/sarif+json" | "application/vnd.aih.baseline-native+json";
  readonly annex: Readonly<{ path: string; sha256: string; byteLength: number }>;
  /** The exact canonical bytes the digest above was taken over. */
  readonly bytes: Buffer;
}

export interface RunDetectorV1Request {
  readonly detectorId: string;
  readonly subject: {
    readonly kind: DetectorSubjectKindV1;
    readonly sourceRoot: string;
    /** Exact, caller-declared selection. Never widened, never discovered. */
    readonly selectedClosurePaths: readonly string[];
    /** Recorded verbatim so evidence can state what was deliberately left out. */
    readonly excludedPaths?: readonly string[];
  };
  /** Optional override; the capability's own default profile is used when absent. */
  readonly executionProfileId?: string;
  /** Applies to the analyzer profiles; it is scrubbed to Scan's allow-list before use. */
  readonly env?: Readonly<NodeJS.ProcessEnv>;
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
      failure: Readonly<{ stage: RunDetectorFailureStageV1; detail: string }>;
      capability: DetectorCapabilityV1;
      executionProfile: DetectorExecutionProfileV1;
      prerequisites: readonly DetectorPrerequisiteStateV1[];
      seams: RunDetectorSeamsV1;
      coverage: ScanCoverageV1;
    }>
  | Readonly<{
      outcome: "succeeded";
      capability: DetectorCapabilityV1;
      /** The profile that actually ran, not the one that was asked for. */
      executionProfile: DetectorExecutionProfileV1;
      prerequisites: readonly DetectorPrerequisiteStateV1[];
      seams: RunDetectorSeamsV1;
      evidence:
        | Readonly<{
            kind: "baseline-analyzer-observation-v1";
            observation: BaselineAnalyzerObservationV1;
          }>
        | Readonly<{ kind: "scan-candidate-v2"; capture: CiscoCaptureV2 }>;
      findings: ScanFindingsV1;
      coverage: ScanCoverageV1;
      sourceSeal: Readonly<{ before: SourceSealV2; after: SourceSealV2 }>;
    }>;

function host(): { os: NodeJS.Platform; architecture: string } {
  return Object.freeze({ os: process.platform, architecture: process.arch });
}

function capabilityPlatform(): DetectorPlatformV1 | undefined {
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

function failureStage(message: string): RunDetectorFailureStageV1 {
  if (message.includes("environment acquisition") || message.includes("image acquisition"))
    return "acquisition";
  if (message.includes("Docker availability")) return "availability";
  if (message.includes("coverage")) return "coverage";
  if (message.includes("observation") || message.includes("emitted no SARIF")) return "output";
  return "execution";
}

function probePrerequisite(
  prerequisite: DetectorPrerequisiteV1,
  env: Readonly<NodeJS.ProcessEnv>,
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
  if (prerequisite.kind === "environment-variable") {
    const value = env[prerequisite.id];
    return typeof value === "string" && value.length > 0 ? "present" : "missing";
  }
  // A container image and a reachable index cannot be settled without running the
  // detector, so they are reported as not probed rather than guessed either way.
  return "not-probed";
}

function coverageRecord(input: {
  readonly seal: SourceSealV2;
  readonly kind: ScanCoverageV1["kind"];
  readonly excludedPaths: readonly string[];
}): ScanCoverageV1 {
  const sealedFiles = input.seal.entries
    .filter((entry) => entry.kind === "file")
    .map((entry) => entry.path);
  const coveredPaths =
    input.kind === "source-tree" ? [...sealedFiles] : [...input.seal.selectedClosurePaths];
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
  return selected;
}

function subjectRefusal(
  capability: DetectorCapabilityV1,
  seal: SourceSealV2,
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
    (entry) => entry.kind === "file" && entry.path === "SKILL.md",
  );
  if (!topLevelSkill)
    return `${capability.detectorId} needs a top-level SKILL.md in the declared source root. Scan does not create, rename, copy or discover one, so this subject is refused unchanged.`;
  if (!selected.has("SKILL.md"))
    return "The top-level SKILL.md is not one of the declared selected closure paths; declare it so the selection and the requirement agree.";
  return undefined;
}

function sameSeal(left: SourceSealV2, right: SourceSealV2): boolean {
  return (
    left.sourceTreeSha256 === right.sourceTreeSha256 &&
    left.selectedClosureSha256 === right.selectedClosureSha256 &&
    left.sealedSnapshotSha256 === right.sealedSnapshotSha256
  );
}

function detail(error: unknown): string {
  return boundedDiagnosticDetailV1(error instanceof Error ? error.message : "unknown failure");
}

/** Runs one detector, returning a refusal, a failure or a success. Never throws. */
export async function runDetectorV1(request: unknown): Promise<RunDetectorV1Result> {
  if (typeof request !== "object" || request === null || Array.isArray(request))
    return refuse("unknown-detector", "A run request must be an object naming a detector.");
  const input = request as RunDetectorV1Request;
  const capability = resolveDetectorCapabilityV1(input.detectorId);
  if (capability === undefined)
    return refuse(
      "unknown-detector",
      `Scan owns no detector ${typeof input.detectorId === "string" ? input.detectorId : "of that shape"}. Known detectors: ${listDetectorCapabilitiesV1()
        .map((entry) => entry.detectorId)
        .join(", ")}.`,
    );

  const subject = input.subject;
  if (typeof subject !== "object" || subject === null || Array.isArray(subject))
    return refuse(
      "subject-requirement-unmet",
      "A run request must carry a subject naming a kind, a source root and the selected closure paths.",
      capability,
    );
  if (!capability.subjectKinds.includes(subject.kind))
    return refuse(
      "unsupported-subject-kind",
      `${capability.detectorId} accepts ${capability.subjectKinds.join(", ")}, not ${
        typeof subject.kind === "string" ? subject.kind : "that subject kind"
      }.`,
      capability,
    );

  const profileOrRefusal = selectProfile(capability, input);
  if ("refusal" in profileOrRefusal)
    return refuse("execution-profile-unavailable", profileOrRefusal.refusal, capability);
  const profile = profileOrRefusal;

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

  let before: SourceSealV2;
  try {
    before = sealSourceV2({
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
  const requirement = subjectRefusal(capability, before, input, profile);
  if (requirement !== undefined)
    return refuse("subject-requirement-unmet", requirement, capability);

  const platform = capabilityPlatform();
  if (
    platform === undefined ||
    !capability.supportedPlatforms.some(
      (entry) => entry.os === platform.os && entry.architecture === platform.architecture,
    )
  )
    return refuse(
      "unsupported-platform",
      `This host is ${process.platform}/${process.arch}; ${capability.detectorId} runs only on ${capability.supportedPlatforms
        .map((entry) => `${entry.os}/${entry.architecture}`)
        .join(", ")}. Scan's hardened detector profiles are Linux amd64 only.`,
      capability,
    );

  const env = input.env ?? process.env;
  const probe = input.prerequisiteProbe;
  const prerequisites: readonly DetectorPrerequisiteStateV1[] = Object.freeze(
    capability.prerequisites.map((prerequisite) =>
      Object.freeze({
        kind: prerequisite.kind,
        id: prerequisite.id,
        required: prerequisite.required,
        state: probe === undefined ? probePrerequisite(prerequisite, env) : probe(prerequisite),
      }),
    ),
  );
  const missing = capability.prerequisites.find(
    (prerequisite, index) => prerequisite.required && prerequisites[index]?.state === "missing",
  );
  if (missing !== undefined)
    return refuse(
      "prerequisite-missing",
      `${capability.detectorId} needs ${missing.kind} ${missing.id}, which is not present. ${missing.detail}`,
      capability,
    );

  const seams: RunDetectorSeamsV1 = Object.freeze({
    runner:
      (input.ociCapture?.runner ?? input.runner) === undefined
        ? ("scan-owned-default" as const)
        : ("caller-supplied" as const),
    prerequisiteProbe: probe === undefined ? "scan-owned-default" : "caller-supplied",
  });
  const coverage = coverageRecord({
    seal: before,
    kind: profile.evidence === "ScanCandidateV2" ? "selected-closure" : "source-tree",
    excludedPaths,
  });
  const failed = (stage: RunDetectorFailureStageV1, error: unknown): RunDetectorV1Result =>
    Object.freeze({
      outcome: "failed" as const,
      failure: Object.freeze({ stage, detail: detail(error) }),
      capability,
      executionProfile: profile,
      prerequisites,
      seams,
      coverage,
    });

  if (profile.evidence === "ScanCandidateV2") {
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
      return failed(failureStage(error instanceof Error ? error.message : ""), error);
    }
    let after: SourceSealV2;
    try {
      after = sealSourceV2({
        sourceRoot: subject.sourceRoot,
        selectedClosurePaths: subject.selectedClosurePaths,
      });
      if (!sameSeal(before, after)) throw new TypeError("source changed during the run");
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
      evidence: Object.freeze({ kind: "scan-candidate-v2" as const, capture }),
      findings,
      coverage,
      sourceSeal: Object.freeze({ before, after }),
    });
  }

  const analyzer = ANALYZER_BY_DETECTOR[capability.detectorId];
  if (analyzer === undefined)
    return refuse(
      "execution-profile-unavailable",
      `${capability.detectorId} has no analyzer backend in this package.`,
      capability,
    );

  let snapshotRoot: string;
  try {
    snapshotRoot = createBaselineAnalyzerSnapshotV1(subject.sourceRoot);
  } catch (error) {
    return failed("availability", error);
  }
  try {
    let observed: Awaited<ReturnType<ReturnType<typeof createBaselineAnalyzerRunV1>>>;
    try {
      const run = createBaselineAnalyzerRunV1({
        ...(input.runner === undefined ? {} : { runner: input.runner }),
        ...(input.env === undefined ? {} : { env: input.env }),
      });
      observed = await run({ analyzer, sourceRoot: snapshotRoot });
    } catch (error) {
      return failed(failureStage(error instanceof Error ? error.message : ""), error);
    }
    let normalized: ReturnType<typeof normalizedObservation>;
    try {
      normalized = normalizedObservation(analyzer, observed);
    } catch (error) {
      return failed("output", error);
    }
    try {
      assertBaselineAnalyzerSnapshotUnchangedV1(snapshotRoot);
      const after = sealSourceV2({
        sourceRoot: subject.sourceRoot,
        selectedClosurePaths: subject.selectedClosurePaths,
      });
      if (!sameSeal(before, after)) throw new TypeError("source changed during the run");
      return Object.freeze({
        outcome: "succeeded" as const,
        capability,
        executionProfile: profile,
        prerequisites,
        seams,
        evidence: Object.freeze({
          kind: "baseline-analyzer-observation-v1" as const,
          observation: Object.freeze({
            protocol: "BaselineAnalyzerObservationV1" as const,
            analyzer,
            analyzerVersion: normalized.analyzerVersion,
            mediaType: normalized.mediaType,
            annex: Object.freeze({
              path: `annex/${analyzer}.json`,
              sha256: createHash("sha256").update(normalized.bytes).digest("hex"),
              byteLength: normalized.bytes.byteLength,
            }),
            bytes: normalized.bytes,
          }),
        }),
        findings: digestBoundAnalyzerFindingsV1(
          `The ${analyzer} output is bound by digest in this observation and is never parsed here, so no rule, severity, message or location is derived from it.`,
        ),
        coverage,
        sourceSeal: Object.freeze({ before, after }),
      });
    } catch (error) {
      return failed("coverage", error);
    }
  } finally {
    rmSync(snapshotRoot, { recursive: true, force: true });
  }
}
