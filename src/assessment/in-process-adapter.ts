import { createHash } from "node:crypto";
import type {
  DetectorCapabilityV1,
  DetectorExecutionProfileV1,
} from "../capability/detector-capability-v1.js";
import { canonicalStrictJsonBytesV1, parseStrictJsonObjectV1 } from "../contract/strict-json-v1.js";
import {
  attachScanCompletionV1,
  scanCompletionEvidenceV1,
  scanCompletionSubjectFilesV1,
} from "../detectors/completion-evidence-v1.js";
import {
  digestBoundAnalyzerFindingsV1,
  projectAnalyzerSarifFindingsV1,
} from "../findings/scan-findings-v1.js";
import {
  type SourceObservationSealV1,
  sealSourceObservationV1,
} from "../observation/source-observation-seal-v1.js";
import type { DetectorOptionsV1 } from "../runner/detector-options-v1.js";
import type {
  RunDetectorFailureCauseV1,
  RunDetectorFailureStageV1,
  RunDetectorRefusalReasonV1,
  RunDetectorV1Result,
} from "../runner/run-detector-v1.js";
import type { Producer } from "./types.js";

export interface InProcessImplementationRequest {
  sourceRoot: string;
  selectedClosurePaths: readonly string[];
  detectorOptions: unknown;
  signal?: AbortSignal;
}
type ImplementationOutcome =
  | { kind: "completed"; sarifText: string }
  | {
      kind: "refused";
      reason: "detector-options-invalid" | "subject-requirement-unmet";
      detail: string;
    }
  | { kind: "failed"; stage: "execution"; detail: string; cause?: "cancelled" }
  | {
      mediaType: "application/vnd.aih.baseline-native+json";
      bytes: Uint8Array;
      analyzerVersion: string;
    };
export interface InProcessAssessmentDetectorInput {
  capability: DetectorCapabilityV1;
  profile: DetectorExecutionProfileV1;
  sourceRoot: string;
  selectedClosurePaths: readonly string[];
  excludedPaths: readonly string[];
  detectorOptions?: DetectorOptionsV1;
  signal?: AbortSignal;
  timeoutMs: number;
  producer: Producer;
  implementation: (request: InProcessImplementationRequest) => ImplementationOutcome;
}
const definitions = new Map([
  ["detector.aih-native", { analyzer: "aih-native" as const, profile: "in-process-native-v1" }],
  [
    "detector.aih-binding-gate",
    { analyzer: "aih-binding-gate" as const, profile: "in-process-binding-gate-v1" },
  ],
  [
    "detector.aih-trust-lint",
    { analyzer: "aih-trust-lint" as const, profile: "in-process-trust-lint-v1" },
  ],
]);
const sameSeal = (before: SourceObservationSealV1, after: SourceObservationSealV1) =>
  before.sourceTreeSha256 === after.sourceTreeSha256 &&
  before.selectedClosureSha256 === after.selectedClosureSha256 &&
  before.sealedSnapshotSha256 === after.sealedSnapshotSha256;

/** Executes only a supplied Scan-owned in-process implementation; imports no global engine or runtime. */
export async function runInProcessAssessmentDetector(
  input: InProcessAssessmentDetectorInput,
): Promise<RunDetectorV1Result> {
  const { capability, profile } = input;
  const definition = definitions.get(capability.detectorId);
  const refuse = (reason: RunDetectorRefusalReasonV1): RunDetectorV1Result => ({
    outcome: "refused",
    reason,
    detail: "The in-process detector cannot run under the requested conditions.",
    capability,
    host: { os: process.platform, architecture: process.arch },
  });
  if (
    !definition ||
    profile.id !== definition.profile ||
    profile.evidence !== "BaselineAnalyzerObservationV1" ||
    profile.prerequisites.length !== 0
  )
    return refuse("execution-profile-unavailable");
  const os = process.platform === "win32" ? "windows" : process.platform;
  const architecture = process.arch === "x64" ? "amd64" : process.arch;
  if (
    !profile.supportedPlatforms.some(
      (platform) => platform.os === os && platform.architecture === architecture,
    )
  )
    return refuse("unsupported-platform");
  if (input.excludedPaths.length) return refuse("subject-requirement-unmet");
  if (definition.analyzer !== "aih-trust-lint" && input.detectorOptions !== undefined)
    return refuse("detector-options-invalid");
  if (!Number.isInteger(input.timeoutMs) || input.timeoutMs < 100 || input.timeoutMs > 3600000)
    return refuse("execution-profile-unavailable");
  let before: SourceObservationSealV1;
  try {
    before = sealSourceObservationV1({
      sourceRoot: input.sourceRoot,
      selectedClosurePaths: input.selectedClosurePaths,
    });
  } catch {
    return refuse("subject-requirement-unmet");
  }
  if (before.entries.length === 0 && capability.emptySource !== "completes")
    return refuse("subject-requirement-unmet");
  const wholeTree = definition.analyzer !== "aih-binding-gate";
  const files = before.entries.flatMap((entry) =>
    entry.kind === "file" || entry.kind === "file-link" ? [entry] : [],
  );
  const coveredPaths = wholeTree
    ? files.map((entry) => entry.path)
    : [...before.selectedClosurePaths];
  const uncoveredPaths = files
    .map((entry) => entry.path)
    .filter((path) => !coveredPaths.includes(path));
  const coverage = {
    kind: wholeTree ? ("source-tree" as const) : ("selected-closure" as const),
    sha256: wholeTree ? before.sourceTreeSha256 : before.selectedClosureSha256,
    complete: uncoveredPaths.length === 0,
    coveredPaths,
    excludedPaths: [],
    uncoveredPaths,
  };
  const common = {
    capability,
    executionProfile: profile,
    prerequisites: [],
    seams: {
      runner: "scan-owned-default" as const,
      prerequisiteProbe: "scan-owned-default" as const,
    },
    producer: input.producer,
    coverage,
  };
  const failed = (
    stage: RunDetectorFailureStageV1,
    cause?: RunDetectorFailureCauseV1,
  ): RunDetectorV1Result => ({
    outcome: "failed",
    ...common,
    failure: {
      stage,
      detail: "The in-process detector did not produce a reliable bounded observation.",
      ...(cause ? { cause } : {}),
    },
  });
  const deadline = Date.now() + input.timeoutMs;
  const lateness = () =>
    input.signal?.aborted
      ? ("cancelled" as const)
      : Date.now() >= deadline
        ? ("timed-out" as const)
        : undefined;
  const early = lateness();
  if (early) return failed("execution", early);
  let outcome: ImplementationOutcome;
  try {
    outcome = input.implementation({
      sourceRoot: input.sourceRoot,
      selectedClosurePaths: input.selectedClosurePaths,
      detectorOptions: input.detectorOptions,
      signal: input.signal,
    });
  } catch {
    return failed("execution");
  }
  const late = lateness();
  if (late) return failed("execution", late);
  if ("kind" in outcome) {
    if (outcome.kind === "refused") return refuse(outcome.reason);
    if (outcome.kind === "failed") return failed("execution", outcome.cause);
  }
  let after: SourceObservationSealV1;
  try {
    after = sealSourceObservationV1({
      sourceRoot: input.sourceRoot,
      selectedClosurePaths: input.selectedClosurePaths,
    });
    if (!sameSeal(before, after)) return failed("coverage");
  } catch {
    return failed("coverage");
  }
  try {
    const nativeOutcome = "mediaType" in outcome ? outcome : undefined;
    const native = nativeOutcome !== undefined;
    const analyzerVersion = nativeOutcome?.analyzerVersion ?? "1.0.0";
    const originalBytes =
      "mediaType" in outcome ? Buffer.from(outcome.bytes) : Buffer.from(outcome.sarifText, "utf8");
    if (
      originalBytes.length === 0 ||
      originalBytes.length > 16 * 1024 * 1024 ||
      !analyzerVersion.trim() ||
      analyzerVersion.length > 200
    )
      return failed("output");
    const text = originalBytes.toString("utf8");
    if (!Buffer.from(text, "utf8").equals(originalBytes)) return failed("output");
    let document = parseStrictJsonObjectV1(text, `${definition.analyzer} observation`);
    if (native) {
      if (
        definition.analyzer !== "aih-native" ||
        document.protocol !== "BaselineNativeObservationV1"
      )
        return failed("output");
    } else {
      if (
        definition.analyzer === "aih-native" ||
        document.version !== "2.1.0" ||
        !Array.isArray(document.runs)
      )
        return failed("output");
      document = attachScanCompletionV1(
        document,
        scanCompletionEvidenceV1({
          detectorId: capability.detectorId,
          files: scanCompletionSubjectFilesV1({
            engine: definition.analyzer,
            entries: before.entries,
            selectedClosurePaths: before.selectedClosurePaths,
            detectorOptions: input.detectorOptions,
          }),
          emptyAllowed: capability.emptySource === "completes",
          analyzer: { version: analyzerVersion, lockSha256: profile.analyzerLock?.sha256 ?? null },
        }),
        { scanBuilt: true },
      );
    }
    const bytes = Buffer.from(canonicalStrictJsonBytesV1(document));
    if (bytes.length > 16 * 1024 * 1024) return failed("output");
    const annex = {
      path: `annex/${definition.analyzer}.json`,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      byteLength: bytes.length,
    };
    const findings = native
      ? digestBoundAnalyzerFindingsV1(
          "The aih-native output is a source identity observation, not a findings report, so no rule, severity, message or location is derived from it.",
        )
      : projectAnalyzerSarifFindingsV1({
          detectorId: capability.detectorId,
          analyzer: definition.analyzer,
          analyzerIdentity: `${definition.analyzer}@${analyzerVersion}`,
          annex: { descriptorId: annex.path, sha256: annex.sha256, byteLength: annex.byteLength },
          bytes,
          sealedFiles: new Map(files.map((file) => [file.path, file.sha256])),
          unboundLocations: "unavailable",
          maxResults: 100000,
        });
    const finalLateness = lateness();
    if (finalLateness) return failed("output", finalLateness);
    return {
      outcome: "succeeded",
      ...common,
      evidence: {
        kind: "baseline-analyzer-observation-v1",
        observation: {
          protocol: "BaselineAnalyzerObservationV1",
          analyzer: definition.analyzer,
          analyzerVersion,
          mediaType: native ? "application/vnd.aih.baseline-native+json" : "application/sarif+json",
          annex,
          bytes,
        },
      },
      findings,
      sourceSeal: { before, after },
    };
  } catch {
    return failed("output");
  }
}
