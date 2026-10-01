import { lstatSync, readFileSync } from "node:fs";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { AuthenticationTrust } from "../artifact/types.js";
import { SEMGREP_RULES_V1 } from "../baseline/runtime-v1.js";
import {
  type DetectorCapabilityV1,
  type DetectorExecutionProfileV1,
  resolveDetectorCapabilityV1,
} from "../capability/detector-capability-v1.js";
import { runBindingGateV1 } from "../detectors/binding-gate/index.js";
import { runTrustLintV1 } from "../detectors/trust-lint/index.js";
import { packageIdentity } from "../public/package-identity.js";
import { type DetectorOptionsV1, readDetectorOptionsV1 } from "../runner/detector-options-v1.js";
import { type RunDetectorV1Result, runDetectorV1 } from "../runner/run-detector-v1.js";
import { type CapturedSource, type CaptureOptions, captureSource } from "./capture.js";
import {
  type InProcessAssessmentDetectorInput,
  runInProcessAssessmentDetector,
} from "./in-process-adapter.js";
import { observationScope } from "./input-scope.js";
import {
  base64Encode,
  bound,
  ContractError,
  canonicalBytes,
  errorDiagnostic,
  fail,
  observationIdFor,
  scanIdFor,
  sha256,
  strictParse,
} from "./json.js";
import { nativeImplementationV1 } from "./native-implementation.js";
import { type PriorArtifactCandidate, readPriorArtifacts } from "./prior-artifacts.js";
import { ordered, validateReport } from "./report.js";
import {
  admitImportedObservationV1,
  admitRetainedObservationV1,
  isRetainedObservationsV1,
  type RetainedAdmissionV1,
  type RetainedAnnexV1,
  type RetainedObservationsV1,
  retainObservationV1,
} from "./reuse.js";
import { requestShape } from "./shapes.js";
import {
  type AnnexDescriptor,
  type DetectorResult,
  type Diagnostic,
  defaultLimits,
  type Finding,
  type Json,
  type Limits,
  limitCeilings,
  type ObservationBody,
  type ObservationInput,
  type ReportBody,
  type RequestedDetector,
  type ScanId,
  type ScanRequest,
  type ScanRunResult,
  schemas,
} from "./types.js";

export interface RunScanOptions extends CaptureOptions {
  /**
   * A Scan-managed own-custody record of successful observations from earlier `runScan`
   * calls in this process, minted only by `createRetainedObservationsV1`. A value Scan did
   * not mint is never own-custody data: it admits nothing and every detector runs fresh.
   * Durable sharing between processes goes through the artifact and authentication
   * boundary, never through this handle.
   */
  retained?: RetainedObservationsV1;
  /**
   * Independently selected trust for imported `priorArtifacts`. Without it, imported
   * observations are never admitted: their bytes are neither authenticated nor read, and
   * the current assessment performs the work itself. This is deliberately separate from
   * `retained`, which is Scan's own process-local custody.
   */
  reuseTrust?: AuthenticationTrust;
}
/** Membership and exact rule identity are one closed support definition. */
const detectorRuleBindings: ReadonlyMap<string, () => Promise<string>> = new Map([
  ["detector.aih-native", () => sha256(canonicalBytes([]))],
  ["detector.semgrep", () => sha256(new TextEncoder().encode(SEMGREP_RULES_V1))],
  ["detector.aih-trust-lint", () => moduleDigest("detectors/trust-lint/index")],
  ["detector.aih-binding-gate", () => moduleDigest("detectors/binding-gate/index")],
]);
/** Actual execution roots: unrelated detector implementations are not adapter dependencies. */
const inProcessImplementations = new Map<
  string,
  { implementation: InProcessAssessmentDetectorInput["implementation"]; adapterRoots: string[] }
>([
  [
    "detector.aih-native",
    {
      implementation: nativeImplementationV1,
      adapterRoots: [
        "assessment/in-process-adapter",
        "assessment/input-scope",
        "assessment/native-implementation",
      ],
    },
  ],
  [
    "detector.aih-binding-gate",
    {
      implementation: runBindingGateV1,
      adapterRoots: ["assessment/in-process-adapter", "assessment/input-scope"],
    },
  ],
  [
    "detector.aih-trust-lint",
    {
      implementation: runTrustLintV1,
      adapterRoots: ["assessment/in-process-adapter", "assessment/input-scope"],
    },
  ],
]);
interface ResolvedDetector {
  request: RequestedDetector;
  capability?: DetectorCapabilityV1;
  profile?: DetectorExecutionProfileV1;
  options?: DetectorOptionsV1;
}
function configurationOptions(id: string, configuration: Json, paths: string[]) {
  const empty =
    configuration !== null &&
    typeof configuration === "object" &&
    !Array.isArray(configuration) &&
    Object.keys(configuration).length === 0;
  return readDetectorOptionsV1(
    id,
    empty && !["detector.aih-trust-lint", "detector.cisco-mcp-scanner"].includes(id)
      ? undefined
      : configuration,
    paths,
  );
}
function requestSnapshot(raw: unknown): ScanRequest {
  const bytes = canonicalBytes(raw);
  bound(
    bytes.length <= limitCeilings.maxRequestBytes,
    "request bytes",
    limitCeilings.maxRequestBytes,
  );
  const parsed = requestShape.safeParse(
    strictParse(bytes, "request", limitCeilings.maxRequestBytes),
  );
  if (!parsed.success) fail("Request does not match the closed supported schema");
  const request = parsed.data as ScanRequest;
  if (new Set(request.detectors.map((d) => d.detectorId)).size !== request.detectors.length)
    fail("Detector IDs must be unique");
  for (const paths of [request.selection.paths, request.selection.excludedPaths])
    if (Array.isArray(paths) && new Set(paths).size !== paths.length)
      fail("Selection paths must be unique");
  if (Array.isArray(request.selection.paths))
    for (const path of request.selection.excludedPaths)
      if (!request.selection.paths.includes(path))
        fail("Exclusions must belong to the requested selection");
  const limits = { ...defaultLimits, ...request.limits };
  bound(bytes.length <= limits.maxRequestBytes, "request bytes", limits.maxRequestBytes);
  for (const detector of request.detectors) {
    if (resolveDetectorCapabilityV1(detector.detectorId)) {
      const configuration = detector.configuration;
      const optionPaths = Array.isArray(request.selection.paths)
        ? request.selection.paths
        : configuration !== null &&
            typeof configuration === "object" &&
            !Array.isArray(configuration) &&
            Array.isArray(configuration.mcpConfigPaths)
          ? configuration.mcpConfigPaths.flatMap((path) =>
              typeof path === "string" && path.includes("/")
                ? [`${path.slice(0, path.lastIndexOf("/"))}/SKILL.md`]
                : [],
            )
          : [];
      const options = configurationOptions(detector.detectorId, configuration, optionPaths);
      // Config path existence is checked after capture. Shape errors prevent every detector effect.
      if (!options.ok) fail("Requested detector configuration is invalid");
    }
  }
  return request;
}
const moduleDirectory = dirname(fileURLToPath(import.meta.url));
/** Bind the actual released adapter dependency closure, conservatively including shared implementation files. */
async function moduleDigest(...entries: string[]): Promise<string> {
  const extension = extname(fileURLToPath(import.meta.url));
  const root = resolve(moduleDirectory, "..");
  const pending = entries.map((entry) => join(root, `${entry}${extension}`)),
    seen = new Set<string>(),
    manifest: { path: string; sha256: string }[] = [];
  while (pending.length) {
    const file = pending.pop()!;
    if (seen.has(file)) continue;
    seen.add(file);
    const before = lstatSync(file);
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1)
      fail("Installed adapter material is unavailable");
    const bytes = readFileSync(file),
      after = lstatSync(file);
    if (
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs ||
      before.ctimeMs !== after.ctimeMs
    )
      fail("Installed adapter material changed");
    manifest.push({
      path: file.slice(root.length + 1).replaceAll("\\", "/"),
      sha256: await sha256(bytes),
    });
    // Type-only declarations disappear from the installed JavaScript graph and
    // must not turn source-mode identity into an unrelated runtime dependency.
    const runtimeSource = bytes
      .toString("utf8")
      .replace(/(?:^|\n)\s*(?:import|export)\s+type\s+[\s\S]*?;/g, "");
    for (const match of runtimeSource.matchAll(/(?:from\s*|import\s*)["'](\.[^"']+)["']/g)) {
      const imported = resolve(dirname(file), match[1]!.replace(/\.js$/, extension));
      if (!imported.startsWith(root + "/") && !imported.startsWith(root + "\\"))
        fail("Adapter dependency is outside the installed module root");
      pending.push(imported);
    }
  }
  manifest.sort((a, b) => (a.path < b.path ? -1 : 1));
  return sha256(canonicalBytes(manifest));
}
/**
 * The execution seams the assessment runner itself supplies. `runScan` passes neither a
 * test process runner nor a caller prerequisite probe, so every detector it runs reports
 * these defaults; a reuse lookup derives the same platform facts a fresh run records.
 */
const assessmentSeams: Readonly<{ runner: string; prerequisiteProbe: string }> = Object.freeze({
  runner: "scan-owned-default",
  prerequisiteProbe: "scan-owned-default",
});
/** The platform facts a run of this package records, from facts it settled before or during it. */
async function observationPlatform(seams: {
  runner: string;
  prerequisiteProbe: string;
}): Promise<ObservationInput["platform"]> {
  return {
    os: process.platform,
    architecture: process.arch,
    relevantFactsSha256: await sha256(
      canonicalBytes({
        node: process.version,
        runner: seams.runner,
        prerequisiteProbe: seams.prerequisiteProbe,
      }),
    ),
  };
}
/** One canonical observation input, built the same way for a fresh run and a reuse lookup. */
function observationInputFor(input: {
  detectorId: string;
  detectorVersion: string;
  adapterSha256: string;
  rulesSha256: string;
  configurationSha256: string;
  profileId: string;
  profileSha256: string;
  platform: ObservationInput["platform"];
  targetPaths: string[];
  entries: ObservationInput["entries"];
  selectedPaths: string[];
}): ObservationInput {
  return {
    detectorId: input.detectorId,
    detectorVersion: input.detectorVersion,
    adapterSha256: input.adapterSha256,
    rulesSha256: input.rulesSha256,
    configurationSha256: input.configurationSha256,
    profileId: input.profileId,
    profileSha256: input.profileSha256,
    platform: input.platform,
    ...observationScope(input.detectorId, input.entries, input.selectedPaths),
    targetPaths: input.targetPaths,
  };
}
async function resolvedDetectors(
  request: ScanRequest,
  paths: string[],
): Promise<ResolvedDetector[]> {
  const resolved: ResolvedDetector[] = [];
  for (const detector of request.detectors) {
    const capability = resolveDetectorCapabilityV1(detector.detectorId),
      profile = capability?.executionProfiles.find(
        (p) => p.id === (detector.profileId ?? capability.executionProfile.id),
      );
    const result: ResolvedDetector = {
      request: {
        detectorId: detector.detectorId,
        profileId: profile?.id ?? null,
        configuration: detector.configuration,
        configurationSha256: await sha256(canonicalBytes(detector.configuration)),
      },
      ...(capability ? { capability } : {}),
      ...(profile ? { profile } : {}),
    };
    if (capability) {
      const options = configurationOptions(detector.detectorId, detector.configuration, paths);
      if (!options.ok) fail("Detector configuration disagrees with resolved selection");
      if (options.options) result.options = options.options;
    }
    resolved.push(result);
  }
  return resolved.sort((a, b) => (a.request.detectorId < b.request.detectorId ? -1 : 1));
}
function emptyResult(
  detectorId: string,
  captured: CapturedSource,
  outcome: DetectorResult["outcome"],
  diagnostics: Diagnostic[],
): DetectorResult {
  const uncovered = captured.selection.paths.filter(
    (path) => !captured.selection.excludedPaths.includes(path),
  );
  return {
    detectorId,
    outcome,
    observations: [],
    coverage: {
      coveredPaths: [],
      excludedPaths: [...captured.selection.excludedPaths],
      uncoveredPaths: uncovered,
      complete: uncovered.length === 0,
    },
    diagnostics,
  };
}
function safeField<T>(
  field: { state: "present"; value: T } | { state: "unavailable"; reason: string; detail: string },
  max: number,
): typeof field {
  return canonicalBytes(field).length <= max
    ? field
    : {
        state: "unavailable",
        reason: "field-too-large",
        detail:
          "The native field exceeds the supported display bound; original bytes remain in the annex.",
      };
}
function findings(
  run: Extract<RunDetectorV1Result, { outcome: "succeeded" }>,
  annexId: string,
  captured: CapturedSource,
): Finding[] {
  return run.findings.findings
    .map((finding) => ({
      rawOccurrenceFingerprint: finding.rawOccurrenceFingerprint,
      multiplicity: finding.multiplicity,
      rule: safeField(finding.rule, 1024),
      severity: safeField(finding.severity, 1024),
      message: safeField(finding.message, 16384),
      location: finding.location,
      supportingEvidence:
        finding.supportingEvidence.state === "present"
          ? {
              state: "present" as const,
              value: { annexId, ordinal: finding.supportingEvidence.value.ordinal },
            }
          : finding.supportingEvidence,
    }))
    .filter((finding) => {
      if (
        finding.location.state === "present" &&
        !captured.selection.paths.includes(finding.location.value.path)
      )
        fail("The detector emitted findings outside the declared output selection");
      return true;
    })
    .sort((a, b) => (a.rawOccurrenceFingerprint < b.rawOccurrenceFingerprint ? -1 : 1));
}
function unsignedArtifact(
  reportBytes: Uint8Array,
  scanId: string,
  reportDigest: string,
  annexes: AnnexDescriptor[],
  payloads: { id: string; bytesBase64: string }[],
) {
  const byId = new Map(payloads.map((payload) => [payload.id, payload.bytesBase64]));
  return {
    schema: schemas.artifact,
    scanId,
    report: {
      schema: schemas.report,
      mediaType: "application/json",
      sha256: reportDigest,
      byteLength: reportBytes.length,
      bytesBase64: base64Encode(reportBytes),
    },
    annexes: annexes.map((annex) => {
      const bytesBase64 = byId.get(annex.id);
      if (bytesBase64 === undefined) fail("Missing staged annex bytes");
      return { ...annex, bytesBase64 };
    }),
  };
}
export async function runScan(raw: unknown, options: RunScanOptions = {}): Promise<ScanRunResult> {
  const diagnostic = (
    phase: "request" | "capture" | "assembly",
    error: unknown,
  ): ScanRunResult => ({
    schema: schemas.runResult,
    status: "diagnostic",
    phase,
    diagnostics: [errorDiagnostic(error)],
  });
  let request: ScanRequest;
  try {
    request = requestSnapshot(raw);
  } catch (error) {
    return diagnostic("request", error);
  }
  const limits: Limits = { ...defaultLimits, ...request.limits };
  let captured: CapturedSource;
  try {
    captured = await captureSource(request, limits, options);
  } catch (error) {
    return diagnostic("capture", error);
  }
  try {
    const resolved = await resolvedDetectors(request, captured.selection.paths),
      results: DetectorResult[] = [],
      annexes: AnnexDescriptor[] = [],
      payloads: { id: string; bytesBase64: string }[] = [];
    // Imported prior artifacts are acquired, authenticated and fully read once, under the
    // caller's independently selected trust. Without that trust they admit nothing.
    const diagnostics: Diagnostic[] = [];
    let priorArtifacts: PriorArtifactCandidate[] = [];
    try {
      const priors = await readPriorArtifacts(request.priorArtifacts ?? [], {
        trust: options.reuseTrust,
        signal: options.signal,
        limits,
      });
      priorArtifacts = priors.artifacts;
      diagnostics.push(...priors.diagnostics);
    } catch {
      diagnostics.push({
        code: "reuse-miss",
        detail:
          "Prior artifacts could not be acquired, authenticated and read within their bounded contract; current work proceeds.",
      });
    }
    const reportFor = (units: DetectorResult[], descriptors: AnnexDescriptor[]): ReportBody => ({
      schema: schemas.report,
      producer: packageIdentity,
      createdAt: new Date().toISOString(),
      source:
        request.source.kind === "git"
          ? {
              kind: "git",
              repository: request.source.repository,
              commit: request.source.commit,
              capture: captured.capture,
            }
          : { kind: "local", capture: captured.capture },
      selection: captured.selection,
      requestedDetectors: resolved.map((d) => d.request),
      results: units,
      completion: units.every((unit) => unit.outcome === "succeeded" && unit.coverage.complete)
        ? "complete"
        : "partial",
      annexes: descriptors,
      effectiveLimits: limits,
      diagnostics,
    });
    const active = captured.selection.paths.filter(
      (path) => !captured.selection.excludedPaths.includes(path),
    );
    /** Fresh units enter custody only once the final report and its Scan ID exist. */
    const pendingRetention: {
      detectorId: string;
      body: ObservationBody;
      annex: RetainedAnnexV1;
    }[] = [];
    /**
     * Validates one candidate unit against the current selection, the report contract and
     * the current budgets, without publishing it. A reused unit is never a shortcut past
     * these checks, and a candidate that fails them is never counted as reuse.
     */
    const validateUnit = async (
      id: string,
      body: ObservationBody,
      origin: "fresh" | "reused",
      fromScanId: ScanId | undefined,
      annex: RetainedAnnexV1,
      admittedDiagnostics: Diagnostic[],
    ): Promise<{
      unit: DetectorResult;
      descriptor: AnnexDescriptor;
      payload: { id: string; bytesBase64: string };
    }> => {
      if (annex.bytes.length > limits.maxAnnexBytes)
        throw new ContractError(
          "resource-limit",
          "The detector annex exceeds the selected annex byte limit.",
        );
      if (annex.byteLength !== annex.bytes.length || annex.sha256 !== (await sha256(annex.bytes)))
        fail("Native observation annex lost its byte binding");
      const covered = body.coverage.coveredPaths.filter((path) => active.includes(path)).sort(),
        uncovered = active.filter((path) => !covered.includes(path));
      ordered(covered, "detector covered paths");
      const descriptor: AnnexDescriptor = {
        id: annex.id,
        mediaType: annex.mediaType,
        sha256: annex.sha256,
        byteLength: annex.bytes.length,
      };
      const unit: DetectorResult = {
        detectorId: id,
        outcome: uncovered.length ? "failed" : "succeeded",
        observations: [
          {
            observationId: await observationIdFor(body),
            body,
            origin,
            ...(fromScanId === undefined ? {} : { fromScanId }),
          },
        ],
        coverage: {
          coveredPaths: covered,
          excludedPaths: [...captured.selection.excludedPaths],
          uncoveredPaths: uncovered,
          complete: uncovered.length === 0,
        },
        diagnostics: [
          ...admittedDiagnostics,
          ...(uncovered.length
            ? [
                {
                  code: "detector-incomplete",
                  detail: "The completed observation left requested paths uncovered.",
                  detectorId: id,
                },
              ]
            : []),
        ],
      };
      const remaining = resolved.slice(results.length + 1);
      const candidate = reportFor(
        [
          ...results,
          unit,
          ...remaining.map((pending) =>
            emptyResult(
              pending.request.detectorId,
              captured,
              pending.request.profileId === null ? "refused" : "failed",
              [
                {
                  code: "detector-output-invalid",
                  detail: "The detector did not produce a valid bounded observation.",
                  detectorId: pending.request.detectorId,
                },
              ],
            ),
          ),
        ],
        [...annexes, descriptor].sort((a, b) => (a.id < b.id ? -1 : 1)),
      );
      await validateReport(candidate);
      const candidateBytes = canonicalBytes(candidate),
        payload = { id: annex.id, bytesBase64: base64Encode(annex.bytes) };
      // Reserve bounded accounting space for later refusal/failure diagnostics.
      bound(
        candidateBytes.length + remaining.length * 512 <= limits.maxReportBytes,
        "report bytes",
        limits.maxReportBytes,
      );
      bound(
        candidateBytes.length +
          candidate.annexes.reduce((sum, part) => sum + part.byteLength, 0) +
          remaining.length * 512 <=
          limits.maxDecodedArtifactBytes,
        "decoded artifact bytes",
        limits.maxDecodedArtifactBytes,
      );
      bound(
        canonicalBytes(
          unsignedArtifact(
            candidateBytes,
            `scan:sha256:${"0".repeat(64)}`,
            "0".repeat(64),
            candidate.annexes,
            [...payloads, payload],
          ),
        ).length +
          remaining.length * 1024 <=
          limits.maxArtifactBytes,
        "artifact bytes",
        limits.maxArtifactBytes,
      );
      return { unit, descriptor, payload };
    };
    /** Publishes a validated unit and retains a complete, successful fresh unit. */
    const publishUnit = (
      id: string,
      unit: DetectorResult,
      descriptor: AnnexDescriptor,
      payload: { id: string; bytesBase64: string },
      origin: "fresh" | "reused",
      body: ObservationBody,
      annex: RetainedAnnexV1,
    ): void => {
      annexes.push(descriptor);
      payloads.push(payload);
      results.push(unit);
      if (origin === "fresh" && unit.coverage.complete)
        pendingRetention.push({ detectorId: id, body, annex });
    };
    /** The one honest failure shape for a detector whose own unit could not be admitted. */
    const failUnit = (id: string, error: unknown, detail: string): void => {
      results.push(
        emptyResult(id, captured, "failed", [
          {
            code:
              errorDiagnostic(error).code === "resource-limit"
                ? "resource-limit"
                : "detector-output-invalid",
            detail,
            detectorId: id,
          },
        ]),
      );
    };
    for (const detector of resolved) {
      const id = detector.request.detectorId;
      if (!detector.capability || !detector.profile) {
        results.push(
          emptyResult(id, captured, "refused", [
            {
              code: detector.capability ? "unsupported-profile" : "unknown-detector",
              detail: "The requested detector or execution profile has no supported definition.",
              detectorId: id,
            },
          ]),
        );
        continue;
      }
      if (options.signal?.aborted) {
        results.push(
          emptyResult(id, captured, "cancelled", [
            {
              code: "detector-cancelled",
              detail: "Requested work was cancelled after reliable source capture.",
              detectorId: id,
            },
          ]),
        );
        continue;
      }
      if (detector.profile.evidence !== "BaselineAnalyzerObservationV1") {
        results.push(
          emptyResult(id, captured, "refused", [
            {
              code: "unsupported-profile",
              detail:
                "The selected legacy capture profile cannot produce the portable observation contract.",
              detectorId: id,
            },
          ]),
        );
        continue;
      }
      const bindRules = detectorRuleBindings.get(id);
      if (bindRules === undefined) {
        results.push(
          emptyResult(id, captured, "refused", [
            {
              code: "rules-material-unavailable",
              detail:
                "This profile cannot bind exact released rule material; current work remains uncovered.",
              detectorId: id,
            },
          ]),
        );
        continue;
      }
      if (captured.capture.entries.some((entry) => entry.kind === "directory-link")) {
        results.push(
          emptyResult(id, captured, "refused", [
            {
              code: "unsupported-source-entry",
              detail:
                "This execution profile cannot preserve directory-link input; the complete source capture remains unchanged.",
              detectorId: id,
            },
          ]),
        );
        continue;
      }
      const inProcess = inProcessImplementations.get(id);
      const adapterSha256 = await moduleDigest(
        ...(inProcess?.adapterRoots ?? ["runner/run-detector-v1"]),
      );
      let rulesPromise: Promise<string> | undefined;
      const ruleDigest = (): Promise<string> => {
        rulesPromise ??= bindRules();
        return rulesPromise;
      };
      captured.assertUnchanged();
      // Reuse is opt-in: with no supplied handle and no admitted prior artifact, nothing
      // below changes the current path.
      const reuseDiagnostics: Diagnostic[] = [];
      if (options.retained !== undefined || priorArtifacts.length > 0) {
        const capability = detector.capability,
          profile = detector.profile;
        const noteMiss = (detail: string): void => {
          if (
            !reuseDiagnostics.some(
              (diagnostic) => diagnostic.code === "reuse-miss" && diagnostic.detail === detail,
            )
          )
            reuseDiagnostics.push({ code: "reuse-miss", detail, detectorId: id });
        };
        /**
         * Validates and publishes an admitted candidate, or records why it is a miss. A
         * candidate that fails current admission is never counted as a reuse.
         */
        const tryAdmitted = async (admission: RetainedAdmissionV1): Promise<boolean> => {
          if (admission.status !== "admitted") {
            noteMiss(admission.detail);
            return false;
          }
          try {
            const validated = await validateUnit(
              id,
              admission.body,
              "reused",
              admission.fromScanId,
              admission.annex,
              [
                {
                  code: "reuse-hit",
                  detail:
                    "The current detector input exactly matches an admissible observation; its original identity, body and observed times are reused unchanged.",
                  detectorId: id,
                },
              ],
            );
            publishUnit(
              id,
              validated.unit,
              validated.descriptor,
              validated.payload,
              "reused",
              admission.body,
              admission.annex,
            );
            return true;
          } catch (error) {
            noteMiss(
              `A candidate observation did not survive current report or budget admission (${errorDiagnostic(error).code}); the current scope is measured fresh.`,
            );
            return false;
          }
        };
        let currentInput: ObservationInput | undefined;
        const platformArchitecture = process.arch === "x64" ? "amd64" : process.arch;
        const platformOs = process.platform === "win32" ? "windows" : process.platform;
        const reusableProfile =
          inProcess !== undefined &&
          profile.prerequisites.length === 0 &&
          profile.supportedPlatforms.some(
            (platform) =>
              platform.os === platformOs && platform.architecture === platformArchitecture,
          ) &&
          captured.selection.excludedPaths.length === 0 &&
          (captured.capture.entries.length > 0 || capability.emptySource === "completes");
        if (reusableProfile) {
          currentInput = observationInputFor({
            detectorId: id,
            detectorVersion: capability.analyzerVersion,
            adapterSha256,
            rulesSha256: await ruleDigest(),
            configurationSha256: detector.request.configurationSha256,
            profileId: profile.id,
            profileSha256: profile.sha256,
            platform: await observationPlatform(assessmentSeams),
            targetPaths: active,
            entries: captured.capture.entries,
            selectedPaths: captured.selection.paths,
          });
        } else {
          // The current tool, runtime and analyzer identity of this profile is settled only
          // by running it, so no trustworthy complete current identity exists yet. The
          // detector reruns rather than binding a claim it cannot check.
          noteMiss(
            "This profile cannot establish an eligible complete current input before execution, so no candidate observation is admitted.",
          );
        }
        if (currentInput !== undefined) {
          let reused = false;
          if (options.retained !== undefined) {
            if (!isRetainedObservationsV1(options.retained))
              noteMiss(
                "The supplied retained-observations handle is not a Scan-managed own-custody record, so no retained observation is admitted.",
              );
            else
              reused = await tryAdmitted(
                await admitRetainedObservationV1({
                  store: options.retained,
                  detectorId: id,
                  input: currentInput,
                  limits,
                }),
              );
          }
          if (!reused && priorArtifacts.length > 0)
            reused = await tryAdmitted(
              await admitImportedObservationV1({
                artifacts: priorArtifacts,
                detectorId: id,
                input: currentInput,
                limits,
              }),
            );
          if (reused) {
            captured.assertUnchanged();
            continue;
          }
        }
      }
      const startedAt = new Date().toISOString();
      let run: RunDetectorV1Result;
      try {
        run = inProcess
          ? await runInProcessAssessmentDetector({
              capability: detector.capability,
              profile: detector.profile,
              sourceRoot: captured.root,
              selectedClosurePaths: captured.selection.paths,
              excludedPaths: captured.selection.excludedPaths,
              detectorOptions: detector.options,
              signal: options.signal,
              timeoutMs: limits.detectorTimeoutMs,
              producer: packageIdentity,
              implementation: inProcess.implementation,
            })
          : await runDetectorV1({
              detectorId: id,
              subject: {
                kind: "source-tree",
                sourceRoot: captured.root,
                selectedClosurePaths: captured.selection.paths,
                excludedPaths: captured.selection.excludedPaths,
              },
              executionProfileId: detector.profile.id,
              signal: options.signal,
              timeoutMs: limits.detectorTimeoutMs,
              ...(detector.options ? { detectorOptions: detector.options } : {}),
            });
      } catch {
        run = {
          outcome: "refused",
          reason: "execution-profile-unavailable",
          detail: "The selected detector did not produce a reliable result.",
          host: { os: process.platform, architecture: process.arch },
        };
      }
      captured.assertUnchanged();
      if (run.outcome === "refused") {
        results.push(
          emptyResult(id, captured, "refused", [
            {
              code: run.reason,
              detail: "The selected detector refused the requested source or execution conditions.",
              detectorId: id,
            },
          ]),
        );
        continue;
      }
      if (run.outcome === "failed") {
        results.push(
          emptyResult(id, captured, run.failure.cause === "cancelled" ? "cancelled" : "failed", [
            {
              code: run.failure.cause ? `detector-${run.failure.cause}` : "detector-failed",
              detail: `The selected detector failed during ${run.failure.stage}; its unfinished scope remains uncovered.`,
              detectorId: id,
            },
          ]),
        );
        continue;
      }
      // Projection, byte binding and semantic validation are local to this detector.
      // Source assertions above and below this catch remain assessment-wide.
      try {
        if (run.evidence.kind !== "baseline-analyzer-observation-v1")
          fail("Detector returned unsupported observation evidence");
        const native = run.evidence.observation,
          annexId = `annex.${await sha256(new TextEncoder().encode(id))}`,
          covered = run.coverage.coveredPaths.filter((path) => active.includes(path)).sort();
        ordered(covered, "detector covered paths");
        const body: ObservationBody = {
          format: "aih-observation-v1",
          input: observationInputFor({
            detectorId: id,
            detectorVersion: native.analyzerVersion,
            adapterSha256,
            rulesSha256: await ruleDigest(),
            configurationSha256: detector.request.configurationSha256,
            profileId: detector.profile.id,
            profileSha256: detector.profile.sha256,
            platform: await observationPlatform(run.seams),
            targetPaths: active,
            entries: captured.capture.entries,
            selectedPaths: captured.selection.paths,
          }),
          startedAt,
          completedAt: new Date().toISOString(),
          producer: { name: packageIdentity.name, version: packageIdentity.version },
          coverage: { coveredPaths: covered },
          findings: findings(run, annexId, captured),
          gaps: run.findings.gaps.map((gap) => ({ reason: gap.kind, detail: gap.detail })),
          annexIds: [annexId],
        };
        const annex: RetainedAnnexV1 = {
          id: annexId,
          mediaType: native.mediaType,
          sha256: native.annex.sha256,
          byteLength: native.bytes.length,
          bytes: native.bytes,
        };
        const validated = await validateUnit(id, body, "fresh", undefined, annex, reuseDiagnostics);
        publishUnit(
          id,
          validated.unit,
          validated.descriptor,
          validated.payload,
          "fresh",
          body,
          annex,
        );
      } catch (error) {
        failUnit(
          id,
          error,
          "The detector did not produce a valid bounded observation; its scope remains uncovered.",
        );
      }
      captured.assertUnchanged();
    }
    captured.assertUnchanged();
    annexes.sort((a, b) => (a.id < b.id ? -1 : 1));
    payloads.sort((a, b) => (a.id < b.id ? -1 : 1));
    const report = await validateReport(reportFor(results, annexes));
    const bytes = canonicalBytes(report);
    bound(bytes.length <= limits.maxReportBytes, "report bytes", limits.maxReportBytes);
    const scanId = await scanIdFor(bytes);
    const unsigned = unsignedArtifact(bytes, scanId, await sha256(bytes), annexes, payloads);
    bound(
      canonicalBytes(unsigned).length <= limits.maxArtifactBytes,
      "artifact bytes",
      limits.maxArtifactBytes,
    );
    // Custody is written only now: a fresh unit's original assessment identity is this
    // report's Scan ID, and a report that failed validation above reaches no custody.
    if (options.retained !== undefined) {
      for (const pending of pendingRetention)
        await retainObservationV1(options.retained, {
          detectorId: pending.detectorId,
          body: pending.body,
          annexes: [pending.annex],
          fromScanId: scanId,
        });
    }
    return {
      schema: schemas.runResult,
      status: "assessment",
      scanId,
      report,
      annexes: payloads,
      diagnostics,
    };
  } catch (error) {
    return diagnostic("assembly", error);
  } finally {
    captured.cleanup();
  }
}
