import { lstatSync, readFileSync } from "node:fs";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { SEMGREP_RULES_V1 } from "../baseline/runtime-v1.js";
import {
  type DetectorCapabilityV1,
  type DetectorExecutionProfileV1,
  resolveDetectorCapabilityV1,
} from "../capability/detector-capability-v1.js";
import { packageIdentity } from "../public/package-identity.js";
import { type DetectorOptionsV1, readDetectorOptionsV1 } from "../runner/detector-options-v1.js";
import { type RunDetectorV1Result, runDetectorV1 } from "../runner/run-detector-v1.js";
import { type CapturedSource, type CaptureOptions, captureSource } from "./capture.js";
import {
  base64Encode,
  bound,
  canonicalBytes,
  errorDiagnostic,
  fail,
  observationIdFor,
  scanIdFor,
  sha256,
  strictParse,
} from "./json.js";
import { ordered, validateReport } from "./report.js";
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
  type RequestedDetector,
  type ScanRequest,
  type ScanRunResult,
  schemas,
} from "./types.js";

export interface RunScanOptions extends CaptureOptions {}
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
async function moduleDigest(entry: string): Promise<string> {
  const extension = extname(fileURLToPath(import.meta.url));
  const root = resolve(moduleDirectory, "..");
  const pending = [join(root, `${entry}${extension}`)],
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
    for (const match of bytes
      .toString("utf8")
      .matchAll(/(?:from\s*|import\s*)["'](\.[^"']+)["']/g)) {
      const imported = resolve(dirname(file), match[1]!.replace(/\.js$/, extension));
      if (!imported.startsWith(root + "/") && !imported.startsWith(root + "\\"))
        fail("Adapter dependency is outside the installed module root");
      pending.push(imported);
    }
  }
  manifest.sort((a, b) => (a.path < b.path ? -1 : 1));
  return sha256(canonicalBytes(manifest));
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
    const diagnostics: Diagnostic[] = (request.priorArtifacts ?? []).map(() => ({
      code: "reuse-miss",
      detail:
        "Observation reuse is not supported by this contract implementation; current requested work is performed.",
    }));
    const adapterSha256 = await moduleDigest("runner/run-detector-v1");
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
      if (
        ![
          "detector.aih-native",
          "detector.semgrep",
          "detector.aih-trust-lint",
          "detector.aih-binding-gate",
        ].includes(id)
      ) {
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
      captured.assertUnchanged();
      const startedAt = new Date().toISOString();
      let run: RunDetectorV1Result;
      try {
        run = await runDetectorV1({
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
      if (run.evidence.kind !== "baseline-analyzer-observation-v1")
        fail("Detector returned unsupported observation evidence");
      const native = run.evidence.observation,
        annexId = `annex.${await sha256(new TextEncoder().encode(id))}`;
      if (native.bytes.length > limits.maxAnnexBytes) {
        results.push(
          emptyResult(id, captured, "failed", [
            {
              code: "resource-limit",
              detail: "The detector annex exceeds the selected annex byte limit.",
              detectorId: id,
            },
          ]),
        );
        continue;
      }
      if (
        native.annex.byteLength !== native.bytes.length ||
        native.annex.sha256 !== (await sha256(native.bytes))
      )
        fail("Native observation annex lost its byte binding");
      const active = captured.selection.paths.filter(
          (path) => !captured.selection.excludedPaths.includes(path),
        ),
        covered = run.coverage.coveredPaths.filter((path) => active.includes(path)).sort();
      ordered(covered, "detector covered paths");
      const uncovered = active.filter((path) => !covered.includes(path));
      const body: ObservationBody = {
        format: "aih-observation-v1",
        input: {
          detectorId: id,
          detectorVersion: native.analyzerVersion,
          adapterSha256,
          rulesSha256:
            id === "detector.semgrep"
              ? await sha256(new TextEncoder().encode(SEMGREP_RULES_V1))
              : id === "detector.aih-trust-lint"
                ? await moduleDigest("detectors/trust-lint/index")
                : id === "detector.aih-binding-gate"
                  ? await moduleDigest("detectors/binding-gate/index")
                  : await sha256(canonicalBytes([])),
          configurationSha256: detector.request.configurationSha256,
          profileId: detector.profile.id,
          profileSha256: detector.profile.sha256,
          platform: {
            os: process.platform,
            architecture: process.arch,
            relevantFactsSha256: await sha256(
              canonicalBytes({
                node: process.version,
                runner: run.seams.runner,
                prerequisiteProbe: run.seams.prerequisiteProbe,
              }),
            ),
          },
          scopeKind: "source-tree",
          targetPaths: active,
          entries: captured.capture.entries,
        },
        startedAt,
        completedAt: new Date().toISOString(),
        producer: { name: packageIdentity.name, version: packageIdentity.version },
        coverage: { coveredPaths: covered },
        findings: findings(run, annexId, captured),
        gaps: run.findings.gaps.map((gap) => ({ reason: gap.kind, detail: gap.detail })),
        annexIds: [annexId],
      };
      annexes.push({
        id: annexId,
        mediaType: native.mediaType,
        sha256: native.annex.sha256,
        byteLength: native.bytes.length,
      });
      payloads.push({ id: annexId, bytesBase64: base64Encode(native.bytes) });
      results.push({
        detectorId: id,
        outcome: uncovered.length ? "failed" : "succeeded",
        observations: [{ observationId: await observationIdFor(body), body, origin: "fresh" }],
        coverage: {
          coveredPaths: covered,
          excludedPaths: [...captured.selection.excludedPaths],
          uncoveredPaths: uncovered,
          complete: uncovered.length === 0,
        },
        diagnostics: uncovered.length
          ? [
              {
                code: "detector-incomplete",
                detail: "The completed observation left requested paths uncovered.",
                detectorId: id,
              },
            ]
          : [],
      });
    }
    captured.assertUnchanged();
    annexes.sort((a, b) => (a.id < b.id ? -1 : 1));
    payloads.sort((a, b) => (a.id < b.id ? -1 : 1));
    const report = await validateReport({
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
      results,
      completion: results.every(
        (result) => result.outcome === "succeeded" && result.coverage.complete,
      )
        ? "complete"
        : "partial",
      annexes,
      effectiveLimits: limits,
      diagnostics,
    });
    const bytes = canonicalBytes(report);
    bound(bytes.length <= limits.maxReportBytes, "report bytes", limits.maxReportBytes);
    const scanId = await scanIdFor(bytes);
    const unsigned = {
      schema: schemas.artifact,
      scanId,
      report: {
        schema: schemas.report,
        mediaType: "application/json",
        sha256: await sha256(bytes),
        byteLength: bytes.length,
        bytesBase64: base64Encode(bytes),
      },
      annexes: annexes.map((annex, index) => ({
        ...annex,
        bytesBase64: payloads[index]!.bytesBase64,
      })),
    };
    bound(
      canonicalBytes(unsigned).length <= limits.maxArtifactBytes,
      "artifact bytes",
      limits.maxArtifactBytes,
    );
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
