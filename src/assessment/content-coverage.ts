import { z } from "zod";
import {
  assertControlJson,
  bound,
  ContractError,
  canonicalBytes,
  errorDiagnostic,
  fail,
  scanIdFor,
} from "./json.js";
import { validateReport } from "./report.js";
import { digestShape, pathShape, scanIdShape } from "./shapes.js";
import type {
  AnnexDescriptor,
  CaptureEntry,
  ContentCoverageExclusionReason,
  ContentCoverageObservation,
  ContentDescriptor,
  ReadContentCoverageInput,
  ReadContentCoverageResult,
  ReportBody,
  ScanId,
} from "./types.js";

/** The largest descriptor set one coverage read accepts. */
export const maxContentDescriptors = 10000;

const descriptorShape = z
  .object({
    path: pathShape,
    sha256: digestShape,
    byteLength: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  })
  .strict();

function own(value: unknown, key: string): unknown {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    fail("Expected a plain object");
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor) return undefined;
  if (!("value" in descriptor)) fail("Inputs require own data properties");
  return descriptor.value;
}

function exactKeys(value: unknown, keys: readonly string[], label: string): void {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, i) => key !== expected[i]))
    fail(`${label} has unsupported or missing fields`);
}

function snapshotDescriptors(input: unknown): ContentDescriptor[] {
  exactKeys(input, ["read", "descriptors"], "Coverage input");
  const value = own(input, "descriptors");
  if (!Array.isArray(value)) fail("Descriptors must be an array");
  if (value.length === 0) fail("At least one descriptor is required");
  bound(value.length <= maxContentDescriptors, "descriptors", maxContentDescriptors);
  assertControlJson(value);
  const descriptors: ContentDescriptor[] = [];
  const paths = new Set<string>();
  for (const item of value) {
    const parsed = descriptorShape.safeParse(item);
    if (!parsed.success)
      fail("Each descriptor requires a safe relative path, lowercase sha256 and byte length");
    if (paths.has(parsed.data.path)) fail("Descriptor paths must be unique");
    paths.add(parsed.data.path);
    descriptors.push(parsed.data);
  }
  return descriptors;
}

const fileEntry = (entry: CaptureEntry | undefined, descriptor: ContentDescriptor) =>
  entry !== undefined &&
  (entry.kind === "file" || entry.kind === "file-link") &&
  entry.sha256 === descriptor.sha256 &&
  entry.byteLength === descriptor.byteLength;

const missing = (entries: readonly CaptureEntry[], descriptors: readonly ContentDescriptor[]) => {
  const byPath = new Map(entries.map((entry) => [entry.path, entry]));
  return descriptors
    .filter((descriptor) => !fileEntry(byPath.get(descriptor.path), descriptor))
    .map((descriptor) => descriptor.path);
};

type ContentCoverageClassification =
  | {
      status: "matched";
      observations: ContentCoverageObservation[];
      excluded: Record<ContentCoverageExclusionReason, number>;
      detectorsWithoutCoverage: string[];
    }
  | { status: "mismatched"; unmatchedPaths: string[] };

/**
 * Classifies a validated report against validated descriptors. Each observation
 * that cannot cover every descriptor is counted under the first reason that
 * excludes it. Report validation already guarantees that every observation annex
 * resolves and that finding supporting evidence names an observation annex.
 */
function classifyContentCoverage(
  report: ReportBody,
  descriptors: readonly ContentDescriptor[],
): ContentCoverageClassification {
  const unmatchedPaths = missing(report.source.capture.entries, descriptors).sort();
  if (unmatchedPaths.length > 0) return { status: "mismatched", unmatchedPaths };
  const annexes = new Map(report.annexes.map((annex) => [annex.id, annex]));
  const excluded: Record<ContentCoverageExclusionReason, number> = {
    "detector-not-succeeded": 0,
    "input-missing-descriptor": 0,
    "coverage-incomplete": 0,
  };
  const observations: ContentCoverageObservation[] = [];
  const detectorsWithoutCoverage: string[] = [];
  for (const result of report.results) {
    let covering = 0;
    for (const observation of result.observations) {
      const { body } = observation,
        { input } = body;
      if (result.outcome !== "succeeded") {
        excluded["detector-not-succeeded"]++;
        continue;
      }
      if (missing(input.entries, descriptors).length > 0) {
        excluded["input-missing-descriptor"]++;
        continue;
      }
      const covered = new Set(body.coverage.coveredPaths);
      if (descriptors.some((descriptor) => !covered.has(descriptor.path))) {
        excluded["coverage-incomplete"]++;
        continue;
      }
      covering++;
      observations.push({
        observationId: observation.observationId,
        origin: observation.origin,
        ...(observation.fromScanId === undefined ? {} : { fromScanId: observation.fromScanId }),
        detector: {
          detectorId: input.detectorId,
          detectorVersion: input.detectorVersion,
          adapterSha256: input.adapterSha256,
          platform: { ...input.platform },
        },
        input: {
          rulesSha256: input.rulesSha256,
          configurationSha256: input.configurationSha256,
          profileId: input.profileId,
          profileSha256: input.profileSha256,
          scopeKind: input.scopeKind,
          targetPaths: [...input.targetPaths],
        },
        coverage: { coveredPaths: [...body.coverage.coveredPaths] },
        detectorCoverage: {
          coveredPaths: [...result.coverage.coveredPaths],
          excludedPaths: [...result.coverage.excludedPaths],
          uncoveredPaths: [...result.coverage.uncoveredPaths],
          complete: result.coverage.complete,
        },
        // The report is a private validated snapshot, so its findings are not shared.
        findings: body.findings,
        annexes: body.annexIds.map((id) => ({ ...(annexes.get(id) as AnnexDescriptor) })),
      });
    }
    if (covering === 0) detectorsWithoutCoverage.push(result.detectorId);
  }
  return { status: "matched", observations, excluded, detectorsWithoutCoverage };
}

const unsupportedDiagnostic = {
  code: "unsupported-report",
  detail: "The read result names a report schema this reader does not support.",
};
const invalidReadDiagnostic = {
  code: "invalid-read",
  detail: "The read result is not a supported result of readReport or readArtifact.",
};

/**
 * Reports whether a read Scan report assessed an exact set of files, and which of
 * its observations cover all of them. Performs no host access and grants no
 * authenticity: the result keeps the read's `authenticity: "unchecked"`.
 */
export async function readContentCoverage(
  input: ReadContentCoverageInput,
): Promise<ReadContentCoverageResult> {
  let descriptors: ContentDescriptor[];
  try {
    descriptors = snapshotDescriptors(input);
  } catch (error) {
    return { status: "invalid", diagnostics: [errorDiagnostic(error)] };
  }
  try {
    const read = own(input, "read");
    const status = own(read, "status");
    if (status === "unsupported-report") {
      const scanId = scanIdShape.safeParse(own(read, "scanId"));
      return {
        status: "unavailable",
        reason: "unsupported-report",
        ...(scanId.success ? { scanId: scanId.data as ScanId } : {}),
        diagnostics: [{ ...unsupportedDiagnostic }],
      };
    }
    if (status === "invalid")
      return {
        status: "unavailable",
        reason: "invalid-read",
        diagnostics: [
          { code: "invalid-read", detail: "The supplied read result reports an invalid document." },
        ],
      };
    if (status !== "read") fail(invalidReadDiagnostic.detail);
    exactKeys(read, ["status", "scanId", "report", "authenticity", "annexBytes"], "Read result");
    if (own(read, "authenticity") !== "unchecked") fail(invalidReadDiagnostic.detail);
    const annexBytes = own(read, "annexBytes");
    if (annexBytes !== "checked" && annexBytes !== "not-supplied")
      fail(invalidReadDiagnostic.detail);
    // Revalidate a snapshot so a hand-built or altered result cannot claim coverage.
    const report = await validateReport(own(read, "report"));
    const scanId = await scanIdFor(canonicalBytes(report));
    if (own(read, "scanId") !== scanId) fail("Read result Scan ID does not identify its report");
    const classified = classifyContentCoverage(report, descriptors);
    return classified.status === "mismatched"
      ? {
          status: "mismatched",
          scanId,
          authenticity: "unchecked",
          unmatchedPaths: classified.unmatchedPaths,
        }
      : { ...classified, scanId, authenticity: "unchecked" };
  } catch (error) {
    return {
      status: "unavailable",
      reason: "invalid-read",
      diagnostics: [
        error instanceof ContractError ? errorDiagnostic(error) : { ...invalidReadDiagnostic },
      ],
    };
  }
}
