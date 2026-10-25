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
import { deepFreezeStrictJsonV1 } from "./strict-json.js";
import type {
  AnnexDescriptor,
  CaptureEntry,
  ContentCoverageBatchRow,
  ContentCoverageExclusionReason,
  ContentCoverageObservation,
  ContentDescriptor,
  ReadContentCoverageBatchInput,
  ReadContentCoverageBatchResult,
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

const missing = (
  byPath: ReadonlyMap<string, CaptureEntry>,
  descriptors: readonly ContentDescriptor[],
) => {
  return descriptors
    .filter((descriptor) => !fileEntry(byPath.get(descriptor.path), descriptor))
    .map((descriptor) => descriptor.path);
};

function indexCoverage(report: ReportBody) {
  return {
    views: new Map<string, ContentCoverageObservation>(),
    capture: new Map(report.source.capture.entries.map((entry) => [entry.path, entry])),
    annexes: new Map(report.annexes.map((annex) => [annex.id, annex])),
    results: report.results.map((result) => ({
      result,
      observations: result.observations.map((observation) => ({
        observation,
        entries: new Map(observation.body.input.entries.map((entry) => [entry.path, entry])),
        covered: new Set(observation.body.coverage.coveredPaths),
      })),
    })),
  };
}
type CoverageIndex = ReturnType<typeof indexCoverage>;

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
  index: CoverageIndex,
  descriptors: readonly ContentDescriptor[],
): ContentCoverageClassification {
  const unmatchedPaths = missing(index.capture, descriptors).sort();
  if (unmatchedPaths.length > 0) return { status: "mismatched", unmatchedPaths };
  const excluded: Record<ContentCoverageExclusionReason, number> = {
    "detector-not-succeeded": 0,
    "input-missing-descriptor": 0,
    "coverage-incomplete": 0,
  };
  const observations: ContentCoverageObservation[] = [];
  const detectorsWithoutCoverage: string[] = [];
  for (const { result, observations: indexed } of index.results) {
    let covering = 0;
    for (const { observation, entries, covered } of indexed) {
      const { body } = observation,
        { input } = body;
      if (result.outcome !== "succeeded") {
        excluded["detector-not-succeeded"]++;
        continue;
      }
      if (missing(entries, descriptors).length > 0) {
        excluded["input-missing-descriptor"]++;
        continue;
      }
      if (descriptors.some((descriptor) => !covered.has(descriptor.path))) {
        excluded["coverage-incomplete"]++;
        continue;
      }
      covering++;
      let view = index.views.get(observation.observationId);
      if (!view) {
        view = {
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
          annexes: body.annexIds.map((id) => ({ ...(index.annexes.get(id) as AnnexDescriptor) })),
        };
        index.views.set(observation.observationId, view);
      }
      observations.push(view);
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
  const admitted = await admitCoverageRead(input);
  if (admitted.status !== "admitted") return admitted;
  const classified = classifyContentCoverage(indexCoverage(admitted.report), descriptors);
  return { ...classified, scanId: admitted.scanId, authenticity: "unchecked" };
}

async function admitCoverageRead(
  input: unknown,
): Promise<
  | { status: "admitted"; report: ReportBody; scanId: ScanId }
  | Extract<ReadContentCoverageResult, { status: "unavailable" }>
> {
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
    const keys = ["status", "scanId", "report", "authenticity", "annexBytes"];
    if (typeof read === "object" && read !== null && Object.hasOwn(read, "capture"))
      keys.push("capture");
    exactKeys(read, keys, "Read result");
    if (own(read, "authenticity") !== "unchecked") fail(invalidReadDiagnostic.detail);
    const annexBytes = own(read, "annexBytes");
    if (annexBytes !== "checked" && annexBytes !== "not-supplied")
      fail(invalidReadDiagnostic.detail);
    // Revalidate a snapshot so a hand-built or altered result cannot claim coverage.
    const suppliedScanId = own(read, "scanId");
    const report = await validateReport(own(read, "report"));
    const scanId = await scanIdFor(canonicalBytes(report));
    if (suppliedScanId !== scanId) fail("Read result Scan ID does not identify its report");
    return { status: "admitted", report, scanId };
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

/** Hard limits for one finite batch; exceeding any bound refuses the whole call. */
export const coverageBatchLimits = Object.freeze({
  maxQueries: 4096,
  maxDescriptorReferences: 50000,
  maxRequestBytes: 16 * 1024 * 1024,
  maxRequestDepth: 8,
  maxRequestNodes: 300000,
  maxResponseBytes: 32 * 1024 * 1024,
  maxObservationAssociations: 100000,
  maxClassificationWork: 10000000,
});

// Bound before traversing potentially hostile extra fields or calling a schema parser.
// Counts the exact JSON encoding size (including keys/punctuation) as it snapshots.
function snapshotQueries(value: unknown): unknown[] {
  if (!Array.isArray(value)) fail("Queries must be an array");
  bound(value.length <= coverageBatchLimits.maxQueries, "queries", coverageBatchLimits.maxQueries);
  if (value.length === 0) fail("At least one query is required");
  let bytes = 0,
    nodes = 0;
  const encoder = new TextEncoder();
  const active = new WeakSet<object>();
  const add = (size: number) => {
    bytes += size;
    bound(
      bytes <= coverageBatchLimits.maxRequestBytes,
      "query bytes",
      coverageBatchLimits.maxRequestBytes,
    );
  };
  const string = (text: string) => {
    // UTF-16 length is a cheap lower bound before allocating its JSON/UTF-8 encoding.
    bound(
      text.length <= coverageBatchLimits.maxRequestBytes,
      "query string",
      coverageBatchLimits.maxRequestBytes,
    );
    add(encoder.encode(JSON.stringify(text)).length);
  };
  const copy = (item: unknown, depth: number): unknown => {
    bound(
      depth <= coverageBatchLimits.maxRequestDepth,
      "query depth",
      coverageBatchLimits.maxRequestDepth,
    );
    bound(
      ++nodes <= coverageBatchLimits.maxRequestNodes,
      "query nodes",
      coverageBatchLimits.maxRequestNodes,
    );
    if (typeof item === "string") {
      string(item);
      return item;
    }
    if (item === null || typeof item === "boolean" || typeof item === "number") {
      add(JSON.stringify(item).length);
      return item;
    }
    if (typeof item !== "object") fail("Queries require JSON data");
    if (active.has(item)) fail("Queries cannot contain cycles");
    if (Object.getOwnPropertySymbols(item).length) fail("Queries cannot contain symbol fields");
    const array = Array.isArray(item);
    if (
      Object.getPrototypeOf(item) !== (array ? Array.prototype : Object.prototype) &&
      !(Object.getPrototypeOf(item) === null && !array)
    )
      fail("Queries require plain objects");
    const keys = Object.keys(item);
    if (Object.getOwnPropertyNames(item).length !== keys.length + Number(array))
      fail("Queries cannot contain hidden fields");
    bound(
      keys.length <= coverageBatchLimits.maxRequestNodes,
      "query keys",
      coverageBatchLimits.maxRequestNodes,
    );
    if (array && (keys.length !== item.length || keys.some((key, at) => key !== String(at))))
      fail("Query arrays require dense own data properties");
    active.add(item);
    add(2 + Math.max(0, keys.length - 1));
    const result: unknown[] | Record<string, unknown> = array ? [] : Object.create(null);
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(item, key);
      if (!descriptor || !("value" in descriptor)) fail("Queries require own data properties");
      if (!array) {
        string(key);
        add(1);
      }
      Object.defineProperty(result, key, {
        value: copy(descriptor.value, depth + 1),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    active.delete(item);
    return result;
  };
  return copy(value, 0) as unknown[];
}

export async function readContentCoverageBatch(
  input: ReadContentCoverageBatchInput,
): Promise<ReadContentCoverageBatchResult> {
  try {
    exactKeys(input, ["read", "queries"], "Coverage batch input");
    if (Object.getPrototypeOf(input) !== Object.prototype && Object.getPrototypeOf(input) !== null)
      fail("Coverage batch input requires a plain object");
    if (Reflect.ownKeys(input).length !== 2) fail("Coverage batch input has unsupported fields");
    const read = own(input, "read");
    const queries = snapshotQueries(own(input, "queries"));
    let references = 0;
    for (const query of queries) {
      const descriptors =
        query !== null && typeof query === "object" && !Array.isArray(query)
          ? own(query, "descriptors")
          : undefined;
      if (Array.isArray(descriptors)) references += descriptors.length;
    }
    bound(
      references <= coverageBatchLimits.maxDescriptorReferences,
      "descriptor references",
      coverageBatchLimits.maxDescriptorReferences,
    );
    const parsed = queries.map((query) => {
      try {
        exactKeys(query, ["descriptors"], "Coverage query");
        return {
          descriptors: snapshotDescriptors({ read: null, descriptors: own(query, "descriptors") }),
        };
      } catch (error) {
        return { invalid: { status: "invalid" as const, diagnostics: [errorDiagnostic(error)] } };
      }
    });
    // validateReport synchronously copies its entire schema before its first await.
    // Capturing all read metadata in admitCoverageRead also precedes that await.
    const admitted = await admitCoverageRead({ read });
    const index = admitted.status === "admitted" ? indexCoverage(admitted.report) : undefined;
    if (index) {
      const units = index.results.reduce((sum, entry) => sum + entry.observations.length + 1, 0);
      bound(
        units * (references + queries.length) <= coverageBatchLimits.maxClassificationWork,
        "classification work",
        coverageBatchLimits.maxClassificationWork,
      );
    }
    const observations: ContentCoverageObservation[] = [],
      results: ContentCoverageBatchRow[] = [];
    const positions = new Map<string, number>();
    let associations = 0;
    // Exact incremental serialized size: measure each row/table entry once, before retaining it.
    let responseBytes = new TextEncoder().encode(
      '{"status":"complete","observations":[],"results":[]}',
    ).length;
    const account = (value: unknown, comma: boolean) => {
      responseBytes += new TextEncoder().encode(JSON.stringify(value)).length + Number(comma);
      bound(
        responseBytes <= coverageBatchLimits.maxResponseBytes,
        "response bytes",
        coverageBatchLimits.maxResponseBytes,
      );
    };
    for (const query of parsed) {
      let row: ContentCoverageBatchRow;
      if (query.invalid) row = query.invalid;
      else if (admitted.status !== "admitted") row = { ...admitted };
      else {
        const classified = classifyContentCoverage(index!, query.descriptors);
        if (classified.status === "mismatched")
          row = { ...classified, scanId: admitted.scanId, authenticity: "unchecked" };
        else {
          const { observations: covering, ...rest } = classified;
          associations += covering.length;
          bound(
            associations <= coverageBatchLimits.maxObservationAssociations,
            "observation associations",
            coverageBatchLimits.maxObservationAssociations,
          );
          const observationIndexes = covering.map((observation) => {
            let at = positions.get(observation.observationId);
            if (at === undefined) {
              at = observations.length;
              account(observation, at > 0);
              positions.set(observation.observationId, at);
              observations.push(observation);
            }
            return at;
          });
          row = { ...rest, scanId: admitted.scanId, authenticity: "unchecked", observationIndexes };
        }
      }
      account(row, results.length > 0);
      results.push(row);
    }
    return deepFreezeStrictJsonV1({ status: "complete", observations, results });
  } catch (error) {
    return { status: "invalid", diagnostics: [errorDiagnostic(error)] };
  }
}
