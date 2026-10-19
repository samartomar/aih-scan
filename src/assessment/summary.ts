import { readArtifact } from "../artifact/read.js";
import { assertControlJson, bound, canonicalBytes, errorDiagnostic, fail } from "./json.js";
import { readReport } from "./report.js";
import { labelShape } from "./shapes.js";
import type {
  EvidenceDocument,
  FindingCounts,
  ReadSummaryInput,
  ReadSummaryResult,
  ScanSummary,
} from "./summary-types.js";
import type { Finding, ReportBody } from "./types.js";

export const maxAssessmentBytes = 128 * 1024 * 1024;

/** Snapshot own-data inputs before the first asynchronous read. */
export function dataObject(
  value: unknown,
  required: string[],
  optional: string[] = [],
): Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Object.getPrototypeOf(value) !== Object.prototype
  )
    fail("Expected a plain own-data object");
  const result: Record<string, unknown> = {};
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string" || ![...required, ...optional].includes(key))
      fail("Unsupported input field");
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor)) fail("Inputs require own data properties");
    Object.defineProperty(result, key, { value: descriptor.value, enumerable: true });
  }
  if (required.some((key) => !Object.hasOwn(result, key))) fail("Missing input field");
  return result;
}

export function snapshotDocument(value: unknown): EvidenceDocument {
  const input = dataObject(value, ["format", "bytes"]);
  if (input.format !== "report" && input.format !== "artifact") fail("Unknown evidence format");
  if (!(input.bytes instanceof Uint8Array)) fail("Evidence must be bytes");
  bound(input.bytes.byteLength <= maxAssessmentBytes, "supplied bytes", maxAssessmentBytes);
  return { format: input.format, bytes: new Uint8Array(input.bytes) };
}

export function snapshotJson<T>(value: T): T {
  assertControlJson(value);
  return JSON.parse(new TextDecoder().decode(canonicalBytes(value))) as T;
}

export function detectorIds(value: unknown = []): string[] {
  const copy = snapshotJson(value);
  if (!Array.isArray(copy) || copy.length > 10000) fail("Detector IDs must be a bounded array");
  const ids = copy.map((item) => labelShape.parse(item));
  return [...new Set(ids)].sort();
}

export const readDocument = (document: EvidenceDocument) =>
  document.format === "report" ? readReport(document.bytes) : readArtifact(document.bytes);

function counts(findings: readonly Finding[]): FindingCounts {
  return {
    records: findings.length,
    occurrences: findings
      .reduce((total, finding) => total + BigInt(finding.multiplicity), 0n)
      .toString(),
  };
}

function severities(findings: readonly Finding[]) {
  const groups = new Map<string, { severity: Finding["severity"]; findings: Finding[] }>();
  for (const finding of findings) {
    const key = new TextDecoder().decode(canonicalBytes(finding.severity));
    const group = groups.get(key) ?? { severity: finding.severity, findings: [] };
    group.findings.push(finding);
    groups.set(key, group);
  }
  return [...groups.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([, group]) => ({ severity: group.severity, ...counts(group.findings) }));
}

export function summarize(
  report: ReportBody,
  scanId: string,
  annexBytes: "checked" | "not-supplied",
  knownIds: string[],
): ScanSummary {
  const allFindings = report.results.flatMap((result) =>
    result.observations.flatMap((o) => o.body.findings),
  );
  const providers: ScanSummary["providers"] = report.results.map((result, index) => {
    const findings = result.observations.flatMap((o) => o.body.findings);
    return {
      detectorId: result.detectorId,
      outcome: result.outcome,
      request: report.requestedDetectors[index] as ReportBody["requestedDetectors"][number],
      coverage: result.coverage,
      diagnostics: result.diagnostics,
      findings: { ...counts(findings), bySeverity: severities(findings) },
      observations: result.observations.map(({ observationId, origin, fromScanId, body }) => {
        const { entries: _entries, ...input } = body.input;
        return {
          observationId,
          origin,
          ...(fromScanId === undefined ? {} : { fromScanId }),
          input,
          producer: body.producer,
          startedAt: body.startedAt,
          completedAt: body.completedAt,
          coverage: body.coverage,
          gaps: body.gaps,
          annexIds: body.annexIds,
          findings: { ...counts(body.findings), bySeverity: severities(body.findings) },
        };
      }),
    };
  });
  for (const id of knownIds)
    if (!report.results.some((result) => result.detectorId === id))
      providers.push({ detectorId: id, outcome: "not-requested" });
  providers.sort((a, b) =>
    a.detectorId < b.detectorId ? -1 : a.detectorId > b.detectorId ? 1 : 0,
  );
  const { capture, ...source } = report.source;
  return {
    scanId,
    createdAt: report.createdAt,
    producer: report.producer,
    source: {
      ...source,
      capture: {
        profile: capture.profile,
        captureSha256: capture.captureSha256,
        entries: capture.entries.length,
        files: capture.entries.filter((entry) => "sha256" in entry).length,
      },
    },
    selection: report.selection,
    completion: report.completion,
    authenticity: "unchecked",
    annexBytes,
    findings: { ...counts(allFindings), bySeverity: severities(allFindings) },
    providers,
    diagnostics: report.diagnostics,
    annexes: report.annexes,
  };
}

/** A derived view of the original checked report, never a second signed format. */
export async function readSummary(input: ReadSummaryInput): Promise<ReadSummaryResult> {
  try {
    const raw = dataObject(input, ["format", "bytes"], ["detectorIds"]);
    const document = snapshotDocument({ format: raw.format, bytes: raw.bytes });
    const ids = detectorIds(raw.detectorIds);
    const read = await readDocument(document);
    if (read.status !== "read") return read;
    return { status: "read", summary: summarize(read.report, read.scanId, read.annexBytes, ids) };
  } catch (error) {
    return { status: "invalid", diagnostics: [errorDiagnostic(error)] };
  }
}
