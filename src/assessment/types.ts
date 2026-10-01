export const schemas = Object.freeze({
  request: "urn:aihq:scan:request:1.0.0",
  runResult: "urn:aihq:scan:run-result:1.0.0",
  report: "urn:aihq:scan:report:1.0.0",
  artifact: "urn:aihq:scan:artifact:1.0.0",
  evidenceAssociation: "urn:aihq:scan:evidence-association:1.0.0",
  materialChange: "urn:aihq:scan:material-change:1.0.0",
} as const);
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export type Digest = string;
export type ScanId = `scan:sha256:${string}`;
export interface Diagnostic {
  code: string;
  detail: string;
  detectorId?: string;
  path?: string;
}
export interface Producer {
  name: "@aihq/scan";
  version: string;
}
export type CaptureEntry =
  | { kind: "directory"; path: string }
  | { kind: "directory-link"; path: string; target: string }
  | { kind: "file"; path: string; sha256: Digest; byteLength: number }
  | { kind: "file-link"; path: string; target: string; sha256: Digest; byteLength: number };
export interface Capture {
  profile: "aih-source-capture-1";
  entries: CaptureEntry[];
  captureSha256: Digest;
}
export interface Selection {
  paths: string[];
  excludedPaths: string[];
}
export type Source =
  | { kind: "local"; capture: Capture }
  | { kind: "git"; repository: string; commit: string; capture: Capture };
export interface Limits {
  maxSourceEntries: number;
  maxSourceBytes: number;
  maxRequestBytes: number;
  maxReportBytes: number;
  maxAnnexBytes: number;
  maxDecodedArtifactBytes: number;
  maxArtifactBytes: number;
  maxStatementBytes: number;
  detectorTimeoutMs: number;
}
export const limitCeilings: Readonly<Limits> = Object.freeze({
  maxSourceEntries: 100000,
  maxSourceBytes: 256 * 1024 * 1024,
  maxRequestBytes: 2 * 1024 * 1024,
  maxReportBytes: 16 * 1024 * 1024,
  maxAnnexBytes: 16 * 1024 * 1024,
  maxDecodedArtifactBytes: 64 * 1024 * 1024,
  maxArtifactBytes: 96 * 1024 * 1024,
  maxStatementBytes: 128 * 1024,
  detectorTimeoutMs: 3600000,
});
export const defaultLimits: Readonly<Limits> = Object.freeze({
  ...limitCeilings,
  detectorTimeoutMs: 600000,
});
export interface AnnexDescriptor {
  id: string;
  mediaType: string;
  sha256: Digest;
  byteLength: number;
}
export interface RequestedDetector {
  detectorId: string;
  profileId: string | null;
  configuration: Json;
  configurationSha256: Digest;
}
export interface ObservationInput {
  detectorId: string;
  detectorVersion: string;
  adapterSha256: Digest;
  rulesSha256: Digest;
  configurationSha256: Digest;
  profileId: string;
  profileSha256: Digest;
  platform: { os: string; architecture: string; relevantFactsSha256: Digest };
  scopeKind: "source-tree" | "selected-closure";
  targetPaths: string[];
  entries: CaptureEntry[];
}
export type Field<T> =
  | { state: "present"; value: T }
  | { state: "unavailable"; reason: string; detail: string };
export interface Finding {
  rawOccurrenceFingerprint: string;
  multiplicity: number;
  rule: Field<{ nativeRuleId: string; name?: string }>;
  severity: Field<{ level: string; vendorSeverity?: string }>;
  message: Field<string>;
  location: Field<{ path: string; fileSha256: Digest; startLine?: number }>;
  supportingEvidence: Field<{ annexId: string; ordinal: number }>;
}
export interface ObservationBody {
  format: "aih-observation-v1";
  input: ObservationInput;
  startedAt: string;
  completedAt: string;
  producer: Producer;
  coverage: { coveredPaths: string[] };
  findings: Finding[];
  gaps: { reason: string; detail: string }[];
  annexIds: string[];
}
export interface Observation {
  observationId: `observation:sha256:${string}`;
  body: ObservationBody;
  origin: "fresh" | "reused";
  fromScanId?: ScanId;
}
export interface DetectorResult {
  detectorId: string;
  outcome: "succeeded" | "failed" | "refused" | "cancelled";
  observations: Observation[];
  coverage: {
    coveredPaths: string[];
    excludedPaths: string[];
    uncoveredPaths: string[];
    complete: boolean;
  };
  diagnostics: Diagnostic[];
}
export interface ReportBody {
  schema: typeof schemas.report;
  producer: Producer;
  createdAt: string;
  source: Source;
  selection: Selection;
  requestedDetectors: RequestedDetector[];
  results: DetectorResult[];
  completion: "complete" | "partial";
  annexes: AnnexDescriptor[];
  effectiveLimits: Limits;
  diagnostics: Diagnostic[];
}
export type Location = { kind: "file"; path: string } | { kind: "https"; url: string };
export interface ScanRequest {
  schema: typeof schemas.request;
  source: { kind: "local"; path: string } | { kind: "git"; repository: string; commit: string };
  selection: { paths: "all" | string[]; excludedPaths: string[] };
  detectors: { detectorId: string; profileId?: string; configuration: Json }[];
  priorArtifacts?: { scanId: ScanId; location: Location }[];
  limits?: Partial<Limits>;
}
export type ScanRunResult =
  | {
      schema: typeof schemas.runResult;
      status: "assessment";
      scanId: ScanId;
      report: ReportBody;
      annexes: { id: string; bytesBase64: string }[];
      diagnostics: Diagnostic[];
    }
  | {
      schema: typeof schemas.runResult;
      status: "diagnostic";
      phase: "request" | "capture" | "assembly";
      diagnostics: Diagnostic[];
    };
export type ReadReportResult =
  | {
      status: "read";
      scanId: ScanId;
      report: ReportBody;
      authenticity: "unchecked";
      annexBytes: "not-supplied";
    }
  | { status: "unsupported-report"; scanId: ScanId; reportSchema: string }
  | { status: "invalid"; diagnostics: Diagnostic[] };
