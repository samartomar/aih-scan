import type { AssociationResult, ReadArtifactResult } from "../artifact/types.js";
import type {
  AnnexDescriptor,
  Diagnostic,
  Finding,
  Observation,
  ObservationInput,
  Producer,
  ReportBody,
  Selection,
} from "./types.js";

export interface EvidenceDocument {
  format: "report" | "artifact";
  bytes: Uint8Array;
}
export interface ReadSummaryInput extends EvidenceDocument {
  /** Additional known providers to display as not-requested when absent. */
  detectorIds?: string[];
}
export interface FindingCounts {
  /** Finding records, without deduplication across observations or providers. */
  records: number;
  /** Exact decimal sum of multiplicity; may exceed JavaScript's safe integer range. */
  occurrences: string;
}
export interface FindingSummary extends FindingCounts {
  bySeverity: (FindingCounts & { severity: Finding["severity"] })[];
}
export interface ObservationSummary {
  observationId: Observation["observationId"];
  origin: Observation["origin"];
  fromScanId?: Observation["fromScanId"];
  input: Omit<ObservationInput, "entries">;
  producer: Producer;
  startedAt: string;
  completedAt: string;
  coverage: { coveredPaths: string[] };
  gaps: { reason: string; detail: string }[];
  annexIds: string[];
  findings: FindingSummary;
}
export type ProviderSummary =
  | { detectorId: string; outcome: "not-requested" }
  | {
      detectorId: string;
      outcome: ReportBody["results"][number]["outcome"];
      request: ReportBody["requestedDetectors"][number];
      coverage: ReportBody["results"][number]["coverage"];
      diagnostics: Diagnostic[];
      findings: FindingSummary;
      observations: ObservationSummary[];
    };
export interface ScanSummary {
  scanId: string;
  createdAt: string;
  producer: Producer;
  source: ({ kind: "local" } | { kind: "git"; repository: string; commit: string }) & {
    capture: { profile: string; captureSha256: string; entries: number; files: number };
  };
  selection: Selection;
  completion: ReportBody["completion"];
  authenticity: "unchecked";
  annexBytes: "checked" | "not-supplied";
  findings: FindingSummary;
  providers: ProviderSummary[];
  diagnostics: Diagnostic[];
  annexes: AnnexDescriptor[];
}
export type ReadSummaryResult =
  | { status: "read"; summary: ScanSummary }
  | Exclude<ReadArtifactResult, { status: "read" }>;

/** Host-supplied acquisition and authentication facts, never verified by selection. */
export interface EvidenceCandidate extends EvidenceDocument {
  sourceId: string;
  location: string;
  expectedScanId?: string;
  authentication?: AssociationResult;
}
export interface EvidenceCheck {
  sourceId: string;
  attemptedAt: string;
  lastSuccessfulAt?: string;
  status: "succeeded" | "failed" | "offline";
  diagnostics: Diagnostic[];
}
export interface AssessmentContext {
  sourceIds: string[];
  descriptors: import("./types.js").ContentDescriptor[];
  selection: Selection;
  git?: { repository: string; commit: string };
  /** Explicit view filter; every requested detector/profile must be present. */
  providers?: { detectorId: string; profileId?: string }[];
}
export interface SelectAssessmentsInput {
  assessments: EvidenceCandidate[];
  context: AssessmentContext;
  evaluationTime: string;
  checks: EvidenceCheck[];
  detectorIds?: string[];
}
export interface EvidenceAcquisition {
  sourceId: string;
  location: string;
  format: EvidenceDocument["format"];
  authentication: AssociationResult;
  annexBytes: "checked" | "not-supplied";
}
export interface AssessmentSelectionEntry {
  summary: ScanSummary;
  acquisitions: EvidenceAcquisition[];
  eligibility:
    | "eligible"
    | "content-mismatch"
    | "scope-mismatch"
    | "git-mismatch"
    | "provider-mismatch"
    | "future-dated"
    | "identity-conflict";
  coverage: import("./types.js").ReadContentCoverageResult;
}
export interface EvidenceSourceFailure {
  sourceId: string;
  location: string;
  diagnostics: Diagnostic[];
}
export type SelectAssessmentsResult =
  | {
      status: "selected";
      selectedScanId: string | null;
      freshness: "checked" | "last-known";
      evaluationTime: string;
      assessments: AssessmentSelectionEntry[];
      checks: EvidenceCheck[];
      failures: EvidenceSourceFailure[];
      conflicts: { scanId: string; locations: { sourceId: string; location: string }[] }[];
    }
  | { status: "invalid"; diagnostics: Diagnostic[] };
