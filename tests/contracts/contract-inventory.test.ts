import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  listDetectorCapabilitiesV1,
  resolveDetectorExecutionProfileDocumentV1,
} from "../../src/capability/detector-capability-v1.js";
import {
  AI_HARNESS_DECISION_V2_SCHEMA_SHA256,
  AI_HARNESS_DECISION_V2_SCHEMA_SHA256_ACCEPTED,
  AI_HARNESS_ORGANIZATION_EVIDENCE_ENVELOPE_V1_SCHEMA_SHA256,
  AI_HARNESS_STRICT_V2_COMMIT,
  AI_HARNESS_STRICT_V2_COMMIT_ACCEPTED,
} from "../../src/core/core-contract-lock-v2.js";
import {
  SCAN_RESULT_RECORD_FORMAT_V1,
  SCAN_RESULT_RECORD_VERSION_V1,
  SCAN_RESULT_SUBJECT_NAME_V1,
} from "../../src/scan-result-record.js";

/**
 * CONTRACTS.md is prose, so it is pinned rather than trusted: every row names a source
 * line, and this test re-reads that line. A renamed constant, a bumped literal or a
 * moved definition fails here instead of leaving the published inventory quietly wrong.
 */
const repositoryRoot = resolve(import.meta.dirname, "..", "..");
const read = (path: string) =>
  readFileSync(resolve(repositoryRoot, path), "utf8").replace(/\r\n/gu, "\n");
const contracts = () => read("CONTRACTS.md");
/** Prose wraps across lines, so sentence checks compare collapsed whitespace. */
const prose = () => contracts().replace(/\s+/gu, " ");

/** Each row's `file:line` reference, and the token that line must still carry. */
const ANCHORS: readonly Readonly<{ path: string; line: number; contains: string }>[] = [
  {
    path: "src/observation/scan-attestation-v2.ts",
    line: 132,
    contains: 'protocol: z.literal("ScanCandidateV2")',
  },
  {
    path: "src/observation/scan-attestation-v2.ts",
    line: 138,
    contains: "commit: z.enum([...AI_HARNESS_STRICT_V2_COMMIT_ACCEPTED])",
  },
  {
    path: "src/observation/scan-attestation-v2.ts",
    line: 225,
    contains: 'predicateType: z.literal("https://aih.dev/ScanAttestationV2")',
  },
  {
    path: "src/observation/scan-attestation-v2.ts",
    line: 228,
    contains: 'protocol: z.literal("ScanAttestationV2")',
  },
  {
    path: "src/observation/scan-attestation-v2.ts",
    line: 265,
    contains: "export interface VerifiedScanAttestationV2",
  },
  {
    path: "src/observation/scan-attestation-v2.ts",
    line: 1073,
    contains: "export function isVerifiedScanAttestationV2",
  },
  {
    path: "src/observation/source-seal-v2.ts",
    line: 40,
    contains: 'protocol: z.literal("SourceSealV2")',
  },
  {
    path: "src/observation/source-seal-v2.ts",
    line: 41,
    contains: 'algorithm: z.literal("code-unit-canonical-json-v1")',
  },
  {
    path: "src/observation/scan-bundle-v2.ts",
    line: 130,
    contains: 'manifest.protocol !== "ScanBundleV2"',
  },
  {
    path: "src/observation/scanner-manifest-v1.ts",
    line: 50,
    contains: 'protocol: z.literal("ScannerManifestV1")',
  },
  {
    path: "src/baseline/batch-v1.ts",
    line: 74,
    contains: 'protocol: z.literal("BaselineVetRequestV1")',
  },
  {
    path: "src/baseline/batch-v1.ts",
    line: 111,
    contains: 'protocol: z.literal("BaselineVetReceiptV1")',
  },
  {
    path: "src/core/organization-evidence-envelope-v1.ts",
    line: 16,
    contains: 'format: z.literal("aih-organization-evidence")',
  },
  {
    path: "src/core/organization-evidence-envelope-v1.ts",
    line: 17,
    contains: "version: z.literal(1)",
  },
  {
    path: "src/core/core-contract-lock-v2.ts",
    line: 19,
    contains: "export const AI_HARNESS_CORE_CONTRACTS_ACCEPTED",
  },
  {
    path: "src/core/core-contract-lock-v2.ts",
    line: 35,
    contains: "export const AI_HARNESS_STRICT_V2_COMMIT_ACCEPTED",
  },
  {
    path: "src/core/core-contract-lock-v2.ts",
    line: 39,
    contains: "export const AI_HARNESS_DECISION_V2_SCHEMA_SHA256_ACCEPTED",
  },
  {
    path: "src/core/core-contract-lock-v2.ts",
    line: 49,
    contains: "export const AI_HARNESS_ORGANIZATION_EVIDENCE_ENVELOPE_V1_SCHEMA_SHA256",
  },
  {
    path: "src/scan-result-record.ts",
    line: 30,
    contains: 'export const SCAN_RESULT_RECORD_FORMAT_V1 = "aih-scan-result-record"',
  },
  {
    path: "src/scan-result-record.ts",
    line: 31,
    contains: "export const SCAN_RESULT_RECORD_VERSION_V1 = 1",
  },
  {
    path: "src/scan-result-record.ts",
    line: 32,
    contains: 'export const SCAN_RESULT_SUBJECT_NAME_V1 = "source-tree"',
  },
  {
    path: "src/scan-result-record.ts",
    line: 444,
    contains: "export function parseScanResultRecordV1",
  },
  {
    path: "src/capability/detector-capability-v1.ts",
    line: 98,
    contains: "export interface DetectorExecutionProfileDocumentV1",
  },
  {
    path: "src/capability/detector-capability-v1.ts",
    line: 122,
    contains: "export interface DetectorCapabilityV1",
  },
  { path: "src/runner/run-detector-v1.ts", line: 65, contains: "RunDetectorRefusalReasonV1" },
  { path: "src/runner/run-detector-v1.ts", line: 81, contains: "export interface ScanCoverageV1" },
  {
    path: "src/runner/run-detector-v1.ts",
    line: 364,
    contains: "export async function runDetectorV1",
  },
  { path: "src/findings/scan-findings-v1.ts", line: 44, contains: "export type FindingFieldV1" },
  {
    path: "src/findings/scan-findings-v1.ts",
    line: 66,
    contains: "export interface ScanFindingsV1",
  },
  {
    path: "src/findings/scan-findings-v1.ts",
    line: 368,
    contains: "export function readScanFindingsV1",
  },
];

describe("published contract inventory", () => {
  it("names a source line for every contract, and that line still defines it", () => {
    const document = contracts();
    for (const anchor of ANCHORS) {
      const reference = `${anchor.path}:${anchor.line}`;
      expect(document, reference).toContain(reference);
      const line = read(anchor.path).split("\n")[anchor.line - 1];
      expect(line, reference).toBeDefined();
      expect(line, reference).toContain(anchor.contains);
    }
  });

  it("restates the exact constants this build compiles", () => {
    const document = contracts();
    for (const value of [
      SCAN_RESULT_RECORD_FORMAT_V1,
      SCAN_RESULT_SUBJECT_NAME_V1,
      AI_HARNESS_ORGANIZATION_EVIDENCE_ENVELOPE_V1_SCHEMA_SHA256,
    ]) {
      expect(document, value).toContain(value);
    }
    expect(document).toContain(`version: ${SCAN_RESULT_RECORD_VERSION_V1}`);
    expect(document).toContain("AI_HARNESS_CORE_CONTRACTS_ACCEPTED");
    expect(document).toContain("AI_HARNESS_STRICT_V2_COMMIT_ACCEPTED");
    expect(document).toContain("AI_HARNESS_DECISION_V2_SCHEMA_SHA256_ACCEPTED");
    // The default emitted pair must be the newest accepted member, and the document
    // must say so rather than naming a value the build no longer emits.
    expect(AI_HARNESS_STRICT_V2_COMMIT).toBe(AI_HARNESS_STRICT_V2_COMMIT_ACCEPTED.at(-1));
    expect(AI_HARNESS_DECISION_V2_SCHEMA_SHA256).toBe(
      AI_HARNESS_DECISION_V2_SCHEMA_SHA256_ACCEPTED.at(-1),
    );
    expect(document).toContain("newest last");
  });

  it("names every refusal a reader can produce", () => {
    const document = contracts();
    for (const reason of [
      "unknown-format",
      "unknown-version",
      "unknown-subject-name",
      "malformed-record",
      "not-an-object",
      "unknown-detector",
      "unsupported-platform",
      "unsupported-subject-kind",
      "subject-requirement-unmet",
      "prerequisite-missing",
      "execution-profile-unavailable",
      "unexpected Core commit",
      "schema digest mismatch",
    ]) {
      expect(document, reason).toContain(reason);
    }
  });

  it("names every detector capability and execution profile this build publishes", () => {
    const document = contracts();
    for (const capability of listDetectorCapabilitiesV1()) {
      for (const profile of capability.executionProfiles) {
        expect(resolveDetectorExecutionProfileDocumentV1(profile.id), profile.id).toBeDefined();
      }
    }
    expect(document).toContain("DetectorCapabilityV1");
    expect(document).toContain("DetectorExecutionProfileDocumentV1");
    expect(document).toContain("ScanFindingsV1");
  });

  it("states that evidence carries no authority and that the document is not the contract", () => {
    const sentences = prose();
    expect(sentences).toContain("Scanner evidence carries no authority");
    expect(sentences).toContain("This document is not the contract. The source is.");
    expect(sentences).toContain("never by version-number equality");
    expect(sentences).toContain("A recorded hash answers *what did we test*");
    expect(sentences).toContain("It is not approval of a Core release");
    // The inventory records what Scan reads and emits; it never claims an effect.
    for (const claim of [
      "grants approval",
      "approves the subject",
      "qualifies the component",
      "authorizes adoption",
      "is production authority",
    ]) {
      expect(sentences, claim).not.toContain(claim);
    }
  });
});
