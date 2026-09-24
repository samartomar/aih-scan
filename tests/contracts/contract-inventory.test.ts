import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { ZodError } from "zod";
import {
  listDetectorCapabilitiesV1,
  resolveDetectorExecutionProfileDocumentV1,
} from "../../src/capability/detector-capability-v1.js";
import { canonicalStrictJsonBytesV1 } from "../../src/contract/strict-json-v1.js";
import {
  AI_HARNESS_DECISION_V2_SCHEMA_SHA256,
  AI_HARNESS_DECISION_V2_SCHEMA_SHA256_ACCEPTED,
  AI_HARNESS_ORGANIZATION_EVIDENCE_ENVELOPE_V1_SCHEMA_SHA256,
  AI_HARNESS_STRICT_V2_COMMIT,
  AI_HARNESS_STRICT_V2_COMMIT_ACCEPTED,
} from "../../src/core/core-contract-lock-v2.js";
import {
  createScanCandidateV2,
  parseScanAttestationEnvelopeV2Json,
  parseScanCandidateV2Json,
} from "../../src/observation/scan-attestation-v2.js";
import { createScannerManifestV1 } from "../../src/observation/scanner-manifest-v1.js";
import { validateSourceSealV2 } from "../../src/observation/source-seal-v2.js";
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
    line: 457,
    contains: "export function parseScanResultRecordV1",
  },
  {
    path: "src/capability/detector-capability-v1.ts",
    line: 122,
    contains: "export interface DetectorExecutionProfileDocumentV1",
  },
  {
    path: "src/capability/detector-capability-v1.ts",
    line: 158,
    contains: "export interface DetectorCapabilityV1",
  },
  { path: "src/runner/run-detector-v1.ts", line: 104, contains: "RunDetectorRefusalReasonV1" },
  {
    path: "src/runner/run-detector-v1.ts",
    line: 200,
    contains: "readonly detectorOptions?: DetectorOptionsV1",
  },
  {
    path: "src/runner/detector-options-v1.ts",
    line: 134,
    contains: "export function readDetectorOptionsV1",
  },
  {
    path: "src/runner/run-detector-v1.ts",
    line: 127,
    contains: "export type RunDetectorFailureCauseV1",
  },
  { path: "src/runner/run-detector-v1.ts", line: 129, contains: "export interface ScanCoverageV1" },
  {
    path: "src/runner/run-detector-v1.ts",
    line: 759,
    contains: "export async function runDetectorV1",
  },
  {
    path: "src/runner/run-detector-v1.ts",
    line: 249,
    contains: "export type RunDetectorProducerV1",
  },
  {
    path: "src/runner/run-detector-v1.ts",
    line: 225,
    contains: "readonly acceptedImageDigests?: readonly string[]",
  },
  {
    path: "src/runner/run-detector-v1.ts",
    line: 165,
    contains: "readonly image?: SkillspectorImageMatchV1",
  },
  {
    path: "src/runner/run-detector-v1.ts",
    line: 167,
    contains: "readonly hostRuntime?: HostProcessRuntimeV1",
  },
  { path: "src/runner/run-detector-v1.ts", line: 202, contains: "readonly signal?: AbortSignal" },
  { path: "src/runner/run-detector-v1.ts", line: 207, contains: "readonly timeoutMs?: number" },
  {
    path: "src/runner/run-detector-v1.ts",
    line: 298,
    contains: "sourceSeal: Readonly<{ before: SourceSealV2; after: SourceSealV2 }> | null",
  },
  {
    path: "src/baseline/runtime-v1.ts",
    line: 48,
    contains: "export const SKILLSPECTOR_LOCAL_IMAGE_TAG_V1",
  },
  {
    path: "src/baseline/runtime-v1.ts",
    line: 708,
    contains: "export function skillspectorAcceptedImageDigestsRefusalV1",
  },
  {
    path: "src/baseline/runtime-v1.ts",
    line: 215,
    contains: "export const HOST_PROCESS_UV_ENVIRONMENT_V1",
  },
  {
    path: "src/baseline/sarif-source-relative-v1.ts",
    line: 130,
    contains: "export function sourceRelativeSarifV1",
  },
  {
    path: "src/baseline/sarif-source-relative-v1.ts",
    line: 210,
    contains: "export function ciscoSourceRelativeSarifV1",
  },
  {
    path: "src/cli/windows-job-supervisor.ts",
    line: 441,
    contains: "export function runUnderWindowsJobV1",
  },
  {
    path: "src/cli/residual-processes.ts",
    line: 178,
    contains: "export async function sweepResidualProcessesV1",
  },
  { path: "src/findings/scan-findings-v1.ts", line: 44, contains: "export type FindingFieldV1" },
  {
    path: "src/findings/scan-findings-v1.ts",
    line: 66,
    contains: "export interface ScanFindingsV1",
  },
  {
    path: "src/findings/scan-findings-v1.ts",
    line: 404,
    contains: "export function projectAnalyzerSarifFindingsV1",
  },
  {
    path: "src/findings/scan-findings-v1.ts",
    line: 534,
    contains: "export function readScanFindingsV1",
  },
];

/**
 * Each byte bound the inventory states, the row phrase that states it, and the source
 * line that enforces it. A bound the source does not enforce cannot be published.
 */
const BOUNDS: readonly Readonly<{
  path: string;
  line: number;
  contains: string;
  phrase: string;
}>[] = [
  {
    path: "src/observation/scan-attestation-v2.ts",
    line: 316,
    contains: "maxBytes = 2 * 1024 * 1024",
    phrase: "decoded payload 2 MiB",
  },
  {
    path: "src/observation/scan-attestation-v2.ts",
    line: 740,
    contains: "payload.byteLength > 2 * 1024 * 1024",
    phrase: "decoded payload 2 MiB",
  },
  {
    path: "src/observation/scan-bundle-v2.ts",
    line: 116,
    contains: "2 * 1024 * 1024",
    phrase: "`candidate.json` 2 MiB",
  },
  {
    path: "src/observation/source-seal-v2.ts",
    line: 24,
    contains: "maxFileBytes = 16 * 1024 * 1024",
    phrase: "16 MiB per file",
  },
  {
    path: "src/observation/source-seal-v2.ts",
    line: 25,
    contains: "maxTotalBytes = 256 * 1024 * 1024",
    phrase: "256 MiB total",
  },
  {
    path: "src/observation/source-seal-v2.ts",
    line: 26,
    contains: "maxSealBytes = 512 * 1024",
    phrase: "512 KiB canonical seal",
  },
  {
    path: "src/observation/scan-bundle-v2.ts",
    line: 171,
    contains: '"bundle annex", 16 * 1024 * 1024',
    phrase: "16 MiB each",
  },
  {
    path: "src/baseline/batch-v1.ts",
    line: 38,
    contains: "maxAnnexBytes = 16 * 1024 * 1024",
    phrase: "16 MiB per annex",
  },
];

type GenuineCandidate = Record<string, unknown> & {
  coreContract: Record<string, string>;
  sourceSeals: { before: Record<string, unknown> };
};
const genuineCandidate = () =>
  JSON.parse(read("tests/fixtures/cisco/genuine-oci-capture-candidate.json")) as GenuineCandidate;
const candidateInput = (patch: Record<string, unknown>) => {
  const { candidateSha256: _digest, ...input } = genuineCandidate();
  return { ...input, ...patch };
};
/** The issue paths of the ZodError `action` throws; fails if it throws anything else. */
const zodIssuePaths = (action: () => unknown): string[] => {
  let thrown: unknown;
  try {
    action();
  } catch (error) {
    thrown = error;
  }
  expect(thrown).toBeInstanceOf(ZodError);
  return (thrown as ZodError).issues.map((issue) => issue.path.join("."));
};
const envelopeText = (statement: Record<string, unknown>, payloadType: string) =>
  JSON.stringify({
    payload: canonicalStrictJsonBytesV1(statement).toString("base64"),
    payloadType,
    signatures: [{ keyid: ["ed25519:", "0".repeat(64)].join(""), sig: "AAAA" }],
  });
const IN_TOTO = "application/vnd.in-toto+json";

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

  it("anchors every source reference it publishes", () => {
    const anchored = new Set([...ANCHORS, ...BOUNDS].map((a) => `${a.path}:${a.line}`));
    const references = [...contracts().matchAll(/`((?:src|tools)\/[^`:]+:\d+)`/gu)].map(
      (match) => match[1],
    );
    expect(references.length).toBeGreaterThan(0);
    for (const reference of references) expect(anchored, reference).toContain(reference);
  });

  it("states only byte bounds the source enforces, on the row that cites them", () => {
    const rows = contracts().split("\n");
    for (const bound of BOUNDS) {
      const reference = `${bound.path}:${bound.line}`;
      const row = rows.find((candidate) => candidate.includes(`\`${reference}\``));
      expect(row, reference).toBeDefined();
      expect(row, reference).toContain(bound.phrase);
      const line = read(bound.path).split("\n")[bound.line - 1];
      expect(line, reference).toContain(bound.contains);
    }
    // The envelope never had an 8 MiB bound; the decoded payload is bounded to 2 MiB.
    expect(contracts()).not.toContain("8 MiB");
  });

  it("describes the refusal each reader actually throws for an unknown identity", () => {
    // Schema-checked identities surface as a ZodError naming the field, not a TypeError.
    const document = contracts();
    expect(document).toContain("a `ZodError` from `parseScanCandidateV2Json`");
    expect(document).toContain("a `ZodError` from `parseScanAttestationEnvelopeV2Json`");
    expect(document).not.toContain("`TypeError` naming the invalid field");
    const candidate = genuineCandidate();
    expect(
      zodIssuePaths(() =>
        parseScanCandidateV2Json(JSON.stringify({ ...candidate, protocol: "ScanCandidateV9" })),
      ),
    ).toContain("protocol");
    const commit = { ...candidate.coreContract, commit: "0".repeat(40) };
    expect(
      zodIssuePaths(() => createScanCandidateV2(candidateInput({ coreContract: commit }))),
    ).toEqual(["coreContract.commit"]);
    const digest = { ...candidate.coreContract, decisionSchemaSha256: "f".repeat(64) };
    expect(
      zodIssuePaths(() => createScanCandidateV2(candidateInput({ coreContract: digest }))),
    ).toEqual(["coreContract.decisionSchemaSha256"]);
    const mixed = {
      commit: AI_HARNESS_STRICT_V2_COMMIT_ACCEPTED[0],
      decisionSchemaSha256: AI_HARNESS_DECISION_V2_SCHEMA_SHA256_ACCEPTED[1],
    };
    expect(
      zodIssuePaths(() => createScanCandidateV2(candidateInput({ coreContract: mixed }))),
    ).toEqual(["coreContract"]);

    const statement = {
      _type: "https://in-toto.io/Statement/v1",
      predicate: { protocol: "ScanAttestationV2" },
      predicateType: "https://aih.dev/ScanAttestationV2",
      subject: [],
    };
    expect(
      zodIssuePaths(() =>
        parseScanAttestationEnvelopeV2Json(envelopeText(statement, "text/plain")),
      ),
    ).toEqual(["payloadType"]);
    for (const [field, patch] of [
      ["_type", { _type: "https://in-toto.io/Statement/v9" }],
      ["predicateType", { predicateType: "https://aih.dev/Other" }],
      ["predicate.protocol", { predicate: { protocol: "ScanAttestationV9" } }],
    ] as const) {
      const text = envelopeText({ ...statement, ...patch }, IN_TOTO);
      expect(
        zodIssuePaths(() => parseScanAttestationEnvelopeV2Json(text)),
        field,
      ).toContain(field);
    }

    const seal = candidate.sourceSeals.before;
    expect(
      zodIssuePaths(() => validateSourceSealV2({ ...seal, protocol: "SourceSealV9" })),
    ).toEqual(["protocol"]);
    expect(zodIssuePaths(() => validateSourceSealV2({ ...seal, algorithm: "other" }))).toEqual([
      "algorithm",
    ]);
    expect(
      zodIssuePaths(() =>
        createScannerManifestV1({ protocol: "ScannerManifestV9", detectors: [] }),
      ),
    ).toContain("protocol");
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
      "schema digest drift: <path>",
      "a tree without git history requires --core-commit",
      "declared commit is not the checked-out commit",
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
