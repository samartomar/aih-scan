import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { expect, test } from "vitest";
import { canonicalBytes, sha256 } from "../../src/assessment/json.js";
import { listDetectorCapabilitiesV1 } from "../../src/index.js";
import type { ReportBody } from "../../src/public/contracts.js";
import { signArtifact } from "../../src/public/host.js";
import * as readApi from "../../src/public/read.js";
import { readSummary, selectAssessments } from "../../src/public/read.js";
import { exerciseSummarySelection } from "../support/summary-selection-cases.mjs";

test("distinct valid envelopes retain per-artifact facts without report conflicts", async () => {
  const examples = JSON.parse(readFileSync("schemas/examples/1.0.0.json", "utf8")).examples;
  const artifact = examples.find(
    (entry: { format: string }) => entry.format === "urn:aihq:scan:artifact:1.0.0",
  ).valid;
  const report = JSON.parse(
    Buffer.from(artifact.report.bytesBase64, "base64").toString(),
  ) as ReportBody;
  const signed = await Promise.all(
    [0, 1].map(async () => {
      const key = generateKeyPairSync("ed25519");
      return signArtifact({
        report,
        annexes: artifact.annexes.map((annex: { id: string; bytesBase64: string }) => ({
          id: annex.id,
          bytes: new Uint8Array(Buffer.from(annex.bytesBase64, "base64")),
        })),
        signer: {
          keyId: `ed25519:${await sha256(key.publicKey.export({ format: "der", type: "spki" }))}`,
          privateKey: key.privateKey,
        },
      });
    }),
  );
  const descriptors = report.source.capture.entries
    .filter((entry) => entry.kind === "file")
    .map(({ path, sha256, byteLength }) => ({ path, sha256, byteLength }));
  const value = await selectAssessments({
    assessments: signed.map((entry, index) => ({
      sourceId: "fixture",
      location: String(index),
      format: "artifact",
      bytes: entry.bytes,
      authentication:
        index === 0
          ? { status: "authenticated", scanId: entry.scanId, producerIdentity: "fixture" }
          : { status: "unverifiable", reason: "untrusted-key" },
    })),
    context: { sourceIds: ["fixture"], descriptors, selection: report.selection },
    evaluationTime: report.createdAt,
    checks: [],
  });
  expect(value).toMatchObject({
    status: "selected",
    selectedScanId: artifact.scanId,
    conflicts: [],
    assessments: [
      {
        acquisitions: [
          { authentication: { status: "authenticated" } },
          { authentication: { status: "unverifiable" } },
        ],
      },
    ],
  });
  if (value.status === "selected") expect(value.assessments).toHaveLength(1);
  const corrupt = structuredClone(artifact);
  corrupt.annexes[0].bytesBase64 = "AA==";
  expect((await readSummary({ format: "artifact", bytes: canonicalBytes(corrupt) })).status).toBe(
    "invalid",
  );
});

test("public summary and selection finite fixture contract", async () => {
  const examples = JSON.parse(readFileSync("schemas/examples/1.0.0.json", "utf8")).examples;
  const report = examples.find(
    (entry: { format: string }) => entry.format === "urn:aihq:scan:report:1.0.0",
  ).valid;
  const evidence = await exerciseSummarySelection(
    readApi,
    report,
    listDetectorCapabilitiesV1().map((item) => item.detectorId),
    JSON.parse(readFileSync("examples/detector-definitions/definition.json", "utf8")),
  );
  expect(evidence.cases).toBeGreaterThan(40);
});

test("reads a compact summary without replacing report identity or authenticating", async () => {
  const examples = JSON.parse(readFileSync("schemas/examples/1.0.0.json", "utf8")).examples;
  const artifact = examples.find(
    (entry: { format: string }) => entry.format === "urn:aihq:scan:artifact:1.0.0",
  ).valid;
  const encode = (value: unknown): string =>
    Array.isArray(value)
      ? `[${value.map(encode).join(",")}]`
      : value !== null && typeof value === "object"
        ? `{${Object.keys(value)
            .sort()
            .map(
              (key) => `${JSON.stringify(key)}:${encode((value as Record<string, unknown>)[key])}`,
            )
            .join(",")}}`
        : JSON.stringify(value);
  const result = await readSummary({
    format: "artifact",
    bytes: new TextEncoder().encode(encode(artifact)),
    detectorIds: ["detector.aih-native", "detector.other"],
  });
  expect(result).toMatchObject({
    status: "read",
    summary: {
      scanId: artifact.scanId,
      authenticity: "unchecked",
      annexBytes: "checked",
      findings: { records: 0, occurrences: "0" },
      providers: [
        { detectorId: "detector.aih-native", outcome: "succeeded" },
        { detectorId: "detector.other", outcome: "not-requested" },
      ],
    },
  });
});

test("selects the newest readable partial report before older complete evidence", async () => {
  const examples = JSON.parse(readFileSync("schemas/examples/1.0.0.json", "utf8")).examples;
  const report = examples.find(
    (entry: { format: string }) => entry.format === "urn:aihq:scan:report:1.0.0",
  ).valid;
  const newer = structuredClone(report);
  newer.createdAt = "2026-10-19T00:00:00.000Z";
  newer.completion = "partial";
  newer.results[0].outcome = "failed";
  newer.results[0].observations = [];
  newer.results[0].coverage = {
    coveredPaths: [],
    excludedPaths: [],
    uncoveredPaths: ["SKILL.md"],
    complete: false,
  };
  newer.results[0].diagnostics = [{ code: "unavailable", detail: "Fixture failure" }];
  const canonical = (value: unknown): string =>
    Array.isArray(value)
      ? `[${value.map(canonical).join(",")}]`
      : value !== null && typeof value === "object"
        ? `{${Object.keys(value)
            .sort()
            .map(
              (key) =>
                `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`,
            )
            .join(",")}}`
        : JSON.stringify(value);
  const result = await selectAssessments({
    assessments: [report, newer].map((value, i) => ({
      sourceId: "producer",
      location: String(i),
      format: "report",
      bytes: new TextEncoder().encode(canonical(value)),
    })),
    context: {
      sourceIds: ["producer"],
      descriptors: [
        {
          path: "SKILL.md",
          sha256: "f8185998ec464c5c9d5fe35c2157e0ad2593c5d5224797b24060a016df079d77",
          byteLength: 138,
        },
      ],
      selection: { paths: ["SKILL.md"], excludedPaths: [] },
    },
    evaluationTime: "2026-10-19T00:00:00.000Z",
    checks: [],
  });
  expect(result).toMatchObject({
    status: "selected",
    assessments: [
      {
        summary: { createdAt: newer.createdAt, completion: "partial" },
        eligibility: "eligible",
        coverage: { status: "matched", observations: [] },
      },
      { summary: { completion: "complete" } },
    ],
    freshness: "last-known",
  });
  if (result.status === "selected")
    expect(result.selectedScanId).toBe(result.assessments[0]?.summary.scanId);
});
