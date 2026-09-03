import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import * as publicApi from "../src/index.js";

const root = resolve(import.meta.dirname, "..");
const read = (path: string) => readFileSync(resolve(root, path), "utf8");

describe("Strict V2 public boundary", () => {
  it("exports only the bounded V2 evidence and compatibility contracts", () => {
    expect(Object.keys(publicApi).sort()).toEqual([
      "AI_HARNESS_DECISION_V2_SCHEMA_SHA256",
      "AI_HARNESS_ORGANIZATION_EVIDENCE_ENVELOPE_V1_SCHEMA_SHA256",
      "AI_HARNESS_STRICT_V2_COMMIT",
      "BASELINE_ANALYZERS_V1",
      "assertCompleteScanAnnexArtifactsV2",
      "baselineVetPublicationResultV1",
      "canonicalBaselineVetAttestationEnvelopeV1Bytes",
      "canonicalBaselineVetDiscoveryV1Bytes",
      "canonicalBaselineVetPublicationV1Bytes",
      "canonicalBaselineVetReceiptV1Bytes",
      "canonicalBaselineVetRequestV1Bytes",
      "canonicalCoreOrganizationEvidenceEnvelopeV1Bytes",
      "canonicalDetectorRegistrationV1Bytes",
      "canonicalDssePaeV2",
      "canonicalScanAttestationEnvelopeBytesV2",
      "canonicalScanCandidateBytesV2",
      "canonicalSourceSealsV2Bytes",
      "captureCiscoOciCandidateV2",
      "captureRegisteredDetectorCandidateV2",
      "createBaselineVetDiscoveryV1",
      "createBaselineVetPublicationV1",
      "createBaselineVetRequestV1",
      "createDetectorRegistrationV1",
      "createScanCandidateV2",
      "ed25519KeyIdV2",
      "isVerifiedScanAttestationV2",
      "parseBaselineVetAttestationEnvelopeV1Json",
      "parseBaselineVetDiscoveryV1Json",
      "parseBaselineVetPublicationV1Json",
      "parseBaselineVetReceiptV1Json",
      "parseBaselineVetRequestV1Json",
      "parseDetectorRegistrationV1Json",
      "parseScanAttestationEnvelopeV2Json",
      "parseScanCandidateV2Json",
      "projectVerifiedScanAttestationToCoreEvidenceEnvelopeV1",
      "readBaselineVetBundleV1",
      "readScanCaptureBundleV2",
      "resolveBaselineVetDiscoveryV1",
      "sealSourceV2",
      "signBaselineVetBundleV1",
      "signScanCandidateV2",
      "verifyAiHarnessCoreEvidenceContractV1",
      "verifyAiHarnessStrictV2Contract",
      "verifyBaselineVetAttestationV1",
      "verifyCoreOrganizationEvidenceEnvelopeSchemaLockV1",
      "verifyScanAttestationV2",
      "writeScanCaptureBundleV2",
    ]);
    expect(read("src/index.ts")).not.toMatch(/observation\/.+-v1\.js/);
  });

  it("makes the 0.x package boundary explicit without treating source as publication evidence", () => {
    const manifest = JSON.parse(read("package.json")) as Record<string, unknown>;
    expect(manifest.name).toBe("@aihq/scan");
    expect(manifest.version).toBe("0.2.5");
    expect(manifest.private).toBeUndefined();
    expect(manifest.bin).toEqual({ "aih-scan": "./dist/cli.js" });
    expect(manifest.exports).toEqual({
      ".": { types: "./dist/index.d.ts", import: "./dist/index.js" },
    });
    const cli = read("src/cli.ts");
    expect(cli).toContain('command === "verify"');
    expect(cli).toContain('command === "project-core-evidence"');
    expect(cli).toContain('command === "baseline-vet"');
    expect(cli).toContain('command === "baseline-sign"');
    expect(cli).toContain('command === "baseline-verify"');
    expect(cli).toContain('command === "baseline-pack"');
    expect(cli).toContain('command === "baseline-inspect"');
    expect(cli).not.toMatch(/npm publish|createRelease|git tag/i);
  });

  it("keeps V1 internal and reports V2 signed claims without adoption authority", () => {
    const source = read("src/observation/scan-attestation-v2.ts");
    expect(source).toContain('origin: "signer-asserted"');
    expect(source).toContain('provenance: "none"');
    expect(source).not.toMatch(/\b(approve|waive|activate|install)\b/i);
  });
});
