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
      "assertCompleteScanAnnexArtifactsV2",
      "canonicalCoreOrganizationEvidenceEnvelopeV1Bytes",
      "canonicalDetectorRegistrationV1Bytes",
      "canonicalDssePaeV2",
      "canonicalScanAttestationEnvelopeBytesV2",
      "canonicalScanCandidateBytesV2",
      "canonicalSourceSealsV2Bytes",
      "captureCiscoOciCandidateV2",
      "captureRegisteredDetectorCandidateV2",
      "createDetectorRegistrationV1",
      "createScanCandidateV2",
      "ed25519KeyIdV2",
      "isVerifiedScanAttestationV2",
      "parseDetectorRegistrationV1Json",
      "parseScanAttestationEnvelopeV2Json",
      "parseScanCandidateV2Json",
      "projectVerifiedScanAttestationToCoreEvidenceEnvelopeV1",
      "readScanCaptureBundleV2",
      "sealSourceV2",
      "signScanCandidateV2",
      "verifyAiHarnessCoreEvidenceContractV1",
      "verifyAiHarnessStrictV2Contract",
      "verifyCoreOrganizationEvidenceEnvelopeSchemaLockV1",
      "verifyScanAttestationV2",
      "writeScanCaptureBundleV2",
    ]);
    expect(read("src/index.ts")).not.toMatch(/observation\/.+-v1\.js/);
  });

  it("makes the 0.1 package boundary explicit without treating source as publication evidence", () => {
    const manifest = JSON.parse(read("package.json")) as Record<string, unknown>;
    expect(manifest.name).toBe("@aihq/scan");
    expect(manifest.version).toBe("0.1.2");
    expect(manifest.private).toBeUndefined();
    expect(manifest.bin).toEqual({ "aih-scan": "./dist/cli.js" });
    expect(manifest.exports).toEqual({
      ".": { types: "./dist/index.d.ts", import: "./dist/index.js" },
    });
    const cli = read("src/cli.ts");
    expect(cli).toContain('command === "verify"');
    expect(cli).toContain('command === "project-core-evidence"');
    expect(cli).not.toMatch(/npm publish|createRelease|git tag/i);
  });

  it("keeps V1 internal and reports V2 signed claims without adoption authority", () => {
    const source = read("src/observation/scan-attestation-v2.ts");
    expect(source).toContain('origin: "signer-asserted"');
    expect(source).toContain('provenance: "none"');
    expect(source).not.toMatch(/\b(approve|waive|activate|install)\b/i);
  });
});
