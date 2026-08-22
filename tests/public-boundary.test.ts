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
      "AI_HARNESS_STRICT_V2_COMMIT",
      "canonicalDssePaeV2",
      "canonicalScanAttestationEnvelopeBytesV2",
      "canonicalScanCandidateBytesV2",
      "canonicalSourceSealsV2Bytes",
      "captureCiscoOciCandidateV2",
      "createScanCandidateV2",
      "ed25519KeyIdV2",
      "isVerifiedScanAttestationV2",
      "parseScanAttestationEnvelopeV2Json",
      "parseScanCandidateV2Json",
      "sealSourceV2",
      "signScanCandidateV2",
      "verifyAiHarnessStrictV2Contract",
      "verifyScanAttestationV2",
    ]);
    expect(read("src/index.ts")).not.toMatch(/-v1\.js/);
  });

  it("makes the 1.0 package boundary and verification CLI explicit without publication", () => {
    const manifest = JSON.parse(read("package.json")) as Record<string, unknown>;
    expect(manifest.name).toBe("@aihq/scan");
    expect(manifest.version).toBe("1.0.0");
    expect(manifest.private).toBeUndefined();
    expect(manifest.bin).toEqual({ "aih-scan": "./dist/cli.js" });
    expect(manifest.exports).toEqual({
      ".": { types: "./dist/index.d.ts", import: "./dist/index.js" },
    });
    const cli = read("src/cli.ts");
    expect(cli).toContain('command === "verify"');
    expect(cli).not.toMatch(/npm publish|createRelease|git tag/i);
  });

  it("keeps V1 internal and reports V2 signed claims without adoption authority", () => {
    const source = read("src/observation/scan-attestation-v2.ts");
    expect(source).toContain('origin: "signer-asserted"');
    expect(source).toContain('provenance: "none"');
    expect(source).not.toMatch(/\b(approve|waive|activate|install|project)\b/i);
  });
});
