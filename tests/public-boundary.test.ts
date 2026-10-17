import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import * as attestationV1 from "../src/baseline/attestation-v1.js";
import * as batchV1 from "../src/baseline/batch-v1.js";
import * as publicationV1 from "../src/baseline/publication-v1.js";
import * as publicApi from "../src/index.js";
import * as attestationV2 from "../src/observation/scan-attestation-v2.js";
import { contractSupport } from "../src/public/contracts.js";
import * as registrationV1 from "../src/registration/detector-registration-v1.js";

const legacyImplementations: Record<string, unknown> = {
  ...attestationV1,
  ...batchV1,
  ...publicationV1,
  ...attestationV2,
  ...registrationV1,
};

const root = resolve(import.meta.dirname, "..");
const read = (path: string) => readFileSync(resolve(root, path), "utf8");

describe("Strict V2 public boundary", () => {
  it("exports only the bounded V2 evidence and compatibility contracts", () => {
    expect(Object.keys(publicApi).sort()).toEqual([
      "AI_HARNESS_CORE_CONTRACTS_ACCEPTED",
      "AI_HARNESS_DECISION_V2_SCHEMA_SHA256",
      "AI_HARNESS_DECISION_V2_SCHEMA_SHA256_ACCEPTED",
      "AI_HARNESS_ORGANIZATION_EVIDENCE_ENVELOPE_V1_SCHEMA_SHA256",
      "AI_HARNESS_STRICT_V2_COMMIT",
      "AI_HARNESS_STRICT_V2_COMMIT_ACCEPTED",
      "BASELINE_ANALYZERS_V1",
      "SCAN_RESULT_RECORD_FORMAT_V1",
      "SCAN_RESULT_RECORD_VERSION_V1",
      "SCAN_RESULT_SUBJECT_NAME_V1",
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
      "coreOrganizationEvidenceEnvelopeDigestV1",
      "createBaselineVetDiscoveryV1",
      "createBaselineVetPublicationV1",
      "createBaselineVetRequestV1",
      "createDetectorRegistrationV1",
      "createScanCandidateV2",
      "ed25519KeyIdV2",
      "isVerifiedScanAttestationV2",
      // Workstream D: Scan owns detector execution, so the capability record, the
      // production runner and the findings reader are part of the public boundary.
      "listDetectorCapabilitiesV1",
      "parseBaselineVetAttestationEnvelopeV1Json",
      "parseBaselineVetDiscoveryV1Json",
      "parseBaselineVetPublicationV1Json",
      "parseBaselineVetReceiptV1Json",
      "parseBaselineVetRequestV1Json",
      "parseDetectorRegistrationV1Json",
      "parseScanAttestationEnvelopeV2Json",
      "parseScanCandidateV2Json",
      "parseScanResultRecordV1",
      "probeDetectorAvailabilityV1",
      "projectVerifiedScanAttestationToCoreEvidenceEnvelopeV1",
      "readBaselineVetBundleV1",
      "readScanCaptureBundleV2",
      "readScanFindingsV1",
      "readScanResultRecordV1",
      "readScanResultSubjectBindingV1",
      "resolveBaselineVetDiscoveryV1",
      "resolveDetectorCapabilityV1",
      "resolveDetectorExecutionProfileDocumentV1",
      "runCiscoShardV1",
      "runDetectorV1",
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

  it("deprecates exactly the retired producers and serialization helpers and describes the legacy root", () => {
    const deprecatedIn = (path: string) => {
      const source = read(path);
      const names = [
        ...source.matchAll(/\/\*\*\n \* @deprecated[\s\S]*?\*\/\nexport const (\w+)/g),
      ].map((match) => match[1] ?? "");
      expect(source.match(/export /g)).toHaveLength(names.length);
      return names.sort();
    };
    const producers = deprecatedIn("src/legacy-root/baseline-production-v1.ts");
    expect(producers).toEqual([
      "BASELINE_ANALYZERS_V1",
      "canonicalBaselineVetAttestationEnvelopeV1Bytes",
      "canonicalBaselineVetDiscoveryV1Bytes",
      "canonicalBaselineVetPublicationV1Bytes",
      "canonicalBaselineVetReceiptV1Bytes",
      "canonicalBaselineVetRequestV1Bytes",
      "createBaselineVetDiscoveryV1",
      "createBaselineVetPublicationV1",
      "createBaselineVetRequestV1",
      "signBaselineVetBundleV1",
    ]);
    const helpers = deprecatedIn("src/legacy-root/serialization-helpers-v2.ts");
    expect(helpers).toEqual([
      "assertCompleteScanAnnexArtifactsV2",
      "canonicalDetectorRegistrationV1Bytes",
      "canonicalDssePaeV2",
      "canonicalScanAttestationEnvelopeBytesV2",
      "canonicalScanCandidateBytesV2",
      "canonicalSourceSealsV2Bytes",
      "ed25519KeyIdV2",
      "isVerifiedScanAttestationV2",
    ]);
    const deprecated = [...producers, ...helpers].sort();
    // Same bindings, not copies: deprecation changes no behavior.
    const rootValues: Record<string, unknown> = { ...publicApi };
    for (const name of deprecated) expect(rootValues[name]).toBe(legacyImplementations[name]);
    expect(
      contractSupport.entries.filter((entry) => entry.status === "current").map((e) => e.export),
    ).toEqual(["@aihq/scan/contracts", "@aihq/scan/read", "@aihq/scan/host"]);
    const rootEntry = contractSupport.entries.find((entry) => entry.export === "@aihq/scan");
    expect(rootEntry?.status).toBe("compatibility-only");
    const operations =
      (rootEntry && "operations" in rootEntry ? rootEntry.operations : undefined) ?? [];
    const runtimeExports = Object.keys(publicApi).sort();
    // The descriptor classifies every root runtime export exactly once, and its
    // deprecated groups are exactly the names whose declarations are deprecated.
    const described = operations.flatMap((operation) => operation.exports);
    expect([...described].sort()).toEqual(runtimeExports);
    expect(
      operations
        .filter((operation) => operation.status === "deprecated")
        .flatMap((operation) => operation.exports)
        .sort(),
    ).toEqual(deprecated);
    // The README legacy-root table states the same classification, row for row.
    const readme = read("README.md");
    const header = "| Group | Status | Root exports | Use instead for new work |";
    const tableStart = readme.indexOf(header);
    expect(tableStart).toBeGreaterThan(-1);
    const rows = readme
      .slice(tableStart)
      .split("\n\n")[0]
      ?.split("\n")
      .slice(2)
      .map((row) => {
        const [group, status, exportsCell] = row.split(" | ").map((cell) => cell.trim());
        const values = (exportsCell ?? "").split("; type")[0] ?? "";
        return {
          group: group?.replace(/^\| /, "").replaceAll("`", ""),
          status: status?.replaceAll("*", ""),
          exports: [...values.matchAll(/`(\w+)`/g)].map((match) => match[1]).sort(),
        };
      });
    expect(rows).toEqual(
      operations.map((operation) => ({
        group: operation.group,
        status: operation.status,
        exports: [...operation.exports].sort(),
      })),
    );
    const tabled = (rows ?? []).flatMap((row) => row.exports);
    expect(tabled.sort()).toEqual(runtimeExports);
  });

  it("makes the 0.x package boundary explicit without treating source as publication evidence", () => {
    const manifest = JSON.parse(read("package.json")) as Record<string, unknown>;
    expect(manifest.name).toBe("@aihq/scan");
    expect(manifest.version).toBe("0.5.0");
    expect(manifest.private).toBeUndefined();
    expect(manifest.bin).toEqual({ "aih-scan": "./dist/cli.js" });
    expect(manifest.exports).toEqual({
      ".": { types: "./dist/index.d.ts", import: "./dist/index.js" },
      "./contracts": {
        types: "./dist/public/contracts.d.ts",
        import: "./dist/public/contracts.js",
      },
      "./read": { types: "./dist/public/read.d.ts", import: "./dist/public/read.js" },
      "./host": { types: "./dist/public/host.d.ts", import: "./dist/public/host.js" },
      "./schemas/request/1.0.0.json": "./schemas/request/1.0.0.json",
      "./schemas/run-result/1.0.0.json": "./schemas/run-result/1.0.0.json",
      "./schemas/report/1.0.0.json": "./schemas/report/1.0.0.json",
      "./schemas/artifact/1.0.0.json": "./schemas/artifact/1.0.0.json",
      "./schemas/evidence-association/1.0.0.json": "./schemas/evidence-association/1.0.0.json",
      "./schemas/material-change/1.0.0.json": "./schemas/material-change/1.0.0.json",
      "./schemas/detector-definition/1.0.0.json": "./schemas/detector-definition/1.0.0.json",
      "./schemas/examples/1.0.0.json": "./schemas/examples/1.0.0.json",
      // Additive and idiomatic: a consumer can locate the package root without deep
      // importing anything. No dist subpath becomes reachable.
      "./package.json": "./package.json",
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
