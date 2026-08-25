import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  AI_HARNESS_DECISION_V2_SCHEMA_SHA256,
  AI_HARNESS_ORGANIZATION_EVIDENCE_ENVELOPE_V1_SCHEMA_SHA256,
  AI_HARNESS_STRICT_V2_COMMIT,
  verifyAiHarnessCoreEvidenceContractV1,
  verifyAiHarnessStrictV2Contract,
  verifyCoreDecisionSchemaLockV2,
  verifyCoreOrganizationEvidenceEnvelopeSchemaLockV1,
} from "../../src/core/core-contract-lock-v2.js";

const repositoryRoot = resolve(import.meta.dirname, "..", "..");
const ciWorkflow = () =>
  readFileSync(resolve(repositoryRoot, ".github", "workflows", "ci.yml"), "utf8");
const lockVerifier = () =>
  readFileSync(resolve(repositoryRoot, "tools", "verify-core-contract-lock-v2.mjs"), "utf8");

describe("Core Strict V2 compatibility lock", () => {
  it("locks the current exact Core commit and both Core schema bytes", () => {
    const bytes = Buffer.from('{"strict":"core-schema"}', "utf8");
    const digest = createHash("sha256").update(bytes).digest("hex");
    expect(AI_HARNESS_STRICT_V2_COMMIT).toBe("74ddf3439df47a947a6f7a022515099602702ac8");
    expect(AI_HARNESS_DECISION_V2_SCHEMA_SHA256).toBe(
      "27295aee8d8be333abe2c73adc72884b534b1c9980a9b7a39d12be8d34c5caff",
    );
    expect(() =>
      verifyCoreDecisionSchemaLockV2({
        coreCommit: AI_HARNESS_STRICT_V2_COMMIT,
        schemaBytes: bytes,
        expectedSchemaSha256: digest,
      }),
    ).not.toThrow();
    expect(AI_HARNESS_ORGANIZATION_EVIDENCE_ENVELOPE_V1_SCHEMA_SHA256).toBe(
      "88c0a36e9177201660e773351958d89059c7d5b54e1c437d0afd06f48c5288bc",
    );
  });

  it("fails closed for unknown, old, mismatched, or hostile organization evidence schema bytes", () => {
    const decisionBytes = Buffer.from('{"decision":"core-schema"}', "utf8");
    const organizationBytes = Buffer.from('{"organization":"core-schema"}', "utf8");
    const input = {
      coreCommit: AI_HARNESS_STRICT_V2_COMMIT,
      decisionSchemaBytes: decisionBytes,
      organizationEvidenceEnvelopeSchemaBytes: organizationBytes,
    };
    expect(() =>
      verifyCoreOrganizationEvidenceEnvelopeSchemaLockV1({
        coreCommit: input.coreCommit,
        schemaBytes: organizationBytes,
        expectedSchemaSha256: AI_HARNESS_ORGANIZATION_EVIDENCE_ENVELOPE_V1_SCHEMA_SHA256,
      }),
    ).toThrow();
    expect(() => verifyAiHarnessCoreEvidenceContractV1(input)).toThrow();
    const hiddenExtra = {
      coreCommit: AI_HARNESS_STRICT_V2_COMMIT,
      schemaBytes: organizationBytes,
      expectedSchemaSha256: AI_HARNESS_ORGANIZATION_EVIDENCE_ENVELOPE_V1_SCHEMA_SHA256,
    } as Record<string, unknown>;
    Object.defineProperty(hiddenExtra, "unexpected", { value: true });
    expect(() => verifyCoreOrganizationEvidenceEnvelopeSchemaLockV1(hiddenExtra)).toThrow();
    expect(() =>
      verifyCoreOrganizationEvidenceEnvelopeSchemaLockV1({
        coreCommit: "0".repeat(40),
        schemaBytes: Buffer.from("{}", "utf8"),
        expectedSchemaSha256: AI_HARNESS_ORGANIZATION_EVIDENCE_ENVELOPE_V1_SCHEMA_SHA256,
      }),
    ).toThrow();
  });

  it("fails closed for drifted commit, schema path, digest, or hostile input", () => {
    const bytes = Buffer.from("{}", "utf8");
    const good = {
      coreCommit: AI_HARNESS_STRICT_V2_COMMIT,
      schemaBytes: bytes,
      expectedSchemaSha256: createHash("sha256").update(bytes).digest("hex"),
    };
    expect(() => verifyCoreDecisionSchemaLockV2({ ...good, coreCommit: "0".repeat(40) })).toThrow();
    expect(() =>
      verifyCoreDecisionSchemaLockV2({ ...good, schemaBytes: Buffer.from("[]") }),
    ).toThrow();
    expect(() =>
      verifyCoreDecisionSchemaLockV2({ ...good, expectedSchemaSha256: "0".repeat(64) }),
    ).toThrow();
    expect(() => verifyCoreDecisionSchemaLockV2({ ...good, unexpected: true })).toThrow();
    expect(() =>
      verifyAiHarnessStrictV2Contract({
        coreCommit: AI_HARNESS_STRICT_V2_COMMIT,
        schemaBytes: bytes,
      }),
    ).toThrow();
  });

  it("verifies and removes the exact Core checkout before scanner checks", () => {
    const workflow = ciWorkflow();
    expect(workflow).toContain(`ref: ${AI_HARNESS_STRICT_V2_COMMIT}`);
    expect(workflow).toContain("path: .core-contract");
    const verifier = "node tools/verify-core-contract-lock-v2.mjs --core-root .core-contract";
    expect(workflow).toContain(verifier);
    const verifierSource = lockVerifier();
    expect(verifierSource).toContain('name: "@aihq/core"');
    expect(verifierSource).toContain('version: "0.1.0"');
    expect(verifierSource).toContain(
      "af64feda4e3e57808e1a262e15a5cb8f41581f77e8f9b49eb9b459317b803ecd",
    );
    expect(verifierSource).toContain("packageManifest.name !== packageIdentity.name");
    expect(verifierSource).toContain("packageManifest.version !== packageIdentity.version");
    expect(verifierSource).toContain("packageManifest.private === true");
    expect(verifierSource).toContain("schemas/aih-organization-evidence-envelope-v1.schema.json");
    expect(verifierSource).toContain(AI_HARNESS_ORGANIZATION_EVIDENCE_ENVELOPE_V1_SCHEMA_SHA256);
    const verifierIndex = workflow.indexOf(verifier);
    const packedProof = "npm run verify:cold-core-evidence";
    const packedProofIndex = workflow.indexOf(packedProof);
    const cleanupIndex = workflow.indexOf("name: Remove exact Core contract checkout");
    expect(verifierIndex).toBeGreaterThanOrEqual(0);
    expect(packedProofIndex).toBeGreaterThan(verifierIndex);
    expect(workflow).toContain("AIH_SCAN_CORE_SOURCE: $" + "{{ github.workspace }}/.core-contract");
    expect(cleanupIndex).toBeGreaterThan(verifierIndex);
    expect(cleanupIndex).toBeGreaterThan(packedProofIndex);
    const cleanupEnd = workflow.indexOf("- run: npm run typecheck", cleanupIndex);
    expect(cleanupEnd).toBeGreaterThan(cleanupIndex);
    const cleanup = workflow.slice(cleanupIndex, cleanupEnd);
    expect(cleanup).toContain('core_root="$GITHUB_WORKSPACE/.core-contract"');
    expect(cleanup).toContain('rm -rf -- "$core_root"');
    expect(cleanup).toContain('test ! -e "$core_root"');
    expect(cleanup).not.toMatch(/[?*]/);
    for (const check of [
      "npm run typecheck",
      "npm run lint",
      "npm run test:cov",
      "npm run build",
    ]) {
      expect(workflow.indexOf(check)).toBeGreaterThan(cleanupIndex);
    }
  });
});
