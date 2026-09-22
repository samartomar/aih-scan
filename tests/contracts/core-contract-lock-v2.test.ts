import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  AI_HARNESS_DECISION_V2_SCHEMA_SHA256,
  AI_HARNESS_DECISION_V2_SCHEMA_SHA256_ACCEPTED,
  AI_HARNESS_ORGANIZATION_EVIDENCE_ENVELOPE_V1_SCHEMA_SHA256,
  AI_HARNESS_STRICT_V2_COMMIT,
  AI_HARNESS_STRICT_V2_COMMIT_ACCEPTED,
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

const OLD_COMMIT = "6130dd837b8e8bd41e999fb40733e0e460e69720";
const NEW_COMMIT = "c31741602b3dbd5f228dafe00591e5679c782878";
const OLD_DIGEST = "27295aee8d8be333abe2c73adc72884b534b1c9980a9b7a39d12be8d34c5caff";
const NEW_DIGEST = "7fdf101568cd7caa28516d0be37704c0dfd51198bc54d41d65829abbe77547cc";
const THIRD_COMMIT = "0".repeat(40);
const THIRD_DIGEST = "f".repeat(64);

describe("Core Strict V2 compatibility lock", () => {
  it("declares an accepted set whose newest member is the default emitted value", () => {
    expect(AI_HARNESS_STRICT_V2_COMMIT_ACCEPTED).toEqual([OLD_COMMIT, NEW_COMMIT]);
    expect(AI_HARNESS_DECISION_V2_SCHEMA_SHA256_ACCEPTED).toEqual([OLD_DIGEST, NEW_DIGEST]);
    // Newest last, and the singular exports stay the values a fresh candidate declares.
    expect(AI_HARNESS_STRICT_V2_COMMIT).toBe(NEW_COMMIT);
    expect(AI_HARNESS_DECISION_V2_SCHEMA_SHA256).toBe(NEW_DIGEST);
    expect(AI_HARNESS_STRICT_V2_COMMIT).toBe(AI_HARNESS_STRICT_V2_COMMIT_ACCEPTED.at(-1));
    expect(AI_HARNESS_DECISION_V2_SCHEMA_SHA256).toBe(
      AI_HARNESS_DECISION_V2_SCHEMA_SHA256_ACCEPTED.at(-1),
    );
    expect(AI_HARNESS_ORGANIZATION_EVIDENCE_ENVELOPE_V1_SCHEMA_SHA256).toBe(
      "88c0a36e9177201660e773351958d89059c7d5b54e1c437d0afd06f48c5288bc",
    );
  });

  it("accepts every declared commit and digest, and refuses a third of either", () => {
    // Each accepted digest is reached with bytes that genuinely hash to it, so the
    // membership check and the byte check are exercised independently.
    for (const digest of AI_HARNESS_DECISION_V2_SCHEMA_SHA256_ACCEPTED) {
      for (const commit of AI_HARNESS_STRICT_V2_COMMIT_ACCEPTED) {
        expect(() =>
          verifyCoreDecisionSchemaLockV2({
            coreCommit: commit,
            schemaBytes: Buffer.from("{}", "utf8"),
            expectedSchemaSha256: digest,
          }),
        ).toThrow(/schema digest mismatch/);
      }
    }
    expect(() =>
      verifyCoreDecisionSchemaLockV2({
        coreCommit: THIRD_COMMIT,
        schemaBytes: Buffer.from("{}", "utf8"),
        expectedSchemaSha256: NEW_DIGEST,
      }),
    ).toThrow(/unexpected Core commit/);
    expect(() =>
      verifyCoreDecisionSchemaLockV2({
        coreCommit: NEW_COMMIT,
        schemaBytes: Buffer.from("{}", "utf8"),
        expectedSchemaSha256: THIRD_DIGEST,
      }),
    ).toThrow(/schema digest mismatch/);
  });

  it("observes the digest from the supplied bytes rather than letting a caller pick one", () => {
    const bytes = Buffer.from("{}", "utf8");
    expect(() =>
      verifyAiHarnessStrictV2Contract({ coreCommit: NEW_COMMIT, schemaBytes: bytes }),
    ).toThrow(/schema digest mismatch/);
    expect(() =>
      verifyAiHarnessStrictV2Contract({ coreCommit: THIRD_COMMIT, schemaBytes: bytes }),
    ).toThrow(/unexpected Core commit/);
    expect(() => verifyAiHarnessStrictV2Contract({ coreCommit: NEW_COMMIT })).toThrow(
      /input fields/,
    );
    expect(() =>
      verifyAiHarnessStrictV2Contract({
        coreCommit: NEW_COMMIT,
        schemaBytes: "not bytes",
      }),
    ).toThrow(/input values/);
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
    // The envelope schema is byte-identical at every accepted commit, so its digest
    // stays a single pinned value while the commit becomes a membership check.
    for (const commit of AI_HARNESS_STRICT_V2_COMMIT_ACCEPTED) {
      expect(() =>
        verifyCoreOrganizationEvidenceEnvelopeSchemaLockV1({
          coreCommit: commit,
          schemaBytes: Buffer.from("{}", "utf8"),
          expectedSchemaSha256: AI_HARNESS_ORGANIZATION_EVIDENCE_ENVELOPE_V1_SCHEMA_SHA256,
        }),
      ).toThrow(/schema digest mismatch/);
    }
    expect(() =>
      verifyCoreOrganizationEvidenceEnvelopeSchemaLockV1({
        coreCommit: THIRD_COMMIT,
        schemaBytes: Buffer.from("{}", "utf8"),
        expectedSchemaSha256: AI_HARNESS_ORGANIZATION_EVIDENCE_ENVELOPE_V1_SCHEMA_SHA256,
      }),
    ).toThrow(/unexpected Core commit/);
    expect(() =>
      verifyCoreOrganizationEvidenceEnvelopeSchemaLockV1({
        coreCommit: NEW_COMMIT,
        schemaBytes: Buffer.from("{}", "utf8"),
        expectedSchemaSha256: THIRD_DIGEST,
      }),
    ).toThrow(/unexpected organization evidence schema digest/);
  });

  it("fails closed for drifted commit, schema path, digest, or hostile input", () => {
    const bytes = Buffer.from("{}", "utf8");
    const good = {
      coreCommit: AI_HARNESS_STRICT_V2_COMMIT,
      schemaBytes: bytes,
      expectedSchemaSha256: createHash("sha256").update(bytes).digest("hex"),
    };
    expect(() => verifyCoreDecisionSchemaLockV2({ ...good, coreCommit: THIRD_COMMIT })).toThrow();
    expect(() =>
      verifyCoreDecisionSchemaLockV2({ ...good, schemaBytes: Buffer.from("[]") }),
    ).toThrow();
    expect(() =>
      verifyCoreDecisionSchemaLockV2({ ...good, expectedSchemaSha256: THIRD_DIGEST }),
    ).toThrow();
    expect(() => verifyCoreDecisionSchemaLockV2({ ...good, unexpected: true })).toThrow();
    expect(() =>
      verifyAiHarnessStrictV2Contract({
        coreCommit: AI_HARNESS_STRICT_V2_COMMIT,
        schemaBytes: bytes,
      }),
    ).toThrow();
  });

  it("verifies the newest accepted Core and removes every Core checkout before scanner checks", () => {
    const workflow = ciWorkflow();
    expect(workflow).toContain(
      "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0",
    );
    expect(workflow).toContain("node-version: 20");
    expect(workflow).toContain("cache: npm");
    expect(workflow).toContain(
      "astral-sh/setup-uv@bec219d24cd3e171d82865faccec33120bb574f4 # v10.1.0",
    );
    expect(workflow).toContain('version: "0.12.13"');
    // The contract gate runs against the newest accepted Core commit.
    expect(workflow).toContain(`ref: ${AI_HARNESS_STRICT_V2_COMMIT}`);
    expect(workflow).toContain("path: .core-contract");
    // The packed-evidence gate keeps its own checkout at the Core package it pins, which
    // must still be a member of the accepted set.
    expect(workflow).toContain("path: .core-cold-evidence");
    const coldEvidenceRef = /ref: ([0-9a-f]{40})\n\s+path: \.core-cold-evidence/u.exec(workflow);
    expect(coldEvidenceRef?.[1]).toBeDefined();
    expect(AI_HARNESS_STRICT_V2_COMMIT_ACCEPTED).toContain(coldEvidenceRef?.[1]);
    expect(lockVerifier()).toContain(coldEvidenceRef?.[1] ?? "unmatched");

    const verifier = "node tools/verify-core-contract-lock-v2.mjs --core-root .core-contract";
    expect(workflow).toContain(verifier);
    const verifierSource = lockVerifier();
    // The contract is the schema bytes; Core's package version is recorded, not required.
    expect(verifierSource).toContain('const corePackageName = "@aihq/core";');
    expect(verifierSource).not.toContain('version: "0.1.1"');
    expect(verifierSource).not.toContain("packageManifest.version !== packageIdentity.version");
    expect(verifierSource).toContain("args.expectedCoreVersion !== undefined");
    expect(verifierSource).toContain("packageManifest.private === true");
    expect(verifierSource).toContain("schemas/aih-organization-evidence-envelope-v1.schema.json");
    expect(verifierSource).toContain(AI_HARNESS_ORGANIZATION_EVIDENCE_ENVELOPE_V1_SCHEMA_SHA256);
    for (const commit of AI_HARNESS_STRICT_V2_COMMIT_ACCEPTED)
      expect(verifierSource).toContain(commit);
    for (const digest of AI_HARNESS_DECISION_V2_SCHEMA_SHA256_ACCEPTED)
      expect(verifierSource).toContain(digest);

    const verifierIndex = workflow.indexOf(verifier);
    const packedProof = "npm run verify:cold-core-evidence";
    const packedProofIndex = workflow.indexOf(packedProof);
    const cleanupIndex = workflow.indexOf("name: Remove exact Core contract checkout");
    expect(verifierIndex).toBeGreaterThanOrEqual(0);
    expect(packedProofIndex).toBeGreaterThan(verifierIndex);
    expect(workflow).toContain(
      "AIH_SCAN_CORE_SOURCE: $" + "{{ github.workspace }}/.core-cold-evidence",
    );
    expect(cleanupIndex).toBeGreaterThan(verifierIndex);
    expect(cleanupIndex).toBeGreaterThan(packedProofIndex);
    const cleanupEnd = workflow.indexOf("- run: npm run typecheck", cleanupIndex);
    expect(cleanupEnd).toBeGreaterThan(cleanupIndex);
    const cleanup = workflow.slice(cleanupIndex, cleanupEnd);
    expect(cleanup).toContain('"$GITHUB_WORKSPACE/.core-contract"');
    expect(cleanup).toContain('"$GITHUB_WORKSPACE/.core-cold-evidence"');
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
