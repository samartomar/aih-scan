import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  AI_HARNESS_CORE_CONTRACTS_ACCEPTED,
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
import {
  createScanCandidateV2,
  parseScanCandidateV2Json,
} from "../../src/observation/scan-attestation-v2.js";

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

/** Core's real decision-schema bytes at each accepted commit, copied byte for byte. */
const schemaBytes = (commit: string) =>
  readFileSync(
    resolve(
      repositoryRoot,
      "tests",
      "fixtures",
      "core",
      `aih-governance-decision-v2.${commit.slice(0, 8)}.schema.json`,
    ),
  );
const OLD_SCHEMA = () => schemaBytes(OLD_COMMIT);
const NEW_SCHEMA = () => schemaBytes(NEW_COMMIT);
/** The genuine capture candidate, which declares the older accepted pair. */
const genuineCandidateText = () =>
  readFileSync(
    resolve(repositoryRoot, "tests", "fixtures", "cisco", "genuine-oci-capture-candidate.json"),
    "utf8",
  );
const candidateDeclaring = (coreContract: { commit: string; decisionSchemaSha256: string }) => {
  const { candidateSha256: _digest, ...input } = JSON.parse(genuineCandidateText()) as Record<
    string,
    unknown
  >;
  return createScanCandidateV2({ ...input, coreContract });
};

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

  it("declares one frozen list of accepted pairs, from which both sets are derived", () => {
    expect(AI_HARNESS_CORE_CONTRACTS_ACCEPTED).toEqual([
      { commit: OLD_COMMIT, decisionSchemaSha256: OLD_DIGEST },
      { commit: NEW_COMMIT, decisionSchemaSha256: NEW_DIGEST },
    ]);
    expect(AI_HARNESS_STRICT_V2_COMMIT_ACCEPTED).toEqual(
      AI_HARNESS_CORE_CONTRACTS_ACCEPTED.map((contract) => contract.commit),
    );
    expect(AI_HARNESS_DECISION_V2_SCHEMA_SHA256_ACCEPTED).toEqual(
      AI_HARNESS_CORE_CONTRACTS_ACCEPTED.map((contract) => contract.decisionSchemaSha256),
    );
    // The default emitted pair is the newest accepted pair, not a mix of two.
    expect(AI_HARNESS_CORE_CONTRACTS_ACCEPTED.at(-1)).toEqual({
      commit: AI_HARNESS_STRICT_V2_COMMIT,
      decisionSchemaSha256: AI_HARNESS_DECISION_V2_SCHEMA_SHA256,
    });
    expect(Object.isFrozen(AI_HARNESS_CORE_CONTRACTS_ACCEPTED)).toBe(true);
    for (const contract of AI_HARNESS_CORE_CONTRACTS_ACCEPTED)
      expect(Object.isFrozen(contract), contract.commit).toBe(true);
  });

  it("freezes every exported accepted set, so no consumer can widen what Scan accepts", () => {
    for (const [name, accepted] of [
      ["AI_HARNESS_CORE_CONTRACTS_ACCEPTED", AI_HARNESS_CORE_CONTRACTS_ACCEPTED],
      ["AI_HARNESS_STRICT_V2_COMMIT_ACCEPTED", AI_HARNESS_STRICT_V2_COMMIT_ACCEPTED],
      [
        "AI_HARNESS_DECISION_V2_SCHEMA_SHA256_ACCEPTED",
        AI_HARNESS_DECISION_V2_SCHEMA_SHA256_ACCEPTED,
      ],
    ] as const) {
      expect(Object.isFrozen(accepted), name).toBe(true);
      expect(() => (accepted as unknown as unknown[]).push(THIRD_DIGEST), name).toThrow(TypeError);
    }
    expect(AI_HARNESS_STRICT_V2_COMMIT_ACCEPTED).toEqual([OLD_COMMIT, NEW_COMMIT]);
    expect(AI_HARNESS_DECISION_V2_SCHEMA_SHA256_ACCEPTED).toEqual([OLD_DIGEST, NEW_DIGEST]);
  });

  it("accepts every declared pair with Core's real schema bytes, and refuses a third of either", () => {
    // The fixtures are Core's own schema bytes at each accepted commit, so the positive
    // path is reached with bytes that genuinely hash to each accepted digest.
    expect(createHash("sha256").update(OLD_SCHEMA()).digest("hex")).toBe(OLD_DIGEST);
    expect(createHash("sha256").update(NEW_SCHEMA()).digest("hex")).toBe(NEW_DIGEST);
    for (const [commit, digest, bytes] of [
      [OLD_COMMIT, OLD_DIGEST, OLD_SCHEMA()],
      [NEW_COMMIT, NEW_DIGEST, NEW_SCHEMA()],
    ] as const) {
      expect(() =>
        verifyCoreDecisionSchemaLockV2({
          coreCommit: commit,
          schemaBytes: bytes,
          expectedSchemaSha256: digest,
        }),
      ).not.toThrow();
      expect(() =>
        verifyAiHarnessStrictV2Contract({ coreCommit: commit, schemaBytes: bytes }),
      ).not.toThrow();
      // Bytes that do not hash to the declared digest still fail.
      expect(() =>
        verifyCoreDecisionSchemaLockV2({
          coreCommit: commit,
          schemaBytes: Buffer.from("{}", "utf8"),
          expectedSchemaSha256: digest,
        }),
      ).toThrow(/schema digest mismatch/);
    }
    expect(() =>
      verifyCoreDecisionSchemaLockV2({
        coreCommit: THIRD_COMMIT,
        schemaBytes: NEW_SCHEMA(),
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

  it("refuses a mixed pair of accepted values in the lock and in a candidate", () => {
    // Each value alone is accepted; together they name a Core contract that never existed.
    for (const [commit, digest, bytes] of [
      [OLD_COMMIT, NEW_DIGEST, NEW_SCHEMA()],
      [NEW_COMMIT, OLD_DIGEST, OLD_SCHEMA()],
    ] as const) {
      expect(() =>
        verifyCoreDecisionSchemaLockV2({
          coreCommit: commit,
          schemaBytes: bytes,
          expectedSchemaSha256: digest,
        }),
      ).toThrow(/schema digest mismatch/);
      expect(() =>
        verifyAiHarnessStrictV2Contract({ coreCommit: commit, schemaBytes: bytes }),
      ).toThrow(/schema digest mismatch/);
      let refusal: unknown;
      try {
        candidateDeclaring({ commit, decisionSchemaSha256: digest });
      } catch (error) {
        refusal = error;
      }
      expect(refusal, commit).toBeDefined();
      const issues = (refusal as { issues?: { path: unknown[]; message: string }[] }).issues;
      expect(issues).toEqual([
        expect.objectContaining({
          path: ["coreContract"],
          message: "Core commit and decision-schema digest are not one accepted pair",
        }),
      ]);
    }
    // Both genuine pairs mint a candidate; the genuine capture still parses unchanged.
    expect(
      candidateDeclaring({ commit: OLD_COMMIT, decisionSchemaSha256: OLD_DIGEST }).coreContract,
    ).toEqual({ commit: OLD_COMMIT, decisionSchemaSha256: OLD_DIGEST });
    expect(
      candidateDeclaring({ commit: NEW_COMMIT, decisionSchemaSha256: NEW_DIGEST }).coreContract,
    ).toEqual({ commit: NEW_COMMIT, decisionSchemaSha256: NEW_DIGEST });
    expect(parseScanCandidateV2Json(genuineCandidateText()).candidateSha256).toBe(
      "b3f4a192b521ccd3af667dc5e1ef1c2317880473bb214483e2c514eda9b2ddd1",
    );
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
