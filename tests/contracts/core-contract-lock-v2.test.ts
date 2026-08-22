import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  AI_HARNESS_DECISION_V2_SCHEMA_SHA256,
  AI_HARNESS_STRICT_V2_COMMIT,
  verifyAiHarnessStrictV2Contract,
  verifyCoreDecisionSchemaLockV2,
} from "../../src/core/core-contract-lock-v2.js";

const repositoryRoot = resolve(import.meta.dirname, "..", "..");
const ciWorkflow = () =>
  readFileSync(resolve(repositoryRoot, ".github", "workflows", "ci.yml"), "utf8");

describe("Core Strict V2 compatibility lock", () => {
  it("accepts only the exact Core commit and decision schema bytes", () => {
    const bytes = Buffer.from('{"strict":"core-schema"}', "utf8");
    const digest = createHash("sha256").update(bytes).digest("hex");
    expect(AI_HARNESS_STRICT_V2_COMMIT).toBe("e27a55dcebb635c8298aa4fd6fd871f59089bcf7");
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

  it("keeps the pinned Core checkout outside the scanner lint root", () => {
    const workflow = ciWorkflow();
    expect(workflow).toContain("path: $" + "{{ runner.temp }}/aih-core-contract");
    expect(workflow).toContain(
      'node tools/verify-core-contract-lock-v2.mjs --core-root "$' +
        '{{ runner.temp }}/aih-core-contract"',
    );
    expect(workflow).not.toContain("path: .core-contract");
    expect(workflow).not.toContain("--core-root .core-contract");
  });
});
