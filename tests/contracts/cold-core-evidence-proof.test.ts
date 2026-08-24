import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "..", "..");
const read = (path: string) => readFileSync(resolve(root, path), "utf8");

describe("packed Core evidence proof", () => {
  it("requires an exact clean Core checkout and runs only packed artifacts in disposable roots", () => {
    const source = read("tools/verify-cold-core-evidence.mjs");
    expect(source).toContain("AIH_SCAN_CORE_SOURCE");
    expect(source).toContain("e53fe219002515c092ebb68c5b91c91a2fc6110d");
    expect(source).toContain("git");
    expect(source).toContain("status");
    expect(source).toContain("npm");
    expect(source).toContain("pack");
    expect(source).toContain("--ignore-scripts");
    expect(source).toContain("project-core-evidence");
    expect(source).toContain("policy");
    expect(source).toContain("resolve");
    expect(source).toContain("authority-unverified");
    expect(source).toContain("createRequire");
    expect(source).toContain("schemaCompatible: true");
    expect(source).toContain("parser; without genuine V3 authority");
    expect(source).not.toContain("parseOrganizationEvidenceEnvelopeV1Bytes");
    expect(source).not.toMatch(/ai-harness.*(?:src|dist)\//i);
    expect(source).not.toMatch(/\b(?:gh|docker|curl|fetch|npm publish|createRelease|git tag)\b/i);
  });
});
