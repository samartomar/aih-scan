import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "..", "..");
const read = (path: string) => readFileSync(resolve(root, path), "utf8");

describe("packed Core evidence proof", () => {
  it("requires an exact clean Core checkout and proves protected-file custody from packed UI", () => {
    const source = read("tools/verify-cold-core-evidence.mjs");
    expect(source).toContain("AIH_SCAN_CORE_SOURCE");
    expect(source).toContain("6130dd837b8e8bd41e999fb40733e0e460e69720");
    expect(source).toContain('"@aihq/core"');
    expect(source).toContain('version: "0.1.1"');
    expect(source).toContain('version: "0.4.0"');
    expect(source).toContain('filename: "aihq-scan-0.4.0.tgz"');
    expect(source).toContain('"@aihq/core"');
    expect(source).not.toContain('"@aihq/harness"');
    expect(source).toContain("git");
    expect(source).toContain("status");
    expect(source).toContain("npm");
    expect(source).toContain("pack");
    expect(source).toContain("--ignore-scripts");
    expect(source).toContain("project-core-evidence");
    expect(source).toContain('"generate", "--apply", "--out"');
    expect(source).toContain("authorProtectedPolicyViaPackedWorkbench");
    expect(source).toContain("AIH_ORG_POLICY: policyPath");
    expect(source).toContain("policy");
    expect(source).toContain("resolve");
    expect(source).toContain("authority-unverified");
    expect(source).toContain("organization-qualified");
    expect(source).toContain("observation-missing");
    expect(source).toContain("createRequire");
    expect(source).toContain("schemaCompatible: true");
    expect(source).toContain("workbenchGenerated: true");
    expect(source).not.toMatch(/ai-harness.*(?:src|dist)\//i);
    expect(source).not.toMatch(/\b(?:gh|docker|curl|fetch|npm publish|createRelease|git tag)\b/i);
  });

  it("drives the protected policy form without exposing editable raw JSON", () => {
    const source = read("tools/lib/author-protected-policy-via-workbench.mjs");
    expect(source).toContain('querySelectorAll("textarea:not([readonly])")');
    expect(source).toContain("packed-workbench-raw-json-authoring-exposed");
    expect(source).toContain("download-protected-bundle");
    expect(source).toContain("aih-policy-bundle.json");
  });

  it("distinguishes the exact Core compatibility lock from public Core 0.2.0", () => {
    for (const path of ["README.md", "ai-coding/project.md"]) {
      const documentation = read(path);
      expect(documentation).toContain("6130dd837b8e8bd41e999fb40733e0e460e69720");
      expect(documentation).toContain("0d63a9853bd51072a5108eee21013d5fb8a8472b");
      expect(documentation).toMatch(/post-`0\.1\.1` compatibility fixture/u);
    }
  });
});
