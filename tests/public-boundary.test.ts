import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "..");
const read = (path: string) => readFileSync(resolve(root, path), "utf8");

describe("dormant contract public boundary", () => {
  it("keeps the package root empty and prevents public/runtime AIH trust cutover", () => {
    expect(read("src/index.ts").trim()).toBe("export {};");
    const sources = [
      "src/contract/strict-json-v1.ts",
      "src/observation/native-observation-v1.ts",
      "src/observation/observation-evidence-v1.ts",
      "src/observation/scanner-manifest-v1.ts",
      "src/observation/scan-attestation-v1.ts",
      "src/cisco/facts-only-v1.ts",
    ];
    for (const source of sources) {
      if (!existsSync(resolve(root, source))) continue;
      const text = read(source);
      expect(text).not.toMatch(/ai-harness|src\/trust|from\s+["'][^"']*trust/);
      expect(text).not.toMatch(
        /\b(PASS|verdict|acknowledg|acceptance|suppression|portable authority)\b/i,
      );
    }
  });

  it("contains no CLI, config, scanner execution, broker verification, or production Cisco identity", () => {
    const publicFiles = ["package.json", "src/index.ts"];
    for (const file of publicFiles)
      expect(read(file)).not.toMatch(
        /\b(bin|cisco-ai-skill-scanner|docker|podman|verify-signature)\b/i,
      );
  });
});
