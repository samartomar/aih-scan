import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "..");
const read = (path: string) => readFileSync(resolve(root, path), "utf8");
const sourceFiles = (path = resolve(root, "src")): string[] =>
  readdirSync(path, { withFileTypes: true }).flatMap((entry) => {
    const next = resolve(path, entry.name);
    return entry.isDirectory()
      ? sourceFiles(next)
      : entry.isFile() && entry.name.endsWith(".ts")
        ? [next]
        : [];
  });

describe("dormant contract public boundary", () => {
  it("keeps the package root empty and prevents public/runtime AIH trust cutover", () => {
    expect(read("src/index.ts").trim()).toBe("export {};");
    expect(sourceFiles()).toContain(resolve(root, "src", "index.ts"));
    for (const source of sourceFiles()) {
      const text = readFileSync(source, "utf8");
      expect(text).not.toMatch(/ai-harness|src\/trust|from\s+["'][^"']*trust|normalization-v1/i);
      expect(text).not.toMatch(
        /\b(PASS|verdict|acknowledg|acceptance|suppression|portable authority|docker|podman|pull|broker(?:execute|verify|enforce)|verify-signature|trusted-root)\b/i,
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
