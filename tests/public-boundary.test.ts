import { existsSync, readdirSync, readFileSync } from "node:fs";
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
const ociLayoutSource = resolve(root, "src", "cisco", "oci-layout-v1.ts");
const ociBrokerSource = resolve(root, "src", "cisco", "oci-broker-v1.ts");

describe("dormant contract public boundary", () => {
  it("keeps the package root empty and prevents public/runtime AIH trust cutover", () => {
    expect(read("src/index.ts").trim()).toBe("export {};");
    const sources = sourceFiles();
    expect(sources).toContain(resolve(root, "src", "index.ts"));
    expect(existsSync(ociLayoutSource)).toBe(true);
    expect(existsSync(ociBrokerSource)).toBe(true);
    for (const source of sources) {
      const text = readFileSync(source, "utf8");
      const restrictedText =
        source === ociBrokerSource
          ? (() => {
              expect(text.match(/--pull=never/g)).toHaveLength(1);
              return text.replace("--pull=never", "");
            })()
          : text;
      expect(text).not.toMatch(/ai-harness|src\/trust|from\s+["'][^"']*trust|normalization-v1/i);
      expect(restrictedText).not.toMatch(
        /\b(PASS|verdict|acknowledg|acceptance|suppression|portable authority|podman|pull|verify-signature|trusted-root)\b/i,
      );
      if (source !== ociBrokerSource)
        expect(text).not.toMatch(/\b(docker|broker(?:execute|verify|enforce))\b/i);
    }
  });

  it("contains no CLI, config, scanner execution, broker verification, or production Cisco identity", () => {
    const publicFiles = ["package.json", "src/index.ts"];
    for (const file of publicFiles)
      expect(read(file)).not.toMatch(
        /\b(bin|cisco-ai-skill-scanner|cisco|docker|podman|verify-signature|oci-(?:layout|broker)-v1)\b/i,
      );
  });
});
