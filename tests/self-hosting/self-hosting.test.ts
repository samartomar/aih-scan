import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../..");
const read = (path: string): string =>
  readFileSync(resolve(root, path), "utf8").replace(/\r\n/g, "\n");
const boundary = "Never run an installed aih-scan against this checkout.";

function managedBody(text: string): string {
  const match = text.match(
    /<!-- BEGIN aih-scan-canonical:shared -->\n\n([\s\S]*?)\n\n<!-- END aih-scan-canonical:shared -->/,
  );
  if (match?.[1] === undefined) throw new Error("missing aih-scan shared canon block");
  return match[1].trim();
}

describe("aih-scan self-hosting boundary", () => {
  it("states the no-self-application boundary on each always-loaded surface", () => {
    for (const path of [
      "AGENTS.md",
      "CLAUDE.md",
      "ai-coding/RULE_ROUTER.md",
      "ai-coding/SELF-HOSTING.md",
      "ai-coding/rules/agent-behavior-core.md",
      "ai-coding/rules/repo-ai-tools.md",
    ]) {
      expect(read(path), path).toContain(boundary);
    }
  });

  it("keeps the Claude and Codex bootloaders byte-aligned with the shared canon", () => {
    const shared = read("ai-coding/adapters/_shared-canonical-block.md").trim();
    for (const path of ["AGENTS.md", "CLAUDE.md"])
      expect(managedBody(read(path)), path).toBe(shared);
  });

  it("keeps scanner product work out of the bootstrap and the canon manual", () => {
    const packageJson = read("package.json");
    expect(packageJson).not.toContain('"bin"');
    expect(packageJson).not.toContain("repo:publish");
    expect(read("ai-coding/SELF-HOSTING.md")).toContain("manual maintenance");
    expect(read("ai-coding/project.json")).toContain('"name": "aih-scan"');
  });
});
