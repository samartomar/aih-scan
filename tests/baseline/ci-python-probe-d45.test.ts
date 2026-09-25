import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

// Coordinator decision D45: Cisco 2.1.0 no longer skips a skill whose SKILL.md is `# Broken\n`;
// it scans it through its skill_loader fallback, which D30 accepts. Only invalid UTF-8, binary,
// oversized, missing-metadata and traversal inputs still hard-fail. The ci.yml Bubblewrap probe
// therefore proves partial coverage with invalid UTF-8 and proves the fallback in a third leg.
// Real Cisco runs only in CI and the container proofs; this pins the probe's text.

/** The ci.yml probe's node heredoc, YAML indentation removed (as U1l's extractor does). */
function ciProbe(): string {
  const lines = readFileSync(resolve(".github/workflows/ci.yml"), "utf8")
    .replace(/\r\n/gu, "\n")
    .split("\n");
  const start = lines.findIndex((line) => line.trim() === "node --input-type=module <<'NODE'");
  expect(start).toBeGreaterThanOrEqual(0);
  const indent = (lines[start] as string).length - (lines[start] as string).trimStart().length;
  const end = lines.findIndex((line, index) => index > start && line.trim() === "NODE");
  expect(end).toBeGreaterThan(start);
  return `${lines
    .slice(start + 1, end)
    .map((line) => line.slice(indent))
    .join("\n")}\n`;
}

describe("ci.yml Bubblewrap probe (D45)", () => {
  it("is one module node can parse", () => {
    const directory = mkdtempSync(join(tmpdir(), "aih-scan-ci-probe-"));
    try {
      writeFileSync(join(directory, "ci-probe.mjs"), ciProbe());
      const result = spawnSync(process.execPath, ["--check", join(directory, "ci-probe.mjs")], {
        encoding: "utf8",
      });
      expect(result.status, result.stderr).toBe(0);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("proves partial coverage with an invalid UTF-8 SKILL.md, still expecting 'skipped 1 skill'", () => {
    const probe = ciProbe();
    expect(probe).toContain(
      '  writeFileSync(join(sourceRoot, "skills", "broken", "SKILL.md"), Buffer.from([0x23, 0x20, 0x42, 0xff, 0x0a]));\n  let rejectedPartialCoverage = false;\n',
    );
    expect(probe).not.toContain('"# Broken\\n", "utf8");\n  let rejectedPartialCoverage');
    expect(probe).toContain('!error.message.includes("skipped 1 skill")');
    expect(probe).toContain(
      'throw new Error("Cisco sandbox probe accepted partial skill coverage");',
    );
  });

  it("adds a third leg: '# Broken\\n' in a fresh root completes with the fallback finding", () => {
    const probe = ciProbe();
    expect(probe.split("// D45 leg 3")).toHaveLength(2);
    const leg3 = probe.slice(probe.indexOf("// D45 leg 3"));
    expect(leg3).toContain('mkdtempSync(join(tmpdir(), "aih-scan-python-fallback-probe-"))');
    expect(leg3).toContain(
      'writeFileSync(join(fallbackRoot, "skills", "broken", "SKILL.md"), "# Broken\\n", "utf8");',
    );
    expect(leg3).toContain('result.ruleId === "SKILL_LOAD_FALLBACK_USED"');
    expect(leg3).toContain('=== "skills/broken/SKILL.md"');
    expect(leg3).toContain("rmSync(fallbackRoot, { recursive: true, force: true });");
    // Leg 3 comes after leg 2, and nothing is guessed: the fallback run must not throw.
    expect(probe.indexOf("// D45 leg 3")).toBeGreaterThan(
      probe.indexOf("Cisco sandbox probe accepted partial skill coverage"),
    );
    expect(leg3).not.toContain("catch");
  });
});
