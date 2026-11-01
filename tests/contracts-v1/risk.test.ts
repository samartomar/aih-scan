import { describe, expect, it } from "vitest";
import {
  displayLabel,
  failAtReached,
  riskLabelForScore,
  type ScoredFinding,
  scoreFindings,
  storedLabel,
} from "../../src/public/contracts.js";

const base = { path: "SKILL.md", line: 1, part: "text" as const };

function finding(overrides: Partial<ScoredFinding>): ScoredFinding {
  return {
    tool: "aih-trust-lint",
    ruleId: "rule",
    code: "trust.prompt-injection",
    ...base,
    ...overrides,
  };
}

describe("aih-risk/1 scoring", () => {
  it("reproduces the worked examples (code multiplier, confidence, half-up rounding)", () => {
    expect(
      scoreFindings([
        finding({ severity: "HIGH", part: "code", confidence: 0.9, path: "hooks/session-start" }),
      ]).score,
    ).toBe(29);
    expect(riskLabelForScore(29)).toBe("CAUTION");
    const brainstorming = scoreFindings([
      finding({ severity: "MEDIUM", part: "code", confidence: 0.6 }),
    ]);
    expect(brainstorming.score).toBe(8);
    expect(riskLabelForScore(brainstorming.score)).toBe("SAFE");
  });

  it("uses SARIF level only when the tool gave no severity", () => {
    expect(scoreFindings([finding({ level: "error" })]).score).toBe(25);
    expect(scoreFindings([finding({ level: "warning" })]).score).toBe(10);
    expect(scoreFindings([finding({ level: "note" })]).score).toBe(5);
    expect(scoreFindings([finding({ severity: "LOW", level: "error" })]).score).toBe(5);
    expect(scoreFindings([finding({ severity: "CRITICAL" })]).score).toBe(50);
  });

  it("counts the same code, file and line from two tools once, keeping the higher points", () => {
    const result = scoreFindings([
      finding({ tool: "skillspector", ruleId: "P1", severity: "MEDIUM" }),
      finding({ tool: "aih-trust-lint", ruleId: "x", severity: "HIGH" }),
    ]);
    expect(result.score).toBe(25);
    expect(result.counted).toHaveLength(1);
    expect(result.counted[0]?.tool).toBe("aih-trust-lint");
  });

  it("does not collapse one tool's findings sharing code, file and line", () => {
    // Same tool, same rule: diminishing weights 25 + 12.5 = 37.5 -> 38.
    const sameTool = scoreFindings([
      finding({ ruleId: "r", severity: "HIGH" }),
      finding({ ruleId: "r", severity: "HIGH" }),
    ]);
    expect(sameTool.counted).toHaveLength(2);
    expect(sameTool.score).toBe(38);
    // Same tool, different rules mapping to the same code: each rule restarts at weight 1.
    expect(
      scoreFindings([
        finding({ ruleId: "r1", severity: "HIGH" }),
        finding({ ruleId: "r2", severity: "HIGH" }),
      ]).score,
    ).toBe(50);
  });

  it("keeps every finding of the preferred tool when two tools report the same code, file and line", () => {
    const result = scoreFindings([
      finding({ tool: "skillspector", ruleId: "P1", severity: "MEDIUM" }),
      finding({ tool: "aih-trust-lint", ruleId: "x", severity: "HIGH" }),
      finding({ tool: "aih-trust-lint", ruleId: "x", severity: "LOW" }),
    ]);
    // trust-lint wins the key (HIGH > MEDIUM); both of its findings count: 25 + 5 * 0.5 = 27.5 -> 28.
    expect(result.counted.map((entry) => entry.tool)).toEqual(["aih-trust-lint", "aih-trust-lint"]);
    expect(result.score).toBe(28);
  });

  it("breaks equal points by higher confidence (missing counts as 1), then tool name", () => {
    const byConfidence = scoreFindings([
      finding({ tool: "a-tool", severity: "HIGH", confidence: 0.5 }),
      finding({ tool: "b-tool", severity: "HIGH" }),
    ]);
    expect(byConfidence.counted[0]?.tool).toBe("b-tool");
    expect(byConfidence.score).toBe(25);
    const byName = scoreFindings([
      finding({ tool: "zeta", severity: "HIGH", confidence: 0.5 }),
      finding({ tool: "alpha", severity: "HIGH", confidence: 0.5 }),
    ]);
    expect(byName.counted[0]?.tool).toBe("alpha");
  });

  it("weighs each tool rule 1, half, quarter and then nothing, highest value first", () => {
    const four = [1, 2, 3, 4].map((line) =>
      finding({ severity: "HIGH", line, ruleId: "same-rule" }),
    );
    // 25 + 12.5 + 6.25 + 0 = 43.75 -> 44
    expect(scoreFindings(four).score).toBe(44);
    // A lower-valued finding first in input order still receives the smaller weight.
    const ordered = scoreFindings([
      finding({ severity: "LOW", line: 1, ruleId: "r" }),
      finding({ severity: "HIGH", line: 2, ruleId: "r" }),
    ]);
    // 25 * 1 + 5 * 0.5 = 27.5 -> 28
    expect(ordered.score).toBe(28);
    // Different rules each restart at weight 1.
    expect(
      scoreFindings([
        finding({ severity: "HIGH", line: 1, ruleId: "r1" }),
        finding({ severity: "HIGH", line: 2, ruleId: "r2" }),
      ]).score,
    ).toBe(50);
  });

  it("orders equal values by file path, then line", () => {
    const result = scoreFindings([
      finding({ severity: "HIGH", path: "b.md", line: 1, ruleId: "r" }),
      finding({ severity: "HIGH", path: "a.md", line: 9, ruleId: "r" }),
      finding({ severity: "HIGH", path: "a.md", line: 2, ruleId: "r" }),
    ]);
    expect(result.counted.map((entry) => [entry.path, entry.line, entry.weight])).toEqual([
      ["a.md", 2, 1],
      ["a.md", 9, 0.5],
      ["b.md", 1, 0.25],
    ]);
  });

  it("rounds half up and caps at 100", () => {
    // 5 * 0.5 = 2.5 -> 3
    expect(scoreFindings([finding({ severity: "LOW", confidence: 0.5 })]).score).toBe(3);
    const many = Array.from({ length: 6 }, (_, index) =>
      finding({ severity: "CRITICAL", ruleId: `r${index}`, line: index + 1 }),
    );
    expect(scoreFindings(many).score).toBe(100);
  });

  it("never scores advisory findings", () => {
    expect(
      scoreFindings([finding({ code: "trust.known-vulnerability", severity: "CRITICAL" })]).score,
    ).toBe(0);
  });

  it("maps score thresholds and the coverage-adjusted stored label", () => {
    expect([0, 20, 21, 50, 51, 100].map(riskLabelForScore)).toEqual([
      "SAFE",
      "SAFE",
      "CAUTION",
      "CAUTION",
      "DO NOT INSTALL",
      "DO NOT INSTALL",
    ]);
    expect(storedLabel({ score: 8, coverage: "partial", routable: true })).toBe("CAUTION");
    expect(storedLabel({ score: 8, coverage: "complete", routable: true })).toBe("SAFE");
    expect(storedLabel({ score: 60, coverage: "partial", routable: true })).toBe("DO NOT INSTALL");
    expect(storedLabel({ score: 0, coverage: "partial", routable: false })).toBe("NOT ASSESSED");
    expect(displayLabel({ label: "CAUTION", coverage: "partial" })).toBe("CAUTION (partial)");
    expect(displayLabel({ label: "SAFE", coverage: "complete" })).toBe("SAFE");
  });

  it("compares --fail-at against the stored label; NOT ASSESSED never meets a threshold", () => {
    expect(failAtReached("CAUTION", "CAUTION")).toBe(true);
    expect(failAtReached("SAFE", "CAUTION")).toBe(false);
    expect(failAtReached("DO NOT INSTALL", "CAUTION")).toBe(true);
    expect(failAtReached("CAUTION", "DO NOT INSTALL")).toBe(false);
    expect(failAtReached("NOT ASSESSED", "CAUTION")).toBe(false);
  });
});
