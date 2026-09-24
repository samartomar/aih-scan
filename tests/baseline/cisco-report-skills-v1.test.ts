import { describe, expect, it } from "vitest";
import {
  CiscoAnalyzerFailureV1,
  ciscoSingleSkillReportV1,
} from "../../src/baseline/cisco-analyzer-failures-v1.js";
import {
  assertCiscoScanAllSkillInventoryV1,
  assertCiscoSingleSkillReportSkillV1,
} from "../../src/baseline/cisco-report-skills-v1.js";
import { failureStage } from "../../src/runner/run-detector-v1.js";

/** The failure `run` throws: its stage and message. */
const failureOf = (run: () => void) => {
  try {
    run();
  } catch (error) {
    if (error instanceof CiscoAnalyzerFailureV1)
      return { stage: error.stage, message: error.message };
    throw error;
  }
  return undefined;
};

// U1j (review of U1i, P1): a job's or the OCI capture's single-skill JSON report is evidence
// only for the skill that job scanned. Its `skill_path` is related to the source root by the
// rule the SARIF side uses (and, on win32 only, bound by owner decision D1), and must name
// exactly the job's directory (`/source` itself for the OCI capture); anything else fails at
// `output`, before the report's analyzers_failed is read.
describe("the single-skill report names the scanned skill (U1j)", () => {
  const report = (skillPath: unknown) => ({ skill_name: "x", skill_path: skillPath, findings: [] });
  const bind = (
    skillPath: unknown,
    skill: string,
    sourceRoots: readonly string[] = ["/scan"],
    platform: NodeJS.Platform = "linux",
  ) =>
    failureOf(() =>
      assertCiscoSingleSkillReportSkillV1(report(skillPath), {
        label: `job ${skill === "" ? "." : skill}`,
        sourceRoots,
        skill,
        platform,
      }),
    );

  it("accepts the job's own directory, and the root for a root job", () => {
    expect(bind("/scan/skills/alpha", "skills/alpha")).toBeUndefined();
    expect(bind("/scan", "")).toBeUndefined();
    expect(bind("/source", "", ["/source"])).toBeUndefined();
  });

  it("refuses another skill's report on an alpha job (the reviewer's case)", () => {
    expect(bind("/scan/skills/beta", "skills/alpha")).toEqual({
      stage: "output",
      message: expect.stringMatching(
        /Cisco JSON report of job skills\/alpha is for skill skills\/beta, not skills\/alpha$/,
      ),
    });
  });

  it("refuses a parent, a child, the root or a path outside the source root", () => {
    for (const [skillPath, skill] of [
      ["/scan/skills", "skills/alpha"],
      ["/scan/skills/alpha/nested", "skills/alpha"],
      ["/scan", "skills/alpha"],
      ["/scan/skills/alpha", ""],
      ["/elsewhere/skills/alpha", "skills/alpha"],
      ["skills/alpha", "skills/alpha"],
      ["/scan/skills/alpha/../beta", "skills/alpha"],
    ] as const)
      expect(bind(skillPath, skill), skillPath).toMatchObject({
        stage: "output",
        message: expect.stringMatching(/Cisco JSON report of job /),
      });
    expect(bind("/source/skills/x", "", ["/source"])).toMatchObject({ stage: "output" });
  });

  it("refuses a report with no string skill identity", () => {
    for (const skillPath of [undefined, null, 1, ["/scan/skills/alpha"]])
      expect(bind(skillPath, "skills/alpha"), String(skillPath)).toMatchObject({
        stage: "output",
      });
  });

  it("binds a normcased identity on win32 only (owner decision D1)", () => {
    expect(bind("c:\\scan\\skills\\alpha", "Skills/Alpha", ["C:/scan"], "win32")).toBeUndefined();
    expect(bind("C:\\scan\\Skills\\Alpha", "Skills/Alpha", ["C:/scan"], "win32")).toBeUndefined();
    expect(bind("c:\\scan\\skills\\alpha", "Skills/Alpha", ["C:/scan"], "linux")).toMatchObject({
      stage: "output",
    });
    expect(bind("c:\\scan\\skills\\beta", "Skills/Alpha", ["C:/scan"], "win32")).toMatchObject({
      stage: "output",
    });
  });

  it("refuses a report holding several results, which is not a single-skill report", () => {
    expect(
      failureOf(() =>
        ciscoSingleSkillReportV1(
          Buffer.from(
            JSON.stringify({
              skill_path: "/scan/skills/alpha",
              findings: [],
              results: [
                { skill_path: "/scan/skills/alpha", findings: [] },
                { skill_path: "/scan/skills/beta", findings: [] },
              ],
            }),
          ),
          "job skills/alpha",
        ),
      ),
    ).toMatchObject({ stage: "output", message: expect.stringMatching(/not a single-skill/) });
  });
});

// U1j (review of U1i, P1): Cisco `scan-all` reports each skill's analyzers_failed under
// `results[i]`, so a report that leaves a skill out, or lists one skill twice in place of
// another, hides that skill's failures from D30. The unique skills a report lists must be the
// expected skill inventory, each exactly once and nothing else, and its summary count must
// agree; anything else fails at `coverage` before any SARIF is read.
describe("the scan-all report lists every expected skill exactly once (U1j)", () => {
  const scanAll = (skillPaths: readonly unknown[], scanned: unknown = skillPaths.length) => ({
    summary: { total_skills_scanned: scanned },
    results: skillPaths.map((skillPath) => ({ skill_path: skillPath, findings: [] })),
  });
  const inventory = (
    report: Record<string, unknown>,
    expected: readonly string[] = ["skills/alpha", "skills/beta"],
    sourceRoots: readonly string[] = ["/scan"],
    platform: NodeJS.Platform = "linux",
  ) =>
    failureOf(() =>
      assertCiscoScanAllSkillInventoryV1(report, { sourceRoots, expected, platform }),
    );

  it("accepts every expected skill exactly once, in any order", () => {
    expect(inventory(scanAll(["/scan/skills/alpha", "/scan/skills/beta"]))).toBeUndefined();
    expect(inventory(scanAll(["/scan/skills/beta", "/scan/skills/alpha"]))).toBeUndefined();
    expect(
      inventory(scanAll(["/scan", "/scan/skills/alpha"]), ["", "skills/alpha"]),
    ).toBeUndefined();
  });

  it("fails coverage for a partial report whose summary still counts two skills (the reviewer's case)", () => {
    expect(inventory(scanAll(["/scan/skills/alpha"], 2))).toEqual({
      stage: "coverage",
      message: expect.stringMatching(
        /Cisco skill coverage mismatch: the JSON report lists 1 result for 2 expected skills \(summary 2\): missing skills\/beta$/,
      ),
    });
  });

  it("fails coverage when a duplicate alpha stands in for beta", () => {
    expect(inventory(scanAll(["/scan/skills/alpha", "/scan/skills/alpha"]))).toEqual({
      stage: "coverage",
      message: expect.stringMatching(
        /lists 2 results for 2 expected skills \(summary 2\): missing skills\/beta; listed more than once skills\/alpha$/,
      ),
    });
  });

  it("fails coverage for an extra skill, and for a summary count that disagrees", () => {
    expect(
      inventory(scanAll(["/scan/skills/alpha", "/scan/skills/beta", "/scan/skills/gamma"])),
    ).toMatchObject({
      stage: "coverage",
      message: expect.stringMatching(/not expected skills\/gamma$/),
    });
    expect(inventory(scanAll(["/scan/skills/alpha", "/scan/skills/beta"], 3))).toMatchObject({
      stage: "coverage",
      message: expect.stringMatching(/\(summary 3\): the summary count disagrees$/),
    });
    expect(inventory(scanAll([], 0))).toMatchObject({ stage: "coverage" });
  });

  it("fails output for a malformed results list or skill path", () => {
    for (const report of [
      { summary: { total_skills_scanned: 1 } },
      { summary: { total_skills_scanned: 1 }, results: {} },
      { summary: { total_skills_scanned: 1 }, results: [1] },
      scanAll([1, "/scan/skills/beta"]),
      scanAll(["/elsewhere/skills/alpha", "/scan/skills/beta"]),
      scanAll(["skills/alpha", "/scan/skills/beta"]),
    ])
      expect(inventory(report), JSON.stringify(report)).toMatchObject({ stage: "output" });
  });

  it("binds normcased skill paths on win32 only (owner decision D1)", () => {
    const lowered = scanAll(["c:\\scan", "c:\\scan\\skills\\nested"]);
    expect(inventory(lowered, ["", "Skills/Nested"], ["C:/scan"], "win32")).toBeUndefined();
    expect(inventory(lowered, ["", "Skills/Nested"], ["C:/scan"], "linux")).toMatchObject({
      stage: "coverage",
      message: expect.stringMatching(/missing Skills\/Nested; not expected skills\/nested$/),
    });
  });

  it("is classified coverage by the runner", () => {
    const message = inventory(scanAll(["/scan/skills/alpha"], 2))?.message ?? "";
    expect(failureStage(message)).toBe("coverage");
  });
});
