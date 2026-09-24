import { describe, expect, it } from "vitest";
import {
  CiscoAnalyzerFailureV1,
  ciscoSingleSkillReportV1,
} from "../../src/baseline/cisco-analyzer-failures-v1.js";
import { assertCiscoSingleSkillReportSkillV1 } from "../../src/baseline/cisco-report-skills-v1.js";

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
