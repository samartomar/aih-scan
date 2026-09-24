import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  assertCiscoSingleSkillAnalyzersCompleteV1,
  CiscoAnalyzerFailureV1,
  ciscoSingleSkillReportV1,
} from "../../src/baseline/cisco-analyzer-failures-v1.js";
import {
  assertCiscoScanAllAnalyzersCompleteV1,
  ciscoSourceRelativeSarifV1,
} from "../../src/baseline/sarif-source-relative-v1.js";

// Coordinator decision D30 (revised 20:58Z, U1i): a Cisco run is complete only when every
// `analyzers_failed` entry is Cisco's documented fallback: analyzer `skill_loader`, once for
// its skill, with a SKILL_LOAD_FALLBACK_USED finding in the same skill result and that
// finding's SARIF counterpart located in the same skill. Anything else fails at stage
// `coverage`, naming each analyzer and error; a malformed `analyzers_failed` fails at `output`;
// an absent key or an empty array is complete. `scan-all` reports it per `results[i]`, the
// single-skill `scan` at the top level.

const REAL_REPORT = readFileSync(
  new URL("../fixtures/cisco/real-2.1.0-win32-malformed.report.json", import.meta.url),
  "utf8",
);
const REAL_SARIF = readFileSync(
  new URL("../fixtures/cisco/real-2.1.0-win32-malformed.sarif", import.meta.url),
  "utf8",
);

type Report = Record<string, unknown> & { results: Record<string, unknown>[] };
const realReport = (): Report =>
  JSON.parse(REAL_REPORT.replaceAll("@SKILL_PATH@", "/scan")) as Report;
const realSarif = () => JSON.parse(REAL_SARIF) as Record<string, unknown>;

/** Normalizes, then decides completion, as the host path does. */
const scanAll = (sarif: Record<string, unknown>, report: Record<string, unknown>) => {
  const normalized = ciscoSourceRelativeSarifV1(sarif, report, ["/scan"]);
  assertCiscoScanAllAnalyzersCompleteV1(report, normalized.document, ["/scan"]);
};

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

describe("Cisco analyzers_failed decides completion (D30, scan-all, real bytes)", () => {
  it("completes the real malformed run: its one failure is the matched skill_loader fallback", () => {
    const report = realReport();
    expect(report.results[0]?.analyzers_failed).toEqual([
      { analyzer: "skill_loader", error: "SkillLoadError:MISSING_REQUIRED_MANIFEST_FIELD" },
    ]);
    expect(failureOf(() => scanAll(realSarif(), report))).toBeUndefined();
  });

  it("fails coverage for a skill_loader failure without its fallback finding", () => {
    // Drop the fallback finding from both reports, so the pairing still holds.
    const report = realReport();
    const findings = report.results[0]?.findings as Record<string, unknown>[];
    const at = findings.findIndex((finding) => finding.rule_id === "SKILL_LOAD_FALLBACK_USED");
    findings.splice(at, 1);
    const sarif = realSarif() as { runs: { results: unknown[] }[] };
    sarif.runs[0]?.results.splice(at, 1);
    expect(failureOf(() => scanAll(sarif, report))).toEqual({
      stage: "coverage",
      message: expect.stringMatching(
        /Cisco reported failed analyzers: skill_loader \(SkillLoadError:MISSING_REQUIRED_MANIFEST_FIELD\) in the root skill: no SKILL_LOAD_FALLBACK_USED finding in that skill$/,
      ),
    });
  });

  it("fails coverage for any other failed analyzer, naming each analyzer and error", () => {
    const report = realReport();
    (report.results[0]?.analyzers_failed as unknown[]).push({
      analyzer: "behavioral",
      error: "Timeout",
    });
    expect(failureOf(() => scanAll(realSarif(), report))).toEqual({
      stage: "coverage",
      message: expect.stringMatching(
        /Cisco reported failed analyzers: skill_loader \(SkillLoadError:MISSING_REQUIRED_MANIFEST_FIELD\), behavioral \(Timeout\) in the root skill$/,
      ),
    });
    const alone = realReport();
    alone.results[0] = {
      ...alone.results[0],
      analyzers_failed: [{ analyzer: "behavioral", error: "Timeout" }],
    };
    expect(failureOf(() => scanAll(realSarif(), alone))?.message).toMatch(
      /Cisco reported failed analyzers: behavioral \(Timeout\) in the root skill$/,
    );
  });

  it("fails coverage for more than one skill_loader entry in one skill", () => {
    const report = realReport();
    (report.results[0]?.analyzers_failed as unknown[]).push({
      analyzer: "skill_loader",
      error: "SkillLoadError:OTHER",
    });
    expect(failureOf(() => scanAll(realSarif(), report))).toMatchObject({
      stage: "coverage",
      message: expect.stringMatching(/more than one skill_loader failure/),
    });
  });

  it("fails coverage for a failure at the report's top level, which names no skill", () => {
    const report = realReport();
    report.analyzers_failed = [{ analyzer: "skill_loader", error: "SkillLoadError:X" }];
    expect(failureOf(() => scanAll(realSarif(), report))).toMatchObject({
      stage: "coverage",
      message: expect.stringMatching(/skill_loader \(SkillLoadError:X\) at the report's top level/),
    });
  });

  it("completes with no analyzers_failed key or an empty array", () => {
    for (const value of [undefined, []]) {
      const report = realReport();
      if (value === undefined) delete report.results[0]?.analyzers_failed;
      else (report.results[0] as Record<string, unknown>).analyzers_failed = value;
      expect(
        failureOf(() => scanAll(realSarif(), report)),
        JSON.stringify(value),
      ).toBeUndefined();
    }
    const top = realReport();
    top.analyzers_failed = [];
    expect(failureOf(() => scanAll(realSarif(), top))).toBeUndefined();
  });

  it("fails output for a malformed analyzers_failed", () => {
    for (const value of [
      "skill_loader",
      {},
      null,
      [1],
      [{ analyzer: 1, error: "e" }],
      [{ analyzer: "a" }],
      [{ analyzer: "a", error: ["e"] }],
      [{ analyzer: "a", error: "e", extra: true }],
    ]) {
      const report = realReport();
      (report.results[0] as Record<string, unknown>).analyzers_failed = value;
      expect(
        failureOf(() => scanAll(realSarif(), report)),
        JSON.stringify(value),
      ).toEqual({
        stage: "output",
        message: expect.stringMatching(/Cisco JSON report analyzers_failed .*is malformed/),
      });
    }
  });
});

describe("Cisco analyzers_failed across skills (D30, scan-all, synthetic)", () => {
  // alpha reports the skill_loader failure; `fallbackIn` names the skill whose result holds
  // the SKILL_LOAD_FALLBACK_USED finding (and its SARIF counterpart).
  const twoSkills = (fallbackIn: "alpha" | "beta") => {
    const skills = ["alpha", "beta"];
    const report = {
      summary: { total_skills_scanned: 2 },
      results: skills.map((skill) => ({
        skill_path: `/scan/skills/${skill}`,
        findings:
          skill === fallbackIn
            ? [
                {
                  id: "SKILL_LOAD_FALLBACK_USED",
                  rule_id: "SKILL_LOAD_FALLBACK_USED",
                  file_path: "SKILL.md",
                  line_number: null,
                },
              ]
            : [],
        ...(skill === "alpha"
          ? { analyzers_failed: [{ analyzer: "skill_loader", error: "SkillLoadError:X" }] }
          : {}),
      })),
    };
    const sarif = {
      version: "2.1.0",
      runs: [
        {
          tool: { driver: { name: "skill-scanner" } },
          results: [
            {
              ruleId: "SKILL_LOAD_FALLBACK_USED",
              message: { text: "fallback" },
              fingerprints: { primaryLocationLineHash: "SKILL_LOAD_FALLBACK_USED" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: "SKILL.md", uriBaseId: "%SRCROOT%" },
                  },
                },
              ],
            },
          ],
        },
      ],
    };
    return { sarif, report };
  };

  it("completes when the fallback finding is in the failing skill", () => {
    const { sarif, report } = twoSkills("alpha");
    expect(failureOf(() => scanAll(sarif, report))).toBeUndefined();
  });

  it("fails coverage when the fallback finding is in a sibling skill", () => {
    const { sarif, report } = twoSkills("beta");
    expect(failureOf(() => scanAll(sarif, report))).toEqual({
      stage: "coverage",
      message: expect.stringMatching(
        /Cisco reported failed analyzers: skill_loader \(SkillLoadError:X\) in skills\/alpha: no SKILL_LOAD_FALLBACK_USED finding in that skill$/,
      ),
    });
  });

  it("never completes on a fallback finding whose SARIF counterpart is another rule", () => {
    // In scan-all the counterpart is the SARIF result paired by position; a different rule
    // already fails that pairing at output, before completion is decided.
    const { sarif, report } = twoSkills("alpha");
    (sarif.runs[0]?.results[0] as Record<string, unknown>).ruleId = "OTHER";
    expect(() => scanAll(sarif, report)).toThrow(/does not match JSON finding 0/);
  });
});

describe("Cisco single-skill scan report (D30, source-tree, shard and OCI jobs)", () => {
  const bytes = (value: unknown) =>
    Buffer.from(typeof value === "string" ? value : JSON.stringify(value));
  const scanReport = (extra: Record<string, unknown> = {}) => ({
    skill_name: "alpha",
    skill_path: "/scan/skills/alpha",
    findings: [
      {
        id: "SKILL_LOAD_FALLBACK_USED",
        rule_id: "SKILL_LOAD_FALLBACK_USED",
        file_path: "SKILL.md",
        line_number: null,
      },
    ],
    ...extra,
  });
  const failed = { analyzers_failed: [{ analyzer: "skill_loader", error: "SkillLoadError:X" }] };

  it("reads the single-skill shape strictly and fails output otherwise", () => {
    expect(ciscoSingleSkillReportV1(bytes(scanReport()), "job skills/alpha")).toMatchObject({
      skill_path: "/scan/skills/alpha",
    });
    for (const [text, reason] of [
      ["", /Cisco JSON report/],
      ["[]", /Cisco JSON report/],
      ['{"findings":[],"findings":[]}', /Cisco JSON report/],
      [JSON.stringify({ summary: {}, results: [] }), /is not a single-skill scan report/],
      [JSON.stringify({ skill_path: "/x" }), /is not a single-skill scan report/],
      [JSON.stringify({ skill_path: "/x", findings: [1] }), /finding .*is malformed/],
    ] as const) {
      const failure = failureOf(() => ciscoSingleSkillReportV1(bytes(text), "job skills/alpha"));
      expect(failure, text).toEqual({ stage: "output", message: expect.stringMatching(reason) });
      expect(failure?.message, text).toMatch(/Cisco JSON report/);
    }
    expect(
      failureOf(() => ciscoSingleSkillReportV1(Buffer.from([0xff]), "job skills/alpha")),
    ).toMatchObject({ stage: "output" });
  });

  it("completes a matched fallback, an empty list or no key", () => {
    for (const report of [scanReport(failed), scanReport({ analyzers_failed: [] }), scanReport()])
      expect(
        failureOf(() =>
          assertCiscoSingleSkillAnalyzersCompleteV1(
            report,
            ["SKILL_LOAD_FALLBACK_USED"],
            "skills/alpha",
          ),
        ),
      ).toBeUndefined();
  });

  it("fails coverage without the fallback finding, without its SARIF counterpart, or for another analyzer", () => {
    const cases: [Record<string, unknown>, string[], RegExp][] = [
      [
        { ...scanReport(failed), findings: [] },
        ["SKILL_LOAD_FALLBACK_USED"],
        /no SKILL_LOAD_FALLBACK_USED finding in that skill/,
      ],
      [scanReport(failed), [], /no SARIF counterpart in that skill/],
      [scanReport(failed), ["OTHER"], /no SARIF counterpart in that skill/],
      [
        scanReport({ analyzers_failed: [{ analyzer: "behavioral", error: "Timeout" }] }),
        ["SKILL_LOAD_FALLBACK_USED"],
        /^.*Cisco reported failed analyzers: behavioral \(Timeout\) in skills\/alpha$/,
      ],
    ];
    for (const [report, ruleIds, reason] of cases)
      expect(
        failureOf(() => assertCiscoSingleSkillAnalyzersCompleteV1(report, ruleIds, "skills/alpha")),
        JSON.stringify([report.analyzers_failed, ruleIds]),
      ).toEqual({ stage: "coverage", message: expect.stringMatching(reason) });
  });

  it("fails output for a malformed top-level analyzers_failed", () => {
    expect(
      failureOf(() =>
        assertCiscoSingleSkillAnalyzersCompleteV1(
          scanReport({ analyzers_failed: [{ analyzer: "skill_loader" }] }),
          ["SKILL_LOAD_FALLBACK_USED"],
          "skills/alpha",
        ),
      ),
    ).toMatchObject({ stage: "output", message: expect.stringMatching(/is malformed/) });
  });
});
