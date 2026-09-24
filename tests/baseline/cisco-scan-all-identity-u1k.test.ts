import { describe, expect, it } from "vitest";
import { CiscoAnalyzerFailureV1 } from "../../src/baseline/cisco-analyzer-failures-v1.js";
import {
  assertCiscoScanAllAnalyzersCompleteV1,
  ciscoSourceRelativeSarifV1,
} from "../../src/baseline/sarif-source-relative-v1.js";
import { failureStage } from "../../src/runner/run-detector-v1.js";

// U1k (review of U1j, P2): on the `scan-all` path a SKILL_LOAD_FALLBACK_USED finding pairs
// with its SARIF result by the D28 identity, JSON (rule_id, id) = SARIF (ruleId,
// fingerprints.primaryLocationLineHash), whatever its file_path: the same rule as jobs and the
// OCI capture, with uniqueness counted in the reporting skill (a job report is one skill).
// Every other finding for which Cisco gives an identity on both sides must carry the same one
// as its paired result, so same-shaped results can no longer be reordered or substituted.

const FALLBACK = "SKILL_LOAD_FALLBACK_USED";
const LOADER = {
  analyzer: "skill_loader",
  error: "SkillLoadError:MISSING_REQUIRED_MANIFEST_FIELD",
};

type Finding = Record<string, unknown>;
const fallback = (id: unknown, file: string | null = "skill.md"): Finding => ({
  rule_id: FALLBACK,
  ...(id === undefined ? {} : { id }),
  file_path: file,
  line_number: null,
});
const finding = (rule: string, id: unknown, file: string, line: number | null): Finding => ({
  rule_id: rule,
  ...(id === undefined ? {} : { id }),
  file_path: file,
  line_number: line,
});
const entry = (skill: string, findings: Finding[], failed: unknown[] = [LOADER]) => ({
  skill_path: skill === "" ? "/scan" : `/scan/${skill}`,
  findings,
  analyzers_failed: failed,
});
const report = (...entries: ReturnType<typeof entry>[]) => ({
  summary: { total_skills_scanned: entries.length },
  results: entries,
});
const result = (ruleId: string, fingerprint: string | undefined, uri: string, line?: number) => ({
  ruleId,
  ...(fingerprint === undefined ? {} : { fingerprints: { primaryLocationLineHash: fingerprint } }),
  message: { text: "m" },
  locations: [
    {
      physicalLocation: {
        artifactLocation: { uri },
        ...(line === undefined ? {} : { region: { startLine: line } }),
      },
    },
  ],
});
const sarif = (...results: ReturnType<typeof result>[]) => ({
  version: "2.1.0",
  runs: [{ tool: { driver: { name: "skill-scanner" } }, results }],
});

/** Normalizes, then decides completion, as the host path does; the failure, if any. */
const scanAll = (log: Record<string, unknown>, json: Record<string, unknown>) => {
  try {
    const normalized = ciscoSourceRelativeSarifV1(log, json, ["/scan"]);
    assertCiscoScanAllAnalyzersCompleteV1(json, normalized.document, ["/scan"]);
  } catch (error) {
    const message = (error as Error).message;
    return {
      stage: error instanceof CiscoAnalyzerFailureV1 ? error.stage : failureStage(message),
      message,
    };
  }
  return undefined;
};

describe("scan-all fallback pairing by identity (U1k)", () => {
  it("refuses a fallback finding paired with another identity's SARIF fallback (the reviewer's case)", () => {
    for (const file of ["SKILL.md", "skill.md"])
      expect(
        scanAll(sarif(result(FALLBACK, "B", file)), report(entry("", [fallback("A", file)]))),
        file,
      ).toEqual({
        stage: "output",
        message: expect.stringMatching(
          /SARIF result 0 \(SKILL_LOAD_FALLBACK_USED, B\) does not carry the identity of JSON finding 0 \(SKILL_LOAD_FALLBACK_USED, A\)$/,
        ),
      });
  });

  it("refuses reordered same-shaped fallbacks of two skills", () => {
    const json = report(
      entry("skills/alpha", [fallback("A")]),
      entry("skills/beta", [fallback("B")]),
    );
    expect(
      scanAll(sarif(result(FALLBACK, "B", "skill.md"), result(FALLBACK, "A", "skill.md")), json),
    ).toEqual({
      stage: "output",
      message: expect.stringMatching(
        /SARIF result 0 \(SKILL_LOAD_FALLBACK_USED, B\) does not carry the identity of JSON finding 0 \(SKILL_LOAD_FALLBACK_USED, A\)$/,
      ),
    });
    expect(
      scanAll(sarif(result(FALLBACK, "A", "skill.md"), result(FALLBACK, "B", "skill.md")), json),
    ).toBeUndefined();
  });

  it("refuses reordered same-shaped fallbacks within one skill", () => {
    const json = report(entry("skills/alpha", [fallback("A"), fallback("B")]));
    expect(
      scanAll(sarif(result(FALLBACK, "B", "skill.md"), result(FALLBACK, "A", "skill.md")), json),
    ).toMatchObject({
      stage: "output",
      message: expect.stringMatching(/does not carry the identity/),
    });
  });

  it("completes real-shaped fallbacks of two skills, whose one identity repeats across skills", () => {
    // Real Cisco 2.1.0 gives every fallback the identity (SKILL_LOAD_FALLBACK_USED,
    // SKILL_LOAD_FALLBACK_USED); uniqueness is counted in the reporting skill, as for a job.
    expect(
      scanAll(
        sarif(result(FALLBACK, FALLBACK, "skill.md"), result(FALLBACK, FALLBACK, "skill.md")),
        report(
          entry("skills/alpha", [fallback(FALLBACK)]),
          entry("skills/beta", [fallback(FALLBACK)]),
        ),
      ),
    ).toBeUndefined();
  });

  it("refuses a fallback identity repeated within one skill", () => {
    expect(
      scanAll(
        sarif(result(FALLBACK, "A", "skill.md"), result(FALLBACK, "A", "skill.md")),
        report(entry("skills/alpha", [fallback("A"), fallback("A")])),
      ),
    ).toEqual({
      stage: "output",
      message: expect.stringMatching(
        /SKILL_LOAD_FALLBACK_USED identity \(SKILL_LOAD_FALLBACK_USED, A\) of JSON finding 0 is not unique in the reporting skill skills\/alpha \(JSON 2, SARIF 2\)$/,
      ),
    });
  });

  it("refuses a fallback finding with no string id", () => {
    for (const log of [
      sarif(result(FALLBACK, undefined, "skill.md")),
      sarif(result(FALLBACK, "X", "skill.md")),
    ])
      expect(scanAll(log, report(entry("", [fallback(undefined)])))).toMatchObject({
        stage: "output",
      });
  });
});

describe("scan-all identity pairing of every other finding (U1k)", () => {
  const R = "PROMPT_INJECTION_IGNORE_INSTRUCTIONS";

  it("refuses a result whose identity differs from its paired finding's", () => {
    expect(
      scanAll(
        sarif(result(R, `${R}_y`, "SKILL.md", 3)),
        report(entry("", [finding(R, `${R}_x`, "SKILL.md", 3)], [])),
      ),
    ).toEqual({
      stage: "output",
      message: expect.stringMatching(
        /SARIF result 0 \(PROMPT_INJECTION_IGNORE_INSTRUCTIONS, PROMPT_INJECTION_IGNORE_INSTRUCTIONS_y\) does not carry the identity of JSON finding 0 \(PROMPT_INJECTION_IGNORE_INSTRUCTIONS, PROMPT_INJECTION_IGNORE_INSTRUCTIONS_x\)$/,
      ),
    });
  });

  it("refuses reordered same-shaped results of two skills", () => {
    const json = report(
      entry("skills/alpha", [finding(R, "a", "SKILL.md", 3)], []),
      entry("skills/beta", [finding(R, "b", "SKILL.md", 3)], []),
    );
    expect(
      scanAll(sarif(result(R, "b", "SKILL.md", 3), result(R, "a", "SKILL.md", 3)), json),
    ).toMatchObject({
      stage: "output",
      message: expect.stringMatching(/does not carry the identity/),
    });
    expect(
      scanAll(sarif(result(R, "a", "SKILL.md", 3), result(R, "b", "SKILL.md", 3)), json),
    ).toBeUndefined();
  });

  it("refuses an identity given on one side only", () => {
    for (const [id, fingerprint] of [
      ["x", undefined],
      [undefined, "x"],
    ] as const)
      expect(
        scanAll(
          sarif(result(R, fingerprint, "SKILL.md", 3)),
          report(entry("", [finding(R, id, "SKILL.md", 3)], [])),
        ),
        String(id),
      ).toMatchObject({
        stage: "output",
        message: expect.stringMatching(/does not carry the identity/),
      });
  });

  it("keeps positional pairing where Cisco gives no identity on either side", () => {
    expect(
      scanAll(
        sarif(result(R, undefined, "SKILL.md", 3)),
        report(entry("", [finding(R, undefined, "SKILL.md", 3)], [])),
      ),
    ).toBeUndefined();
  });
});

describe("scan-all D30 counts a fallback's counterpart by identity (U1k)", () => {
  // Direct: the counterpart is the one result in the skill's part of the normalized SARIF
  // with the fallback's identity, never the result that merely sits at its position.
  const normalized = (...results: ReturnType<typeof result>[]) => sarif(...results);
  const decide = (json: Record<string, unknown>, document: Record<string, unknown>) => {
    try {
      assertCiscoScanAllAnalyzersCompleteV1(json, document, ["/scan"]);
    } catch (error) {
      if (error instanceof CiscoAnalyzerFailureV1)
        return { stage: error.stage, message: error.message };
      throw error;
    }
    return undefined;
  };

  it("fails coverage when the skill's only fallback result carries another identity", () => {
    expect(
      decide(
        report(entry("skills/alpha", [fallback("A")])),
        normalized(result(FALLBACK, "B", "skills/alpha/SKILL.md")),
      ),
    ).toEqual({
      stage: "coverage",
      message: expect.stringMatching(
        /skill_loader \(SkillLoadError:MISSING_REQUIRED_MANIFEST_FIELD\) in skills\/alpha: its SKILL_LOAD_FALLBACK_USED finding \(SKILL_LOAD_FALLBACK_USED, A\) has no SARIF counterpart in that skill$/,
      ),
    });
  });

  it("fails coverage when the counterpart lies in another skill's part of the SARIF", () => {
    expect(
      decide(
        report(entry("skills/alpha", [fallback("A")]), entry("skills/beta", [fallback("B")])),
        normalized(
          result(FALLBACK, "B", "skills/beta/SKILL.md"),
          result(FALLBACK, "A", "skills/alpha/SKILL.md"),
        ),
      ),
    ).toMatchObject({
      stage: "coverage",
      message: expect.stringMatching(
        /in skills\/alpha: its SKILL_LOAD_FALLBACK_USED finding \(SKILL_LOAD_FALLBACK_USED, A\) has no SARIF counterpart in that skill; /,
      ),
    });
  });

  it("completes when each skill's fallback has its own identity counterpart", () => {
    expect(
      decide(
        report(entry("skills/alpha", [fallback("A")]), entry("skills/beta", [fallback("B")])),
        normalized(
          result(FALLBACK, "A", "skills/alpha/SKILL.md"),
          result(FALLBACK, "B", "skills/beta/SKILL.md"),
        ),
      ),
    ).toBeUndefined();
  });
});
