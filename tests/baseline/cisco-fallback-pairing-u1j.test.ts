import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  CiscoAnalyzerFailureV1,
  ciscoSingleSkillReportV1,
} from "../../src/baseline/cisco-analyzer-failures-v1.js";
import {
  assertCiscoSingleSkillAnalyzersCompleteV1,
  assertCiscoSingleSkillReportSkillV1,
  type CiscoSarifResultIdentityV1,
  ciscoSarifResultIdentitiesV1,
} from "../../src/baseline/cisco-report-skills-v1.js";
import { ciscoJobSarifV1 } from "../../src/detectors/cisco-multi-skill/merge-v1.js";

// U1j (review of U1i, P2): on the job and OCI paths a skill_loader failure is the matched
// fallback only when EACH JSON SKILL_LOAD_FALLBACK_USED finding is paired with exactly one
// SARIF result by the D28 identity, JSON (rule_id, id) = SARIF (ruleId,
// fingerprints.primaryLocationLineHash), unique on both sides, and that SARIF result lies in
// the same skill. A rule-name match proves nothing: an unrelated SARIF fallback result, or
// one SARIF result shared by several JSON findings, fails at coverage.

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

const FALLBACK = "SKILL_LOAD_FALLBACK_USED";
const LOADER = [{ analyzer: "skill_loader", error: "SkillLoadError:X" }];
const finding = (id: unknown, file = "SKILL.md") => ({
  id,
  rule_id: FALLBACK,
  file_path: file,
  line_number: null,
});
const report = (findings: unknown[], failures: unknown = LOADER) => ({
  skill_name: "alpha",
  skill_path: "/scan/skills/alpha",
  findings,
  ...(failures === undefined ? {} : { analyzers_failed: failures }),
});
const counterpart = (
  fingerprint: unknown,
  uri: unknown = "skills/alpha/SKILL.md",
  ruleId = FALLBACK,
): CiscoSarifResultIdentityV1 => ({ ruleId, fingerprint, uri });
const decide = (value: Record<string, unknown>, sarif: CiscoSarifResultIdentityV1[]) =>
  failureOf(() => assertCiscoSingleSkillAnalyzersCompleteV1(value, sarif, "skills/alpha"));

describe("the job and OCI fallback is paired by identity (U1j)", () => {
  it("completes a fallback finding paired with its one SARIF counterpart in the skill", () => {
    expect(decide(report([finding(FALLBACK)]), [counterpart(FALLBACK)])).toBeUndefined();
    // Other results never disturb the pairing.
    expect(
      decide(report([finding(FALLBACK)]), [
        counterpart("p-1", "skills/alpha/SKILL.md", "PROMPT"),
        counterpart(FALLBACK),
      ]),
    ).toBeUndefined();
  });

  it("fails coverage for a fallback finding paired only with an unrelated SARIF fallback result (the reviewer's case)", () => {
    expect(decide(report([finding("A")]), [counterpart("B")])).toEqual({
      stage: "coverage",
      message: expect.stringMatching(
        /skill_loader \(SkillLoadError:X\) in skills\/alpha: its SKILL_LOAD_FALLBACK_USED finding \(SKILL_LOAD_FALLBACK_USED, A\) has no SARIF counterpart in that skill$/,
      ),
    });
  });

  it("fails coverage when duplicate JSON fallback findings share one SARIF result (the reviewer's case)", () => {
    expect(decide(report([finding("A"), finding("A")]), [counterpart("A")])).toEqual({
      stage: "coverage",
      message: expect.stringMatching(
        /its SKILL_LOAD_FALLBACK_USED identity \(SKILL_LOAD_FALLBACK_USED, A\) is not unique across the paired reports \(JSON 2, SARIF 1\)$/,
      ),
    });
    // Two distinct findings each need their own counterpart; one pair does not cover both.
    expect(decide(report([finding("A"), finding("B")]), [counterpart("A")])).toMatchObject({
      stage: "coverage",
      message: expect.stringMatching(/\(SKILL_LOAD_FALLBACK_USED, B\) has no SARIF counterpart/),
    });
  });

  it("fails coverage for a duplicated SARIF counterpart, a counterpart in another skill, or a finding with no id", () => {
    for (const [findings, sarif, reason] of [
      [[finding("A")], [counterpart("A"), counterpart("A")], /\(JSON 1, SARIF 2\)$/],
      [
        [finding("A")],
        [counterpart("A", "skills/beta/SKILL.md")],
        /its SKILL_LOAD_FALLBACK_USED finding \(SKILL_LOAD_FALLBACK_USED, A\): its SARIF counterpart names "skills\/beta\/SKILL\.md", which is not in that skill$/,
      ],
      [[finding("A")], [counterpart("A", null)], /which is not in that skill$/],
      [[finding(undefined)], [counterpart(FALLBACK)], /has no string id, so no SARIF counterpart$/],
      [
        [finding(FALLBACK)],
        [counterpart(FALLBACK, "skills/alpha/SKILL.md", "OTHER")],
        /has no SARIF counterpart/,
      ],
    ] as const)
      expect(
        decide(report([...findings]), [...sarif]),
        JSON.stringify([findings, sarif]),
      ).toMatchObject({ stage: "coverage", message: expect.stringMatching(reason) });
  });

  it("still completes with no failed analyzer, whatever the fallback findings", () => {
    const { analyzers_failed: _absent, ...noKey } = report([finding("A"), finding("A")]);
    expect(decide(noKey, [])).toBeUndefined();
    expect(decide(report([finding("A"), finding("A")], []), [])).toBeUndefined();
  });
});

describe("real Cisco 2.1.0 job captures still complete (U1j)", () => {
  // U1i captured on win32 through the installed tarball: the shard jobs
  // `node_modules/ignored-pkg` (corpus multi-skill-nested) and `skills/injected`
  // (proof-semgrep-positive), each reporting the matched skill_loader fallback.
  for (const [name, skill] of [
    ["real-2.1.0-win32-job-ignored-pkg", "node_modules/ignored-pkg"],
    ["real-2.1.0-win32-job-injected", "skills/injected"],
  ] as const)
    it(`completes ${skill}: its fallback pairs by identity with the SARIF result in the job`, () => {
      const fixture = (extension: string) =>
        readFileSync(new URL(`../fixtures/cisco/${name}.${extension}`, import.meta.url));
      const skillPath = `/scan/${skill}`;
      const reportBytes = Buffer.from(
        fixture("report.json").toString("utf8").replace("@SKILL_PATH@", skillPath),
      );
      const job = ciscoJobSarifV1(fixture("sarif"), "/scan", skillPath);
      if (!job.ok) throw new Error(job.detail);
      const parsed = ciscoSingleSkillReportV1(reportBytes, `job ${skill}`);
      const identities = ciscoSarifResultIdentitiesV1(job.log);
      expect(identities.filter((entry) => entry.ruleId === FALLBACK)).toEqual([
        { ruleId: FALLBACK, fingerprint: FALLBACK, uri: `${skill}/skill.md` },
      ]);
      expect(
        failureOf(() => {
          assertCiscoSingleSkillReportSkillV1(parsed, {
            label: `job ${skill}`,
            sourceRoots: ["/scan"],
            skill,
            platform: "linux",
          });
          assertCiscoSingleSkillAnalyzersCompleteV1(parsed, identities, skill);
        }),
      ).toBeUndefined();
      // Rename the SARIF result's identity and the same bytes no longer complete.
      const unrelated = identities.map((entry) =>
        entry.ruleId === FALLBACK ? { ...entry, fingerprint: "unrelated" } : entry,
      );
      expect(
        failureOf(() => assertCiscoSingleSkillAnalyzersCompleteV1(parsed, unrelated, skill)),
      ).toMatchObject({ stage: "coverage" });
    });
});
