import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  bindCiscoSarifToSealedFilesV1,
  unboundCiscoSarifResultV1,
} from "../../src/baseline/cisco-sealed-case-binding-v1.js";
import { ciscoSourceRelativeSarifV1 } from "../../src/baseline/sarif-source-relative-v1.js";

// Coordinator decision D28 (U1h): Cisco 2.1.0 reports some findings about a whole skill with
// `"file_path": null` (LOW_ANALYZABILITY on a skill with opaque files). Such a finding is
// accepted only as a skill-level finding at the reporting skill's own SKILL.md, and only when
// its pairing is bijective: JSON (rule_id, id) <-> SARIF (ruleId,
// fingerprints.primaryLocationLineHash), unique on both sides across the paired reports, and
// the SARIF counterpart's own location resolves, through every location, index and D1 rule,
// to that SKILL.md. Scan never generates the location. The pairing proves no analysis:
// completion is decided exactly as before (the runner tests pin it).

// Real skill-scanner 2.1.0 output on win32 for the golden `malformed` case (U1g real-output
// capture); the one machine path, the scanned snapshot, is @SKILL_PATH@.
const REAL_REPORT = readFileSync(
  new URL("../fixtures/cisco/real-2.1.0-win32-malformed.report.json", import.meta.url),
  "utf8",
);
const REAL_SARIF = readFileSync(
  new URL("../fixtures/cisco/real-2.1.0-win32-malformed.sarif", import.meta.url),
  "utf8",
);
/** The golden `malformed` tree's files, the subject the capture analyzed. */
const MALFORMED_FILES = [
  ".mcp.json",
  "SKILL.md",
  "agents/bad.md",
  "assets/blob.bin",
  "docs/latin1.md",
  "package.json",
  "scripts/install-data.bin",
  "settings.json",
];

type Log = {
  runs: {
    results: {
      ruleId: string;
      fingerprints?: Record<string, unknown>;
      locations: { physicalLocation: { artifactLocation: Record<string, unknown> } }[];
    }[];
  }[];
};
type Report = {
  results: { skill_path: string; findings: Record<string, unknown>[] }[];
};

const realReport = (skillPath: string): Report =>
  JSON.parse(REAL_REPORT.replaceAll("@SKILL_PATH@", JSON.stringify(skillPath).slice(1, -1)));
const realSarif = (): Log => JSON.parse(REAL_SARIF);
const uris = (document: Record<string, unknown>) =>
  (document as Log).runs[0]?.results.map(
    (result) =>
      `${result.ruleId} ${String(result.locations[0]?.physicalLocation.artifactLocation.uri)}`,
  );

describe("Cisco skill-level findings with file_path null (D28, real bytes)", () => {
  it("accepts LOW_ANALYZABILITY as a skill-level finding at the skill's own SKILL.md", () => {
    const report = realReport("/scan");
    const normalized = ciscoSourceRelativeSarifV1(realSarif(), report, ["/scan"]);
    expect(uris(normalized.document)?.[0]).toBe("LOW_ANALYZABILITY SKILL.md");
    // The rest of the real run is unchanged by D28; on win32 D1 then binds Cisco's normcased
    // skill.md to the sealed SKILL.md, and every location names a sealed file of the subject.
    const bound = bindCiscoSarifToSealedFilesV1(normalized.document, MALFORMED_FILES, "win32");
    expect(uris(bound.document)).toEqual([
      "LOW_ANALYZABILITY SKILL.md",
      "UNANALYZABLE_BINARY assets/blob.bin",
      "BINARY_FILE_DETECTED assets/blob.bin",
      "BINARY_FILE_DETECTED docs/latin1.md",
      "UNANALYZABLE_BINARY scripts/install-data.bin",
      "BINARY_FILE_DETECTED scripts/install-data.bin",
      "FILE_MAGIC_MISMATCH SKILL.md",
      "SKILL_LOAD_FALLBACK_USED SKILL.md",
    ]);
    expect(
      unboundCiscoSarifResultV1(bound.document, new Set(MALFORMED_FILES), "subject"),
    ).toBeUndefined();
    // The report still says the skill loader failed; D28 neither reads nor changes it.
    expect(JSON.stringify(report)).toContain('"analyzers_failed":[{"analyzer":"skill_loader"');
  });

  it("accepts it in a nested skill, at that skill's SKILL.md", () => {
    const report = realReport("/scan/skills/opaque");
    const normalized = ciscoSourceRelativeSarifV1(realSarif(), report, ["/scan"]);
    expect(uris(normalized.document)?.[0]).toBe("LOW_ANALYZABILITY skills/opaque/SKILL.md");
  });
});

describe("Cisco skill-level findings: refusals (D28)", () => {
  const scan = (sarif: unknown, report: unknown) =>
    ciscoSourceRelativeSarifV1(sarif as Record<string, unknown>, report as Report, ["/scan"]);

  it("refuses a skill-level finding with no SARIF counterpart", () => {
    const report = realReport("/scan");
    for (const fingerprints of [
      { primaryLocationLineHash: "LOW_ANALYZABILITY_OTHER" },
      {},
      undefined,
    ]) {
      const sarif = realSarif();
      const first = sarif.runs[0]?.results[0];
      if (first === undefined) throw new Error("fixture");
      if (fingerprints === undefined) delete first.fingerprints;
      else first.fingerprints = fingerprints;
      expect(() => scan(sarif, report), JSON.stringify(fingerprints)).toThrow(
        /skill-level .*has no SARIF counterpart/,
      );
    }
    // A counterpart of another rule is no counterpart either.
    const sarif = realSarif();
    const first = sarif.runs[0]?.results[0];
    if (first !== undefined) first.ruleId = "OTHER";
    expect(() => scan(sarif, report)).toThrow(/does not match|no SARIF counterpart/);
  });

  it("refuses a skill-level finding without a string id, or with a line", () => {
    for (const change of [{ id: undefined }, { id: 7 }, { line_number: 3 }]) {
      const report = realReport("/scan");
      Object.assign(report.results[0]?.findings[0] ?? {}, change);
      if ("id" in change && change.id === undefined) delete report.results[0]?.findings[0]?.id;
      expect(() => scan(realSarif(), report), JSON.stringify(change)).toThrow(
        /JSON report finding is malformed|skill-level finding 0 .*(no string id|a line)/,
      );
    }
  });

  // Two skills, each with one skill-level finding; `sarifUri(skill)` is its counterpart.
  const twoSkills = (
    sarifUri: (skill: string) => Record<string, unknown>,
    ids: [string, string] = ["LOW_ANALYZABILITY_CRITICAL", "LOW_ANALYZABILITY_CRITICAL"],
  ) => {
    const skills = ["alpha", "beta"];
    const report = {
      summary: { total_skills_scanned: 2 },
      results: skills.map((skill, index) => ({
        skill_path: `/scan/skills/${skill}`,
        findings: [
          { id: ids[index], rule_id: "LOW_ANALYZABILITY", file_path: null, line_number: null },
        ],
      })),
    };
    const sarif = {
      version: "2.1.0",
      runs: [
        {
          tool: { driver: { name: "skill-scanner" } },
          originalUriBaseIds: { ROOT: { uri: "file:///scan/" } },
          results: skills.map((skill, index) => ({
            ruleId: "LOW_ANALYZABILITY",
            message: { text: "low analyzability" },
            fingerprints: { primaryLocationLineHash: ids[index] },
            locations: [{ physicalLocation: { artifactLocation: sarifUri(skill) } }],
          })),
        },
      ],
    };
    return { sarif, report };
  };

  it("refuses a duplicate identity across skills that nothing disambiguates", () => {
    const { sarif, report } = twoSkills(() => ({ uri: "SKILL.md", uriBaseId: "%SRCROOT%" }));
    expect(() => scan(sarif, report)).toThrow(
      /\(LOW_ANALYZABILITY, LOW_ANALYZABILITY_CRITICAL\) is not unique/,
    );
  });

  it("refuses a duplicate identity even when each counterpart names its own skill through a base (U1i)", () => {
    // The analyzer supplies the base, so it cannot disambiguate an identity D28 requires to be
    // unique: (rule_id, id) must occur exactly once among the JSON findings and exactly once
    // among the SARIF results (review of U1h, P2).
    const { sarif, report } = twoSkills((skill) => ({
      uri: `skills/${skill}/SKILL.md`,
      uriBaseId: "ROOT",
    }));
    expect(() => scan(sarif, report)).toThrow(
      /\(LOW_ANALYZABILITY, LOW_ANALYZABILITY_CRITICAL\) is not unique across the paired reports \(JSON 2, SARIF 2\)$/,
    );
  });

  it("still accepts two skills whose skill-level identities differ", () => {
    const { sarif, report } = twoSkills(
      (skill) => ({
        uri: `skills/${skill}/SKILL.md`,
        uriBaseId: "ROOT",
      }),
      ["A", "B"],
    );
    expect(uris(scan(sarif, report).document)).toEqual([
      "LOW_ANALYZABILITY skills/alpha/SKILL.md",
      "LOW_ANALYZABILITY skills/beta/SKILL.md",
    ]);
  });

  it("refuses an identity duplicated on one side only", () => {
    // JSON ids differ; the SARIF fingerprints do not: the SARIF side is not unique.
    const { sarif, report } = twoSkills(
      () => ({ uri: "SKILL.md", uriBaseId: "%SRCROOT%" }),
      ["A", "B"],
    );
    const second = sarif.runs[0]?.results[1];
    if (second !== undefined) second.fingerprints = { primaryLocationLineHash: "A" };
    expect(() => scan(sarif, report)).toThrow(/is not unique|no SARIF counterpart/);
  });

  it("refuses a counterpart in a sibling skill", () => {
    const { sarif, report } = twoSkills(
      () => ({ uri: "skills/beta/SKILL.md", uriBaseId: "ROOT" }),
      ["A", "B"],
    );
    expect(() => scan(sarif, report)).toThrow(
      /skill-level finding 0 .*names skills\/beta\/SKILL\.md, not the reporting skill's skills\/alpha\/SKILL\.md/,
    );
  });

  it("refuses a counterpart at a file other than the skill's manifest", () => {
    for (const artifactLocation of [
      { uri: "README.md" },
      { uri: "skill.md" },
      { uri: "skills/alpha/README.md", uriBaseId: "ROOT" },
    ]) {
      const { sarif, report } = twoSkills(() => artifactLocation, ["A", "B"]);
      expect(() => scan(sarif, report), JSON.stringify(artifactLocation)).toThrow(
        /skill-level finding 0 .*not the reporting skill's skills\/alpha\/SKILL\.md/,
      );
    }
  });

  it("keeps every location and index rule for the counterpart", () => {
    // A further location of the counterpart in a sibling skill fails as for any result.
    const { sarif, report } = twoSkills(() => ({ uri: "SKILL.md" }), ["A", "B"]);
    const first = sarif.runs[0]?.results[0] as Record<string, unknown>;
    first.relatedLocations = [
      {
        physicalLocation: { artifactLocation: { uri: "skills/beta/SKILL.md", uriBaseId: "ROOT" } },
      },
    ];
    expect(() => scan(sarif, report)).toThrow(/not in the reporting skill skills\/alpha/);
    // An index beside the URI must name the same artifact.
    const indexed = twoSkills(() => ({ uri: "SKILL.md", index: 0 }), ["A", "B"]);
    (indexed.sarif.runs[0] as Record<string, unknown>).artifacts = [
      { location: { uri: "skills/beta/README.md", uriBaseId: "ROOT" } },
    ];
    expect(() => scan(indexed.sarif, indexed.report)).toThrow(/disagree/);
  });
});
