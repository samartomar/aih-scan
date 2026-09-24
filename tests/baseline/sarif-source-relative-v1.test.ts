import { describe, expect, it } from "vitest";
import {
  ciscoSourceRelativeSarifV1,
  sourceRelativeSarifV1,
} from "../../src/baseline/sarif-source-relative-v1.js";

const result = (uri: string, extra: Record<string, unknown> = {}) => ({
  ruleId: "semgrep.prompt-injection",
  level: "warning",
  message: { text: "prompt injection shape in trust content" },
  locations: [
    {
      physicalLocation: {
        artifactLocation: { uri, uriBaseId: "%SRCROOT%" },
        region: { startLine: 2 },
      },
    },
  ],
  ...extra,
});
const sarif = (...results: unknown[]) => ({
  version: "2.1.0",
  runs: [{ tool: { driver: { name: "semgrep" } }, results }],
});
const uris = (document: Record<string, unknown>) =>
  (
    (
      document.runs as {
        results: { locations: { physicalLocation: { artifactLocation: { uri: string } } }[] }[];
      }[]
    )[0]?.results ?? []
  ).map((entry) => entry.locations[0]?.physicalLocation.artifactLocation.uri);

describe("sourceRelativeSarifV1", () => {
  it("makes Semgrep's absolute Windows paths relative, with forward slashes", () => {
    const root = "C:\\Users\\me\\AppData\\Local\\Temp\\aih-scan-baseline-source-AbC123";
    const document = sarif(
      result(`${root}\\skills\\demo\\SKILL.md`),
      result(`${root.toLowerCase()}\\NOTES.md`),
    );

    const normalized = sourceRelativeSarifV1(document, [root]);

    expect(uris(normalized.document)).toEqual(["skills/demo/SKILL.md", "NOTES.md"]);
    expect(normalized.rewritten).toBe(2);
    expect(JSON.stringify(normalized.document)).not.toContain("aih-scan-baseline-source");
  });

  it("accepts either spelling of a Windows temporary root, such as an 8.3 short path", () => {
    const short = "C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\aih-scan-baseline-source-x1";
    const long = "C:\\Users\\runneradmin\\AppData\\Local\\Temp\\aih-scan-baseline-source-x1";
    const normalized = sourceRelativeSarifV1(
      sarif(result(`${long}\\a.md`), result(`${short}\\b.md`)),
      [short, long],
    );
    expect(uris(normalized.document)).toEqual(["a.md", "b.md"]);
  });

  it("strips the namespace mount and file:// URIs, and keeps already relative paths", () => {
    const normalized = sourceRelativeSarifV1(
      sarif(
        result("/aih/source/skills/x/SKILL.md"),
        result("file:///tmp/aih-scan-baseline-source-q/a%20b.md"),
        result("./README.md"),
        result("docs/guide.md"),
      ),
      ["/aih/source", "/tmp/aih-scan-baseline-source-q"],
    );
    expect(uris(normalized.document)).toEqual([
      "skills/x/SKILL.md",
      "a b.md",
      "README.md",
      "docs/guide.md",
    ]);
  });

  it("rewrites run artifacts and drops base URIs that point into the private root", () => {
    const document = {
      version: "2.1.0",
      runs: [
        {
          tool: { driver: { name: "x" } },
          originalUriBaseIds: { "%SRCROOT%": { uri: "file:///aih/source/" } },
          artifacts: [{ location: { uri: "/aih/source/a.md" } }],
          results: [result("/aih/source/a.md")],
        },
      ],
    };
    const normalized = sourceRelativeSarifV1(document, ["/aih/source"]);
    const run = (normalized.document.runs as Record<string, unknown>[])[0];
    expect(run?.originalUriBaseIds).toBeUndefined();
    expect(run?.artifacts).toEqual([{ location: { uri: "a.md" } }]);
    expect(normalized.removedBaseUris).toBe(1);
  });

  it.each([
    ["an absolute path outside the source root", "/etc/passwd"],
    ["another drive", "D:\\elsewhere\\a.md"],
    ["a parent escape", "../outside.md"],
    ["the root itself", "/aih/source"],
    ["a file URL with an authority", "file://host/aih/source/a.md"],
    ["an encoded parent escape", "file:///aih/source/%2e%2e/x"],
    ["an empty URI", ""],
  ])("refuses %s rather than guessing", (_label, uri) => {
    expect(() => sourceRelativeSarifV1(sarif(result(uri)), ["/aih/source"])).toThrow(
      /artifact URI/,
    );
  });

  it("does not modify the document it was given", () => {
    const document = sarif(result("/aih/source/a.md"));
    const before = JSON.stringify(document);
    sourceRelativeSarifV1(document, ["/aih/source"]);
    expect(JSON.stringify(document)).toBe(before);
  });
});

describe("ciscoSourceRelativeSarifV1", () => {
  const root = "C:\\Temp\\aih-scan-baseline-source-z9";
  const cisco = (...entries: [string, string, number | undefined][]) => ({
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "skill-scanner" } },
        results: entries.map(([ruleId, uri, startLine]) => ({
          ruleId,
          level: "error",
          message: { text: ruleId },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri, uriBaseId: "%SRCROOT%" },
                ...(startLine === undefined ? {} : { region: { startLine } }),
              },
            },
          ],
        })),
      },
    ],
  });
  const report = (...skills: [string, [string, string, number | null][]][]) => ({
    summary: { total_skills_scanned: skills.length },
    results: skills.map(([skillPath, findings]) => ({
      skill_path: skillPath,
      findings: findings.map(([ruleId, filePath, line]) => ({
        rule_id: ruleId,
        file_path: filePath,
        line_number: line,
      })),
    })),
  });

  it("prefixes each result with the directory of the skill that reported it", () => {
    const normalized = ciscoSourceRelativeSarifV1(
      cisco(
        ["MANIFEST_MISSING_LICENSE", "SKILL.md", undefined],
        ["YARA_prompt_injection_generic", "skills/injected/SKILL.md", 8],
        ["YARA_prompt_injection_generic", "SKILL.md", 3],
      ),
      report(
        [
          root,
          [
            ["MANIFEST_MISSING_LICENSE", "SKILL.md", null],
            ["YARA_prompt_injection_generic", "skills\\injected\\SKILL.md", 8],
          ],
        ],
        [`${root}\\skills\\injected`, [["YARA_prompt_injection_generic", "SKILL.md", 3]]],
      ),
      [root],
    );

    expect(uris(normalized.document)).toEqual([
      "SKILL.md",
      "skills/injected/SKILL.md",
      "skills/injected/SKILL.md",
    ]);
  });

  it("maps the namespace profile's mounted skill paths the same way", () => {
    const normalized = ciscoSourceRelativeSarifV1(
      cisco(["R", "notes.md", 1]),
      report(["/aih/source/skills/a", [["R", "notes.md", 1]]]),
      ["/aih/source"],
    );
    expect(uris(normalized.document)).toEqual(["skills/a/notes.md"]);
  });

  it.each([
    ["a count mismatch", cisco(["R", "SKILL.md", 1]), report([root, []])],
    ["a rule mismatch", cisco(["R", "SKILL.md", 1]), report([root, [["S", "SKILL.md", 1]]])],
    ["a path mismatch", cisco(["R", "SKILL.md", 1]), report([root, [["R", "OTHER.md", 1]]])],
    ["a line mismatch", cisco(["R", "SKILL.md", 1]), report([root, [["R", "SKILL.md", 2]]])],
    [
      "a skill outside the root",
      cisco(["R", "SKILL.md", 1]),
      report(["C:\\elsewhere", [["R", "SKILL.md", 1]]]),
    ],
  ])("fails closed on %s between the SARIF and JSON reports", (_label, document, json) => {
    expect(() => ciscoSourceRelativeSarifV1(document, json, [root])).toThrow(/Cisco/);
  });
});
