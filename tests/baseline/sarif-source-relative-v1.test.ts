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

  const based = (
    baseIds: Record<string, unknown> | undefined,
    uri: string,
    uriBaseId: string,
  ): Record<string, unknown> => ({
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "x" } },
        ...(baseIds === undefined ? {} : { originalUriBaseIds: baseIds }),
        results: [
          {
            ruleId: "r",
            message: { text: "m" },
            locations: [{ physicalLocation: { artifactLocation: { uri, uriBaseId } } }],
          },
        ],
      },
    ],
  });
  const artifactLocation = (document: Record<string, unknown>) =>
    (
      document.runs as {
        results: { locations: { physicalLocation: { artifactLocation: unknown } }[] }[];
      }[]
    )[0]?.results[0]?.locations[0]?.physicalLocation.artifactLocation;

  it("refuses a relative URI whose declared base lies outside the source root", () => {
    expect(() =>
      sourceRelativeSarifV1(
        based({ EXTERNAL: { uri: "file:///outside/" } }, "SKILL.md", "EXTERNAL"),
        ["/scan"],
      ),
    ).toThrow(/outside the declared source root/);
    expect(() =>
      sourceRelativeSarifV1(
        based({ "%SRCROOT%": { uri: "file:///outside/" } }, "SKILL.md", "%SRCROOT%"),
        ["/scan"],
      ),
    ).toThrow(/outside the declared source root/);
  });

  it("refuses an undeclared base other than %SRCROOT%, a base cycle and a malformed base", () => {
    expect(() => sourceRelativeSarifV1(based(undefined, "SKILL.md", "NOPE"), ["/scan"])).toThrow(
      /base NOPE/,
    );
    expect(() =>
      sourceRelativeSarifV1(
        based({ A: { uri: "a/", uriBaseId: "B" }, B: { uri: "b/", uriBaseId: "A" } }, "x.md", "A"),
        ["/scan"],
      ),
    ).toThrow(/base A/);
    expect(() =>
      sourceRelativeSarifV1(based({ REL: { uri: "sub/" } }, "x.md", "REL"), ["/scan"]),
    ).toThrow(/base REL/);
    expect(() =>
      sourceRelativeSarifV1(based({ BAD: { uri: 7 } }, "x.md", "BAD"), ["/scan"]),
    ).toThrow(/base BAD/);
  });

  it("resolves declared and chained bases inside the root, then drops the obsolete references", () => {
    const direct = sourceRelativeSarifV1(
      based({ SRC: { uri: "file:///scan/skills/" } }, "x/SKILL.md", "SRC"),
      ["/scan"],
    );
    expect(artifactLocation(direct.document)).toEqual({ uri: "skills/x/SKILL.md" });

    const chained = sourceRelativeSarifV1(
      based(
        { ROOT: { uri: "file:///C:/Scan/" }, SKILLS: { uri: "skills/", uriBaseId: "ROOT" } },
        "a.md",
        "SKILLS",
      ),
      ["C:\\scan"],
    );
    expect(artifactLocation(chained.document)).toEqual({ uri: "skills/a.md" });

    // An undeclared %SRCROOT% means the root the analyzer was given, and still does.
    const conventional = sourceRelativeSarifV1(based(undefined, "SKILL.md", "%SRCROOT%"), [
      "/scan",
    ]);
    expect(artifactLocation(conventional.document)).toEqual({
      uri: "SKILL.md",
      uriBaseId: "%SRCROOT%",
    });
    // A base cannot move an absolute URI, which is checked on its own.
    expect(() =>
      sourceRelativeSarifV1(
        based({ SRC: { uri: "file:///scan/" } }, "file:///outside/x.md", "SRC"),
        ["/scan"],
      ),
    ).toThrow(/outside the declared source root/);
  });

  it("resolves a relative reference against its base before percent-decoding once", () => {
    const spaced = sourceRelativeSarifV1(
      based({ SRC: { uri: "file:///scan/" } }, "a%20b.md", "SRC"),
      ["/scan"],
    );
    expect(artifactLocation(spaced.document)).toEqual({ uri: "a b.md" });
    const nested = sourceRelativeSarifV1(
      based({ SRC: { uri: "file:///scan/my%20skills/" } }, "x%2Fy.md", "SRC"),
      ["/scan"],
    );
    expect(artifactLocation(nested.document)).toEqual({ uri: "my skills/x/y.md" });
    // Decoding happens once: %2520 is a literal "%20" in the name (which the safe-path
    // rule refuses), never a second decoding to "a b.md".
    expect(() =>
      sourceRelativeSarifV1(based({ SRC: { uri: "file:///scan/" } }, "a%2520b.md", "SRC"), [
        "/scan",
      ]),
    ).toThrow(/safe path/);
    // Containment is enforced on the decoded result.
    expect(() =>
      sourceRelativeSarifV1(based({ SRC: { uri: "file:///scan/" } }, "%2E%2E/x.md", "SRC"), [
        "/scan",
      ]),
    ).toThrow(/safe path|outside/);
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

  const basedCisco = (
    baseIds: Record<string, unknown> | undefined,
    uri: string,
    uriBaseId: string,
  ) => {
    const document = cisco(["R", uri, 1]);
    const run = document.runs[0] as unknown as Record<string, unknown> & {
      results: {
        locations: { physicalLocation: { artifactLocation: Record<string, unknown> } }[];
      }[];
    };
    if (baseIds !== undefined) run.originalUriBaseIds = baseIds;
    const artifact = run.results[0]?.locations[0]?.physicalLocation.artifactLocation;
    if (artifact !== undefined) artifact.uriBaseId = uriBaseId;
    return document;
  };

  it.each([
    ["a base outside the root", { EXTERNAL: { uri: "file:///outside/" } }, "EXTERNAL"],
    [
      "a declared %SRCROOT% outside the root",
      { "%SRCROOT%": { uri: "file:///outside/" } },
      "%SRCROOT%",
    ],
    ["an undeclared base", undefined, "EXTERNAL"],
    ["a cyclic base", { A: { uri: "a/", uriBaseId: "B" }, B: { uri: "b/", uriBaseId: "A" } }, "A"],
    ["a relative base naming no base", { REL: { uri: "sub/" } }, "REL"],
    [
      "a base inside the root naming another file than the JSON finding",
      { OTHER: { uri: "file:///scan/elsewhere/" } },
      "OTHER",
    ],
  ])("validates each Cisco location's base: fails closed on %s", (_label, baseIds, baseId) => {
    expect(() =>
      ciscoSourceRelativeSarifV1(
        basedCisco(baseIds, "SKILL.md", baseId),
        report(["/scan", [["R", "SKILL.md", 1]]]),
        ["/scan"],
      ),
    ).toThrow(/Cisco/);
  });

  it("accepts a declared Cisco base that resolves to the paired JSON finding", () => {
    const normalized = ciscoSourceRelativeSarifV1(
      basedCisco({ SKILL: { uri: "file:///scan/skills/a/" } }, "SKILL.md", "SKILL"),
      report(["/scan/skills/a", [["R", "SKILL.md", 1]]]),
      ["/scan"],
    );
    expect(uris(normalized.document)).toEqual(["skills/a/SKILL.md"]);
    const spaced = ciscoSourceRelativeSarifV1(
      basedCisco({ SKILL: { uri: "file:///scan/skills/a/" } }, "my%20notes.md", "SKILL"),
      report(["/scan/skills/a", [["R", "my notes.md", 1]]]),
      ["/scan"],
    );
    expect(uris(spaced.document)).toEqual(["skills/a/my notes.md"]);
  });
});
