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

// S2g (W2 phase B finding 1): the pinned SkillSpector image reports a directory it skipped as
// a tool-execution notification whose location URI is `node_modules/`, modelled here on its
// captured hidden-file note. A contained directory URI (trailing slash) is accepted on
// notification and run-artifact locations only, keeping its trailing slash; result locations
// must still name files, and every traversal and base rule still applies.
describe("directory URIs on notification and artifact locations (S2g)", () => {
  const skipped = (uri: string, key = "toolExecutionNotifications") => ({
    level: "note",
    locations: [{ physicalLocation: { artifactLocation: { uri } } }],
    message: { text: "Directory is excluded from the configured scan scope." },
    properties: { fatal: false, outcome: "out_of_scope", phase: "discovery" },
    ...(key === "toolExecutionNotifications" ? {} : { descriptor: { id: "skip" } }),
  });
  const skillspector = (
    notifications: unknown[],
    extra: Record<string, unknown> = {},
    key = "toolExecutionNotifications",
  ) => ({
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "SkillSpector" } },
        invocations: [{ executionSuccessful: true, [key]: notifications }],
        results: [result("/scan/SKILL.md")],
        ...extra,
      },
    ],
  });
  type Run = {
    invocations: {
      [key: string]: { locations: { physicalLocation: { artifactLocation: { uri: string } } }[] }[];
    }[];
    artifacts?: { location: { uri: string } }[];
  };
  const notificationUris = (
    document: Record<string, unknown>,
    key = "toolExecutionNotifications",
  ) =>
    ((document.runs as Run[])[0]?.invocations[0]?.[key] ?? []).map(
      (entry) => entry.locations[0]?.physicalLocation.artifactLocation.uri,
    );

  it("keeps the exact SkillSpector skipped-directory notification (W2 phase B finding 1)", () => {
    const normalized = sourceRelativeSarifV1(skillspector([skipped("node_modules/")]), ["/scan"]);
    expect(notificationUris(normalized.document)).toEqual(["node_modules/"]);
    expect(uris(normalized.document)).toEqual(["SKILL.md"]);
  });

  it("relates the mounted, file: and nested directory spellings to the source root", () => {
    const normalized = sourceRelativeSarifV1(
      skillspector([
        skipped("/scan/node_modules/"),
        skipped("file:///scan/vendor/"),
        skipped("skills/demo/node_modules/"),
        skipped("./dist/"),
      ]),
      ["/scan"],
    );
    expect(notificationUris(normalized.document)).toEqual([
      "node_modules/",
      "vendor/",
      "skills/demo/node_modules/",
      "dist/",
    ]);
    const configuration = sourceRelativeSarifV1(
      skillspector(
        [skipped("/scan/.git/", "toolConfigurationNotifications")],
        {},
        "toolConfigurationNotifications",
      ),
      ["/scan"],
    );
    expect(notificationUris(configuration.document, "toolConfigurationNotifications")).toEqual([
      ".git/",
    ]);
  });

  it("accepts a contained directory on a run artifact's location", () => {
    const normalized = sourceRelativeSarifV1(
      skillspector([], { artifacts: [{ location: { uri: "/scan/node_modules/" } }] }),
      ["/scan"],
    );
    expect((normalized.document.runs as Run[])[0]?.artifacts?.[0]?.location.uri).toBe(
      "node_modules/",
    );
  });

  it("refuses hostile directory URIs on a notification", () => {
    for (const uri of [
      "../",
      "../outside/",
      "node_modules/../../",
      "/etc/",
      "/scan/../etc/",
      "file:///scan/%2E%2E/%2E%2E/etc/",
      "file:///etc/",
      "%2E%2E/",
      "node_modules//",
      "/scan/",
      "./",
      "/",
      "C:/Windows/",
      "node_modules\\",
    ])
      expect(() => sourceRelativeSarifV1(skillspector([skipped(uri)]), ["/scan"]), uri).toThrow(
        /SARIF artifact URI/,
      );
  });

  it("still requires every result location to name a file, never a directory", () => {
    for (const uri of ["node_modules/", "/scan/node_modules/", "file:///scan/SKILL.md/"])
      expect(() => sourceRelativeSarifV1(sarif(result(uri)), ["/scan"]), uri).toThrow(/safe path/);
    const related = {
      ...result("/scan/SKILL.md"),
      relatedLocations: [
        { physicalLocation: { artifactLocation: { uri: "/scan/node_modules/" } } },
      ],
    };
    expect(() => sourceRelativeSarifV1(sarif(related), ["/scan"])).toThrow(/safe path/);
  });

  it("keeps directories out of a notification nested in a result", () => {
    const nested = sarif({
      ...result("/scan/SKILL.md"),
      toolExecutionNotifications: [skipped("node_modules/")],
    });
    expect(() => sourceRelativeSarifV1(nested, ["/scan"])).toThrow(/safe path/);
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

  // S2f sweep: a run without a results list is never skipped, even beside a run that has one.
  it("fails a run that holds no results list instead of skipping it", () => {
    const document = cisco(["R", "SKILL.md", 1]);
    const withBare = { ...document, runs: [...document.runs, { tool: document.runs[0]?.tool }] };
    expect(() =>
      ciscoSourceRelativeSarifV1(withBare, report([root, [["R", "SKILL.md", 1]]]), [root]),
    ).toThrow(/Cisco.*results list is malformed/);
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

  // U1e review P2: Cisco writes every location relative to the skill it scanned, so a
  // related location belongs to its result's paired skill, never to the source root.
  const withRelated = (related: unknown[], extra: Record<string, unknown> = {}) => {
    const document = cisco(["R", "SKILL.md", 1]);
    const run = document.runs[0] as unknown as Record<string, unknown> & {
      results: Record<string, unknown>[];
    };
    const first = run.results[0] as Record<string, unknown>;
    first.relatedLocations = related;
    Object.assign(run, extra);
    return document;
  };
  const relatedUris = (document: Record<string, unknown>) =>
    (
      (
        document.runs as {
          results: {
            relatedLocations?: { physicalLocation: { artifactLocation: { uri: string } } }[];
          }[];
        }[]
      )[0]?.results[0]?.relatedLocations ?? []
    ).map((entry) => entry.physicalLocation.artifactLocation.uri);
  const related = (uri: string, uriBaseId?: string) => ({
    physicalLocation: {
      artifactLocation: { uri, ...(uriBaseId === undefined ? {} : { uriBaseId }) },
    },
  });

  it("resolves a related location against its result's paired skill (U1e review P2)", () => {
    const normalized = ciscoSourceRelativeSarifV1(
      withRelated([related("guide.md"), related("refs/notes.md", "%SRCROOT%")]),
      report(["/scan/skills/a", [["R", "SKILL.md", 1]]]),
      ["/scan"],
    );
    expect(uris(normalized.document)).toEqual(["skills/a/SKILL.md"]);
    expect(relatedUris(normalized.document)).toEqual([
      "skills/a/guide.md",
      "skills/a/refs/notes.md",
    ]);
  });

  it.each([
    ["an escaping related location", "../outside.md"],
    ["an absolute related location", "/etc/passwd"],
    ["a drive-letter related location", "C:/Windows/win.ini"],
  ])("fails closed on %s", (_label, uri) => {
    expect(() =>
      ciscoSourceRelativeSarifV1(
        withRelated([related(uri)]),
        report(["/scan/skills/a", [["R", "SKILL.md", 1]]]),
        ["/scan"],
      ),
    ).toThrow(/Cisco/);
  });

  it("refuses a run artifact location whose skill context cannot be established", () => {
    expect(() =>
      ciscoSourceRelativeSarifV1(
        withRelated([], { artifacts: [{ location: { uri: "guide.md", uriBaseId: "%SRCROOT%" } }] }),
        report(["/scan/skills/a", [["R", "SKILL.md", 1]]]),
        ["/scan"],
      ),
    ).toThrow(/Cisco.*no skill/);
    expect(() =>
      ciscoSourceRelativeSarifV1(
        withRelated([], { artifacts: [{ location: { uri: "guide.md" } }] }),
        report(["/scan/skills/a", [["R", "SKILL.md", 1]]]),
        ["/scan"],
      ),
    ).toThrow(/Cisco.*no skill/);
  });

  it("keeps a run artifact location whose base resolves inside the source root", () => {
    const normalized = ciscoSourceRelativeSarifV1(
      withRelated([], {
        originalUriBaseIds: { SRC: { uri: "file:///scan/" } },
        artifacts: [{ location: { uri: "skills/a/guide.md", uriBaseId: "SRC" } }],
      }),
      report(["/scan/skills/a", [["R", "SKILL.md", 1]]]),
      ["/scan"],
    );
    const run = (normalized.document.runs as { artifacts: { location: { uri: string } }[] }[])[0];
    expect(run?.artifacts.map((artifact) => artifact.location.uri)).toEqual(["skills/a/guide.md"]);
  });
});

// S2i (review of S2h): a result's `analysisTarget` is an artifact location, so it is
// normalized exactly like every other one: its base resolved, its URI related to the root.
describe("analysisTarget is normalized like every other artifact location (S2i)", () => {
  const targeted = (analysisTarget: unknown, run: Record<string, unknown> = {}) => ({
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "x" } },
        ...run,
        results: [{ ...result("/scan/skills/a/SKILL.md"), analysisTarget }],
      },
    ],
  });
  const target = (document: Record<string, unknown>) =>
    (document.runs as { results: { analysisTarget: unknown }[] }[])[0]?.results[0]?.analysisTarget;

  it("relates an absolute or file: analysis target to the source root", () => {
    expect(
      target(sourceRelativeSarifV1(targeted({ uri: "/scan/a.md" }), ["/scan"]).document),
    ).toEqual({ uri: "a.md" });
    expect(
      target(sourceRelativeSarifV1(targeted({ uri: "file:///scan/b%20c.md" }), ["/scan"]).document),
    ).toEqual({ uri: "b c.md" });
  });

  it("resolves an analysis target's base, then drops the obsolete reference", () => {
    const normalized = sourceRelativeSarifV1(
      targeted(
        { uri: "SKILL.md", uriBaseId: "SKILL" },
        {
          originalUriBaseIds: { SKILL: { uri: "file:///scan/skills/a/" } },
        },
      ),
      ["/scan"],
    );
    expect(target(normalized.document)).toEqual({ uri: "skills/a/SKILL.md" });
  });

  it("fails closed on an analysis target outside the root, escaping it or on a bad base", () => {
    for (const analysisTarget of [
      { uri: "/elsewhere/a.md" },
      { uri: "../a.md" },
      { uri: "/scan" },
      { uri: 7 },
      { uri: "a.md", uriBaseId: "NOPE" },
      { index: 0, uriBaseId: "NOPE" },
    ])
      expect(() => sourceRelativeSarifV1(targeted(analysisTarget), ["/scan"])).toThrow(
        /artifact URI|artifact uriBaseId/,
      );
    expect(() =>
      sourceRelativeSarifV1(
        targeted(
          { uri: "a.md", uriBaseId: "OUT" },
          {
            originalUriBaseIds: { OUT: { uri: "file:///outside/" } },
          },
        ),
        ["/scan"],
      ),
    ).toThrow(/outside the declared source root/);
  });

  it("prefixes a Cisco analysis target with its skill's directory, as its locations are", () => {
    const document = {
      version: "2.1.0",
      runs: [
        {
          tool: { driver: { name: "skill-scanner" } },
          results: [
            {
              ruleId: "R",
              message: { text: "R" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: "SKILL.md", uriBaseId: "%SRCROOT%" },
                    region: { startLine: 1 },
                  },
                },
              ],
              analysisTarget: { uri: "SKILL.md", uriBaseId: "%SRCROOT%" },
            },
          ],
        },
      ],
    };
    const report = {
      results: [
        {
          skill_path: "/scan/skills/a",
          findings: [{ rule_id: "R", file_path: "SKILL.md", line_number: 1 }],
        },
      ],
    };
    const normalized = ciscoSourceRelativeSarifV1(document, report, ["/scan"]);
    expect(target(normalized.document)).toEqual({
      uri: "skills/a/SKILL.md",
      uriBaseId: "%SRCROOT%",
    });
    const run = document.runs[0] as { originalUriBaseIds?: unknown };
    const escaping = structuredClone(document);
    (escaping.runs[0]?.results[0] as { analysisTarget: unknown }).analysisTarget = {
      uri: "SKILL.md",
      uriBaseId: "OUT",
    };
    (escaping.runs[0] as typeof run).originalUriBaseIds = { OUT: { uri: "file:///outside/" } };
    expect(() => ciscoSourceRelativeSarifV1(escaping, report, ["/scan"])).toThrow(/Cisco/);
  });
});

// U1g (review of S2i, P2): `analysisTarget` is an artifact location only at its schema
// position, `result.analysisTarget`; a property bag is the analyzer's own data and is never
// normalized or rewritten, whatever keys it holds.
describe("property bags and analysisTarget outside its schema position (U1g)", () => {
  const bag = () => ({
    analysisTarget: { uri: "../example" },
    artifactLocation: { uri: "/elsewhere/x.md" },
    nested: [{ physicalLocation: { artifactLocation: { uri: "SKILL.md" } } }],
  });

  it("leaves result, run and log property bags untouched on a host run", () => {
    const document = {
      version: "2.1.0",
      properties: bag(),
      runs: [
        {
          tool: { driver: { name: "x", properties: bag() } },
          properties: bag(),
          results: [{ ...result("/scan/SKILL.md"), properties: bag() }],
        },
      ],
    };
    const normalized = sourceRelativeSarifV1(document, ["/scan"]).document as typeof document;
    expect(uris(normalized)).toEqual(["SKILL.md"]);
    expect(normalized.properties).toEqual(bag());
    expect(normalized.runs[0]?.properties).toEqual(bag());
    expect(normalized.runs[0]?.tool.driver.properties).toEqual(bag());
    expect(normalized.runs[0]?.results[0]?.properties).toEqual(bag());
  });

  it("treats an analysisTarget key anywhere but result.analysisTarget as ordinary data", () => {
    const document = sarif({
      ...result("/scan/SKILL.md"),
      relatedLocations: [
        {
          physicalLocation: { artifactLocation: { uri: "/scan/guide.md" } },
          analysisTarget: { uri: "../not-a-location" },
        },
      ],
    });
    const normalized = sourceRelativeSarifV1(document, ["/scan"]).document as {
      runs: { results: { relatedLocations: Record<string, unknown>[] }[] }[];
    };
    expect(normalized.runs[0]?.results[0]?.relatedLocations[0]).toEqual({
      physicalLocation: { artifactLocation: { uri: "guide.md" } },
      analysisTarget: { uri: "../not-a-location" },
    });
  });

  it("never rewrites a Cisco scan-all property bag", () => {
    const document = {
      version: "2.1.0",
      runs: [
        {
          tool: { driver: { name: "skill-scanner" } },
          results: [
            {
              ruleId: "R",
              message: { text: "R" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: "SKILL.md" },
                    region: { startLine: 1 },
                  },
                },
              ],
              properties: bag(),
            },
          ],
        },
      ],
    };
    const report = {
      results: [
        {
          skill_path: "/scan/skills/a",
          findings: [{ rule_id: "R", file_path: "SKILL.md", line_number: 1 }],
        },
      ],
    };
    const normalized = ciscoSourceRelativeSarifV1(document, report, ["/scan"]).document as {
      runs: { results: { properties: unknown }[] }[];
    };
    expect(uris(normalized)).toEqual(["skills/a/SKILL.md"]);
    expect(normalized.runs[0]?.results[0]?.properties).toEqual(bag());
  });
});

// U1g (review of S2i, P1): an `artifactLocation.index` names `run.artifacts[index]`. Every
// normalizer (host runs, Cisco jobs, Cisco scan-all, the shard) resolves it by one rule after
// the run is normalized: the index must be a non-negative integer naming an artifact whose
// location has a URI (and names no other index), and a URI beside it must name that file.
describe("artifact indices resolve by one rule on every path (U1g)", () => {
  const indexed = (analysisTarget: unknown, artifacts: unknown[] = []) => ({
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "x" } },
        artifacts,
        results: [{ ...result("/scan/SKILL.md"), analysisTarget }],
      },
    ],
  });
  const artifact = (uri: string, extra: Record<string, unknown> = {}) => ({
    location: { uri, ...extra },
  });

  it("accepts an index, alone or beside the same URI, that names a run artifact", () => {
    for (const analysisTarget of [{ index: 0 }, { uri: "/scan/SKILL.md", index: 0 }]) {
      const normalized = sourceRelativeSarifV1(
        indexed(analysisTarget, [artifact("/scan/SKILL.md", { index: 0 })]),
        ["/scan"],
      ).document as { runs: { results: { analysisTarget: unknown }[] }[] };
      expect(normalized.runs[0]?.results[0]?.analysisTarget).toEqual(
        "uri" in analysisTarget ? { uri: "SKILL.md", index: 0 } : { index: 0 },
      );
    }
  });

  it("refuses a URI and an index that name different files (reviewer case)", () => {
    expect(() =>
      sourceRelativeSarifV1(indexed({ uri: "SKILL.md", index: 0 }, [artifact("/scan/other.md")]), [
        "/scan",
      ]),
    ).toThrow(/disagree/);
  });

  it("refuses a missing, out-of-range, malformed or self-contradicting index", () => {
    for (const [analysisTarget, artifacts] of [
      [{ index: 0 }, []],
      [{ index: 1 }, [artifact("/scan/SKILL.md")]],
      [{ index: -1 }, [artifact("/scan/SKILL.md")]],
      [{ index: 0.5 }, [artifact("/scan/SKILL.md")]],
      [{ index: "0" }, [artifact("/scan/SKILL.md")]],
      [{ index: 0 }, [{ location: { index: 0 } }]],
      [{ index: 0 }, [artifact("/scan/SKILL.md", { index: 1 })]],
    ] as const)
      expect(
        () => sourceRelativeSarifV1(indexed(analysisTarget, [...artifacts]), ["/scan"]),
        JSON.stringify(analysisTarget),
      ).toThrow(/artifact index/);
  });

  it("resolves an index on related locations and code flows too", () => {
    const document = sarif({
      ...result("/scan/SKILL.md"),
      relatedLocations: [{ physicalLocation: { artifactLocation: { index: 3 } } }],
    });
    expect(() => sourceRelativeSarifV1(document, ["/scan"])).toThrow(/artifact index 3/);
    const flows = sarif({
      ...result("/scan/SKILL.md"),
      codeFlows: [
        {
          threadFlows: [
            {
              locations: [
                {
                  location: {
                    physicalLocation: { artifactLocation: { uri: "/scan/a.md", index: 0 } },
                  },
                },
              ],
            },
          ],
        },
      ],
    });
    (flows.runs[0] as Record<string, unknown>).artifacts = [artifact("/scan/b.md")];
    expect(() => sourceRelativeSarifV1(flows, ["/scan"])).toThrow(/disagree/);
  });

  it("refuses a Cisco scan-all index that disagrees with the skill-relative URI, or is missing", () => {
    const scanAll = (analysisTarget: unknown, artifacts: unknown[]) => ({
      version: "2.1.0",
      runs: [
        {
          tool: { driver: { name: "skill-scanner" } },
          originalUriBaseIds: { ROOT: { uri: "file:///scan/" } },
          artifacts,
          results: [
            {
              ruleId: "R",
              message: { text: "R" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: "SKILL.md" },
                    region: { startLine: 1 },
                  },
                },
              ],
              analysisTarget,
            },
          ],
        },
      ],
    });
    const report = {
      results: [
        {
          skill_path: "/scan/skills/a",
          findings: [{ rule_id: "R", file_path: "SKILL.md", line_number: 1 }],
        },
      ],
    };
    const beta = { location: { uri: "skills/b/SKILL.md", uriBaseId: "ROOT" } };
    const alpha = { location: { uri: "skills/a/SKILL.md", uriBaseId: "ROOT" } };
    expect(() =>
      ciscoSourceRelativeSarifV1(scanAll({ uri: "SKILL.md", index: 0 }, [beta]), report, ["/scan"]),
    ).toThrow(/disagree/);
    expect(() =>
      ciscoSourceRelativeSarifV1(scanAll({ index: 1 }, [alpha]), report, ["/scan"]),
    ).toThrow(/artifact index 1/);
    const normalized = ciscoSourceRelativeSarifV1(
      scanAll({ uri: "SKILL.md", index: 0 }, [alpha]),
      report,
      ["/scan"],
    ).document as { runs: { results: { analysisTarget: unknown }[] }[] };
    expect(normalized.runs[0]?.results[0]?.analysisTarget).toEqual({
      uri: "skills/a/SKILL.md",
      index: 0,
    });
  });
});

// U1g (review of S2i, P1): Cisco scan-all reports one merged run. Every location a result
// carries (related locations, code flows, stacks, fixes, the analysis target, by URI or by
// index) belongs to the skill that reported it: a relative URI is read in that skill's
// directory, and whatever the spelling, the file it names must lie in that skill and in no
// other reported skill nested inside it.
describe("Cisco scan-all nested locations stay in the reporting skill (U1g)", () => {
  const report = (...skills: [string, boolean][]) => ({
    results: skills.map(([skillPath, reporting]) => ({
      skill_path: skillPath,
      findings: reporting ? [{ rule_id: "R", file_path: "SKILL.md", line_number: 1 }] : [],
    })),
  });
  const log = (fields: Record<string, unknown>, run: Record<string, unknown> = {}) => ({
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "skill-scanner" } },
        originalUriBaseIds: { ROOT: { uri: "file:///scan/" } },
        ...run,
        results: [
          {
            ruleId: "R",
            message: { text: "R" },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "SKILL.md" },
                  region: { startLine: 1 },
                },
              },
            ],
            ...fields,
          },
        ],
      },
    ],
  });
  const at = (artifactLocation: Record<string, unknown>) => ({
    physicalLocation: { artifactLocation },
  });
  const alphaAndBeta = report(["/scan/skills/alpha", true], ["/scan/skills/beta", false]);
  const relatedOf = (document: Record<string, unknown>) =>
    (
      document.runs as {
        results: { relatedLocations: { physicalLocation: { artifactLocation: unknown } }[] }[];
      }[]
    )[0]?.results[0]?.relatedLocations.map((entry) => entry.physicalLocation.artifactLocation);

  it("reads a sibling-looking or bare URI in the reporting skill (reviewer case)", () => {
    const normalized = ciscoSourceRelativeSarifV1(
      log({ relatedLocations: [at({ uri: "skills/beta/SKILL.md" }), at({ uri: "SKILL.md" })] }),
      alphaAndBeta,
      ["/scan"],
    );
    expect(relatedOf(normalized.document)).toEqual([
      { uri: "skills/alpha/skills/beta/SKILL.md" },
      { uri: "skills/alpha/SKILL.md" },
    ]);
  });

  it("refuses a based URI that names a sibling skill's file", () => {
    expect(() =>
      ciscoSourceRelativeSarifV1(
        log({ relatedLocations: [at({ uri: "skills/beta/SKILL.md", uriBaseId: "ROOT" })] }),
        alphaAndBeta,
        ["/scan"],
      ),
    ).toThrow(/skills\/beta\/SKILL\.md.*not in the reporting skill skills\/alpha/);
  });

  it("refuses an index that resolves to a sibling skill's file (reviewer case)", () => {
    const beta = { artifacts: [{ location: { uri: "skills/beta/SKILL.md", uriBaseId: "ROOT" } }] };
    for (const fields of [
      { relatedLocations: [at({ index: 0 })] },
      { analysisTarget: { index: 0 } },
      {
        locations: [
          { physicalLocation: { artifactLocation: { uri: "SKILL.md" }, region: { startLine: 1 } } },
          at({ index: 0 }),
        ],
      },
    ])
      expect(() => ciscoSourceRelativeSarifV1(log(fields, beta), alphaAndBeta, ["/scan"])).toThrow(
        /not in the reporting skill/,
      );
    const alpha = {
      artifacts: [{ location: { uri: "skills/alpha/SKILL.md", uriBaseId: "ROOT" } }],
    };
    expect(
      relatedOf(
        ciscoSourceRelativeSarifV1(
          log({ relatedLocations: [at({ index: 0 })] }, alpha),
          alphaAndBeta,
          ["/scan"],
        ).document,
      ),
    ).toEqual([{ index: 0 }]);
  });

  it("refuses a code-flow, stack or fix location outside the reporting skill", () => {
    const beta = at({ uri: "skills/beta/SKILL.md", uriBaseId: "ROOT" });
    for (const fields of [
      { codeFlows: [{ threadFlows: [{ locations: [{ location: beta }] }] }] },
      { stacks: [{ frames: [{ location: beta }] }] },
      {
        fixes: [
          {
            artifactChanges: [
              {
                artifactLocation: { uri: "skills/beta/SKILL.md", uriBaseId: "ROOT" },
                replacements: [],
              },
            ],
          },
        ],
      },
    ])
      expect(() => ciscoSourceRelativeSarifV1(log(fields), alphaAndBeta, ["/scan"])).toThrow(
        /not in the reporting skill/,
      );
  });

  it("keeps a root skill's location in a nested skill's directory, which its scan covers", () => {
    // Cisco's scan of a parent skill walks its whole directory, nested skills included, and
    // reports their files under the parent (the real shape pinned above).
    const nested = report(["/scan", true], ["/scan/skills/b", false]);
    const normalized = ciscoSourceRelativeSarifV1(
      log({ relatedLocations: [at({ uri: "skills/b/SKILL.md" }), at({ uri: "docs/guide.md" })] }),
      nested,
      ["/scan"],
    );
    expect(relatedOf(normalized.document)).toEqual([
      { uri: "skills/b/SKILL.md" },
      { uri: "docs/guide.md" },
    ]);
  });
});

// U1h (review of U1g, P1): a result also names every location of the run-level objects it
// references: `run.threadFlowLocations[i]` through a thread-flow location's `index`, and
// `run.graphs[i]` through a graph traversal's `runGraphIndex`. Each reference is resolved for
// that result and the file it names must lie in the reporting skill; an unresolved,
// out-of-range, malformed or ambiguous reference fails.
describe("Cisco scan-all shared references resolve per result (U1h)", () => {
  const report = {
    results: [
      {
        skill_path: "/scan/skills/alpha",
        findings: [{ rule_id: "R", file_path: "SKILL.md", line_number: 1 }],
      },
      { skill_path: "/scan/skills/beta", findings: [] },
    ],
  };
  const at = (uri: string) => ({
    physicalLocation: { artifactLocation: { uri, uriBaseId: "ROOT" } },
  });
  const log = (fields: Record<string, unknown>, run: Record<string, unknown> = {}) => ({
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "skill-scanner" } },
        originalUriBaseIds: { ROOT: { uri: "file:///scan/" } },
        ...run,
        results: [
          {
            ruleId: "R",
            message: { text: "R" },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "SKILL.md" },
                  region: { startLine: 1 },
                },
              },
            ],
            ...fields,
          },
        ],
      },
    ],
  });
  const flowTo = (index: unknown) => ({
    codeFlows: [{ threadFlows: [{ locations: [{ index }] }] }],
  });
  const graph = (uri: string) => ({ nodes: [{ id: "n", location: at(uri) }], edges: [] });
  const scan = (fields: Record<string, unknown>, run: Record<string, unknown> = {}) =>
    ciscoSourceRelativeSarifV1(log(fields, run), report, ["/scan"]);

  it("refuses a shared thread-flow location in a sibling skill (reviewer case)", () => {
    expect(() =>
      scan(flowTo(0), { threadFlowLocations: [{ location: at("skills/beta/SKILL.md") }] }),
    ).toThrow(/skills\/beta\/SKILL\.md.*not in the reporting skill skills\/alpha/);
  });

  it("refuses a run graph in a sibling skill, reached through runGraphIndex", () => {
    expect(() =>
      scan(
        { graphTraversals: [{ runGraphIndex: 0 }] },
        { graphs: [graph("skills/beta/SKILL.md")] },
      ),
    ).toThrow(/skills\/beta\/SKILL\.md.*not in the reporting skill skills\/alpha/);
  });

  it("keeps shared references inside the reporting skill", () => {
    const normalized = scan(
      { ...flowTo(0), graphTraversals: [{ runGraphIndex: 0 }] },
      {
        threadFlowLocations: [{ location: at("skills/alpha/SKILL.md") }],
        graphs: [graph("skills/alpha/notes.md")],
      },
    );
    const run = (normalized.document.runs as Record<string, unknown>[])[0] as {
      threadFlowLocations: { location: { physicalLocation: { artifactLocation: unknown } } }[];
    };
    expect(run.threadFlowLocations[0]?.location.physicalLocation.artifactLocation).toEqual({
      uri: "skills/alpha/SKILL.md",
    });
  });

  it("refuses an unresolved, out-of-range, malformed or ambiguous reference", () => {
    const shared = { threadFlowLocations: [{ location: at("skills/alpha/SKILL.md") }] };
    const cases: [Record<string, unknown>, Record<string, unknown>, RegExp][] = [
      [flowTo(1), shared, /thread-flow location index 1 resolves to no/],
      [flowTo(0), {}, /thread-flow location index 0 resolves to no/],
      [flowTo(-1), shared, /thread-flow location index -1 is malformed/],
      [flowTo("0"), shared, /thread-flow location index "0" is malformed/],
      [
        flowTo(0),
        { threadFlowLocations: [{ index: 1, location: at("skills/alpha/SKILL.md") }] },
        /names another index/,
      ],
      [
        { graphTraversals: [{ runGraphIndex: 1 }] },
        { graphs: [graph("skills/alpha/SKILL.md")] },
        /run graph index 1 resolves to no/,
      ],
      [{ graphTraversals: [{ resultGraphIndex: 0 }] }, {}, /result graph index 0 resolves to no/],
      [
        { graphTraversals: [{ runGraphIndex: 0, resultGraphIndex: 0 }], graphs: [{ nodes: [] }] },
        { graphs: [graph("skills/alpha/SKILL.md")] },
        /exactly one of runGraphIndex and resultGraphIndex/,
      ],
      [{ graphTraversals: [{}] }, {}, /exactly one of runGraphIndex and resultGraphIndex/],
      [{ codeFlows: { threadFlows: [] } }, {}, /codeFlows is not an array/],
    ];
    for (const [fields, run, reason] of cases)
      expect(() => scan(fields, run), JSON.stringify(fields)).toThrow(reason);
  });
});

// U1i (review of U1h, P1): an artifact a result references by index is located inside its
// parent (`run.artifacts[i].parentIndex`), and that parent inside its own. A result therefore
// also reaches every artifact of that ancestry; each must lie in the reporting skill, and a
// malformed, out-of-range or cyclic parentIndex fails at output.
describe("Cisco scan-all artifact ancestry resolves per result (U1i)", () => {
  const report = {
    results: [
      {
        skill_path: "/scan/skills/alpha",
        findings: [{ rule_id: "R", file_path: "SKILL.md", line_number: 1 }],
      },
      { skill_path: "/scan/skills/beta", findings: [] },
    ],
  };
  const artifact = (uri: string, parentIndex?: unknown) => ({
    location: { uri, uriBaseId: "ROOT" },
    ...(parentIndex === undefined ? {} : { parentIndex }),
  });
  const log = (artifacts: unknown[], primaryIndex = false) => ({
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "skill-scanner" } },
        originalUriBaseIds: { ROOT: { uri: "file:///scan/" } },
        artifacts,
        results: [
          {
            ruleId: "R",
            message: { text: "R" },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "SKILL.md", ...(primaryIndex ? { index: 0 } : {}) },
                  region: { startLine: 1 },
                },
              },
            ],
            ...(primaryIndex
              ? {}
              : { relatedLocations: [{ physicalLocation: { artifactLocation: { index: 0 } } }] }),
          },
        ],
      },
    ],
  });
  const scan = (artifacts: unknown[], primaryIndex = false) =>
    ciscoSourceRelativeSarifV1(log(artifacts, primaryIndex), report, ["/scan"]);

  it("refuses a parent in a sibling skill (reviewer case)", () => {
    for (const primaryIndex of [true, false])
      expect(() =>
        scan(
          [artifact("skills/alpha/SKILL.md", 1), artifact("skills/beta/archive.zip")],
          primaryIndex,
        ),
      ).toThrow(/skills\/beta\/archive\.zip.*not in the reporting skill skills\/alpha/);
    // A grandparent in the sibling skill escapes no better.
    expect(() =>
      scan([
        artifact("skills/alpha/SKILL.md", 1),
        artifact("skills/alpha/bundle.zip", 2),
        artifact("skills/beta/outer.zip"),
      ]),
    ).toThrow(/skills\/beta\/outer\.zip.*not in the reporting skill skills\/alpha/);
  });

  it("keeps a parent chain inside the reporting skill", () => {
    const normalized = scan([
      artifact("skills/alpha/SKILL.md", 1),
      artifact("skills/alpha/bundle.zip", 2),
      artifact("skills/alpha/outer.zip"),
    ]);
    const run = (normalized.document.runs as Record<string, unknown>[])[0] as {
      artifacts: { location: unknown; parentIndex?: number }[];
    };
    expect(run.artifacts.map((entry) => [entry.location, entry.parentIndex])).toEqual([
      [{ uri: "skills/alpha/SKILL.md" }, 1],
      [{ uri: "skills/alpha/bundle.zip" }, 2],
      [{ uri: "skills/alpha/outer.zip" }, undefined],
    ]);
  });

  it("refuses a cyclic, out-of-range or malformed parentIndex", () => {
    const cases: [unknown[], RegExp][] = [
      [[artifact("skills/alpha/SKILL.md", 0)], /run artifact 0 parentIndex 0 forms a cycle/],
      [
        [artifact("skills/alpha/SKILL.md", 1), artifact("skills/alpha/a.zip", 0)],
        /parentIndex 0 forms a cycle/,
      ],
      [
        [artifact("skills/alpha/SKILL.md", 5)],
        /run artifact 0 parentIndex 5 resolves to no run artifact URI/,
      ],
      [
        [artifact("skills/alpha/SKILL.md", 1), { parentIndex: 0 }],
        /run artifact 0 parentIndex 1 resolves to no run artifact URI/,
      ],
      [[artifact("skills/alpha/SKILL.md", -1)], /run artifact 0 parentIndex -1 is malformed/],
      [[artifact("skills/alpha/SKILL.md", "1")], /run artifact 0 parentIndex "1" is malformed/],
      [[artifact("skills/alpha/SKILL.md", 0.5)], /run artifact 0 parentIndex 0.5 is malformed/],
    ];
    for (const [artifacts, reason] of cases)
      expect(() => scan(artifacts), JSON.stringify(artifacts)).toThrow(reason);
  });

  it("refuses a malformed chain even among artifacts no result references", () => {
    expect(() =>
      scan([
        artifact("skills/alpha/SKILL.md"),
        artifact("skills/alpha/a.md", 2),
        artifact("skills/alpha/b.md", 1),
      ]),
    ).toThrow(/parentIndex 1 forms a cycle|parentIndex 2 forms a cycle/);
  });
});
