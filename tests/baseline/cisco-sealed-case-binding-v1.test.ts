import { describe, expect, it } from "vitest";
import {
  bindCiscoSarifToSealedFilesV1,
  ciscoSealedPathBinderV1,
  unboundCiscoSarifResultV1,
} from "../../src/baseline/cisco-sealed-case-binding-v1.js";

const sarif = (...uris: string[]) => ({
  version: "2.1.0",
  runs: [
    {
      tool: { driver: { name: "skill-scanner" } },
      artifacts: uris.map((uri) => ({ location: { uri } })),
      results: uris.map((uri) => ({
        ruleId: "rule",
        locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: 1 } } }],
        relatedLocations: [{ physicalLocation: { artifactLocation: { uri } } }],
      })),
    },
  ],
});

type Run = {
  artifacts: { location: { uri: string } }[];
  results: {
    locations: { physicalLocation: { artifactLocation: { uri: string } } }[];
    relatedLocations: { physicalLocation: { artifactLocation: { uri: string } } }[];
  }[];
};
const uris = (document: Record<string, unknown>) => {
  const run = (document.runs as Run[])[0] as Run;
  return {
    artifacts: run.artifacts.map((artifact) => artifact.location.uri),
    results: run.results.map(
      (result) => result.locations[0]?.physicalLocation.artifactLocation.uri,
    ),
    related: run.results.map(
      (result) => result.relatedLocations[0]?.physicalLocation.artifactLocation.uri,
    ),
  };
};

describe("Cisco sealed-file case binding on win32", () => {
  it("binds a normcased SKILL.md to the sealed file and keeps its real name", () => {
    const bind = ciscoSealedPathBinderV1(["skills/injected/SKILL.md"], "win32");
    expect(bind("skills/injected/skill.md")).toBe("skills/injected/SKILL.md");
  });

  it("binds when directories were lowercased too", () => {
    const bind = ciscoSealedPathBinderV1(["Skills/Injected/Docs/Guide.MD", "README.md"], "win32");
    expect(bind("skills/injected/docs/guide.md")).toBe("Skills/Injected/Docs/Guide.MD");
  });

  // U1k (review of U1j, P2): owner decision D1 binds only a UNIQUE match. When two sealed
  // files are equal ignoring case, even an exact spelling of one is refused: on win32 Cisco
  // normcases every path, so its spelling cannot say which of the two it scanned.
  it("refuses even an exact spelling when another sealed file differs only in case (U1k)", () => {
    const bind = ciscoSealedPathBinderV1(["skills/a/SKILL.md", "skills/a/skill.md"], "win32");
    expect(() => bind("skills/a/SKILL.md")).toThrow(
      "skills/a/SKILL.md matches 2 sealed files ignoring case",
    );
    expect(() => bind("skills/a/skill.md")).toThrow(
      "skills/a/skill.md matches 2 sealed files ignoring case",
    );
    const skills = ciscoSealedPathBinderV1(["skills/A/SKILL.md", "skills/a/SKILL.md"], "win32");
    expect(() => skills("skills/A/SKILL.md")).toThrow("matches 2 sealed files ignoring case");
    expect(() => skills("skills/a/SKILL.md")).toThrow("matches 2 sealed files ignoring case");
  });

  it("still binds a unique exact match (U1k)", () => {
    const bind = ciscoSealedPathBinderV1(
      ["skills/A/SKILL.md", "skills/b/SKILL.md", "skills/b/guide.md"],
      "win32",
    );
    expect(bind("skills/A/SKILL.md")).toBe("skills/A/SKILL.md");
    expect(bind("skills/b/guide.md")).toBe("skills/b/guide.md");
  });

  it("fails when two sealed files differ only in case", () => {
    const bind = ciscoSealedPathBinderV1(["skills/a/SKILL.md", "skills/a/Skill.md"], "win32");
    expect(() => bind("skills/a/skill.md")).toThrow(
      "skills/a/skill.md matches 2 sealed files ignoring case",
    );
    const directories = ciscoSealedPathBinderV1(
      ["Skills/a/SKILL.md", "skills/A/SKILL.md"],
      "win32",
    );
    expect(() => directories("skills/a/skill.md")).toThrow("matches 2 sealed files");
  });

  it("leaves a lowercased path that matches no sealed file unbound", () => {
    const bind = ciscoSealedPathBinderV1(["skills/injected/SKILL.md"], "win32");
    expect(bind("skills/injected/missing.md")).toBe("skills/injected/missing.md");
    expect(bind("skills/other/skill.md")).toBe("skills/other/skill.md");
  });

  it("never matches across a Unicode normalization form or a case fold beyond lowercase", () => {
    // "é" precomposed (NFC) against "e" + combining acute (NFD); "ß" against "SS".
    const bind = ciscoSealedPathBinderV1(["skills/Café/SKILL.md", "skills/STRASSE.md"], "win32");
    expect(bind("skills/café/skill.md")).toBe("skills/café/skill.md");
    expect(bind("skills/straße.md")).toBe("skills/straße.md");
    expect(bind("skills/café/skill.md")).toBe("skills/Café/SKILL.md");
  });

  it("rewrites every result, related and artifact location in the SARIF", () => {
    const document = sarif("skills/injected/skill.md", "skills/injected/SKILL.md");
    const bound = bindCiscoSarifToSealedFilesV1(document, ["skills/injected/SKILL.md"], "win32");
    expect(bound.rebound).toBe(3);
    expect(uris(bound.document)).toEqual({
      artifacts: ["skills/injected/SKILL.md", "skills/injected/SKILL.md"],
      results: ["skills/injected/SKILL.md", "skills/injected/SKILL.md"],
      related: ["skills/injected/SKILL.md", "skills/injected/SKILL.md"],
    });
    expect(uris(document).results[0]).toBe("skills/injected/skill.md");
  });

  it("fails the SARIF when a location is ambiguous", () => {
    expect(() =>
      bindCiscoSarifToSealedFilesV1(
        sarif("skills/a/skill.md"),
        ["skills/a/SKILL.md", "skills/a/Skill.md"],
        "win32",
      ),
    ).toThrow("matches 2 sealed files ignoring case");
    // U1k: an exact spelling of one of two case-variant sealed files is ambiguous too.
    expect(() =>
      bindCiscoSarifToSealedFilesV1(
        sarif("skills/a/SKILL.md"),
        ["skills/a/SKILL.md", "skills/a/Skill.md"],
        "win32",
      ),
    ).toThrow("skills/a/SKILL.md matches 2 sealed files ignoring case");
  });

  it("leaves an unsafe URI for the projection to refuse", () => {
    const document = sarif("../outside/skill.md");
    const bound = bindCiscoSarifToSealedFilesV1(document, ["outside/SKILL.md"], "win32");
    expect(bound.rebound).toBe(0);
    expect(uris(bound.document).results).toEqual(["../outside/skill.md"]);
  });
});

describe("Cisco sealed-file case binding off win32", () => {
  for (const platform of ["linux", "darwin"] as const) {
    it(`is strict on ${platform}`, () => {
      const bind = ciscoSealedPathBinderV1(["skills/injected/SKILL.md"], platform);
      expect(bind("skills/injected/skill.md")).toBe("skills/injected/skill.md");
      const document = sarif("skills/injected/skill.md");
      const bound = bindCiscoSarifToSealedFilesV1(document, ["skills/injected/SKILL.md"], platform);
      expect(bound.rebound).toBe(0);
      expect(bound.document).toEqual(document);
      expect(() =>
        bindCiscoSarifToSealedFilesV1(
          sarif("skills/a/skill.md"),
          ["skills/a/SKILL.md", "skills/a/Skill.md"],
          platform,
        ),
      ).not.toThrow();
      // U1k: case-variant twins stay distinct off win32; each exact spelling is itself.
      const twins = ciscoSealedPathBinderV1(["skills/A/SKILL.md", "skills/a/SKILL.md"], platform);
      expect(twins("skills/A/SKILL.md")).toBe("skills/A/SKILL.md");
      expect(twins("skills/a/SKILL.md")).toBe("skills/a/SKILL.md");
    });
  }
});

// U1h (review of U1g, P1): the result binding resolves each result's references to the run's
// shared thread-flow locations and graphs, and refuses one that resolves to nothing.
describe("unboundCiscoSarifResultV1 shared references (U1h)", () => {
  const log = (fields: Record<string, unknown>, run: Record<string, unknown>) => ({
    runs: [
      {
        ...run,
        results: [
          {
            locations: [{ physicalLocation: { artifactLocation: { uri: "skills/a/SKILL.md" } } }],
            ...fields,
          },
        ],
      },
    ],
  });
  const sealed = new Set(["skills/a/SKILL.md"]);
  const shared = {
    threadFlowLocations: [
      { location: { physicalLocation: { artifactLocation: { uri: "skills/a/SKILL.md" } } } },
    ],
  };
  const flowTo = (index: unknown) => ({
    codeFlows: [{ threadFlows: [{ locations: [{ index }] }] }],
  });

  it("binds a resolved shared reference", () => {
    expect(unboundCiscoSarifResultV1(log(flowTo(0), shared), sealed, "subject")).toBeUndefined();
  });

  it("refuses an unresolved, malformed or ambiguous shared reference", () => {
    for (const [fields, reason] of [
      [flowTo(3), /SARIF result 0: .*thread-flow location index 3 resolves to no/],
      [flowTo(1.5), /thread-flow location index 1\.5 is malformed/],
      [{ graphTraversals: [{}] }, /exactly one of runGraphIndex and resultGraphIndex/],
      [{ graphTraversals: [{ runGraphIndex: 0 }] }, /run graph index 0 resolves to no/],
    ] as const)
      expect(unboundCiscoSarifResultV1(log(fields, shared), sealed, "subject")).toMatch(reason);
  });
});

// U1i (review of U1h, P1): an artifact a result references by index is bound together with its
// whole parentIndex ancestry; every ancestor must be a sealed file, and a malformed,
// out-of-range or cyclic parent is refused.
describe("unboundCiscoSarifResultV1 artifact ancestry (U1i)", () => {
  const log = (artifacts: unknown[]) => ({
    runs: [
      {
        artifacts,
        results: [
          {
            locations: [
              { physicalLocation: { artifactLocation: { uri: "skills/a/SKILL.md", index: 0 } } },
            ],
          },
        ],
      },
    ],
  });
  const artifact = (uri: string, parentIndex?: unknown) => ({
    location: { uri },
    ...(parentIndex === undefined ? {} : { parentIndex }),
  });
  const sealed = new Set(["skills/a/SKILL.md", "skills/a/bundle.zip"]);

  it("binds a parent chain of sealed files", () => {
    expect(
      unboundCiscoSarifResultV1(
        log([artifact("skills/a/SKILL.md", 1), artifact("skills/a/bundle.zip")]),
        sealed,
        "job",
      ),
    ).toBeUndefined();
  });

  it("refuses an ancestor that is not a sealed file (reviewer case)", () => {
    expect(
      unboundCiscoSarifResultV1(
        log([artifact("skills/a/SKILL.md", 1), artifact("skills/b/archive.zip")]),
        sealed,
        "job",
      ),
    ).toMatch(/SARIF result 0 .*"skills\/b\/archive\.zip", which is not a sealed file of the job/);
  });

  it("refuses a cyclic, out-of-range or malformed parent", () => {
    for (const [artifacts, reason] of [
      [
        [artifact("skills/a/SKILL.md", 1), artifact("skills/a/bundle.zip", 0)],
        /SARIF result 0: run artifact 1 parentIndex 0 forms a cycle/,
      ],
      [[artifact("skills/a/SKILL.md", 2)], /run artifact 0 parentIndex 2 resolves to no/],
      [[artifact("skills/a/SKILL.md", -1)], /run artifact 0 parentIndex -1 is malformed/],
    ] as const)
      expect(unboundCiscoSarifResultV1(log([...artifacts]), sealed, "job")).toMatch(reason);
  });
});
