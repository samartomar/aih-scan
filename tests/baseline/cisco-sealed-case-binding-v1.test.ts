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

  it("keeps an exact match even when another sealed file differs only in case", () => {
    const bind = ciscoSealedPathBinderV1(["skills/a/SKILL.md", "skills/a/skill.md"], "win32");
    expect(bind("skills/a/SKILL.md")).toBe("skills/a/SKILL.md");
    expect(bind("skills/a/skill.md")).toBe("skills/a/skill.md");
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
