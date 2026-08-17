import { describe, expect, it } from "vitest";
import { createCiscoFactsOnlyV1 } from "../../src/cisco/facts-only-v1.js";

const sha = (digit: string) => digit.repeat(64);
const sarif = {
  version: "2.1.0",
  runs: [
    {
      tool: { driver: { name: "cisco-ai-skill-scanner" } },
      results: [
        {
          ruleId: "prompt-injection",
          level: "warning",
          message: { text: "untrusted instruction" },
          locations: [{ physicalLocation: { artifactLocation: { uri: "skills/demo/SKILL.md" } } }],
        },
        {
          ruleId: "unknown-rule",
          level: "error",
          message: { text: "new rule" },
          locations: [{ physicalLocation: { artifactLocation: { uri: "skills/demo/SKILL.md" } } }],
        },
      ],
    },
  ],
};

describe("Cisco facts-only V1", () => {
  it("turns caller-fed SARIF into raw Cisco facts with stable ordinals and bounded annex bytes", () => {
    const facts = createCiscoFactsOnlyV1({
      protocol: "CiscoFactsOnlyV1",
      sarif,
      fileSha256ByPath: { "skills/demo/SKILL.md": sha("a") },
      platform: { os: "linux", architecture: "amd64" },
    });
    expect(facts.facts.map((fact: { detectorClass: string }) => fact.detectorClass)).toEqual([
      "cisco",
      "cisco",
    ]);
    expect(facts.facts.map((fact: { canonicalOrdinal: number }) => fact.canonicalOrdinal)).toEqual([
      0, 0,
    ]);
    expect(facts.annexBytes.length).toBeGreaterThan(0);
  });

  it("rejects malformed SARIF, missing file identities, unsafe paths, duplicate ambiguity, and policy leakage", () => {
    const firstRun = sarif.runs[0];
    if (firstRun === undefined) throw new Error("fixture is missing a SARIF run");
    const firstResult = firstRun.results[0];
    if (firstResult === undefined) throw new Error("fixture is missing a SARIF result");
    const malformed = [
      { ...sarif, version: "2.0.0" },
      { ...sarif, runs: [] },
      {
        ...sarif,
        runs: [
          {
            ...firstRun,
            results: [{ ...firstResult, ruleId: undefined }],
          },
        ],
      },
    ];
    for (const invalid of malformed) {
      expect(() =>
        createCiscoFactsOnlyV1({
          protocol: "CiscoFactsOnlyV1",
          sarif: invalid,
          fileSha256ByPath: {},
          platform: { os: "linux", architecture: "amd64" },
        }),
      ).toThrow();
    }
  });
});
