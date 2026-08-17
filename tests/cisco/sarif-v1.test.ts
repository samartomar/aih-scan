import { describe, expect, it } from "vitest";
import { canonicalCiscoSarifV1Bytes, parseCiscoSarifV1 } from "../../src/cisco/sarif-v1.js";

const validSarif = {
  version: "2.1.0",
  runs: [
    {
      tool: { driver: { name: "cisco-ai-skill-scanner" } },
      results: [
        {
          ruleId: "MANIFEST_MISSING_LICENSE",
          level: "warning",
          message: { text: "Skill manifest does not include a license field." },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "SKILL.md" },
                region: { startLine: 1, startColumn: 1, endLine: 1, endColumn: 2 },
              },
            },
          ],
        },
        {
          ruleId: "PROMPT_INJECTION_IGNORE_INSTRUCTIONS",
          level: "error",
          message: { text: "Pattern detected: Ignore previous instructions" },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "SKILL.md" },
                region: { startLine: 4 },
              },
            },
          ],
        },
        {
          ruleId: "FUTURE_CISCO_RULE",
          message: { text: "future scanner finding" },
          locations: [{ physicalLocation: { artifactLocation: { uri: "SKILL.md" } } }],
        },
      ],
    },
  ],
};

const text = (value: unknown) => JSON.stringify(value);
const exactKeys = (value: object, keys: readonly string[]) =>
  expect(Object.keys(value).sort()).toEqual([...keys].sort());
const clone = <Value>(value: Value): Value => structuredClone(value);
const expectRecursivelyFrozen = (value: unknown, seen = new Set<object>()) => {
  if (value === null || typeof value !== "object" || ArrayBuffer.isView(value)) return;
  if (seen.has(value)) return;
  seen.add(value);
  expect(Object.isFrozen(value)).toBe(true);
  for (const child of Object.values(value)) expectRecursivelyFrozen(child, seen);
};

/**
 * A future Linux-only capture can pass its raw scanner output here. This proves
 * the observed shape through the same closed parser and canonical projection;
 * it intentionally does not whitelist unobserved SARIF optional fields.
 */
const observeCiscoSarifV1Capture = (rawSarif: string) =>
  JSON.parse(canonicalCiscoSarifV1Bytes(parseCiscoSarifV1(rawSarif)).toString("utf8"));

describe("Cisco SARIF V1 projection", () => {
  it("projects the closed Cisco 2.0.13 SARIF subset into the existing facts-only shape", () => {
    const parsed = parseCiscoSarifV1(text(validSarif));

    exactKeys(parsed, ["version", "runs"]);
    expect(parsed.version).toBe("2.1.0");
    expect(parsed.runs).toHaveLength(1);
    const run = parsed.runs[0];
    if (run === undefined) throw new Error("projected Cisco run is missing");
    exactKeys(run, ["tool", "results"]);
    exactKeys(run.tool, ["driver"]);
    exactKeys(run.tool.driver, ["name"]);
    expect(run.tool.driver.name).toBe("cisco-ai-skill-scanner");
    expect(run.results.map((result: { ruleId: string }) => result.ruleId)).toEqual([
      "MANIFEST_MISSING_LICENSE",
      "PROMPT_INJECTION_IGNORE_INSTRUCTIONS",
      "FUTURE_CISCO_RULE",
    ]);
    expect(run.results[2]?.message.text).toBe("future scanner finding");
    exactKeys(run.results[0] ?? {}, ["ruleId", "level", "message", "locations"]);
    exactKeys(run.results[0]?.message ?? {}, ["text"]);
    exactKeys(run.results[0]?.locations[0] ?? {}, ["physicalLocation"]);
    exactKeys(run.results[0]?.locations[0]?.physicalLocation ?? {}, ["artifactLocation", "region"]);
    exactKeys(run.results[0]?.locations[0]?.physicalLocation.artifactLocation ?? {}, ["uri"]);
    exactKeys(run.results[0]?.locations[0]?.physicalLocation.region ?? {}, [
      "startLine",
      "startColumn",
      "endLine",
      "endColumn",
    ]);
    expectRecursivelyFrozen(parsed);
    expect(() => {
      (run.results as unknown as { push: (value: unknown) => void }).push({});
    }).toThrow();
  });

  it("retains duplicate raw results and is byte-stable for semantically repeated input", () => {
    const repeated = clone(validSarif);
    const run = repeated.runs[0];
    const first = run?.results[1];
    if (run === undefined || first === undefined) throw new Error("Cisco fixture is incomplete");
    run.results.push(clone(first));

    const forward = parseCiscoSarifV1(text(repeated));
    const reverse = parseCiscoSarifV1(text(repeated));
    expect(forward.runs[0]?.results).toHaveLength(4);
    expect(canonicalCiscoSarifV1Bytes(forward)).toEqual(canonicalCiscoSarifV1Bytes(reverse));
    expect(() => canonicalCiscoSarifV1Bytes({ ...forward })).toThrow(/validated|branded/i);
    expect(() => canonicalCiscoSarifV1Bytes(clone(forward))).toThrow(/validated|branded/i);
  });

  it("makes a caller-captured Linux SARIF document provable against only the observed closed shape", () => {
    const captured = observeCiscoSarifV1Capture(text(validSarif));

    exactKeys(captured, ["runs", "version"]);
    exactKeys(captured.runs[0] ?? {}, ["results", "tool"]);
    exactKeys(captured.runs[0]?.tool ?? {}, ["driver"]);
    expect(captured.runs[0]?.tool.driver.name).toBe("cisco-ai-skill-scanner");
    expect(() =>
      observeCiscoSarifV1Capture(
        text({ ...validSarif, properties: { anUnobservedSarifOptionalField: true } }),
      ),
    ).toThrow();
  });

  it("accepts NFC Unicode in known fields but rejects non-NFC accepted-field data", () => {
    const run = validSarif.runs[0];
    const result = run?.results[0];
    if (run === undefined || result === undefined) throw new Error("Cisco fixture is incomplete");
    const unicode = {
      ...validSarif,
      runs: [
        {
          ...run,
          results: [
            {
              ...result,
              message: { text: "Résumé évidence" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: "skills/résumé/SKILL.md" },
                    region: { startLine: 1, startColumn: 1 },
                  },
                },
              ],
            },
          ],
        },
      ],
    };

    expect(parseCiscoSarifV1(text(unicode)).runs[0]?.results[0]?.message.text).toBe(
      "Résumé évidence",
    );
    expect(() => parseCiscoSarifV1(text(unicode).replace(/résumé/g, "résumé"))).toThrow();
  });

  it("bounds result, location, string, path, and region data before it can feed observations", () => {
    const run = validSarif.runs[0];
    const result = run?.results[0];
    if (run === undefined || result === undefined) throw new Error("Cisco fixture is incomplete");
    const withResults = (results: unknown[]) =>
      text({ ...validSarif, runs: [{ ...run, results }] });
    const withOne = (entry: object) => withResults([{ ...result, ...entry }]);
    const tooManyLocations = Array.from({ length: 17 }, () => clone(result.locations[0]));
    const tooManyResults = Array.from({ length: 4097 }, () => clone(result));
    const cases = [
      withOne({ ruleId: "r".repeat(257) }),
      withOne({ level: "l".repeat(65) }),
      withOne({ message: { text: "m".repeat(4097) } }),
      withOne({
        locations: [{ physicalLocation: { artifactLocation: { uri: "p".repeat(1025) } } }],
      }),
      withOne({ locations: tooManyLocations }),
      withOne({
        locations: [
          { physicalLocation: { artifactLocation: { uri: "SKILL.md" }, region: { startLine: 0 } } },
        ],
      }),
      withOne({
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: "SKILL.md" },
              region: { startLine: 10_000_001 },
            },
          },
        ],
      }),
      withOne({
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: "SKILL.md" },
              region: { startLine: 1, startColumn: 1_000_001 },
            },
          },
        ],
      }),
      withResults(tooManyResults),
    ];

    for (const value of cases) expect(() => parseCiscoSarifV1(value)).toThrow();
  });

  it("fails closed for malformed JSON, duplicate decoded keys, Unicode ambiguity, and unknown fields", () => {
    const cases = [
      '{"version":"2.1.0","runs":[]}',
      '{"version":"2.1.0","version":"2.1.0","runs":[]}',
      '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"cisco-ai-skill-scanner","na\\u006de":"other"}},"results":[]}]}',
      '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"cisco-ai-skill-scanner"}},"results":[]}],"note":"e\\u0301"}',
      '{"version":"2.1.0","runs":[],}',
      '{"version":"2.1.0","runs":[] // comment\n}',
      '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"cisco-ai-skill-scanner"}},"results":[]}],"bad":"\\ud800"}',
      text({ ...validSarif, extra: true }),
      text({ ...validSarif, runs: [{ ...validSarif.runs[0], extra: true }] }),
      text({
        ...validSarif,
        runs: [
          {
            ...validSarif.runs[0],
            tool: { driver: { name: "cisco-ai-skill-scanner", extra: true } },
          },
        ],
      }),
    ];

    for (const value of cases) expect(() => parseCiscoSarifV1(value)).toThrow();
  });

  it("rejects unsafe or incomplete locations and malformed required facts", () => {
    const run = validSarif.runs[0];
    const result = run?.results[0];
    if (run === undefined || result === undefined) throw new Error("Cisco fixture is incomplete");
    const cases = [
      { ...validSarif, version: "2.0.0" },
      { ...validSarif, runs: [] },
      { ...validSarif, runs: [{ ...run, tool: { driver: { name: "other" } } }] },
      { ...validSarif, runs: [{ ...run, results: [{ ...result, ruleId: "" }] }] },
      { ...validSarif, runs: [{ ...run, results: [{ ...result, message: {} }] }] },
      { ...validSarif, runs: [{ ...run, results: [{ ...result, locations: [] }] }] },
      {
        ...validSarif,
        runs: [
          {
            ...run,
            results: [
              {
                ...result,
                locations: [{ physicalLocation: { artifactLocation: { uri: "../escape" } } }],
              },
            ],
          },
        ],
      },
      {
        ...validSarif,
        runs: [
          {
            ...run,
            results: [
              {
                ...result,
                locations: [
                  { physicalLocation: { artifactLocation: { uri: "skills\\bad\\SKILL.md" } } },
                ],
              },
            ],
          },
        ],
      },
    ];

    for (const value of cases) expect(() => parseCiscoSarifV1(text(value))).toThrow();
  });
});
