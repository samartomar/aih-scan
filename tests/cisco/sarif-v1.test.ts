import { describe, expect, it } from "vitest";
import { canonicalCiscoSarifV1Bytes, parseCiscoSarifV1 } from "../../src/cisco/sarif-v1.js";

/**
 * Exact reporter contract from Cisco skill-scanner 2.0.13, wheel SHA-256
 * d81fde291d60b6f8134375c33b49a2f41f5bb3072b74153dafea4774d627a837:
 * skill_scanner/core/reporters/sarif_reporter.py.
 */
const validSarif = {
  $schema:
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  version: "2.1.0",
  runs: [
    {
      tool: {
        driver: {
          name: "skill-scanner",
          version: "1.0.0",
          informationUri: "https://github.com/cisco-ai-defense/skill-scanner",
          rules: [
            {
              id: "MANIFEST_MISSING_LICENSE",
              name: "Manifest Missing License",
              shortDescription: { text: "Skill manifest is missing a license." },
              fullDescription: { text: "Skill manifest does not include a license field." },
              defaultConfiguration: { level: "warning" },
              properties: {
                category: "metadata",
                severity: "medium",
                tags: ["metadata", "security"],
              },
            },
            {
              id: "PROMPT_INJECTION_IGNORE_INSTRUCTIONS",
              name: "Prompt Injection Ignore Instructions",
              shortDescription: { text: "Prompt injection pattern." },
              fullDescription: { text: "Pattern detected: Ignore previous instructions" },
              defaultConfiguration: { level: "error" },
              properties: {
                category: "prompt-injection",
                severity: "high",
                tags: ["prompt-injection", "security"],
              },
              help: {
                text: "Remove the injected instruction.",
                markdown: "**Remediation**: Remove the injected instruction.",
              },
            },
            {
              id: "FUTURE_CISCO_RULE",
              name: "Future Cisco Rule",
              shortDescription: { text: "Future scanner fact." },
              fullDescription: { text: "future scanner finding" },
              defaultConfiguration: { level: "warning" },
              properties: { category: "future", severity: "info", tags: ["future", "security"] },
            },
          ],
        },
      },
      invocations: [{ executionSuccessful: true, endTimeUtc: "2026-08-17T12:34:56Z" }],
      results: [
        {
          ruleId: "MANIFEST_MISSING_LICENSE",
          level: "warning",
          message: { text: "Skill manifest does not include a license field." },
          properties: { category: "metadata", severity: "medium" },
          fingerprints: { primaryLocationLineHash: "finding-license" },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "SKILL.md", uriBaseId: "%SRCROOT%" },
                region: { startLine: 1, snippet: { text: "license: MIT" } },
              },
            },
          ],
        },
        {
          ruleId: "PROMPT_INJECTION_IGNORE_INSTRUCTIONS",
          level: "error",
          message: { text: "Pattern detected: Ignore previous instructions" },
          properties: {
            category: "prompt-injection",
            severity: "high",
            remediation: "Remove the injected instruction.",
          },
          fingerprints: { primaryLocationLineHash: "finding-prompt" },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "SKILL.md", uriBaseId: "%SRCROOT%" },
                region: { startLine: 8 },
              },
            },
          ],
        },
        {
          ruleId: "FUTURE_CISCO_RULE",
          level: "warning",
          message: { text: "future scanner finding" },
          properties: { category: "future", severity: "info" },
          fingerprints: { primaryLocationLineHash: "finding-future" },
          locations: [
            { physicalLocation: { artifactLocation: { uri: "SKILL.md", uriBaseId: "%SRCROOT%" } } },
          ],
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
    exactKeys(run.results[0]?.locations[0]?.physicalLocation.region ?? {}, ["startLine"]);
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

  it("projects an absolute reporter artifact URI only through the supplied sealed source root", () => {
    const absolute = clone(validSarif);
    const location = absolute.runs[0]?.results[0]?.locations[0];
    if (location === undefined) throw new Error("Cisco fixture is incomplete");
    location.physicalLocation.artifactLocation.uri = "/sealed/source/SKILL.md";

    expect(
      parseCiscoSarifV1(text(absolute), { sourceRoot: "/sealed/source" }).runs[0]?.results[0],
    ).toMatchObject({
      locations: [{ physicalLocation: { artifactLocation: { uri: "SKILL.md" } } }],
    });
    expect(() => parseCiscoSarifV1(text(absolute))).toThrow(/absolute|source root|path/i);
    expect(() => parseCiscoSarifV1(text(validSarif), { sourceRoot: "relative/source" })).toThrow(
      /context|source root|path/i,
    );

    const windows = clone(absolute);
    const windowsLocation = windows.runs[0]?.results[0]?.locations[0];
    if (windowsLocation === undefined) throw new Error("Cisco fixture is incomplete");
    windowsLocation.physicalLocation.artifactLocation.uri = "C:\\sealed\\source\\SKILL.md";
    expect(
      parseCiscoSarifV1(text(windows), { sourceRoot: "C:\\sealed\\source" }).runs[0]?.results[0],
    ).toMatchObject({
      locations: [{ physicalLocation: { artifactLocation: { uri: "SKILL.md" } } }],
    });

    for (const uri of [
      "/sealed/outside/SKILL.md",
      "/sealed/source/../outside/SKILL.md",
      "file:///sealed/source/SKILL.md",
      "https://example.invalid/SKILL.md",
      "C:\\sealed\\source\\SKILL.md",
      "\\\\server\\share\\SKILL.md",
    ]) {
      const hostile = clone(absolute);
      const hostileLocation = hostile.runs[0]?.results[0]?.locations[0];
      if (hostileLocation === undefined) throw new Error("Cisco fixture is incomplete");
      hostileLocation.physicalLocation.artifactLocation.uri = uri;
      expect(() => parseCiscoSarifV1(text(hostile), { sourceRoot: "/sealed/source" })).toThrow();
    }
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
                    artifactLocation: { uri: "skills/résumé/SKILL.md", uriBaseId: "%SRCROOT%" },
                    region: { startLine: 1 },
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

  it("bounds the exact reporter rules, metadata, fingerprints, and invocation timestamp", () => {
    const run = validSarif.runs[0];
    const driver = run?.tool.driver;
    const result = run?.results[0];
    if (run === undefined || driver === undefined || result === undefined)
      throw new Error("Cisco fixture is incomplete");
    const withDriver = (nextDriver: object) =>
      text({ ...validSarif, runs: [{ ...run, tool: { driver: nextDriver } }] });
    const withResult = (nextResult: object) =>
      text({ ...validSarif, runs: [{ ...run, results: [nextResult] }] });
    const cases = [
      withDriver({ ...driver, rules: Array.from({ length: 4097 }, () => clone(driver.rules[0])) }),
      withDriver({
        ...driver,
        rules: [
          {
            ...driver.rules[0],
            properties: {
              ...driver.rules[0]?.properties,
              tags: Array.from({ length: 65 }, () => "security"),
            },
          },
        ],
      }),
      withDriver({
        ...driver,
        rules: [{ ...driver.rules[0], fullDescription: { text: "d".repeat(4097) } }],
      }),
      withDriver({
        ...driver,
        rules: [{ ...driver.rules[1], help: { text: "h".repeat(4097), markdown: "m" } }],
      }),
      withResult({ ...result, properties: { ...result.properties, category: "c".repeat(257) } }),
      withResult({ ...result, fingerprints: { primaryLocationLineHash: "f".repeat(513) } }),
      text({
        ...validSarif,
        runs: [
          { ...run, invocations: [{ executionSuccessful: true, endTimeUtc: "not-a-timestamp" }] },
        ],
      }),
    ];

    for (const value of cases) expect(() => parseCiscoSarifV1(value)).toThrow();
  });

  it("fails closed for malformed JSON, duplicate decoded keys, Unicode ambiguity, and unknown fields", () => {
    const run = validSarif.runs[0];
    if (run === undefined) throw new Error("Cisco fixture is incomplete");
    const cases = [
      '{"version":"2.1.0","runs":[]}',
      '{"version":"2.1.0","version":"2.1.0","runs":[]}',
      '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"cisco-ai-skill-scanner","na\\u006de":"other"}},"results":[]}]}',
      '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"cisco-ai-skill-scanner"}},"results":[]}],"note":"e\\u0301"}',
      '{"version":"2.1.0","runs":[],}',
      '{"version":"2.1.0","runs":[] // comment\n}',
      '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"cisco-ai-skill-scanner"}},"results":[]}],"bad":"\\ud800"}',
      text({ ...validSarif, extra: true }),
      text({ ...validSarif, runs: [{ ...run, extra: true }] }),
      text({
        ...validSarif,
        runs: [
          {
            ...run,
            tool: { driver: { ...run.tool.driver, extra: true } },
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
      {
        ...validSarif,
        runs: [{ ...run, tool: { driver: { ...run.tool.driver, name: "other" } } }],
      },
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
