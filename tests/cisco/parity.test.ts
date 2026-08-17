import { describe, expect, it } from "vitest";
import { createCiscoFactsOnlyV1 } from "../../src/cisco/facts-only-v1.js";

const sha = "a".repeat(64);
const result = (message: string) => ({
  ruleId: "prompt-injection",
  level: "warning",
  message: { text: message },
  locations: [{ physicalLocation: { artifactLocation: { uri: "skills/demo/SKILL.md" } } }],
});
const locatedResult = (line: number) => ({
  ...result("same diagnostic"),
  locations: [
    {
      physicalLocation: {
        artifactLocation: { uri: "skills/demo/SKILL.md" },
        region: { startLine: line, startColumn: 1, endLine: line, endColumn: 2 },
      },
    },
  ],
});
const input = (results: unknown[]) => ({
  protocol: "CiscoFactsOnlyV1",
  sarif: {
    version: "2.1.0",
    runs: [{ tool: { driver: { name: "cisco-ai-skill-scanner" } }, results }],
  },
  fileSha256ByPath: { "skills/demo/SKILL.md": sha },
  platform: { os: "linux", architecture: "amd64" },
});

describe("Cisco facts-only parity", () => {
  it("is permutation-stable for identical raw results and allocates a contiguous ordinal set", () => {
    const forward = createCiscoFactsOnlyV1(input([result("a"), result("a"), result("b")]));
    const reverse = createCiscoFactsOnlyV1(input([result("b"), result("a"), result("a")]));
    expect(
      forward.facts.map((fact: { rawOccurrenceFingerprint: string; canonicalOrdinal: number }) => [
        fact.rawOccurrenceFingerprint,
        fact.canonicalOrdinal,
      ]),
    ).toEqual(
      reverse.facts.map((fact: { rawOccurrenceFingerprint: string; canonicalOrdinal: number }) => [
        fact.rawOccurrenceFingerprint,
        fact.canonicalOrdinal,
      ]),
    );
    expect(forward.facts.every((fact: { code?: string }) => !fact.code?.startsWith("trust."))).toBe(
      true,
    );
  });

  it("binds protocol, detector, rule, safe path, exact file digest, and ordinal but not message/location diagnostics", () => {
    const left = createCiscoFactsOnlyV1(input([result("first")]));
    const right = createCiscoFactsOnlyV1(input([result("second")]));
    expect(left.facts[0]?.rawOccurrenceFingerprint).toBe(right.facts[0]?.rawOccurrenceFingerprint);
    expect(left.facts[0]?.rawOccurrenceFingerprint).toBe(
      "raw-occurrence-v1:da89dc078001a939f501966c99d4f346fd83c201a3101e6a0da640c46adf5bd3",
    );
    expect(left.annexBytes.equals(right.annexBytes)).toBe(false);
    const changedRule = createCiscoFactsOnlyV1(
      input([{ ...result("first"), ruleId: "other-rule" }]),
    );
    const changedFile = createCiscoFactsOnlyV1({
      ...input([result("first")]),
      fileSha256ByPath: { "skills/demo/SKILL.md": "b".repeat(64) },
    });
    expect(changedRule.facts[0]?.rawOccurrenceFingerprint).not.toBe(
      left.facts[0]?.rawOccurrenceFingerprint,
    );
    expect(changedFile.facts[0]?.rawOccurrenceFingerprint).not.toBe(
      left.facts[0]?.rawOccurrenceFingerprint,
    );
  });

  it("changes a raw occurrence fingerprint when canonical ordinal alone changes", () => {
    const duplicates = createCiscoFactsOnlyV1(input([result("same"), result("same")]));
    const ordered = [...duplicates.facts].sort(
      (left: { canonicalOrdinal: number }, right: { canonicalOrdinal: number }) =>
        left.canonicalOrdinal - right.canonicalOrdinal,
    );
    expect(ordered.map((fact: { canonicalOrdinal: number }) => fact.canonicalOrdinal)).toEqual([
      0, 1,
    ]);
    expect(ordered[0]?.rawOccurrenceFingerprint).not.toBe(ordered[1]?.rawOccurrenceFingerprint);
  });

  it("sorts full diagnostic detail before assigning ordinals, including regions and locations", () => {
    const forward = createCiscoFactsOnlyV1(input([locatedResult(9), locatedResult(3)]));
    const reverse = createCiscoFactsOnlyV1(input([locatedResult(3), locatedResult(9)]));
    expect(forward.annexBytes).toEqual(reverse.annexBytes);
    expect(forward.facts).toEqual(reverse.facts);
  });

  it("allows an exact zero-result coverage claim without inventing a trust conclusion", () => {
    const zero = createCiscoFactsOnlyV1(input([]));
    expect(zero.facts).toEqual([]);
    expect(zero.coverage).toHaveLength(1);
    expect(JSON.stringify(zero)).not.toMatch(/trust|policy|verdict|acceptance|acknowledg/i);
  });
});
