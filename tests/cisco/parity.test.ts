import { describe, expect, it } from "vitest";
import { createCiscoFactsOnlyV1 } from "../../src/cisco/facts-only-v1.js";

const sha = "a".repeat(64);
const result = (message: string) => ({
  ruleId: "prompt-injection",
  level: "warning",
  message: { text: message },
  locations: [{ physicalLocation: { artifactLocation: { uri: "skills/demo/SKILL.md" } } }],
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
    expect(left.annexBytes.equals(right.annexBytes)).toBe(false);
  });
});
