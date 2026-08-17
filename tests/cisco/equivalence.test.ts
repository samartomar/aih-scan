import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { createCiscoFactsOnlyV1 } from "../../src/cisco/facts-only-v1.js";
import { createObservationSetV1 } from "../../src/observation/observation-evidence-v1.js";

const fixture = JSON.parse(
  readFileSync(resolve(import.meta.dirname, "../fixtures/cisco/semantic-equivalence.json"), "utf8"),
) as {
  files: Record<string, string>;
  sarif: { runs: Array<{ results: Array<Record<string, unknown>> }> };
  zeroSarif: object;
};
const fileHashes = Object.fromEntries(
  Object.entries(fixture.files).map(([path, contents]) => [
    path,
    createHash("sha256").update(contents, "utf8").digest("hex"),
  ]),
);
const input = (sarif = fixture.sarif) => ({
  protocol: "CiscoFactsOnlyV1" as const,
  sarif,
  fileSha256ByPath: fileHashes,
  platform: { os: "linux" as const, architecture: "amd64" as const },
});
type SemanticTuple = {
  detectorClass: string;
  nativeRuleId: unknown;
  path: string;
  fileSha256: string | undefined;
  startLine: number | undefined;
  message: string;
  level: unknown;
};
type AnnexDetail = Omit<SemanticTuple, "startLine"> & { locations: unknown[] };
type Fact = {
  detectorClass: string;
  nativeRuleId: string;
  path: string;
  fileSha256: string;
  canonicalOrdinal: number;
  multiplicity: number;
  rawOccurrenceFingerprint: string;
};
const tuples = (sarif: typeof fixture.sarif): SemanticTuple[] =>
  sarif.runs.flatMap((run) =>
    run.results.map((result) => {
      const location = (
        result.locations as Array<{
          physicalLocation: { artifactLocation: { uri: string }; region?: { startLine?: number } };
        }>
      )[0];
      if (location === undefined) throw new Error("fixture location missing");
      return {
        detectorClass: "cisco",
        nativeRuleId: result.ruleId,
        path: location.physicalLocation.artifactLocation.uri,
        fileSha256: fileHashes[location.physicalLocation.artifactLocation.uri],
        startLine: location.physicalLocation.region?.startLine,
        message: (result.message as { text: string }).text,
        level: result.level,
      };
    }),
  );
const annexTuple = (entry: AnnexDetail): SemanticTuple => {
  const firstLocation = entry.locations[0] as {
    physicalLocation: { artifactLocation: { uri: string }; region?: { startLine?: number } };
  };
  return {
    detectorClass: entry.detectorClass,
    nativeRuleId: entry.nativeRuleId,
    path: entry.path,
    fileSha256: entry.fileSha256,
    startLine: firstLocation.physicalLocation.region?.startLine,
    message: entry.message,
    level: entry.level,
  };
};
const sortedJson = <T>(values: readonly T[]) =>
  [...values].sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
const hasAuthorityField = (value: unknown): boolean => {
  if (Array.isArray(value)) return value.some(hasAuthorityField);
  if (value === null || typeof value !== "object") return false;
  return Object.entries(value).some(
    ([key, child]) =>
      /trust|policy|verdict|acceptance|acknowledg|signature|disposition|suppression/i.test(key) ||
      hasAuthorityField(child),
  );
};
const observationKey = {
  protocol: "ObservationKeyV1" as const,
  sourceSeal: {
    protocol: "SourceSealV1" as const,
    sourceTreeSha256: "a".repeat(64),
    selectedClosureSha256: "b".repeat(64),
    sealedSnapshotSha256: "c".repeat(64),
  },
  nativeAnalyzerIdentity: "native.0123456789ab",
  observationConfigurationSha256: "d".repeat(64),
  platform: {
    os: "linux" as const,
    architecture: "amd64" as const,
    relevantFactsSha256: "e".repeat(64),
  },
  scannerManifestEntrySha256: "f".repeat(64),
};

describe("Cisco semantic equivalence", () => {
  it("keeps an independently computed neutral SARIF multiset and full locations in annex evidence", () => {
    const produced = createCiscoFactsOnlyV1(input());
    const annex = JSON.parse(produced.annexBytes.toString("utf8")) as AnnexDetail[];
    const facts = produced.facts as Fact[];
    const neutral = tuples(fixture.sarif);
    expect(sortedJson(annex.map(annexTuple))).toEqual(sortedJson(neutral));
    expect(facts.every((fact) => fact.multiplicity === 1)).toBe(true);
    expect(new Set(facts.map((fact) => fact.rawOccurrenceFingerprint)).size).toBe(facts.length);
    for (const [index, fact] of facts.entries()) {
      expect(annex[index]).toMatchObject({
        detectorClass: fact.detectorClass,
        nativeRuleId: fact.nativeRuleId,
        path: fact.path,
        fileSha256: fact.fileSha256,
      });
    }
    expect(sortedJson(annex.map((entry) => entry.locations))).toEqual(
      sortedJson(
        fixture.sarif.runs.flatMap((run) => run.results.map((result) => result.locations)),
      ),
    );
    for (const group of new Set(
      facts.map((fact) => `${fact.nativeRuleId}\0${fact.path}\0${fact.fileSha256}`),
    )) {
      const ordinals = facts
        .filter((fact) => `${fact.nativeRuleId}\0${fact.path}\0${fact.fileSha256}` === group)
        .map((fact) => fact.canonicalOrdinal);
      expect(ordinals).toEqual(ordinals.map((_, index) => index));
    }
    const shuffled = structuredClone(fixture.sarif);
    shuffled.runs[0]?.results.reverse();
    const again = createCiscoFactsOnlyV1(input(shuffled));
    expect(again.annexBytes).toEqual(produced.annexBytes);
    expect(again.facts).toEqual(produced.facts);
    const zero = createCiscoFactsOnlyV1(input(fixture.zeroSarif as typeof fixture.sarif));
    expect(zero.facts).toEqual([]);
    expect(zero.coverage).not.toEqual([]);
    expect(hasAuthorityField(produced)).toBe(false);
  });

  it("binds rule, path, file hash, and ordinal while retaining diagnostic-only drift in annex bytes", () => {
    const run = fixture.sarif.runs[0];
    const prompt = run?.results[1];
    if (run === undefined || prompt === undefined) throw new Error("fixture prompt missing");
    const one = { ...fixture.sarif, runs: [{ ...run, results: [prompt] }] };
    const oneRun = one.runs[0];
    if (oneRun === undefined) throw new Error("single-result fixture missing");
    const diagnosticOnly = {
      ...one,
      runs: [
        {
          ...oneRun,
          results: [
            {
              ...prompt,
              message: { text: "changed diagnostic only" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: "skills/demo/SKILL.md" },
                    region: { startLine: 999 },
                  },
                },
              ],
            },
          ],
        },
      ],
    };
    const base = createCiscoFactsOnlyV1(input(one));
    const changedDiagnostic = createCiscoFactsOnlyV1(input(diagnosticOnly));
    expect(changedDiagnostic.facts[0]?.rawOccurrenceFingerprint).toBe(
      base.facts[0]?.rawOccurrenceFingerprint,
    );
    expect(changedDiagnostic.annexBytes).not.toEqual(base.annexBytes);
    const changedRule = createCiscoFactsOnlyV1(
      input({ ...one, runs: [{ ...run, results: [{ ...prompt, ruleId: "other-rule" }] }] }),
    );
    const changedPath = createCiscoFactsOnlyV1({
      ...input(one),
      sarif: {
        ...one,
        runs: [
          {
            ...run,
            results: [
              {
                ...prompt,
                locations: [
                  { physicalLocation: { artifactLocation: { uri: "skills/other/SKILL.md" } } },
                ],
              },
            ],
          },
        ],
      },
      fileSha256ByPath: { ...fileHashes, "skills/other/SKILL.md": "9".repeat(64) },
    });
    const changedHash = createCiscoFactsOnlyV1({
      ...input(one),
      fileSha256ByPath: { "skills/demo/SKILL.md": "9".repeat(64) },
    });
    const duplicate = createCiscoFactsOnlyV1(
      input({ ...one, runs: [{ ...run, results: [prompt, prompt] }] }),
    );
    expect(changedRule.facts[0]?.rawOccurrenceFingerprint).not.toBe(
      base.facts[0]?.rawOccurrenceFingerprint,
    );
    expect(changedPath.facts[0]?.rawOccurrenceFingerprint).not.toBe(
      base.facts[0]?.rawOccurrenceFingerprint,
    );
    expect(changedHash.facts[0]?.rawOccurrenceFingerprint).not.toBe(
      base.facts[0]?.rawOccurrenceFingerprint,
    );
    expect(duplicate.facts[0]?.rawOccurrenceFingerprint).toBe(
      base.facts[0]?.rawOccurrenceFingerprint,
    );
    expect(duplicate.facts[1]?.rawOccurrenceFingerprint).not.toBe(
      base.facts[0]?.rawOccurrenceFingerprint,
    );
  });

  it("keeps unknown rules visible, binds coverage to caller file identities, and rejects legacy fingerprints", () => {
    const produced = createCiscoFactsOnlyV1(input());
    expect(produced.facts.some((fact: Fact) => fact.nativeRuleId === "future-rule")).toBe(true);
    const changedSourceBytes = "# Demo\n\nChanged neutral fixture.\n";
    const changedSourceMap = {
      "skills/demo/SKILL.md": createHash("sha256").update(changedSourceBytes, "utf8").digest("hex"),
    };
    const changedCoverage = createCiscoFactsOnlyV1({
      ...input(),
      fileSha256ByPath: changedSourceMap,
    });
    expect(changedCoverage.coverage).not.toEqual(produced.coverage);
    for (const legacy of ["trust-raw:abc", "trust.raw:abc", "trust-anything"]) {
      expect(() =>
        createObservationSetV1({
          protocol: "ObservationSetV1",
          observationKey,
          facts: [{ rawOccurrenceFingerprint: legacy, multiplicity: 1 }],
          coverage: [{ coverageKind: "selected-closure", coverageSha256: "0".repeat(64) }],
        }),
      ).toThrow();
    }
  });
});
