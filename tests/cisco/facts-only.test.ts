import { describe, expect, it } from "vitest";
import { createCiscoFactsOnlyV1 } from "../../src/cisco/facts-only-v1.js";
import { verifyEvidenceAnnexBytesV1 } from "../../src/observation/observation-evidence-v1.js";

const sha = (digit: string) => digit.repeat(64);
const sourceSeal = {
  protocol: "SourceSealV1",
  sourceTreeSha256: sha("b"),
  selectedClosureSha256: sha("c"),
  sealedSnapshotSha256: sha("d"),
};
const callerIdentities = {
  analyzer: {
    identity: "native.0123456789ab",
    version: "1.0.0",
    lockSha256: sha("e"),
  },
  observationConfigurationSha256: sha("f"),
  sourceSeal,
  coverage: [
    { coverageKind: "selected-closure", coverageSha256: sha("0") },
    { coverageKind: "source-tree", coverageSha256: sha("1") },
  ],
  ociImage: {
    reference: `example.invalid/cisco@sha256:${sha("2")}`,
    sha256: sha("2"),
  },
  adapter: { identity: "adapter.0123456789ab", sha256: sha("3") },
  executionProfileSha256: sha("4"),
  supportedPlatforms: [{ os: "linux", architecture: "amd64" }],
  sbom: { mediaType: "application/spdx+json", sha256: sha("5") },
  provenance: { mediaType: "application/vnd.in-toto+json", sha256: sha("6") },
};
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
          ruleId: "prompt-injection",
          level: "warning",
          message: { text: "untrusted instruction" },
          locations: [{ physicalLocation: { artifactLocation: { uri: "skills/demo/SKILL.md" } } }],
        },
        {
          // Public AIH Cisco SARIF vector anchor: skill-metadata-license alongside prompt-injection.
          ruleId: "skill-metadata-license",
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
      "cisco",
    ]);
    const prompts = facts.facts.filter(
      (fact: { nativeRuleId: string }) => fact.nativeRuleId === "prompt-injection",
    );
    expect(prompts.map((fact: { canonicalOrdinal: number }) => fact.canonicalOrdinal)).toEqual([
      0, 1,
    ]);
    expect(prompts.map((fact: { multiplicity: number }) => fact.multiplicity)).toEqual([1, 1]);
    expect(
      facts.facts.some(
        (fact: { nativeRuleId: string }) => fact.nativeRuleId === "skill-metadata-license",
      ),
    ).toBe(true);
    expect(facts.annexBytes.length).toBeGreaterThan(0);
    expect(Object.keys(facts.evidenceAnnex).sort()).toEqual([
      "descriptors",
      "evidenceAnnexSha256",
      "protocol",
    ]);
    const descriptor = facts.evidenceAnnex.descriptors[0];
    if (descriptor === undefined) throw new Error("Cisco raw evidence descriptor is missing");
    expect(descriptor).toMatchObject({
      descriptorId: "annex.cisco-raw",
      mediaType: "application/json",
      uri: "annex/cisco-raw.json",
      byteLength: facts.annexBytes.length,
      sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
    });
    expect(
      verifyEvidenceAnnexBytesV1({
        annex: facts.evidenceAnnex,
        descriptors: [{ descriptorId: descriptor.descriptorId, bytes: facts.annexBytes }],
      }),
    ).toEqual({ kind: "complete" });
    expect(
      verifyEvidenceAnnexBytesV1({
        annex: facts.evidenceAnnex,
        descriptors: [
          { descriptorId: descriptor.descriptorId, bytes: Buffer.from("substitution") },
        ],
      }),
    ).toMatchObject({ kind: "required" });
    expect(JSON.stringify(facts)).not.toMatch(
      /trust\.|policy|suppression|disposition|verdict|acceptance|acknowledg|signature/i,
    );
  });

  it("rejects malformed SARIF, missing file identities, unsafe paths, duplicate ambiguity, and policy leakage", () => {
    const firstRun = sarif.runs[0];
    if (firstRun === undefined) throw new Error("fixture is missing a SARIF run");
    const firstResult = firstRun.results[0];
    if (firstResult === undefined) throw new Error("fixture is missing a SARIF result");
    const malformedWithIdentity = [
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
    for (const invalid of malformedWithIdentity) {
      expect(() =>
        createCiscoFactsOnlyV1({
          protocol: "CiscoFactsOnlyV1",
          sarif: invalid,
          fileSha256ByPath: { "skills/demo/SKILL.md": sha("a") },
          platform: { os: "linux", architecture: "amd64" },
        }),
      ).toThrow();
    }
    expect(() =>
      createCiscoFactsOnlyV1({
        protocol: "CiscoFactsOnlyV1",
        sarif,
        fileSha256ByPath: {},
        platform: { os: "linux", architecture: "amd64" },
      }),
    ).toThrow();
    expect(() =>
      createCiscoFactsOnlyV1({
        protocol: "CiscoFactsOnlyV1",
        sarif: {
          ...sarif,
          runs: [
            {
              ...firstRun,
              results: [
                {
                  ...firstResult,
                  locations: [{ physicalLocation: { artifactLocation: { uri: "../escape" } } }],
                },
              ],
            },
          ],
        },
        fileSha256ByPath: { "../escape": sha("a") },
        platform: { os: "linux", architecture: "amd64" },
      }),
    ).toThrow();
  });

  it("accepts only the closed, bounded Cisco SARIF profile and never reads hostile maps", () => {
    const firstRun = sarif.runs[0];
    if (firstRun === undefined) throw new Error("fixture is missing a SARIF run");
    const firstResult = firstRun.results[0];
    if (firstResult === undefined) throw new Error("fixture is missing a SARIF result");
    const base = {
      protocol: "CiscoFactsOnlyV1",
      sarif,
      fileSha256ByPath: { "skills/demo/SKILL.md": sha("a") },
      platform: { os: "linux", architecture: "amd64" },
    };
    const invalid = [
      { ...base, unexpected: true },
      { ...base, sarif: { ...sarif, unexpected: true } },
      { ...base, sarif: { ...sarif, runs: [{ ...firstRun, unexpected: true }] } },
      {
        ...base,
        sarif: {
          ...sarif,
          runs: [
            { ...firstRun, tool: { driver: { name: "cisco-ai-skill-scanner", extra: true } } },
          ],
        },
      },
      {
        ...base,
        sarif: {
          ...sarif,
          runs: [
            {
              ...firstRun,
              results: [
                {
                  ...firstResult,
                  locations: [
                    ...firstResult.locations,
                    { physicalLocation: { artifactLocation: { uri: "../escape" } } },
                  ],
                },
              ],
            },
          ],
        },
      },
      {
        ...base,
        sarif: { ...sarif, runs: [{ ...firstRun, results: [{ ...firstResult, extra: true }] }] },
      },
      {
        ...base,
        sarif: {
          ...sarif,
          runs: [
            {
              ...firstRun,
              results: [{ ...firstResult, message: { ...firstResult.message, extra: true } }],
            },
          ],
        },
      },
      {
        ...base,
        sarif: {
          ...sarif,
          runs: [
            {
              ...firstRun,
              results: [
                {
                  ...firstResult,
                  locations: [
                    {
                      physicalLocation: {
                        artifactLocation: {
                          uri: "skills/demo/SKILL.md",
                          extra: true,
                        },
                      },
                    },
                  ],
                },
              ],
            },
          ],
        },
      },
      {
        ...base,
        sarif: {
          ...sarif,
          runs: [{ ...firstRun, results: [{ ...firstResult, ruleId: "x".repeat(257) }] }],
        },
      },
    ];
    for (const value of invalid) expect(() => createCiscoFactsOnlyV1(value)).toThrow();

    const accessorDigest = { ...base.fileSha256ByPath } as Record<string, unknown>;
    Object.defineProperty(accessorDigest, "skills/demo/SKILL.md", {
      enumerable: true,
      get: () => {
        throw new Error("must not execute a digest accessor");
      },
    });
    expect(() => createCiscoFactsOnlyV1({ ...base, fileSha256ByPath: accessorDigest })).toThrow();
  });

  it("keeps an unknown Cisco rule as a raw fact without mapping it into another namespace", () => {
    const firstRun = sarif.runs[0];
    if (firstRun === undefined) throw new Error("fixture is missing a SARIF run");
    const firstResult = firstRun.results[0];
    if (firstResult === undefined) throw new Error("fixture is missing a SARIF result");
    const result = createCiscoFactsOnlyV1({
      protocol: "CiscoFactsOnlyV1",
      sarif: {
        ...sarif,
        runs: [{ ...firstRun, results: [{ ...firstResult, ruleId: "future-rule" }] }],
      },
      fileSha256ByPath: { "skills/demo/SKILL.md": sha("a") },
      platform: { os: "linux", architecture: "amd64" },
    });
    expect(result.facts[0]?.nativeRuleId).toBe("future-rule");
  });

  it("rejects inherited or accessor-backed file maps without reading attacker-controlled properties", () => {
    const inherited = Object.create({ "skills/demo/SKILL.md": sha("a") });
    const accessor: Record<string, unknown> = {};
    Object.defineProperty(accessor, "skills/demo/SKILL.md", {
      enumerable: true,
      get: () => {
        throw new Error("must not execute accessor");
      },
    });
    for (const fileSha256ByPath of [inherited, accessor]) {
      expect(() =>
        createCiscoFactsOnlyV1({
          protocol: "CiscoFactsOnlyV1",
          sarif,
          fileSha256ByPath,
          platform: { os: "linux", architecture: "amd64" },
        }),
      ).toThrow();
    }
  });

  it("binds caller-provided analyzer version, lock, configuration, source seal, and coverage into its entry and key", () => {
    const create = (identities: typeof callerIdentities) =>
      createCiscoFactsOnlyV1({
        protocol: "CiscoFactsOnlyV1",
        sarif,
        fileSha256ByPath: { "skills/demo/SKILL.md": sha("a") },
        platform: { os: "linux", architecture: "amd64" },
        identities,
      });
    const base = create(callerIdentities);
    const changedVersion = create({
      ...callerIdentities,
      analyzer: { ...callerIdentities.analyzer, version: "1.0.1" },
    });
    const changedLock = create({
      ...callerIdentities,
      analyzer: { ...callerIdentities.analyzer, lockSha256: sha("2") },
    });
    const changedConfiguration = create({
      ...callerIdentities,
      observationConfigurationSha256: sha("3"),
    });
    expect(base.scannerManifestEntrySha256).toMatch(/^[a-f0-9]{64}$/);
    expect(base.scannerManifest.protocol).toBe("ScannerManifestV1");
    expect(base.scannerManifest.detectors).toHaveLength(1);
    const detector = base.scannerManifest.detectors[0];
    expect(detector).toMatchObject({
      detectorId: "detector.cisco",
      analyzerIdentity: callerIdentities.analyzer.identity,
      ociImage: callerIdentities.ociImage,
      adapter: callerIdentities.adapter,
      executionProfileSha256: callerIdentities.executionProfileSha256,
      supportedPlatforms: [{ os: "linux", architecture: "amd64" }],
      sbom: callerIdentities.sbom,
      provenance: callerIdentities.provenance,
    });
    expect(detector?.observationConfigurationSha256).not.toBe(
      callerIdentities.observationConfigurationSha256,
    );
    expect(base.scannerManifestEntrySha256).toBe(detector?.scannerManifestEntrySha256);
    expect(base.observationKey.scannerManifestEntrySha256).toBe(base.scannerManifestEntrySha256);
    expect(base.observationKey.observationConfigurationSha256).toBe(
      detector?.observationConfigurationSha256,
    );
    expect(base.observationKey.sourceSeal).toEqual(sourceSeal);
    expect(base.observationSet.coverage).toEqual(callerIdentities.coverage);
    for (const changed of [changedVersion, changedLock, changedConfiguration]) {
      expect(changed.scannerManifestEntrySha256).not.toBe(base.scannerManifestEntrySha256);
      expect(changed.observationKey.observationKeySha256).not.toBe(
        base.observationKey.observationKeySha256,
      );
    }
  });

  it("requires complete immutable caller manifest identities when identities are present", () => {
    const { provenance: _provenance, ...incomplete } = callerIdentities;
    expect(() =>
      createCiscoFactsOnlyV1({
        protocol: "CiscoFactsOnlyV1",
        sarif,
        fileSha256ByPath: { "skills/demo/SKILL.md": sha("a") },
        platform: { os: "linux", architecture: "amd64" },
        identities: incomplete,
      }),
    ).toThrow();
  });
});
