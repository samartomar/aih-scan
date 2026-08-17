import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  createEvidenceAnnexV1,
  createObservationKeyV1,
  createObservationSetV1,
  verifyEvidenceAnnexBytesV1,
} from "../../src/observation/observation-evidence-v1.js";

const sha = (digit: string) => digit.repeat(64);
const key = {
  protocol: "ObservationKeyV1",
  sourceSeal: {
    protocol: "SourceSealV1",
    sourceTreeSha256: sha("a"),
    selectedClosureSha256: sha("b"),
    sealedSnapshotSha256: sha("c"),
  },
  nativeAnalyzerIdentity: "native.0123456789ab",
  observationConfigurationSha256: sha("d"),
  platform: { os: "linux", architecture: "amd64", relevantFactsSha256: sha("e") },
  scannerManifestEntrySha256: sha("f"),
};

describe("ObservationKey/Set/EvidenceAnnex V1", () => {
  it("keeps entry identity in keys, aggregate identity out, and preserves only valid multiplicity", () => {
    const observationKey = createObservationKeyV1(key);
    const set = createObservationSetV1({
      protocol: "ObservationSetV1",
      observationKey: key,
      facts: [],
      coverage: [{ coverageKind: "selected-closure", coverageSha256: sha("a") }],
    });
    expect(observationKey.observationKeySha256).toMatch(/^[a-f0-9]{64}$/);
    expect(set.observationSetSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(Object.keys(observationKey).sort()).toEqual([
      "nativeAnalyzerIdentity",
      "observationConfigurationSha256",
      "observationKeySha256",
      "platform",
      "protocol",
      "scannerManifestEntrySha256",
      "sourceSeal",
    ]);
    expect(Object.keys(set).sort()).toEqual([
      "coverage",
      "facts",
      "observationKey",
      "observationSetSha256",
      "protocol",
    ]);
    expect(set.observationKey).toEqual(observationKey);
    expect(Object.isFrozen(set.facts)).toBe(true);
    expect(() =>
      createObservationSetV1({
        protocol: "ObservationSetV1",
        observationKey: key,
        facts: [{ rawOccurrenceFingerprint: `raw-occurrence-v1:${sha("0")}`, multiplicity: 0 }],
        coverage: [{ coverageKind: "selected-closure", coverageSha256: sha("a") }],
      }),
    ).toThrow();
  });

  it("verifies bounded content-addressed annex bytes separately and rejects substitution", () => {
    const bytes = Buffer.from('{"detail":"bounded"}', "utf8");
    const digest = createHash("sha256").update(bytes).digest("hex");
    const annex = createEvidenceAnnexV1({
      protocol: "EvidenceAnnexV1",
      descriptors: [
        {
          descriptorId: "annex.cisco-raw",
          mediaType: "application/json",
          sha256: digest,
          byteLength: bytes.length,
          uri: "annex/cisco.json",
        },
      ],
    });
    expect(Object.keys(annex).sort()).toEqual(["descriptors", "evidenceAnnexSha256", "protocol"]);
    expect(Object.keys(annex.descriptors[0] ?? {}).sort()).toEqual([
      "byteLength",
      "descriptorId",
      "mediaType",
      "sha256",
      "uri",
    ]);
    expect(
      verifyEvidenceAnnexBytesV1({
        annex,
        descriptors: [{ descriptorId: "annex.cisco-raw", bytes }],
      }),
    ).toEqual({
      kind: "complete",
    });
    for (const descriptors of [
      [],
      [{ descriptorId: "annex.unknown", bytes }],
      [
        { descriptorId: "annex.cisco-raw", bytes },
        { descriptorId: "annex.cisco-raw", bytes },
      ],
      [{ descriptorId: "annex.cisco-raw", bytes: Buffer.from("substitution") }],
    ]) {
      expect(verifyEvidenceAnnexBytesV1({ annex, descriptors })).toMatchObject({
        kind: "required",
      });
    }
    expect(() =>
      createEvidenceAnnexV1({
        protocol: "EvidenceAnnexV1",
        descriptors: [
          {
            descriptorId: "annex.escape",
            mediaType: "application/json",
            sha256: sha("a"),
            byteLength: 1,
            uri: "../escape",
          },
        ],
      }),
    ).toThrow();
  });
});
