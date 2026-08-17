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
  sourceTreeSha256: sha("a"),
  selectedClosureSha256: sha("b"),
  analyzerIdentity: "cisco.0123456789ab",
  observationConfigurationSha256: sha("c"),
  platform: { os: "linux", architecture: "amd64", relevantFactsSha256: sha("d") },
  scannerManifestEntrySha256: sha("e"),
};

describe("ObservationKey/Set/EvidenceAnnex V1", () => {
  it("keeps entry identity in keys, aggregate identity out, and preserves only valid multiplicity", () => {
    const observationKey = createObservationKeyV1(key);
    const set = createObservationSetV1({
      protocol: "ObservationSetV1",
      observationKey,
      facts: [],
      coverage: [{ kind: "cisco-sarif", sha256: sha("f") }],
    });
    expect(observationKey.observationKeySha256).toMatch(/^[a-f0-9]{64}$/);
    expect(set.observationSetSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(() =>
      createObservationSetV1({
        protocol: "ObservationSetV1",
        observationKey,
        facts: [{ rawOccurrenceFingerprint: sha("0"), multiplicity: 0 }],
        coverage: [{ kind: "cisco-sarif", sha256: sha("f") }],
      }),
    ).toThrow();
  });

  it("verifies bounded content-addressed annex bytes separately and rejects substitution", () => {
    const bytes = Buffer.from('{"detail":"bounded"}', "utf8");
    const annex = createEvidenceAnnexV1({
      protocol: "EvidenceAnnexV1",
      descriptors: [{ id: "cisco-raw", sha256: sha("a"), byteLength: bytes.length }],
    });
    expect(
      verifyEvidenceAnnexBytesV1({ annex, bytes: [{ id: "cisco-raw", bytes }] }),
    ).toMatchObject({ kind: "required" });
    expect(() =>
      createEvidenceAnnexV1({
        protocol: "EvidenceAnnexV1",
        descriptors: [{ id: "../escape", sha256: sha("a"), byteLength: 1 }],
      }),
    ).toThrow();
  });
});
