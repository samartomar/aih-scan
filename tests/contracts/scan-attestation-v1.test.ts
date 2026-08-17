import { describe, expect, it } from "vitest";
import {
  canonicalScanAttestationStatementBytesV1,
  createScanAttestationV1,
  parseScanAttestationV1Json,
} from "../../src/observation/scan-attestation-v1.js";

const sha = (digit: string) => digit.repeat(64);
const input = {
  protocol: "ScanAttestationV1",
  sourceTarget: { name: "source-tree", sha256: sha("a") },
  scannerManifestSha256: sha("b"),
  observations: [
    {
      detectorId: "detector.cisco",
      observationKeySha256: sha("c"),
      observationSetSha256: sha("d"),
    },
  ],
  brokerEnforcement: {
    protocol: "BrokerEnforcementBindingV1",
    brokerIdentity: "broker.0123456789ab",
    policyDigestSha256: sha("e"),
    appliedFactsSha256: sha("f"),
    enforcementState: "unverified",
  },
  cleanup: { outcome: "completed" },
  annexDescriptors: [],
};

describe("ScanAttestationV1", () => {
  it("emits coherent canonical DSSE/in-toto shape with empty signatures and no verification authority", () => {
    const attestation = createScanAttestationV1(input);
    expect(Object.keys(attestation).sort()).toEqual([
      "envelope",
      "protocol",
      "scanAttestationSha256",
      "statement",
      "validationState",
    ]);
    expect(Object.keys(attestation.envelope).sort()).toEqual([
      "payload",
      "payloadType",
      "signatures",
    ]);
    expect(Object.keys(attestation.statement).sort()).toEqual([
      "_type",
      "predicate",
      "predicateType",
      "subject",
    ]);
    expect(Object.keys(attestation.statement.predicate).sort()).toEqual([
      "annexDescriptors",
      "brokerEnforcement",
      "cleanup",
      "observations",
      "protocol",
      "scannerManifestSha256",
    ]);
    expect(attestation.validationState).toBe("cryptographically-unverified");
    expect(attestation.envelope.signatures).toEqual([]);
    expect(Buffer.from(attestation.envelope.payload, "base64")).toEqual(
      canonicalScanAttestationStatementBytesV1(attestation.statement),
    );
    expect(Object.isFrozen(attestation.statement.predicate.brokerEnforcement)).toBe(true);
    expect(() =>
      parseScanAttestationV1Json('{"protocol":"ScanAttestationV1","protocol":"x"}'),
    ).toThrow();
  });

  it("rejects inconsistent payloads, duplicate detectors, policy verdict fields, and signed claims", () => {
    for (const invalid of [
      { ...input, observations: [input.observations[0], input.observations[0]] },
      { ...input, verdict: "pass" },
      { ...input, brokerEnforcement: { ...input.brokerEnforcement, enforcementState: "verified" } },
      { ...input, signatures: [{ sig: "forbidden" }] },
    ])
      expect(() => createScanAttestationV1(invalid)).toThrow();
  });

  it("rejects arbitrary, noncanonical, and statement-mismatched DSSE base64 payloads", () => {
    const current = createScanAttestationV1(input);
    const parse = (value: unknown) => parseScanAttestationV1Json(JSON.stringify(value));
    const arbitrary = structuredClone(current);
    arbitrary.envelope.payload = Buffer.from('{"arbitrary":true}', "utf8").toString("base64");
    expect(() => parse(arbitrary)).toThrow();
    const noncanonical = structuredClone(current);
    noncanonical.envelope.payload = `${current.envelope.payload}=`;
    expect(() => parse(noncanonical)).toThrow();
    const malformed = structuredClone(current);
    malformed.envelope.payload = "%%%";
    expect(() => parse(malformed)).toThrow();
    const mutatedStatement = structuredClone(current);
    mutatedStatement.statement.predicate.cleanup.outcome = "failed";
    expect(() => parse(mutatedStatement)).toThrow();
    const mismatchedDigest = structuredClone(current) as { scanAttestationSha256: string };
    mismatchedDigest.scanAttestationSha256 = sha("0");
    expect(() => parse(mismatchedDigest)).toThrow();
  });

  it("matches the public AIH fixed statement-and-envelope digest vector", () => {
    const attestation = createScanAttestationV1(input);
    expect(attestation.scanAttestationSha256).toBe(
      "d655c6b9fe6ac6fa33eb587ade6b232358eb9e9e8df2a7d655373622a3a12c71",
    );
    expect(() =>
      createScanAttestationV1({
        ...input,
        observations: Array.from({ length: 129 }, (_, index) => ({
          ...input.observations[0],
          detectorId: `detector.vector-${String(index)}`,
        })),
      }),
    ).toThrow();
    expect(() =>
      createScanAttestationV1({
        ...input,
        annexDescriptors: Array.from({ length: 129 }, (_, index) => ({
          descriptorId: `annex.vector-${String(index)}`,
          mediaType: "application/json" as const,
          sha256: sha("a"),
          byteLength: 1,
          uri: `annex/${String(index)}.json`,
        })),
      }),
    ).toThrow();
  });
});
