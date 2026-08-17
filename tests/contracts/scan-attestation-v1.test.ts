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
});
