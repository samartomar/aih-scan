import { describe, expect, it } from "vitest";
import {
  canonicalScanAttestationStatementBytesV1,
  createScanAttestationV1,
} from "../../src/observation/scan-attestation-v1.js";

const sha = (digit: string) => digit.repeat(64);
const input = {
  protocol: "ScanAttestationV1",
  subject: { name: "source", digest: { sha256: sha("a") } },
  scannerManifestSha256: sha("b"),
  detectors: [
    { detectorId: "cisco", observationKeySha256: sha("c"), observationSetSha256: sha("d") },
  ],
  brokerEnforcement: {
    protocol: "BrokerEnforcementBindingV1",
    brokerIdentity: "caller.example.invalid",
    policyDigestSha256: sha("e"),
    appliedFactsSha256: sha("f"),
    enforcementState: "unverified",
  },
  cleanup: { outcome: "unverified" },
  annexDescriptors: [],
};

describe("ScanAttestationV1", () => {
  it("emits coherent canonical DSSE/in-toto shape with empty signatures and no verification authority", () => {
    const attestation = createScanAttestationV1(input);
    expect(attestation.validationState).toBe("cryptographically-unverified");
    expect(attestation.envelope.signatures).toEqual([]);
    expect(Buffer.from(attestation.envelope.payload, "base64")).toEqual(
      canonicalScanAttestationStatementBytesV1(attestation.statement),
    );
  });

  it("rejects inconsistent payloads, duplicate detectors, policy verdict fields, and signed claims", () => {
    for (const invalid of [
      { ...input, detectors: [input.detectors[0], input.detectors[0]] },
      { ...input, verdict: "pass" },
      { ...input, brokerEnforcement: { ...input.brokerEnforcement, enforcementState: "verified" } },
      { ...input, signatures: [{ sig: "forbidden" }] },
    ])
      expect(() => createScanAttestationV1(invalid)).toThrow();
  });
});
