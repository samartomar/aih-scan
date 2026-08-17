import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  canonicalCiscoOciCandidateBytesV1,
  createCiscoOciCandidateV1,
  parseCiscoOciCandidateV1Json,
} from "../../src/cisco/oci-candidate-v1.js";

const sha256 = (value: string) => createHash("sha256").update(value).digest("hex");
const digest = (seed: string) => sha256(`candidate:${seed}`);

const layout = {
  protocol: "CiscoOciLayoutV1",
  manifestDigestSha256: `sha256:${digest("manifest")}`,
  configDigestSha256: `sha256:${digest("config")}`,
  logicalReference: `local.invalid/aih-scan/cisco@sha256:${digest("manifest")}`,
  manifestPlatform: { os: "linux", architecture: "amd64" },
  manifestDescriptor: {
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    digest: `sha256:${digest("manifest")}`,
    size: 123,
    platform: { os: "linux", architecture: "amd64" },
    annotations: { "org.opencontainers.image.ref.name": "candidate" },
  },
};
const brokerResult = {
  protocol: "CiscoOciBrokerV1",
  observationScope: "candidate",
  validationState: "cryptographically-unverified",
  manifestDigestSha256: layout.manifestDigestSha256,
  configDigestSha256: layout.configDigestSha256,
  logicalReference: layout.logicalReference,
  platform: { os: "linux", architecture: "amd64" },
  sourceSeal: {
    protocol: "SourceSealV1",
    sourceTreeSha256: digest("tree"),
    selectedClosureSha256: digest("closure"),
    sealedSnapshotSha256: digest("snapshot"),
  },
  sarifSha256: digest("sarif"),
  facts: [
    {
      detectorClass: "cisco",
      nativeRuleId: "PROMPT_INJECTION_IGNORE_INSTRUCTIONS",
      path: "SKILL.md",
      fileSha256: digest("file"),
      canonicalOrdinal: 0,
      rawOccurrenceFingerprint: `raw-occurrence-v1:${digest("raw")}`,
      multiplicity: 1,
    },
  ],
  coverage: [{ coverageKind: "selected-closure", coverageSha256: digest("closure") }],
  evidenceAnnex: {
    protocol: "EvidenceAnnexV1",
    descriptors: [
      {
        descriptorId: "annex.cisco-raw",
        mediaType: "application/json",
        sha256: digest("annex"),
        byteLength: 2,
        uri: "annex/cisco-raw.json",
      },
    ],
    evidenceAnnexSha256: digest("annex-descriptor"),
  },
  annexBytes: Buffer.from("[]"),
  cleanup: { kind: "clean" },
};

const input = () => ({
  protocol: "CiscoOciCandidateV1",
  layout,
  brokerResult,
  runtime: {
    detectorId: "detector.cisco",
    analyzerIdentity: "native.0123456789ab",
    ociImage: {
      reference: `local.invalid/aih-scan/cisco@sha256:${digest("manifest")}`,
      sha256: digest("manifest"),
    },
    adapter: { identity: "adapter.0123456789ab", sha256: digest("adapter") },
    observationConfigurationSha256: digest("configuration"),
    executionProfileSha256: digest("execution"),
    supportedPlatforms: [{ os: "linux", architecture: "amd64" }],
    sbom: { mediaType: "application/spdx+json", sha256: digest("sbom") },
    provenance: { mediaType: "application/vnd.in-toto+json", sha256: digest("provenance") },
  },
  brokerEnforcement: {
    protocol: "BrokerEnforcementBindingV1",
    brokerIdentity: "broker.0123456789ab",
    policyDigestSha256: digest("broker-policy"),
    appliedFactsSha256: digest("broker-facts"),
    enforcementState: "unverified",
  },
});

function recursivelyFrozen(value: unknown, seen = new Set<object>()): void {
  if (value === null || typeof value !== "object" || ArrayBuffer.isView(value)) return;
  if (seen.has(value)) return;
  seen.add(value);
  expect(Object.isFrozen(value)).toBe(true);
  for (const child of Object.values(value)) recursivelyFrozen(child, seen);
}

function noAuthority(value: unknown): void {
  if (typeof value === "string") {
    expect(
      value === "cryptographically-unverified" ||
        !/qualified|verified|pass|trusted|signer|signature|policy|verdict|acceptance|acknowledgement|public/i.test(
          value,
        ),
    ).toBe(true);
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    expect(
      key === "policyDigestSha256" ||
        !/qualified|verified|pass|trusted|signer|signature|policy|verdict|acceptance|acknowledgement|public/i.test(
          key,
        ),
    ).toBe(true);
    noAuthority(child);
  }
}

describe("Cisco OCI candidate V1", () => {
  it("binds independently supplied local OCI and broker observations into the dormant evidence contracts", () => {
    const result = createCiscoOciCandidateV1(input() as unknown);

    expect(Object.keys(result).sort()).toEqual(
      [
        "annexBytes",
        "attestation",
        "evidenceAnnex",
        "layout",
        "observationKey",
        "observationSet",
        "protocol",
        "scannerManifest",
        "validationState",
      ].sort(),
    );
    expect(result.layout.manifestDigestSha256).toBe(layout.manifestDigestSha256);
    expect(result.layout.configDigestSha256).toBe(layout.configDigestSha256);
    expect(result.scannerManifest.detectors[0]?.scannerManifestEntrySha256).toBe(
      result.observationKey.scannerManifestEntrySha256,
    );
    expect(result.attestation.statement.predicate.scannerManifestSha256).toBe(
      result.scannerManifest.scannerManifestSha256,
    );
    expect(result.observationSet.observationKey.observationKeySha256).toBe(
      result.observationKey.observationKeySha256,
    );
    expect(result.evidenceAnnex.descriptors[0]?.sha256).toBe(sha256(result.annexBytes));
    expect(result.attestation.envelope.signatures).toEqual([]);
    expect(result.validationState).toBe("cryptographically-unverified");
    recursivelyFrozen(result);
    expect(() => canonicalCiscoOciCandidateBytesV1({ ...result } as never)).toThrow();
    noAuthority(result);
  });

  it("rejects substitutions, forgeries, unknown fields, and noncanonical candidate bytes", () => {
    const cases = [
      { ...input(), unknown: true },
      { ...input(), layout: { ...layout } },
      { ...input(), brokerResult: { ...brokerResult } },
      {
        ...input(),
        brokerResult: { ...brokerResult, configDigestSha256: `sha256:${digest("other")}` },
      },
      { ...input(), runtime: { ...input().runtime, detectorId: "detector.other" } },
      {
        ...input(),
        brokerResult: {
          ...brokerResult,
          evidenceAnnex: { ...brokerResult.evidenceAnnex, descriptors: [] },
        },
      },
    ];
    for (const value of cases) expect(() => createCiscoOciCandidateV1(value as unknown)).toThrow();

    expect(() => parseCiscoOciCandidateV1Json('{"protocol":"CiscoOciCandidateV1"}')).toThrow();
    expect(() => canonicalCiscoOciCandidateBytesV1({} as never)).toThrow();
  });
});
