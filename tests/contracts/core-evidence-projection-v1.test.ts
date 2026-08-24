import { createHash, generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { canonicalStrictJsonBytesV1 } from "../../src/contract/strict-json-v1.js";
import {
  AI_HARNESS_DECISION_V2_SCHEMA_SHA256,
  AI_HARNESS_STRICT_V2_COMMIT,
} from "../../src/core/core-contract-lock-v2.js";
import {
  canonicalCoreOrganizationEvidenceEnvelopeV1Bytes,
  projectVerifiedScanAttestationToCoreEvidenceEnvelopeV1,
} from "../../src/core/organization-evidence-envelope-v1.js";
import {
  createObservationKeyV1,
  createObservationSetV1,
} from "../../src/observation/observation-evidence-v1.js";
import {
  createScanCandidateV2,
  ed25519KeyIdV2,
  signScanCandidateV2,
  verifyScanAttestationV2,
} from "../../src/observation/scan-attestation-v2.js";
import { createScannerManifestV1 } from "../../src/observation/scanner-manifest-v1.js";

const sha = (value: string | Uint8Array) => createHash("sha256").update(value).digest("hex");
const keyPair = generateKeyPairSync("ed25519");
const keyId = ed25519KeyIdV2(keyPair.publicKey);
const annexArtifacts = [
  { descriptorId: "annex.cisco-raw", bytes: Buffer.from("raw", "utf8") },
  { descriptorId: "annex.provenance", bytes: Buffer.from("provenance", "utf8") },
  { descriptorId: "annex.sbom", bytes: Buffer.from("sbom", "utf8") },
] as const;
const source = sha("projection-source");
const entries = [{ kind: "file" as const, path: "SKILL.md", sha256: source, byteLength: 17 }];
const seal = () => {
  const sourceTreeSha256 = sha(canonicalStrictJsonBytesV1({ protocol: "SourceTreeV2", entries }));
  const selectedClosureSha256 = sha(
    canonicalStrictJsonBytesV1({ protocol: "SelectedClosureV2", files: entries }),
  );
  return {
    protocol: "SourceSealV2" as const,
    algorithm: "code-unit-canonical-json-v1" as const,
    entries,
    selectedClosurePaths: ["SKILL.md"],
    selectedFiles: entries,
    sourceTreeSha256,
    selectedClosureSha256,
    sealedSnapshotSha256: sha(
      canonicalStrictJsonBytesV1({
        protocol: "SealedSnapshotV2",
        sourceTreeSha256,
        selectedClosureSha256,
      }),
    ),
  };
};
const sourceSealV1 = {
  protocol: "SourceSealV1" as const,
  sourceTreeSha256: sha("v1-source"),
  selectedClosureSha256: sha("v1-closure"),
  sealedSnapshotSha256: sha("v1-snapshot"),
};
function candidate(outcome: "succeeded" | "failed" | "refused" = "succeeded") {
  const detector = {
    detectorId: "detector.cisco" as const,
    analyzerIdentity: "native.0123456789ab",
    ociImage: {
      reference: `local.invalid/scanner@sha256:${sha("manifest")}`,
      sha256: sha("manifest"),
    },
    adapter: { identity: "adapter.0123456789ab", sha256: sha("adapter") },
    observationConfigurationSha256: sha("configuration"),
    executionProfileSha256: sha("execution"),
    supportedPlatforms: [{ os: "linux" as const, architecture: "amd64" as const }],
    sbom: { mediaType: "application/spdx+json" as const, sha256: sha(annexArtifacts[2].bytes) },
    provenance: {
      mediaType: "application/vnd.in-toto+json" as const,
      sha256: sha(annexArtifacts[1].bytes),
    },
  };
  const manifest = createScannerManifestV1({
    protocol: "ScannerManifestV1",
    detectors: [detector],
  });
  const entry = manifest.detectors[0];
  if (entry === undefined) throw new Error("scanner entry missing");
  const rawFacts = [
    { rawOccurrenceFingerprint: `raw-occurrence-v1:${sha("fact")}`, multiplicity: 1 },
  ];
  const rawCoverage = [
    {
      coverageKind: "selected-closure" as const,
      coverageSha256: sourceSealV1.selectedClosureSha256,
    },
  ];
  const relevantFactsSha256 = sha(
    canonicalStrictJsonBytesV1({
      domain: "aih.cisco.oci-candidate.relevant-facts-v1",
      sourceSeal: sourceSealV1,
    }),
  );
  const observationInput = {
    protocol: "ObservationKeyV1" as const,
    sourceSeal: sourceSealV1,
    nativeAnalyzerIdentity: detector.analyzerIdentity,
    observationConfigurationSha256: detector.observationConfigurationSha256,
    platform: { os: "linux" as const, architecture: "amd64" as const, relevantFactsSha256 },
    scannerManifestEntrySha256: entry.scannerManifestEntrySha256,
  };
  const observationKey = createObservationKeyV1(observationInput);
  const observationSet = createObservationSetV1({
    protocol: "ObservationSetV1",
    observationKey: observationInput,
    facts: rawFacts,
    coverage: rawCoverage,
  });
  return createScanCandidateV2({
    protocol: "ScanCandidateV2",
    coreContract: {
      commit: AI_HARNESS_STRICT_V2_COMMIT,
      decisionSchemaSha256: AI_HARNESS_DECISION_V2_SCHEMA_SHA256,
    },
    subject: { name: "source-tree", digest: { sha256: seal().sourceTreeSha256 } },
    sourceSeals: { before: seal(), after: seal() },
    observation: {
      keySha256: observationKey.observationKeySha256,
      setSha256: observationSet.observationSetSha256,
    },
    scanner: {
      manifestSha256: manifest.scannerManifestSha256,
      runtimeSha256: sha(
        canonicalStrictJsonBytesV1({ domain: "aih.cisco.capture-v2.runtime", detector: entry }),
      ),
      configurationSha256: detector.observationConfigurationSha256,
      cisco: {
        detectorId: detector.detectorId,
        analyzerIdentity: detector.analyzerIdentity,
        oci: {
          logicalReference: detector.ociImage.reference,
          manifestDigestSha256: `sha256:${detector.ociImage.sha256}`,
          configDigestSha256: `sha256:${sha("config")}`,
        },
        adapter: detector.adapter,
        observationConfigurationSha256: detector.observationConfigurationSha256,
        executionProfileSha256: detector.executionProfileSha256,
        supportedPlatform: detector.supportedPlatforms[0],
        sbom: { ...detector.sbom, state: "digest-bound-unverified" as const },
        provenance: { ...detector.provenance, state: "digest-bound-unverified" as const },
        scannerManifestEntrySha256: entry.scannerManifestEntrySha256,
        sourceSealV1,
        platform: observationInput.platform,
        observation: {
          keySha256: observationKey.observationKeySha256,
          setSha256: observationSet.observationSetSha256,
          facts: rawFacts,
          coverage: rawCoverage,
        },
        broker: {
          identity: "broker.0123456789ab",
          sarifSha256: sha("sarif"),
          enforcementState: "unverified" as const,
          policyDigestSha256: sha(
            canonicalStrictJsonBytesV1({
              domain: "aih.cisco.oci-candidate.broker-binding-v1",
              brokerIdentity: "broker.0123456789ab",
              scannerManifestEntrySha256: entry.scannerManifestEntrySha256,
              sarifSha256: sha("sarif"),
            }),
          ),
          appliedFactsSha256: sha(
            canonicalStrictJsonBytesV1({
              domain: "aih.cisco.oci-candidate.applied-facts-v1",
              facts: rawFacts,
              coverage: rawCoverage,
            }),
          ),
        },
      },
    },
    platform: { os: "linux", architecture: "amd64" },
    coverage: { kind: "selected-closure", sha256: seal().selectedClosureSha256, complete: true },
    annexes: annexArtifacts.map(({ descriptorId, bytes }) => ({
      descriptorId,
      sha256: sha(bytes),
      byteLength: bytes.byteLength,
    })),
    cleanup: { outcome: "completed" },
    scan: { outcome },
  });
}
function verified(
  options: {
    outcome?: "succeeded" | "failed" | "refused";
    signerClass?: "organization" | "test-ephemeral";
  } = {},
) {
  const scan = candidate(options.outcome);
  const signerClass = options.signerClass ?? "organization";
  const claims = {
    repository: "aihq/scan",
    workflow: ".github/workflows/evidence.yml",
    issuer: "https://token.actions.githubusercontent.com",
    sourceRef: "refs/heads/main",
    commit: AI_HARNESS_STRICT_V2_COMMIT,
    environment: "production",
    runId: "123",
    runAttempt: 1,
    signedAt: "2026-08-24T00:00:00.000Z",
    expiresAt: "2026-08-24T01:00:00.000Z",
  } as const;
  const signer = { identity: "organization.scanner", class: signerClass, keyId };
  const evidence = signScanCandidateV2({
    candidate: scan,
    signer: { ...signer, privateKey: keyPair.privateKey },
    claims,
    annexArtifacts,
  });
  return verifyScanAttestationV2({
    envelope: evidence,
    candidate: scan,
    annexArtifacts,
    roots: [{ ...signer, publicKey: keyPair.publicKey }],
    expected: {
      ...claims,
      now: "2026-08-24T00:30:00.000Z",
      subjectSha256: scan.subject.digest.sha256,
      signer,
    },
  });
}
const coreSubjectDigest = `sha256:${sha("core-subject")}`;

describe("Core organization evidence projection V1", () => {
  it("projects only a custody-verified successful organization scan into deterministic canonical non-authority evidence", () => {
    const result = projectVerifiedScanAttestationToCoreEvidenceEnvelopeV1({
      verified: verified(),
      subjectDigest: coreSubjectDigest,
    });
    expect(result).toMatchObject({
      format: "aih-organization-evidence",
      version: 1,
      subjectDigest: coreSubjectDigest,
      evidence: {
        kind: "scan-attestation-v2",
        id: "scanner-evidence-v2",
        summary:
          "Verified scanner evidence only; not qualification, admission, approval, finding disposition, or effect authority.",
      },
      issuedAt: "2026-08-24T00:00:00.000Z",
      notBefore: "2026-08-24T00:00:00.000Z",
      expiresAt: "2026-08-24T01:00:00.000Z",
    });
    expect(result.evidence.artifactDigests).toEqual([...result.evidence.artifactDigests].sort());
    expect(result.evidence.artifactDigests).toContain(
      `sha256:${result.evidence.payloadDigest.slice("sha256:".length)}`,
    );
    expect(canonicalCoreOrganizationEvidenceEnvelopeV1Bytes(result).toString("utf8")).toBe(
      JSON.stringify(
        JSON.parse(canonicalCoreOrganizationEvidenceEnvelopeV1Bytes(result).toString("utf8")),
      ),
    );
    expect(
      projectVerifiedScanAttestationToCoreEvidenceEnvelopeV1({
        verified: verified(),
        subjectDigest: coreSubjectDigest,
      }),
    ).toEqual(result);
  });

  it("refuses raw, copied, test-ephemeral, unsuccessful, and hostile input before projecting", () => {
    const good = verified();
    expect(() =>
      projectVerifiedScanAttestationToCoreEvidenceEnvelopeV1({
        verified: { ...good },
        subjectDigest: coreSubjectDigest,
      }),
    ).toThrow(/verified/i);
    expect(() =>
      projectVerifiedScanAttestationToCoreEvidenceEnvelopeV1({
        verified: verified({ signerClass: "test-ephemeral" }),
        subjectDigest: coreSubjectDigest,
      }),
    ).toThrow(/organization/i);
    expect(() =>
      projectVerifiedScanAttestationToCoreEvidenceEnvelopeV1({
        verified: verified({ outcome: "failed" }),
        subjectDigest: coreSubjectDigest,
      }),
    ).toThrow(/successful/i);
    expect(() =>
      projectVerifiedScanAttestationToCoreEvidenceEnvelopeV1({
        verified: verified({ outcome: "refused" }),
        subjectDigest: coreSubjectDigest,
      }),
    ).toThrow(/successful/i);
    expect(() =>
      projectVerifiedScanAttestationToCoreEvidenceEnvelopeV1({
        verified: good,
        subjectDigest: sha("missing-prefix"),
      }),
    ).toThrow();
    const hiddenExtra = { verified: good, subjectDigest: coreSubjectDigest } as Record<
      string,
      unknown
    >;
    Object.defineProperty(hiddenExtra, "unexpected", { value: true });
    expect(() => projectVerifiedScanAttestationToCoreEvidenceEnvelopeV1(hiddenExtra)).toThrow();
    let reads = 0;
    const hostile = { verified: good, subjectDigest: coreSubjectDigest } as Record<string, unknown>;
    Object.defineProperty(hostile, "subjectDigest", {
      enumerable: true,
      get: () => {
        reads += 1;
        throw new Error("accessor");
      },
    });
    expect(() => projectVerifiedScanAttestationToCoreEvidenceEnvelopeV1(hostile)).toThrow();
    expect(reads).toBe(0);
  });

  it("binds caller subject and every verified evidence, candidate, payload, source, and annex identity", () => {
    const value = verified();
    const first = projectVerifiedScanAttestationToCoreEvidenceEnvelopeV1({
      verified: value,
      subjectDigest: coreSubjectDigest,
    });
    const second = projectVerifiedScanAttestationToCoreEvidenceEnvelopeV1({
      verified: value,
      subjectDigest: `sha256:${sha("changed-core-subject")}`,
    });
    expect(second.subjectDigest).not.toBe(first.subjectDigest);
    for (const digest of [
      value.facts.evidenceDigestSha256,
      value.facts.payloadSha256,
      value.facts.candidateSha256,
      value.facts.subject.sha256,
      value.facts.sourceSeals.before.selectedClosureSha256,
      ...value.facts.annexDescriptors.map((entry) => entry.sha256),
    ])
      expect(first.evidence.artifactDigests).toContain(`sha256:${digest}`);
    expect(first.attestor).not.toContain("test-ephemeral");
  });
});
