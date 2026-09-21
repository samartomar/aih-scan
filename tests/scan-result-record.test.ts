import { createHash, generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { canonicalStrictJsonBytesV1 } from "../src/contract/strict-json-v1.js";
import {
  createObservationKeyV1,
  createObservationSetV1,
} from "../src/observation/observation-evidence-v1.js";
import {
  canonicalScanAttestationEnvelopeBytesV2,
  createScanCandidateV2,
  ed25519KeyIdV2,
  isVerifiedScanAttestationV2 as isVerifiedReExport,
  parseScanAttestationEnvelopeV2Json,
  type ScanAnnexArtifactV2,
  signScanCandidateV2,
  type VerifiedScanAttestationV2,
  verifyScanAttestationV2,
} from "../src/observation/scan-attestation-v2.js";
import { createScannerManifestV1 } from "../src/observation/scanner-manifest-v1.js";
import {
  readScanResultRecordV1,
  readScanResultSubjectBindingV1,
  type ScanResultRecordV1,
} from "../src/scan-result-record.js";

/**
 * These fixtures are synthesized here purely so the reader's refusal and
 * pass-through behaviour can be exercised in-process. They are unit-test
 * evidence only and are never presented as a real detector run.
 */
const sha = (value: string | Uint8Array) => createHash("sha256").update(value).digest("hex");
const keyPair = generateKeyPairSync("ed25519");
const keyId = ed25519KeyIdV2(keyPair.publicKey);
const source = sha("source");
const ociManifest = sha("oci manifest");
const rawAnnexBytes = Buffer.from("raw annex", "utf8");
const annexBytes = Buffer.from("annex", "utf8");
const provenanceBytes = Buffer.from("provenance", "utf8");
const annexArtifacts: ScanAnnexArtifactV2[] = [
  { descriptorId: "annex.cisco-raw", bytes: rawAnnexBytes },
  { descriptorId: "annex.provenance", bytes: provenanceBytes },
  { descriptorId: "annex.sbom", bytes: annexBytes },
];
const seal = () => {
  const entries = [{ kind: "file" as const, path: "SKILL.md", sha256: source, byteLength: 6 }];
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
const subjectSource = seal().sourceTreeSha256;
const sourceSealV1 = {
  protocol: "SourceSealV1" as const,
  sourceTreeSha256: sha("v1 source"),
  selectedClosureSha256: sha("v1 selected"),
  sealedSnapshotSha256: sha("v1 snapshot"),
};
const rawFacts = [
  { rawOccurrenceFingerprint: `raw-occurrence-v1:${sha("fact")}`, multiplicity: 1 },
];
const rawCoverage = [
  { coverageKind: "selected-closure" as const, coverageSha256: sha("v1 selected") },
];
const observationConfigurationSha256 = sha("config");
const detectorInput = {
  detectorId: "detector.cisco" as const,
  analyzerIdentity: "native.0123456789ab",
  ociImage: {
    reference: `local.invalid/aih-scan/cisco@sha256:${ociManifest}`,
    sha256: ociManifest,
  },
  adapter: { identity: "adapter.0123456789ab", sha256: sha("adapter") },
  observationConfigurationSha256,
  executionProfileSha256: sha("execution"),
  supportedPlatforms: [{ os: "linux" as const, architecture: "amd64" as const }],
  sbom: { mediaType: "application/spdx+json" as const, sha256: sha(annexBytes) },
  provenance: { mediaType: "application/vnd.in-toto+json" as const, sha256: sha(provenanceBytes) },
};
const scannerManifest = createScannerManifestV1({
  protocol: "ScannerManifestV1",
  detectors: [detectorInput],
});
const scannerManifestEntry =
  scannerManifest.detectors[0] ??
  (() => {
    throw new Error("missing scanner manifest entry");
  })();
const relevantFactsSha256 = sha(
  canonicalStrictJsonBytesV1({
    domain: "aih.cisco.oci-candidate.relevant-facts-v1",
    sourceSeal: sourceSealV1,
  }),
);
const observationKeyInput = {
  protocol: "ObservationKeyV1" as const,
  sourceSeal: sourceSealV1,
  nativeAnalyzerIdentity: detectorInput.analyzerIdentity,
  observationConfigurationSha256,
  platform: { os: "linux" as const, architecture: "amd64" as const, relevantFactsSha256 },
  scannerManifestEntrySha256: scannerManifestEntry.scannerManifestEntrySha256,
};
const observationKey = createObservationKeyV1(observationKeyInput);
const observationSet = createObservationSetV1({
  protocol: "ObservationSetV1",
  observationKey: observationKeyInput,
  facts: rawFacts,
  coverage: rawCoverage,
});
const broker = {
  identity: "broker.0123456789ab",
  sarifSha256: sha("sarif"),
  enforcementState: "unverified" as const,
  policyDigestSha256: sha(
    canonicalStrictJsonBytesV1({
      domain: "aih.cisco.oci-candidate.broker-binding-v1",
      brokerIdentity: "broker.0123456789ab",
      scannerManifestEntrySha256: scannerManifestEntry.scannerManifestEntrySha256,
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
};
const candidate = () =>
  createScanCandidateV2({
    protocol: "ScanCandidateV2",
    coreContract: {
      commit: "6130dd837b8e8bd41e999fb40733e0e460e69720",
      decisionSchemaSha256: "27295aee8d8be333abe2c73adc72884b534b1c9980a9b7a39d12be8d34c5caff",
    },
    subject: { name: "source-tree", digest: { sha256: subjectSource } },
    sourceSeals: { before: seal(), after: seal() },
    observation: {
      keySha256: observationKey.observationKeySha256,
      setSha256: observationSet.observationSetSha256,
    },
    scanner: {
      manifestSha256: scannerManifest.scannerManifestSha256,
      runtimeSha256: sha(
        canonicalStrictJsonBytesV1({
          domain: "aih.cisco.capture-v2.runtime",
          detector: scannerManifestEntry,
        }),
      ),
      configurationSha256: observationConfigurationSha256,
      detector: {
        adapterCapability: "cisco-oci-v1",
        detectorId: detectorInput.detectorId,
        analyzerIdentity: detectorInput.analyzerIdentity,
        oci: {
          logicalReference: detectorInput.ociImage.reference,
          manifestDigestSha256: `sha256:${ociManifest}`,
          configDigestSha256: `sha256:${sha("oci config")}`,
        },
        adapter: detectorInput.adapter,
        observationConfigurationSha256,
        executionProfileSha256: detectorInput.executionProfileSha256,
        supportedPlatform: { os: "linux", architecture: "amd64" },
        sbom: { ...detectorInput.sbom, state: "digest-bound-unverified" },
        provenance: { ...detectorInput.provenance, state: "digest-bound-unverified" },
        scannerManifestEntrySha256: scannerManifestEntry.scannerManifestEntrySha256,
        sourceSealV1,
        platform: observationKeyInput.platform,
        observation: {
          keySha256: observationKey.observationKeySha256,
          setSha256: observationSet.observationSetSha256,
          facts: rawFacts,
          coverage: rawCoverage,
        },
        broker,
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
    scan: { outcome: "succeeded" },
  });
const claims = {
  repository: "samartomar/aih-scan",
  workflow: ".github/workflows/disposable-evidence-chain.yml",
  issuer: "https://token.actions.githubusercontent.com",
  sourceRef: "refs/heads/main",
  commit: "e27a55dcebb635c8298aa4fd6fd871f59089bcf7",
  environment: "test",
  runId: "123",
  runAttempt: 1,
  signedAt: "2026-08-22T00:00:00.000Z",
  expiresAt: "2026-08-22T01:00:00.000Z",
} as const;
const signed = () =>
  signScanCandidateV2({
    candidate: candidate(),
    signer: {
      identity: "scanner.ci",
      class: "test-ephemeral",
      keyId,
      privateKey: keyPair.privateKey,
    },
    claims,
    annexArtifacts,
  });
const expected = {
  ...claims,
  now: "2026-08-22T00:30:00.000Z",
  subjectSha256: subjectSource,
  signer: { identity: "scanner.ci", class: "test-ephemeral", keyId },
};
const roots = () => [
  { identity: "scanner.ci", class: "test-ephemeral" as const, keyId, publicKey: keyPair.publicKey },
];
const verified = (): VerifiedScanAttestationV2 =>
  verifyScanAttestationV2({
    envelope: signed(),
    candidate: candidate(),
    roots: roots(),
    expected,
    annexArtifacts,
  });

describe("public Scan result record reader", () => {
  it("exposes the genuine scanned-content digest for Core's source-to-content binding", () => {
    const binding = readScanResultSubjectBindingV1({ verified: verified() });
    expect(binding.status).toBe("bound");
    if (binding.status !== "bound") return;
    // Bare 64-hex, exactly what Core's content binding compares.
    expect(binding.subjectSha256).toBe(subjectSource);
    expect(binding.subjectSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(binding.subjectName).toBe("source-tree");
  });

  it("refuses a binding for anything that is not a verified attestation", () => {
    for (const value of [
      undefined,
      null,
      0,
      "scan",
      [],
      {},
      { facts: { subject: { sha256: subjectSource } } },
      { protocol: "ScanAttestationV2" },
      // A structurally identical forged object is still not a verified value.
      JSON.parse(JSON.stringify(verified())) as unknown,
    ]) {
      expect(readScanResultSubjectBindingV1({ verified: value }).status, String(value)).toBe(
        "unverified",
      );
    }
    expect(readScanResultSubjectBindingV1(null as never).status).toBe("unverified");
    expect(readScanResultRecordV1({ verified: {} }).status).toBe("unverified");
  });

  it("normalizes a verified attestation into declared result facts without inventing any", () => {
    const record = readScanResultRecordV1({
      verified: verified(),
      annexArtifacts,
      envelopeBytes: canonicalScanAttestationEnvelopeBytesV2(signed()),
    });
    expect(record.status).toBe("available");
    if (record.status !== "available") return;
    const result = record.result as ScanResultRecordV1;

    expect(result.subject).toEqual({ name: "source-tree", sha256: subjectSource });
    expect(result.run.state).toBe("succeeded");
    expect(result.run.cleanupOutcome).toBe("completed");
    expect(result.run.provenance).toBe("none");
    expect(result.platform).toEqual({ os: "linux", architecture: "amd64" });

    // Detector identity, configuration and profile are the attestation's own declared facts.
    expect(result.detector.id).toBe("detector.cisco");
    expect(result.detector.adapterCapability).toBe("cisco-oci-v1");
    expect(result.detector.analyzerIdentity).toBe("native.0123456789ab");
    expect(result.detector.observationConfigurationSha256).toBe(observationConfigurationSha256);
    expect(result.detector.executionProfileSha256).toBe(sha("execution"));
    expect(result.detector.oci.logicalReference).toBe(
      `local.invalid/aih-scan/cisco@sha256:${ociManifest}`,
    );
    expect(result.detector.oci.manifestDigestSha256).toBe(`sha256:${ociManifest}`);

    // Honest, non-synthesized states are preserved verbatim.
    expect(result.evidenceBindings.sbom.state).toBe("digest-bound-unverified");
    expect(result.evidenceBindings.provenance.state).toBe("digest-bound-unverified");
    expect(result.evidenceBindings.brokerEnforcementState).toBe("unverified");
    expect(result.evidenceBindings.sarifSha256).toBe(sha("sarif"));

    // Raw fact grouping and coverage are preserved, with no severity invented.
    expect(result.observations).toEqual([
      { rawOccurrenceFingerprint: `raw-occurrence-v1:${sha("fact")}`, multiplicity: 1 },
    ]);
    expect(result.coverage).toEqual({
      kind: "selected-closure",
      sha256: seal().selectedClosureSha256,
      complete: true,
    });
    expect(result.detector.observationCoverage).toEqual(rawCoverage);
    expect(result.detector.sourceSealV1).toEqual(sourceSealV1);

    // Signer, replay identity and validity are copied; the reader mints nothing.
    expect(result.signer).toEqual({ identity: "scanner.ci", class: "test-ephemeral", keyId });
    expect(result.claims).toEqual({
      signedAt: claims.signedAt,
      expiresAt: claims.expiresAt,
      origin: "signer-asserted",
      provenance: "none",
    });
    // The wider CI claim set is not in the public verified facts, so it is not restated.
    for (const absent of ["repository", "workflow", "sourceRef", "commit", "environment", "runId"])
      expect(result.claims).not.toHaveProperty(absent);
    expect(result.coreContract.commit).toBe("6130dd837b8e8bd41e999fb40733e0e460e69720");
    expect(result.replayIdentity).toBe(verified().facts.replayIdentity);
    expect(result.evidenceBindings.payloadSha256).toBe(verified().facts.payloadSha256);

    // Annexes stay digest-bound references; the reader never parses detector output.
    expect(result.annexes.map((annex) => annex.descriptorId)).toEqual([
      "annex.cisco-raw",
      "annex.provenance",
      "annex.sbom",
    ]);
    for (const annex of result.annexes) expect(annex.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("reports honestly which facts are absent instead of synthesizing defaults", () => {
    const record = readScanResultRecordV1({ verified: verified() });
    expect(record.status).toBe("available");
    if (record.status !== "available") return;
    const kinds = record.result.gaps.map((gap) => gap.kind);
    expect(kinds).toContain("finding-message-and-location-not-read-from-annex");
    expect(kinds).toContain("sarif-not-interpreted");
    expect(kinds).toContain("severity-not-declared-by-attestation");
    expect(kinds).toContain("ci-claim-set-not-restated");
    // No severity, message or location field exists on any finding record.
    for (const finding of record.result.findings) {
      expect(finding).not.toHaveProperty("severity");
      expect(finding).not.toHaveProperty("message");
      expect(finding).not.toHaveProperty("location");
      expect(finding.rawOccurrenceFingerprint).toMatch(/^raw-occurrence-v1:[0-9a-f]{64}$/);
    }
    // Honest comparison signals are preserved rather than defaulted.
    expect(record.result.evidenceBindings.brokerAppliedFactsSha256).toBe(broker.appliedFactsSha256);
    expect(record.result.detector.supportedPlatform).toEqual({
      os: "linux",
      architecture: "amd64",
    });
  });

  it("returns typed absence for unverified, malformed and mismatched input", () => {
    expect(readScanResultRecordV1({ verified: undefined }).status).toBe("unverified");
    // Structurally plausible but never verified.
    const forged = JSON.parse(JSON.stringify(verified())) as unknown;
    expect(readScanResultRecordV1({ verified: forged }).status).toBe("unverified");

    const real = verified();
    // A caller cannot widen a verified value into an unverified result.
    expect(isVerifiedReExport(real)).toBe(true);
    expect(isVerifiedReExport(forged)).toBe(false);

    // Mismatched annex bytes must not be normalized into a result.
    const wrongAnnexes: ScanAnnexArtifactV2[] = annexArtifacts.map((annex) => ({
      descriptorId: annex.descriptorId,
      bytes: annex.descriptorId === "annex.sbom" ? Buffer.from("other", "utf8") : annex.bytes,
    }));
    expect(readScanResultRecordV1({ verified: real, annexArtifacts: wrongAnnexes }).status).toBe(
      "invalid-input",
    );
    expect(readScanResultRecordV1({ verified: real, annexArtifacts: [] }).status).toBe(
      "invalid-input",
    );
    expect(readScanResultRecordV1({ verified: real, annexArtifacts: "x" as never }).status).toBe(
      "invalid-input",
    );
    expect(readScanResultRecordV1(null as never).status).toBe("unverified");

    // Envelope bytes that are not the canonical envelope of this attestation are refused.
    const envelope = parseScanAttestationEnvelopeV2Json(
      canonicalScanAttestationEnvelopeBytesV2(signed()).toString("utf8"),
    );
    expect(envelope.payloadType).toBe("application/vnd.in-toto+json");
    expect(
      readScanResultRecordV1({ verified: real, envelopeBytes: Buffer.from("{}", "utf8") }).status,
    ).toBe("invalid-input");
  });

  it("returns frozen data so a consumer cannot mutate declared facts", () => {
    const record = readScanResultRecordV1({ verified: verified(), annexArtifacts });
    expect(record.status).toBe("available");
    if (record.status !== "available") return;
    expect(Object.isFrozen(record.result)).toBe(true);
    expect(Object.isFrozen(record.result.detector)).toBe(true);
    expect(Object.isFrozen(record.result.observations)).toBe(true);
    expect(Object.isFrozen(record.result.annexes)).toBe(true);
  });
});
