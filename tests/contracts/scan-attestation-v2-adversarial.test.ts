import { createHash, generateKeyPairSync, sign as signDetached } from "node:crypto";
import { describe, expect, it } from "vitest";
import { canonicalStrictJsonBytesV1 } from "../../src/contract/strict-json-v1.js";
import {
  createObservationKeyV1,
  createObservationSetV1,
} from "../../src/observation/observation-evidence-v1.js";
import {
  canonicalDssePaeV2,
  createScanCandidateV2,
  ed25519KeyIdV2,
  parseScanAttestationEnvelopeV2Json,
  signScanCandidateV2,
  verifyScanAttestationV2,
} from "../../src/observation/scan-attestation-v2.js";
import { createScannerManifestV1 } from "../../src/observation/scanner-manifest-v1.js";

const sha = (value: string | Uint8Array) => createHash("sha256").update(value).digest("hex");
const keyPair = generateKeyPairSync("ed25519");
const rotatedKeyPair = generateKeyPairSync("ed25519");
const keyId = ed25519KeyIdV2(keyPair.publicKey);
const rotatedKeyId = ed25519KeyIdV2(rotatedKeyPair.publicKey);
const source = sha("source");
const rawAnnex = Buffer.from("raw annex", "utf8");
const provenanceAnnex = Buffer.from("provenance annex", "utf8");
const sbomAnnex = Buffer.from("sbom annex", "utf8");
const annexArtifacts = [
  { descriptorId: "annex.cisco-raw", bytes: rawAnnex },
  { descriptorId: "annex.provenance", bytes: provenanceAnnex },
  { descriptorId: "annex.sbom", bytes: sbomAnnex },
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
const sourceSealV1 = {
  protocol: "SourceSealV1" as const,
  sourceTreeSha256: sha("v1 source"),
  selectedClosureSha256: sha("v1 selected"),
  sealedSnapshotSha256: sha("v1 snapshot"),
};
const detector = {
  detectorId: "detector.cisco" as const,
  analyzerIdentity: "native.0123456789ab",
  ociImage: {
    reference: `local.invalid/aih-scan/cisco@sha256:${sha("oci manifest")}`,
    sha256: sha("oci manifest"),
  },
  adapter: { identity: "adapter.0123456789ab", sha256: sha("adapter") },
  observationConfigurationSha256: sha("configuration"),
  executionProfileSha256: sha("execution"),
  supportedPlatforms: [{ os: "linux" as const, architecture: "amd64" as const }],
  sbom: { mediaType: "application/spdx+json" as const, sha256: sha(sbomAnnex) },
  provenance: {
    mediaType: "application/vnd.in-toto+json" as const,
    sha256: sha(provenanceAnnex),
  },
};
const manifest = createScannerManifestV1({ protocol: "ScannerManifestV1", detectors: [detector] });
const manifestEntry =
  manifest.detectors[0] ??
  (() => {
    throw new Error("missing scanner manifest entry");
  })();
const facts = [{ rawOccurrenceFingerprint: `raw-occurrence-v1:${sha("fact")}`, multiplicity: 1 }];
const coverage = [
  { coverageKind: "selected-closure" as const, coverageSha256: sha("v1 selected") },
];
const relevantFactsSha256 = sha(
  canonicalStrictJsonBytesV1({
    domain: "aih.cisco.oci-candidate.relevant-facts-v1",
    sourceSeal: sourceSealV1,
  }),
);
const observationKeyInput = {
  protocol: "ObservationKeyV1" as const,
  sourceSeal: sourceSealV1,
  nativeAnalyzerIdentity: detector.analyzerIdentity,
  observationConfigurationSha256: detector.observationConfigurationSha256,
  platform: { os: "linux" as const, architecture: "amd64" as const, relevantFactsSha256 },
  scannerManifestEntrySha256: manifestEntry.scannerManifestEntrySha256,
};
const observationKey = createObservationKeyV1(observationKeyInput);
const observationSet = createObservationSetV1({
  protocol: "ObservationSetV1",
  observationKey: observationKeyInput,
  facts,
  coverage,
});
const candidate = () => {
  const appliedFactsSha256 = sha(
    canonicalStrictJsonBytesV1({
      domain: "aih.cisco.oci-candidate.applied-facts-v1",
      facts,
      coverage,
    }),
  );
  const policyDigestSha256 = sha(
    canonicalStrictJsonBytesV1({
      domain: "aih.cisco.oci-candidate.broker-binding-v1",
      brokerIdentity: "broker.0123456789ab",
      scannerManifestEntrySha256: manifestEntry.scannerManifestEntrySha256,
      sarifSha256: sha("sarif"),
    }),
  );
  const runtimeSha256 = sha(
    canonicalStrictJsonBytesV1({
      domain: "aih.cisco.capture-v2.runtime",
      detector: manifestEntry,
    }),
  );
  return createScanCandidateV2({
    protocol: "ScanCandidateV2",
    coreContract: {
      commit: "e53fe219002515c092ebb68c5b91c91a2fc6110d",
      decisionSchemaSha256: "27295aee8d8be333abe2c73adc72884b534b1c9980a9b7a39d12be8d34c5caff",
    },
    subject: { name: "source-tree", digest: { sha256: seal().sourceTreeSha256 } },
    sourceSeals: { before: seal(), after: seal() },
    observation: {
      keySha256: observationKey.observationKeySha256,
      setSha256: observationSet.observationSetSha256,
    },
    scanner: {
      manifestSha256: manifest.scannerManifestSha256,
      runtimeSha256,
      configurationSha256: detector.observationConfigurationSha256,
      detector: {
        adapterCapability: "cisco-oci-v1",
        detectorId: detector.detectorId,
        analyzerIdentity: detector.analyzerIdentity,
        oci: {
          logicalReference: detector.ociImage.reference,
          manifestDigestSha256: `sha256:${detector.ociImage.sha256}`,
          configDigestSha256: `sha256:${sha("oci config")}`,
        },
        adapter: detector.adapter,
        observationConfigurationSha256: detector.observationConfigurationSha256,
        executionProfileSha256: detector.executionProfileSha256,
        supportedPlatform: detector.supportedPlatforms[0],
        sbom: { ...detector.sbom, state: "digest-bound-unverified" as const },
        provenance: { ...detector.provenance, state: "digest-bound-unverified" as const },
        scannerManifestEntrySha256: manifestEntry.scannerManifestEntrySha256,
        sourceSealV1,
        platform: observationKeyInput.platform,
        observation: {
          keySha256: observationKey.observationKeySha256,
          setSha256: observationSet.observationSetSha256,
          facts,
          coverage,
        },
        broker: {
          identity: "broker.0123456789ab",
          sarifSha256: sha("sarif"),
          enforcementState: "unverified" as const,
          policyDigestSha256,
          appliedFactsSha256,
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
    scan: { outcome: "succeeded" },
  });
};
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
const expected = {
  ...claims,
  now: "2026-08-22T00:30:00.000Z",
  subjectSha256: seal().sourceTreeSha256,
  signer: { identity: "scanner.ci", class: "test-ephemeral" as const, keyId },
};
const roots = () => [
  { identity: "scanner.ci", class: "test-ephemeral" as const, keyId, publicKey: keyPair.publicKey },
];
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

describe("ScanAttestationV2 adversarial verifier contract", () => {
  it("rejects raw-payload signatures, malformed base64, and mismatched key identifiers", () => {
    const evidence = signed();
    const envelope = evidence.envelope;
    const rawSignature = signDetached(
      null,
      Buffer.from(envelope.payload, "base64"),
      keyPair.privateKey,
    );
    const variants = [
      {
        ...envelope,
        signatures: [{ ...envelope.signatures[0], sig: rawSignature.toString("base64") }],
      },
      { ...envelope, payload: "YQ=" },
      { ...envelope, payload: "YQ==\n" },
      { ...envelope, payload: "!!!!" },
      { ...envelope, signatures: [{ ...envelope.signatures[0], sig: "YQ==" }] },
      { ...envelope, signatures: [{ ...envelope.signatures[0], keyid: rotatedKeyId }] },
    ];
    for (const adversarialEnvelope of variants)
      expect(() =>
        verifyScanAttestationV2({
          envelope: adversarialEnvelope,
          candidate: candidate(),
          roots: roots(),
          expected,
          annexArtifacts,
        }),
      ).toThrow();
  });

  it("rejects wrong trust bindings while accepting old and rotated valid roots", () => {
    const evidence = signed();
    const originalRoot = roots()[0];
    if (originalRoot === undefined) throw new Error("missing original trust root");
    const rotatedRoot = {
      identity: "scanner.ci",
      class: "test-ephemeral" as const,
      keyId: rotatedKeyId,
      publicKey: rotatedKeyPair.publicKey,
    };
    expect(() =>
      verifyScanAttestationV2({
        envelope: evidence,
        candidate: candidate(),
        roots: [{ ...originalRoot, publicKey: rotatedKeyPair.publicKey }],
        expected,
        annexArtifacts,
      }),
    ).toThrow();
    expect(() =>
      verifyScanAttestationV2({
        envelope: evidence,
        candidate: candidate(),
        roots: [...roots(), originalRoot],
        expected,
        annexArtifacts,
      }),
    ).toThrow();
    expect(() =>
      verifyScanAttestationV2({
        envelope: evidence,
        candidate: candidate(),
        roots: [...roots(), { ...rotatedRoot, class: "organization" as const }],
        expected,
        annexArtifacts,
      }),
    ).toThrow();
    expect(
      verifyScanAttestationV2({
        envelope: evidence,
        candidate: candidate(),
        roots: [...roots(), rotatedRoot],
        expected,
        annexArtifacts,
      }).facts.envelopeValid,
    ).toBe(true);
  });

  it("rejects every expected CI identity mismatch and evidence that is not yet valid", () => {
    const evidence = signed();
    const expectedMutations = [
      { workflow: ".github/workflows/other.yml" },
      { issuer: "https://issuer.invalid" },
      { sourceRef: "refs/tags/v1" },
      { commit: "0123456789012345678901234567890123456789" },
      { environment: "production" },
      { runId: "124" },
      { runAttempt: 2 },
      { subjectSha256: sha("other source") },
      { signer: { identity: "other", class: "test-ephemeral" as const, keyId } },
    ];
    for (const mutation of expectedMutations)
      expect(() =>
        verifyScanAttestationV2({
          envelope: evidence,
          candidate: candidate(),
          roots: roots(),
          expected: { ...expected, ...mutation },
          annexArtifacts,
        }),
      ).toThrow();
    const future = signScanCandidateV2({
      candidate: candidate(),
      signer: {
        identity: "scanner.ci",
        class: "test-ephemeral",
        keyId,
        privateKey: keyPair.privateKey,
      },
      claims: {
        ...claims,
        signedAt: "2026-08-22T00:31:00.000Z",
        expiresAt: "2026-08-22T01:31:00.000Z",
      },
      annexArtifacts,
    });
    expect(() =>
      verifyScanAttestationV2({
        envelope: future,
        candidate: candidate(),
        roots: roots(),
        expected: {
          ...expected,
          signedAt: "2026-08-22T00:31:00.000Z",
          expiresAt: "2026-08-22T01:31:00.000Z",
        },
        annexArtifacts,
      }),
    ).toThrow();
  });

  it("rejects inherited, extra, and accessor-backed expected signers without reading accessors", () => {
    const evidence = signed();
    let accessorReads = 0;
    const accessorSigner = { ...expected.signer } as Record<string, unknown>;
    Object.defineProperty(accessorSigner, "identity", {
      enumerable: true,
      get: () => {
        accessorReads += 1;
        throw new Error("must not read expected signer accessor");
      },
    });
    const hiddenExtraSigner = { ...expected.signer } as Record<string, unknown>;
    Object.defineProperty(hiddenExtraSigner, "unexpected", { value: true });
    const signers: unknown[] = [
      Object.create(expected.signer),
      { ...expected.signer, unexpected: true },
      hiddenExtraSigner,
      accessorSigner,
    ];
    for (const signer of signers)
      expect(() =>
        verifyScanAttestationV2({
          envelope: evidence,
          candidate: candidate(),
          roots: roots(),
          expected: { ...expected, signer },
          annexArtifacts,
        }),
      ).toThrow();
    expect(accessorReads).toBe(0);
  });

  it("rejects V1, unknown predicate, and noncanonical V2 envelope or payload JSON", () => {
    const evidence = signed();
    const decodePayload = () =>
      JSON.parse(Buffer.from(evidence.envelope.payload, "base64").toString("utf8"));
    const invalidPayloads = [
      {
        ...decodePayload(),
        predicate: { ...decodePayload().predicate, protocol: "ScanAttestationV1" },
      },
      { ...decodePayload(), predicateType: "https://aih.dev/UnknownPredicateV2" },
      { ...decodePayload(), _type: "https://in-toto.io/Statement/v0" },
    ];
    for (const payload of invalidPayloads) {
      const encoded = canonicalStrictJsonBytesV1(payload).toString("base64");
      expect(() =>
        parseScanAttestationEnvelopeV2Json(
          canonicalStrictJsonBytesV1({ ...evidence.envelope, payload: encoded }).toString("utf8"),
        ),
      ).toThrow();
    }
    expect(() =>
      parseScanAttestationEnvelopeV2Json(JSON.stringify(evidence.envelope, null, 2)),
    ).toThrow();
    const noncanonicalPayload = Buffer.from(JSON.stringify(decodePayload(), null, 2)).toString(
      "base64",
    );
    expect(() =>
      parseScanAttestationEnvelopeV2Json(
        canonicalStrictJsonBytesV1({ ...evidence.envelope, payload: noncanonicalPayload }).toString(
          "utf8",
        ),
      ),
    ).toThrow();
  });

  it("signs and verifies DSSE PAE bytes rather than the bare payload", () => {
    const evidence = signed();
    const payload = Buffer.from(evidence.envelope.payload, "base64");
    expect(canonicalDssePaeV2(evidence.envelope.payloadType, payload).equals(payload)).toBe(false);
  });
});
