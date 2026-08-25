import { createHash, generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { canonicalStrictJsonBytesV1 } from "../../src/contract/strict-json-v1.js";
import { canonicalSourceSealsV2Bytes } from "../../src/index.js";
import {
  createObservationKeyV1,
  createObservationSetV1,
} from "../../src/observation/observation-evidence-v1.js";
import {
  canonicalDssePaeV2,
  canonicalScanAttestationEnvelopeBytesV2,
  createScanCandidateV2,
  ed25519KeyIdV2,
  isVerifiedScanAttestationV2,
  signScanCandidateV2,
  verifyScanAttestationV2,
} from "../../src/observation/scan-attestation-v2.js";
import { createScannerManifestV1 } from "../../src/observation/scanner-manifest-v1.js";

const sha = (value: string | Uint8Array) => createHash("sha256").update(value).digest("hex");
const keyPair = generateKeyPairSync("ed25519");
const keyId = ed25519KeyIdV2(keyPair.publicKey);
const source = sha("source");
const ociManifest = sha("oci manifest");
const rawAnnexBytes = Buffer.from("raw annex", "utf8");
const annexBytes = Buffer.from("annex", "utf8");
const provenanceBytes = Buffer.from("provenance", "utf8");
const annexArtifacts = [
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
      commit: "aa93128ff56b3ed978ec428e29d1b1ce8036e53b",
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
describe("ScanAttestationV2 signed evidence", () => {
  it("canonicalizes valid public V2 source seals deterministically and rejects malformed variants", () => {
    const before = seal();
    const after = seal();
    const expectedBytes = canonicalStrictJsonBytesV1({ before, after });

    expect(canonicalSourceSealsV2Bytes({ after, before }).equals(expectedBytes)).toBe(true);
    expect(canonicalSourceSealsV2Bytes({ before, after }).equals(expectedBytes)).toBe(true);
    expect(() =>
      canonicalSourceSealsV2Bytes({
        before: { ...before, protocol: "SourceSealV1" },
        after,
      }),
    ).toThrow();
    expect(() =>
      canonicalSourceSealsV2Bytes({
        before: { ...before, selectedClosurePaths: ["z.md", "A.md"] },
        after,
      }),
    ).toThrow();
    expect(() => canonicalSourceSealsV2Bytes({ before })).toThrow();
  });

  it("rejects hidden, symbol, extra, and accessor-backed public source-seal inputs", () => {
    const before = seal();
    const after = seal();
    let accessorReads = 0;
    const accessor = { after } as Record<string, unknown>;
    Object.defineProperty(accessor, "before", {
      enumerable: true,
      get: () => {
        accessorReads += 1;
        throw new Error("must not read source-seal accessor");
      },
    });
    const hidden = { before, after } as Record<string, unknown>;
    Object.defineProperty(hidden, "unexpected", { value: true });
    const symbol = { before, after } as Record<string | symbol, unknown>;
    symbol[Symbol("unexpected")] = true;
    const extra = { before, after, unexpected: true };
    const nestedHidden = { before: { ...before }, after } as {
      before: Record<string, unknown>;
      after: typeof after;
    };
    Object.defineProperty(nestedHidden.before, "unexpected", { value: true });

    expect(() => canonicalSourceSealsV2Bytes(accessor)).toThrow();
    expect(accessorReads).toBe(0);
    expect(() => canonicalSourceSealsV2Bytes(hidden)).toThrow();
    expect(() => canonicalSourceSealsV2Bytes(symbol)).toThrow();
    expect(() => canonicalSourceSealsV2Bytes(extra)).toThrow();
    expect(() => canonicalSourceSealsV2Bytes(nestedHidden)).toThrow();
  });

  it("signs deterministic canonical DSSE bytes and verifies exact configured signer claims", () => {
    const first = signed();
    const second = signed();
    expect(
      canonicalScanAttestationEnvelopeBytesV2(first).equals(
        canonicalScanAttestationEnvelopeBytesV2(second),
      ),
    ).toBe(true);
    expect(
      canonicalDssePaeV2(
        first.envelope.payloadType,
        Buffer.from(first.envelope.payload, "base64"),
      ).toString("utf8"),
    ).toContain("DSSEv1");
    const verified = verifyScanAttestationV2({
      envelope: first,
      roots: roots(),
      expected,
      candidate: candidate(),
      annexArtifacts,
    });
    expect(isVerifiedScanAttestationV2(verified)).toBe(true);
    expect(verified.facts).toMatchObject({
      envelopeValid: true,
      signerAssertedClaimsMatchPolicy: true,
      scan: { outcome: "succeeded" },
    });
    expect(verified.facts.provenance).toBe("none");
    expect(verified.facts.scanner.detector).toMatchObject({
      detectorId: "detector.cisco",
      broker: { identity: "broker.0123456789ab" },
      observation: { facts: [{ rawOccurrenceFingerprint: `raw-occurrence-v1:${sha("fact")}` }] },
    });
  });
  it("fails closed for malformed signatures, mismatched roots/claims, time, replay, and raw or cloned custody", () => {
    const evidence = signed();
    expect(() =>
      verifyScanAttestationV2({
        envelope: evidence,
        roots: roots(),
        expected: { ...expected, now: "2026-08-22T01:00:00.000Z" },
        candidate: candidate(),
        annexArtifacts,
      }),
    ).toThrow();
    expect(() =>
      verifyScanAttestationV2({
        envelope: evidence,
        roots: [],
        expected,
        candidate: candidate(),
        annexArtifacts,
      }),
    ).toThrow();
    expect(() =>
      verifyScanAttestationV2({
        envelope: evidence,
        roots: roots(),
        expected: { ...expected, repository: "other/repo" },
        candidate: candidate(),
        annexArtifacts,
      }),
    ).toThrow();
    expect(() =>
      verifyScanAttestationV2({
        envelope: evidence,
        roots: roots(),
        expected,
        candidate: candidate(),
        seenReplayIdentities: [`scanner.ci|${evidence.payloadSha256}`],
        annexArtifacts,
      }),
    ).toThrow();
    expect(() =>
      verifyScanAttestationV2({
        envelope: { ...evidence, envelope: { ...evidence.envelope, signatures: [] } },
        roots: roots(),
        expected,
        candidate: candidate(),
        annexArtifacts,
      }),
    ).toThrow();
    const verified = verifyScanAttestationV2({
      envelope: evidence,
      roots: roots(),
      expected,
      candidate: candidate(),
      annexArtifacts,
    });
    expect(isVerifiedScanAttestationV2({ ...verified })).toBe(false);
    expect(isVerifiedScanAttestationV2(JSON.parse(JSON.stringify(verified)))).toBe(false);
  });
  it("requires the exact complete detached annex set before signing or reporting verified evidence facts", () => {
    const input = {
      candidate: candidate(),
      signer: {
        identity: "scanner.ci",
        class: "test-ephemeral" as const,
        keyId,
        privateKey: keyPair.privateKey,
      },
      claims,
    };
    expect(() => signScanCandidateV2({ ...input, annexArtifacts: [] })).toThrow(/annex artifact/i);
    expect(() =>
      signScanCandidateV2({
        ...input,
        annexArtifacts: [
          ...annexArtifacts,
          { descriptorId: "annex.extra", bytes: Buffer.from("extra", "utf8") },
        ],
      }),
    ).toThrow(/annex artifact/i);
    const evidence = signed();
    expect(() =>
      verifyScanAttestationV2({
        envelope: evidence,
        roots: roots(),
        expected,
        candidate: candidate(),
        annexArtifacts: [],
      }),
    ).toThrow(/annex artifact/i);
    expect(() =>
      verifyScanAttestationV2({
        envelope: evidence,
        roots: roots(),
        expected,
        candidate: candidate(),
        annexArtifacts: [
          { descriptorId: "annex.sbom", bytes: Buffer.from("substitution", "utf8") },
        ],
      }),
    ).toThrow(/annex artifact/i);
    const verified = verifyScanAttestationV2({
      envelope: evidence,
      roots: roots(),
      expected,
      candidate: candidate(),
      annexArtifacts,
    });
    expect(verified.facts).toMatchObject({ annexesComplete: true });
    expect(verified.facts.annexDescriptors).toContainEqual(
      expect.objectContaining({ descriptorId: "annex.sbom", sha256: sha(annexBytes) }),
    );
  });
  it("refuses source-subject and coverage bindings that do not describe the sealed selected closure", () => {
    const input = {
      protocol: "ScanCandidateV2",
      coreContract: {
        commit: "aa93128ff56b3ed978ec428e29d1b1ce8036e53b",
        decisionSchemaSha256: "27295aee8d8be333abe2c73adc72884b534b1c9980a9b7a39d12be8d34c5caff",
      },
      subject: { name: "source-tree", digest: { sha256: sha("wrong") } },
      sourceSeals: candidate().sourceSeals,
      observation: candidate().observation,
      scanner: candidate().scanner,
      platform: candidate().platform,
      coverage: candidate().coverage,
      annexes: candidate().annexes,
      cleanup: candidate().cleanup,
      scan: candidate().scan,
    };
    expect(() => createScanCandidateV2(input)).toThrow(/subject source seal/i);
    expect(() =>
      createScanCandidateV2({
        ...input,
        subject: candidate().subject,
        coverage: { ...input.coverage, sha256: sha("wrong") },
      }),
    ).toThrow(/coverage selected closure/i);
  });
  it("refuses an unregistered custom detector identity in direct V2 candidate evidence", () => {
    const direct = JSON.parse(JSON.stringify(candidate())) as Record<string, unknown>;
    delete direct.candidateSha256;
    const scanner = direct.scanner as Record<string, unknown>;
    const detector = scanner.detector as Record<string, unknown>;
    detector.detectorId = "detector.acme.policy";
    expect(() => createScanCandidateV2(direct)).toThrow(/unregistered detector identity/i);
  });
  it("recomputes Cisco manifest, observation, broker, runtime, and annex identities instead of carrying claims", () => {
    const input = () => {
      const value = JSON.parse(JSON.stringify(candidate())) as Record<string, unknown>;
      delete value.candidateSha256;
      return value as {
        scanner: {
          manifestSha256: string;
          runtimeSha256: string;
          detector: {
            scannerManifestEntrySha256: string;
            observation: { setSha256: string };
            platform: { relevantFactsSha256: string };
            broker: { appliedFactsSha256: string; sarifSha256: string };
          };
        };
        annexes: { descriptorId: string; sha256: string }[];
      };
    };
    for (const mutate of [
      (value: ReturnType<typeof input>) =>
        (value.scanner.manifestSha256 = sha("substituted manifest")),
      (value: ReturnType<typeof input>) =>
        (value.scanner.detector.scannerManifestEntrySha256 = sha("substituted entry")),
      (value: ReturnType<typeof input>) =>
        (value.scanner.detector.observation.setSha256 = sha("substituted observation set")),
      (value: ReturnType<typeof input>) =>
        (value.scanner.detector.platform.relevantFactsSha256 = sha("substituted relevant facts")),
      (value: ReturnType<typeof input>) =>
        (value.scanner.detector.broker.appliedFactsSha256 = sha("substituted applied facts")),
      (value: ReturnType<typeof input>) =>
        (value.scanner.detector.broker.sarifSha256 = sha("substituted sarif")),
      (value: ReturnType<typeof input>) => {
        const sbom = value.annexes.find((entry) => entry.descriptorId === "annex.sbom");
        if (sbom === undefined) throw new Error("missing SBOM annex");
        sbom.sha256 = sha("substituted SBOM");
      },
    ]) {
      const value = input();
      mutate(value);
      expect(() => createScanCandidateV2(value)).toThrow();
    }
  });
});
