import { createHash, generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createCiscoFactsOnlyV1 } from "../../src/cisco/facts-only-v1.js";
import { canonicalStrictJsonBytesV1 } from "../../src/contract/strict-json-v1.js";
import { readScanFindingsV1 } from "../../src/findings/scan-findings-v1.js";
import {
  createObservationKeyV1,
  createObservationSetV1,
} from "../../src/observation/observation-evidence-v1.js";
import {
  createScanCandidateV2,
  ed25519KeyIdV2,
  type ScanAnnexArtifactV2,
  signScanCandidateV2,
  type VerifiedScanAttestationV2,
  verifyScanAttestationV2,
} from "../../src/observation/scan-attestation-v2.js";
import { createScannerManifestV1 } from "../../src/observation/scanner-manifest-v1.js";

/**
 * The raw annex and the occurrence facts below are produced by Scan's own
 * `createCiscoFactsOnlyV1`, so the binding this reader recomputes is the binding the
 * producer minted. The signing chain is ephemeral unit-test evidence only and is never
 * presented as a real detector run or as any kind of approval.
 */
const sha = (value: string | Uint8Array) => createHash("sha256").update(value).digest("hex");
const keyPair = generateKeyPairSync("ed25519");
const keyId = ed25519KeyIdV2(keyPair.publicKey);

const skillSha256 = sha("SKILL.md bytes");
const readmeSha256 = sha("README.md bytes");
const fileSha256ByPath = { "SKILL.md": skillSha256, "README.md": readmeSha256 };

function location(uri: string, startLine?: number) {
  return {
    physicalLocation: {
      artifactLocation: { uri },
      ...(startLine === undefined ? {} : { region: { startLine } }),
    },
  };
}

/** Three results; two share a rule, path and file digest so the ordinal is exercised. */
const ciscoSarif = {
  version: "2.1.0" as const,
  runs: [
    {
      tool: { driver: { name: "cisco-ai-skill-scanner" as const } },
      results: [
        {
          ruleId: "PROMPT_INJECTION",
          level: "error",
          message: { text: "ignore previous instructions" },
          locations: [location("SKILL.md", 1)],
        },
        {
          ruleId: "PROMPT_INJECTION",
          level: "error",
          message: { text: "disregard all previous instructions" },
          locations: [location("SKILL.md", 9)],
        },
        {
          ruleId: "DOWNLOAD_AND_EXECUTE",
          message: { text: "curl piped to sh" },
          locations: [location("README.md", 4)],
        },
      ],
    },
  ],
};

type CiscoFacts = {
  facts: readonly { rawOccurrenceFingerprint: string; multiplicity: number }[];
  annexBytes: Buffer;
};

function ciscoFacts(sarif: unknown): CiscoFacts {
  return createCiscoFactsOnlyV1({
    protocol: "CiscoFactsOnlyV1",
    sarif,
    fileSha256ByPath,
    platform: { os: "linux", architecture: "amd64" },
  }) as CiscoFacts;
}

const sbomBytes = Buffer.from('{"spdxVersion":"SPDX-2.3"}', "utf8");
const provenanceBytes = Buffer.from('{"_type":"https://in-toto.io/Statement/v1"}', "utf8");
const ociManifest = sha("oci manifest");
const observationConfigurationSha256 = sha("configuration");
const sourceSealV1 = {
  protocol: "SourceSealV1" as const,
  sourceTreeSha256: sha("v1 source"),
  selectedClosureSha256: sha("v1 selected"),
  sealedSnapshotSha256: sha("v1 snapshot"),
};
const rawCoverage = [
  { coverageKind: "selected-closure" as const, coverageSha256: sourceSealV1.selectedClosureSha256 },
];
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
  sbom: { mediaType: "application/spdx+json" as const, sha256: sha(sbomBytes) },
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
const seal = () => {
  const entries = [
    { kind: "file" as const, path: "README.md", sha256: readmeSha256, byteLength: 14 },
    { kind: "file" as const, path: "SKILL.md", sha256: skillSha256, byteLength: 15 },
  ];
  const sourceTreeSha256 = sha(canonicalStrictJsonBytesV1({ protocol: "SourceTreeV2", entries }));
  const selectedClosureSha256 = sha(
    canonicalStrictJsonBytesV1({ protocol: "SelectedClosureV2", files: entries }),
  );
  return {
    protocol: "SourceSealV2" as const,
    algorithm: "code-unit-canonical-json-v1" as const,
    entries,
    selectedClosurePaths: ["README.md", "SKILL.md"],
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

function chain(input: { readonly facts: CiscoFacts["facts"]; readonly annexBytes: Buffer }): {
  verified: VerifiedScanAttestationV2;
  annexArtifacts: ScanAnnexArtifactV2[];
} {
  const declaredFacts = input.facts.map(({ rawOccurrenceFingerprint, multiplicity }) => ({
    rawOccurrenceFingerprint,
    multiplicity,
  }));
  const annexArtifacts: ScanAnnexArtifactV2[] = [
    { descriptorId: "annex.cisco-raw", bytes: input.annexBytes },
    { descriptorId: "annex.provenance", bytes: provenanceBytes },
    { descriptorId: "annex.sbom", bytes: sbomBytes },
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
    nativeAnalyzerIdentity: detectorInput.analyzerIdentity,
    observationConfigurationSha256,
    platform: { os: "linux" as const, architecture: "amd64" as const, relevantFactsSha256 },
    scannerManifestEntrySha256: scannerManifestEntry.scannerManifestEntrySha256,
  };
  const observationKey = createObservationKeyV1(observationKeyInput);
  const observationSet = createObservationSetV1({
    protocol: "ObservationSetV1",
    observationKey: observationKeyInput,
    facts: declaredFacts,
    coverage: rawCoverage,
  });
  // The observation set is the canonical, sorted fact order the verifier recomputes.
  const facts = observationSet.facts as readonly {
    rawOccurrenceFingerprint: string;
    multiplicity: number;
  }[];
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
        facts,
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
      subject: { name: "source-tree", digest: { sha256: seal().sourceTreeSha256 } },
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
            facts,
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
  const verified = verifyScanAttestationV2({
    envelope: signScanCandidateV2({
      candidate: candidate(),
      signer: {
        identity: "scanner.ci",
        class: "test-ephemeral",
        keyId,
        privateKey: keyPair.privateKey,
      },
      claims,
      annexArtifacts,
    }),
    candidate: candidate(),
    roots: [
      {
        identity: "scanner.ci",
        class: "test-ephemeral" as const,
        keyId,
        publicKey: keyPair.publicKey,
      },
    ],
    expected: {
      ...claims,
      now: "2026-08-22T00:30:00.000Z",
      subjectSha256: seal().sourceTreeSha256,
      signer: { identity: "scanner.ci", class: "test-ephemeral", keyId },
    },
    annexArtifacts,
  });
  return { verified, annexArtifacts };
}

describe("ScanFindingsV1", () => {
  it("reads three findings from digest-verified annex bytes and binds each to one fact", () => {
    const produced = ciscoFacts(ciscoSarif);
    const { verified, annexArtifacts } = chain(produced);

    const read = readScanFindingsV1({ verified, annexArtifacts });

    expect(read.status).toBe("available");
    if (read.status !== "available") return;
    const findings = read.findings;
    expect(findings.protocol).toBe("ScanFindingsV1");
    expect(findings.source).toBe("annex");
    expect(findings.findings).toHaveLength(3);
    expect(findings.findings.map((finding) => finding.rawOccurrenceFingerprint).sort()).toEqual(
      produced.facts.map((fact) => fact.rawOccurrenceFingerprint).sort(),
    );
    for (const finding of findings.findings) {
      expect(finding.detector).toEqual({
        state: "present",
        value: { id: "detector.cisco", analyzerIdentity: "native.0123456789ab" },
      });
      expect(finding.message.state).toBe("present");
      expect(finding.location.state).toBe("present");
      expect(finding.supportingEvidence.state).toBe("present");
      if (finding.rule.state !== "present") throw new Error("rule must be present");
      expect(finding.rule.value.name).toBeUndefined();
    }
    const downloadAndExecute = findings.findings.find(
      (finding) =>
        finding.rule.state === "present" && finding.rule.value.nativeRuleId.startsWith("D"),
    );
    // The third SARIF result declares no level, so severity is absent, never defaulted.
    expect(downloadAndExecute?.severity).toEqual({
      state: "unavailable",
      reason: "severity-not-declared-by-attestation",
      detail: expect.stringContaining("no SARIF level"),
    });
    expect(findings.gaps.map((entry) => entry.kind)).toEqual([
      "vendor-severity-not-projected",
      "sarif-not-interpreted",
      "no-effect-or-qualification-authority",
    ]);
  });

  it("reports every field as unavailable with a reason when no annex bytes are supplied", () => {
    const produced = ciscoFacts(ciscoSarif);
    const { verified } = chain(produced);

    const read = readScanFindingsV1({ verified });

    expect(read.status).toBe("available");
    if (read.status !== "available") return;
    expect(read.findings.source).toBe("attestation-facts-only");
    expect(read.findings.findings).toHaveLength(3);
    for (const finding of read.findings.findings) {
      expect(finding.rawOccurrenceFingerprint).toMatch(/^raw-occurrence-v1:[0-9a-f]{64}$/);
      for (const field of [
        finding.detector,
        finding.rule,
        finding.severity,
        finding.message,
        finding.location,
        finding.supportingEvidence,
      ]) {
        expect(field.state).toBe("unavailable");
        if (field.state !== "unavailable") continue;
        expect(field.reason).toBe("annex-bytes-not-supplied");
        expect(field.detail.length).toBeGreaterThan(0);
      }
    }
    expect(read.findings.gaps.map((entry) => entry.kind)).toContain("annex-bytes-not-supplied");
  });

  it("refuses an annex entry that does not bind to a declared fact instead of dropping it", () => {
    const declared = ciscoFacts(ciscoSarif);
    const substituted = ciscoFacts({
      ...ciscoSarif,
      runs: [
        {
          ...ciscoSarif.runs[0],
          results: [
            ...(ciscoSarif.runs[0]?.results.slice(0, 2) ?? []),
            {
              ruleId: "SUBSTITUTED_RULE",
              message: { text: "injected by a tampered annex" },
              locations: [location("README.md", 4)],
            },
          ],
        },
      ],
    });
    // The candidate declares the genuine facts while the annex carries a substituted
    // entry whose digest matches the descriptor, which is the attack this must refuse.
    const { verified, annexArtifacts } = chain({
      facts: declared.facts,
      annexBytes: substituted.annexBytes,
    });

    const read = readScanFindingsV1({ verified, annexArtifacts });

    expect(read.status).toBe("invalid-input");
    if (read.status !== "invalid-input") return;
    expect(read.reason).toContain("does not bind to exactly one declared occurrence fact");
  });

  it("refuses annex bytes whose digest does not match the declared descriptor", () => {
    const produced = ciscoFacts(ciscoSarif);
    const { verified, annexArtifacts } = chain(produced);

    const read = readScanFindingsV1({
      verified,
      annexArtifacts: annexArtifacts.map((artifact) =>
        artifact.descriptorId === "annex.cisco-raw"
          ? { descriptorId: artifact.descriptorId, bytes: Buffer.from("[]", "utf8") }
          : artifact,
      ),
    });

    expect(read.status).toBe("invalid-input");
  });

  it("refuses anything that is not a value minted by the verifier", () => {
    const produced = ciscoFacts(ciscoSarif);
    const { verified } = chain(produced);

    expect(readScanFindingsV1({ verified: { facts: verified.facts } })).toEqual({
      status: "unverified",
    });
    expect(readScanFindingsV1({ verified: undefined })).toEqual({ status: "unverified" });
    expect(
      readScanFindingsV1({ verified, annexArtifacts: "not an array" as unknown as [] }),
    ).toEqual({ status: "invalid-input", reason: "annex artifacts" });
  });
});
