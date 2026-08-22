import { createHash, generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  canonicalDssePaeV2,
  canonicalScanAttestationEnvelopeBytesV2,
  createScanCandidateV2,
  isVerifiedScanAttestationV2,
  signScanCandidateV2,
  verifyScanAttestationV2,
} from "../../src/observation/scan-attestation-v2.js";

const sha = (value: string) => createHash("sha256").update(value).digest("hex");
const keyPair = generateKeyPairSync("ed25519");
const source = sha("source");
const candidate = () =>
  createScanCandidateV2({
    protocol: "ScanCandidateV2",
    coreContract: {
      commit: "e27a55dcebb635c8298aa4fd6fd871f59089bcf7",
      decisionSchemaSha256: "27295aee8d8be333abe2c73adc72884b534b1c9980a9b7a39d12be8d34c5caff",
    },
    subject: { name: "source-tree", digest: { sha256: source } },
    sourceSeals: {
      before: { sourceTreeSha256: source, selectedClosureSha256: sha("closure"), sealedSnapshotSha256: sha("seal") },
      run: { sourceTreeSha256: source, selectedClosureSha256: sha("closure"), sealedSnapshotSha256: sha("seal") },
      after: { sourceTreeSha256: source, selectedClosureSha256: sha("closure"), sealedSnapshotSha256: sha("seal") },
    },
    observation: { keySha256: sha("key"), setSha256: sha("set") },
    scanner: { manifestSha256: sha("manifest"), runtimeSha256: sha("runtime"), configurationSha256: sha("config") },
    platform: { os: "linux", architecture: "amd64" },
    coverage: { kind: "selected-closure", sha256: sha("coverage"), complete: true },
    annexes: [{ descriptorId: "annex.sbom", sha256: sha("annex"), byteLength: 4 }],
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
    signer: { identity: "scanner.ci", class: "test-ephemeral", keyId: "ed25519:test", privateKey: keyPair.privateKey },
    claims,
  });
const expected = {
  ...claims,
  now: "2026-08-22T00:30:00.000Z",
  subjectSha256: source,
  signer: { identity: "scanner.ci", class: "test-ephemeral", keyId: "ed25519:test" },
};
const roots = () => [
  { identity: "scanner.ci", class: "test-ephemeral" as const, keyId: "ed25519:test", publicKey: keyPair.publicKey },
];

describe("ScanAttestationV2 signed evidence", () => {
  it("signs deterministic canonical DSSE bytes and verifies exact configured signer claims", () => {
    const first = signed();
    const second = signed();
    expect(canonicalScanAttestationEnvelopeBytesV2(first).equals(canonicalScanAttestationEnvelopeBytesV2(second))).toBe(true);
    expect(canonicalDssePaeV2(first.envelope.payloadType, Buffer.from(first.envelope.payload, "base64")).toString("utf8")).toContain("DSSEv1");
    const verified = verifyScanAttestationV2({ envelope: first, roots: roots(), expected });
    expect(isVerifiedScanAttestationV2(verified)).toBe(true);
    expect(verified.facts).toMatchObject({ envelopeValid: true, signerAssertedClaimsMatchPolicy: true, scan: { outcome: "succeeded" } });
    expect(verified.facts.provenanceVerified).toBe(false);
  });

  it("fails closed for malformed signatures, mismatched roots/claims, time, replay, and raw or cloned custody", () => {
    const evidence = signed();
    expect(() => verifyScanAttestationV2({ envelope: evidence, roots: roots(), expected: { ...expected, now: "2026-08-22T01:00:00.000Z" } })).toThrow();
    expect(() => verifyScanAttestationV2({ envelope: evidence, roots: [], expected })).toThrow();
    expect(() => verifyScanAttestationV2({ envelope: evidence, roots: roots(), expected: { ...expected, repository: "other/repo" } })).toThrow();
    expect(() => verifyScanAttestationV2({ envelope: evidence, roots: roots(), expected, seenPayloadSha256: [evidence.payloadSha256] })).toThrow();
    expect(() => verifyScanAttestationV2({ envelope: { ...evidence, envelope: { ...evidence.envelope, signatures: [] } }, roots: roots(), expected })).toThrow();
    const verified = verifyScanAttestationV2({ envelope: evidence, roots: roots(), expected });
    expect(isVerifiedScanAttestationV2({ ...verified })).toBe(false);
    expect(isVerifiedScanAttestationV2(JSON.parse(JSON.stringify(verified)))).toBe(false);
  });
});
