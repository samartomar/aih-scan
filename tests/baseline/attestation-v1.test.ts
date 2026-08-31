import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  canonicalBaselineVetAttestationEnvelopeV1Bytes,
  parseBaselineVetAttestationEnvelopeV1Json,
  signBaselineVetBundleV1,
  verifyBaselineVetAttestationV1,
} from "../../src/baseline/attestation-v1.js";
import {
  type BaselineAnalyzerExecutionV1,
  createBaselineVetRequestV1,
  executeBaselineVetBatchV1,
} from "../../src/baseline/batch-v1.js";
import { canonicalStrictJsonBytesV1 } from "../../src/contract/strict-json-v1.js";
import { ed25519KeyIdV2 } from "../../src/observation/scan-attestation-v2.js";
import { hashComponentTreeV1, hashSourceTreeV1 } from "../../src/observation/source-hash-v1.js";

const temporaryDirectories: string[] = [];
afterEach(() => {
  for (const directory of temporaryDirectories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

async function fixture() {
  const root = mkdtempSync(join(tmpdir(), "aih-scan-baseline-attestation-"));
  temporaryDirectories.push(root);
  mkdirSync(join(root, "rules"));
  writeFileSync(join(root, "rules", "base.md"), "# Rule\n", "utf8");
  const request = createBaselineVetRequestV1({
    protocol: "BaselineVetRequestV1",
    profile: "aih-baseline-v1",
    source: {
      id: "ecc",
      owner: "affaan-m",
      repository: "everything-claude-code",
      pinnedCommit: "a".repeat(40),
      treeSha256: hashSourceTreeV1(root).treeSha256,
    },
    components: [
      {
        id: "rules-core",
        content: "general",
        paths: ["rules"],
        treeSha256: hashComponentTreeV1(root, ["rules"]).treeSha256,
        analyzers: ["aih-native", "skillspector", "semgrep"],
      },
    ],
  });
  const execute: BaselineAnalyzerExecutionV1 = async ({ analyzer }) =>
    analyzer === "aih-native"
      ? {
          mediaType: "application/vnd.aih.baseline-native+json",
          bytes: canonicalStrictJsonBytesV1({
            protocol: "BaselineNativeObservationV1",
            files: [],
          }),
          analyzerVersion: "native.0123456789ab",
        }
      : {
          mediaType: "application/sarif+json",
          bytes: canonicalStrictJsonBytesV1({
            version: "2.1.0",
            runs: [{ tool: { driver: { name: analyzer } }, results: [] }],
          }),
          analyzerVersion: `${analyzer}.0123456789ab`,
        };
  return {
    request,
    result: await executeBaselineVetBatchV1(request, { sourceRoot: root, execute }),
  };
}

describe("BaselineVetAttestationV1", () => {
  it("requires a trusted organization signature before evidence is complete", async () => {
    const { request, result } = await fixture();
    const keys = generateKeyPairSync("ed25519");
    const keyId = ed25519KeyIdV2(keys.publicKey);
    const signer = { identity: "organization-scanner", class: "organization" as const, keyId };
    const claims = {
      signedAt: "2026-08-31T05:00:00.000Z",
      expiresAt: "2026-08-31T06:00:00.000Z",
    };
    const evidence = signBaselineVetBundleV1({
      request,
      result,
      signer: { ...signer, privateKey: keys.privateKey },
      claims,
    });
    const envelopeBytes = canonicalBaselineVetAttestationEnvelopeV1Bytes(evidence);
    const envelope = parseBaselineVetAttestationEnvelopeV1Json(envelopeBytes.toString("utf8"));
    const roots = [{ ...signer, publicKey: keys.publicKey }];
    const expected = { now: "2026-08-31T05:30:00.000Z", signer };

    const verified = verifyBaselineVetAttestationV1({
      envelope,
      request,
      result,
      roots,
      expected,
      seenEvidenceDigests: [],
      seenReceiptBindings: [],
    });

    expect(verified.facts).toMatchObject({
      envelopeValid: true,
      authority: "none",
      requestSha256: request.requestSha256,
      receiptSha256: result.receipt.receiptSha256,
      annexesComplete: true,
      signer,
    });
    expect(Object.isFrozen(verified.facts)).toBe(true);

    const wrongKeys = generateKeyPairSync("ed25519");
    expect(() =>
      verifyBaselineVetAttestationV1({
        envelope,
        request,
        result,
        roots: [{ ...signer, publicKey: wrongKeys.publicKey }],
        expected,
        seenEvidenceDigests: [],
        seenReceiptBindings: [],
      }),
    ).toThrow(/trusted public key/);
    expect(() =>
      verifyBaselineVetAttestationV1({
        envelope,
        request,
        result,
        roots,
        expected: { ...expected, now: "2026-08-31T07:00:00.000Z" },
        seenEvidenceDigests: [],
        seenReceiptBindings: [],
      }),
    ).toThrow(/freshness/);
    expect(() =>
      verifyBaselineVetAttestationV1({
        envelope,
        request,
        result,
        roots,
        expected,
        seenEvidenceDigests: [evidence.evidenceDigestSha256],
        seenReceiptBindings: [],
      }),
    ).toThrow(/replayed/);
    expect(() =>
      verifyBaselineVetAttestationV1({
        envelope,
        request,
        result,
        roots,
        expected,
        seenEvidenceDigests: [],
        seenReceiptBindings: [
          { requestSha256: request.requestSha256, receiptSha256: "f".repeat(64) },
        ],
      }),
    ).toThrow(/receipt and annex/);
  });

  it("rejects signed-envelope, receipt-annex, and signer substitutions", async () => {
    const { request, result } = await fixture();
    const keys = generateKeyPairSync("ed25519");
    const keyId = ed25519KeyIdV2(keys.publicKey);
    const signer = { identity: "organization-scanner", class: "organization" as const, keyId };
    const evidence = signBaselineVetBundleV1({
      request,
      result,
      signer: { ...signer, privateKey: keys.privateKey },
      claims: {
        signedAt: "2026-08-31T05:00:00.000Z",
        expiresAt: "2026-08-31T06:00:00.000Z",
      },
    });
    const verify = (overrides: Record<string, unknown>) =>
      verifyBaselineVetAttestationV1({
        envelope: evidence.envelope,
        request,
        result,
        roots: [{ ...signer, publicKey: keys.publicKey }],
        expected: { now: "2026-08-31T05:30:00.000Z", signer },
        seenEvidenceDigests: [],
        seenReceiptBindings: [],
        ...overrides,
      });

    const envelope = structuredClone(evidence.envelope);
    const signature = Buffer.from(envelope.signatures[0]?.sig ?? "", "base64");
    signature[0] = (signature[0] ?? 0) ^ 1;
    if (envelope.signatures[0] === undefined) throw new Error("expected signature fixture");
    envelope.signatures[0].sig = signature.toString("base64");
    expect(() => verify({ envelope })).toThrow(/signature/);

    const first = result.annexArtifacts[0];
    if (first === undefined) throw new Error("expected annex fixture");
    expect(() =>
      verify({
        result: {
          receipt: result.receipt,
          annexArtifacts: [{ ...first, bytes: createHash("sha256").update("forged").digest() }],
        },
      }),
    ).toThrow(/receipt and annex/);

    const attacker = generateKeyPairSync("ed25519");
    const attackerKeyId = ed25519KeyIdV2(attacker.publicKey);
    const attackerEvidence = signBaselineVetBundleV1({
      request,
      result,
      signer: {
        identity: "attacker-scanner",
        class: "organization",
        keyId: attackerKeyId,
        privateKey: attacker.privateKey,
      },
      claims: {
        signedAt: "2026-08-31T05:00:00.000Z",
        expiresAt: "2026-08-31T06:00:00.000Z",
      },
    });
    expect(() => verify({ envelope: attackerEvidence.envelope })).toThrow(/expected signer/);
  });
});
