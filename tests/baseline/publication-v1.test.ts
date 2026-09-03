import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  canonicalBaselineVetAttestationEnvelopeV1Bytes,
  signBaselineVetBundleV1,
  verifyBaselineVetAttestationV1,
} from "../../src/baseline/attestation-v1.js";
import {
  type BaselineAnalyzerExecutionV1,
  createBaselineVetRequestV1,
  executeBaselineVetBatchV1,
} from "../../src/baseline/batch-v1.js";
import {
  baselineVetPublicationResultV1,
  canonicalBaselineVetDiscoveryV1Bytes,
  canonicalBaselineVetPublicationV1Bytes,
  createBaselineVetDiscoveryV1,
  createBaselineVetPublicationV1,
  parseBaselineVetDiscoveryV1Json,
  parseBaselineVetPublicationV1Json,
  resolveBaselineVetDiscoveryV1,
} from "../../src/baseline/publication-v1.js";
import { canonicalStrictJsonBytesV1 } from "../../src/contract/strict-json-v1.js";
import { ed25519KeyIdV2 } from "../../src/observation/scan-attestation-v2.js";
import { hashComponentTreeV1, hashSourceTreeV1 } from "../../src/observation/source-hash-v1.js";

const temporaryDirectories: string[] = [];
afterEach(() => {
  for (const directory of temporaryDirectories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

async function fixture(rule = "# Rule\n") {
  const root = mkdtempSync(join(tmpdir(), "aih-scan-baseline-publication-"));
  temporaryDirectories.push(root);
  mkdirSync(join(root, "rules"));
  writeFileSync(join(root, "rules", "base.md"), rule, "utf8");
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
  const result = await executeBaselineVetBatchV1(request, { sourceRoot: root, execute });
  const keys = generateKeyPairSync("ed25519");
  const keyId = ed25519KeyIdV2(keys.publicKey);
  const signer = { identity: "organization-scanner", class: "organization" as const, keyId };
  const expected = { now: "2026-09-03T05:30:00.000Z", signer };
  const signed = signBaselineVetBundleV1({
    request,
    result,
    signer: { ...signer, privateKey: keys.privateKey },
    claims: {
      signedAt: "2026-09-03T05:00:00.000Z",
      expiresAt: "2026-09-03T06:00:00.000Z",
    },
  });
  return {
    request,
    result,
    envelope: JSON.parse(canonicalBaselineVetAttestationEnvelopeV1Bytes(signed).toString("utf8")),
    roots: [{ ...signer, publicKey: keys.publicKey }],
    expected,
  };
}

describe("BaselineVetPublicationV1", () => {
  it("packs one verified request, receipt, annex set, and attestation deterministically", async () => {
    const input = await fixture();
    const publication = createBaselineVetPublicationV1({
      ...input,
      seenEvidenceDigests: [],
      seenReceiptBindings: [],
    });
    const bytes = canonicalBaselineVetPublicationV1Bytes(publication);
    const parsed = parseBaselineVetPublicationV1Json(bytes.toString("utf8"));

    expect(canonicalBaselineVetPublicationV1Bytes(parsed)).toEqual(bytes);
    expect(parsed.request.requestSha256).toBe(input.request.requestSha256);
    expect(parsed.receipt.receiptSha256).toBe(input.result.receipt.receiptSha256);
    expect(parsed.annexes.map((annex) => annex.path)).toEqual(
      input.result.receipt.observations.map((observation) => observation.annex.path),
    );
    const portable = baselineVetPublicationResultV1(parsed);
    expect(
      verifyBaselineVetAttestationV1({
        ...portable,
        seenEvidenceDigests: [],
        seenReceiptBindings: [],
      }).facts.evidenceDigestSha256,
    ).toMatch(/^[0-9a-f]{64}$/);
    expect(Object.isFrozen(parsed)).toBe(true);
  });

  it("refuses a mismatched attestation before producing publication bytes", async () => {
    const input = await fixture();
    const other = await fixture("# Other rule\n");

    expect(() =>
      createBaselineVetPublicationV1({
        ...input,
        envelope: other.envelope,
        seenEvidenceDigests: [],
        seenReceiptBindings: [],
      }),
    ).toThrow(/request or receipt binding/);
  });

  it("rejects noncanonical, unknown, duplicated, and substituted publication content", async () => {
    const input = await fixture();
    const publication = createBaselineVetPublicationV1({
      ...input,
      seenEvidenceDigests: [],
      seenReceiptBindings: [],
    });
    const canonical = canonicalBaselineVetPublicationV1Bytes(publication).toString("utf8");
    expect(() => parseBaselineVetPublicationV1Json(`${canonical}\n`)).toThrow(/canonical/);
    expect(() =>
      parseBaselineVetPublicationV1Json(JSON.stringify({ ...publication, unexpected: true })),
    ).toThrow();
    expect(() =>
      parseBaselineVetPublicationV1Json(
        JSON.stringify({
          ...publication,
          annexes: [publication.annexes[0], publication.annexes[0]],
        }),
      ),
    ).toThrow(/annex/);
    const changed = JSON.parse(canonical) as {
      annexes: Array<{ bytesBase64: string }>;
    };
    const firstAnnex = changed.annexes[0];
    if (firstAnnex === undefined) throw new Error("test fixture requires one annex");
    firstAnnex.bytesBase64 = Buffer.from("changed", "utf8").toString("base64");
    expect(() => parseBaselineVetPublicationV1Json(JSON.stringify(changed))).toThrow(/annex/);
  });
});

describe("BaselineVetDiscoveryV1", () => {
  it("maps the exact request to immutable publication bytes without granting authority", async () => {
    const input = await fixture();
    const publication = createBaselineVetPublicationV1({
      ...input,
      seenEvidenceDigests: [],
      seenReceiptBindings: [],
    });
    const discovery = createBaselineVetDiscoveryV1({
      publication,
      locator:
        "https://github.com/samartomar/aih-scan/releases/download/baseline-request/publication.json",
    });
    const discoveryBytes = canonicalBaselineVetDiscoveryV1Bytes(discovery);
    const parsed = parseBaselineVetDiscoveryV1Json(discoveryBytes.toString("utf8"));
    const resolved = resolveBaselineVetDiscoveryV1({
      discovery: parsed,
      publicationBytes: canonicalBaselineVetPublicationV1Bytes(publication),
      expectedRequestSha256: input.request.requestSha256,
    });

    expect(resolved).toEqual(publication);
    expect(parsed.authority).toBe("none");
    expect(parsed.publicationSha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it.each([
    "http://github.com/samartomar/aih-scan/publication.json",
    "https://user:secret@github.com/samartomar/aih-scan/publication.json",
    "https://github.com:8443/samartomar/aih-scan/publication.json",
    "https://github.com/samartomar/aih-scan/publication.json?mutable=1",
    "https://github.com/samartomar/aih-scan/publication.json#mutable",
  ])("refuses an unsafe discovery locator: %s", async (locator) => {
    const input = await fixture();
    const publication = createBaselineVetPublicationV1({
      ...input,
      seenEvidenceDigests: [],
      seenReceiptBindings: [],
    });
    expect(() => createBaselineVetDiscoveryV1({ publication, locator })).toThrow(/locator/);
  });

  it("rejects substituted publication bytes and a wrong expected request", async () => {
    const input = await fixture();
    const publication = createBaselineVetPublicationV1({
      ...input,
      seenEvidenceDigests: [],
      seenReceiptBindings: [],
    });
    const discovery = createBaselineVetDiscoveryV1({
      publication,
      locator:
        "https://github.com/samartomar/aih-scan/releases/download/baseline-request/publication.json",
    });
    const bytes = canonicalBaselineVetPublicationV1Bytes(publication);
    expect(() =>
      resolveBaselineVetDiscoveryV1({
        discovery,
        publicationBytes: Buffer.concat([bytes, Buffer.from("\n")]),
        expectedRequestSha256: input.request.requestSha256,
      }),
    ).toThrow(/publication digest/);
    expect(() =>
      resolveBaselineVetDiscoveryV1({
        discovery,
        publicationBytes: bytes,
        expectedRequestSha256: "f".repeat(64),
      }),
    ).toThrow(/request digest/);
  });
});
