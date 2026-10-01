import { createHash, X509Certificate } from "node:crypto";
import dns from "node:dns";
import { readFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import { syncBuiltinESMExports } from "node:module";
import net from "node:net";
import tls from "node:tls";
import { bundleFromJSON } from "@sigstore/bundle";
import { TrustedRoot } from "@sigstore/protobuf-specs";
import { toSignedEntity, toTrustMaterial, Verifier } from "@sigstore/verify";
import { describe, expect, test, vi } from "vitest";
import type { Artifact, SigstoreBundle, VerificationPublisher } from "../../src/artifact/types.js";
import { canonicalBytes } from "../../src/assessment/json.js";
import { attachAttestation, authenticateArtifact, prepareArtifact } from "../../src/public/host.js";
import { emptyReport } from "../assessment/fixtures.js";

const fixture = (name: string) =>
  JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8"));
const retained = fixture("keyless-research-bundle.json") as SigstoreBundle;
const roots = fixture("public-sigstore-root.json") as Record<string, unknown>;
const upstream = fixture("upstream-dsse-002.json") as SigstoreBundle;
const upstreamRoot = fixture("upstream-test-root.json") as Record<string, unknown>;
const san =
  "https://github.com/samartomar/aih-scan/.github/workflows/scan-keyless-smoke.yml@refs/heads/codex/scan-keyless-contract-smoke";
const issuer = "https://token.actions.githubusercontent.com";
const der = (value: string) =>
  Buffer.concat([Buffer.from([12, Buffer.byteLength(value)]), Buffer.from(value)]);
const extensions = [
  { oid: [1, 3, 6, 1, 4, 1, 57264, 1, 15], valueDerBase64: der("1336836161").toString("base64") },
  { oid: [1, 3, 6, 1, 4, 1, 57264, 1, 17], valueDerBase64: der("9993940").toString("base64") },
];
const publisher = (): VerificationPublisher => ({
  profile: "sigstore-public",
  identity: "TEST-ONLY-retained-research",
  purposes: ["scan-report"],
  trustedRoot: structuredClone(roots),
  policy: {
    issuer,
    subjectAlternativeName: san,
    requiredCertificateExtensions: structuredClone(extensions),
  },
});
const verifyResearch = (bundle = retained, root = roots, selected = publisher()) => {
  const literal = new RegExp(
    `^${selected.policy.subjectAlternativeName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`,
  );
  return new Verifier(toTrustMaterial(TrustedRoot.fromJSON(root)), {
    ctlogThreshold: 1,
    tlogThreshold: 1,
    timestampThreshold: 1,
  }).verify(toSignedEntity(bundleFromJSON(bundle)), {
    subjectAlternativeName: literal,
    extensions: { issuer: selected.policy.issuer },
    oids: selected.policy.requiredCertificateExtensions.map((extension) => ({
      oid: { id: extension.oid },
      value: Buffer.from(extension.valueDerBase64, "base64"),
    })),
  });
};

describe("retained test-only keyless mechanisms", () => {
  test("the pinned upstream verifier authenticates the retained research bundle after leaf expiry", () => {
    const certificate = new X509Certificate(
      Buffer.from(retained.verificationMaterial.certificate!.rawBytes, "base64"),
    );
    expect(Date.parse(certificate.validTo)).toBeLessThan(Date.now());
    expect(certificate.publicKey.asymmetricKeyDetails?.namedCurve).toBe("prime256v1");
    expect(verifyResearch().identity).toMatchObject({
      subjectAlternativeName: san,
      extensions: { issuer },
    });
  });
  test("the upstream DSSE 0.0.2 proof and RFC3161 witness verify after leaf expiry", () => {
    const certificate = new X509Certificate(
      Buffer.from(upstream.verificationMaterial.certificate!.rawBytes, "base64"),
    );
    expect(Date.parse(certificate.validTo)).toBeLessThan(Date.now());
    const signer = new Verifier(toTrustMaterial(TrustedRoot.fromJSON(upstreamRoot)), {
      ctlogThreshold: 1,
      tlogThreshold: 1,
      timestampThreshold: 1,
    }).verify(toSignedEntity(bundleFromJSON(upstream)), {
      subjectAlternativeName: /^brian@dehamer\.com$/,
      extensions: { issuer: "https://github.com/login/oauth" },
    });
    expect(signer.identity?.subjectAlternativeName).toBe("brian@dehamer.com");
    const missing = structuredClone(upstream);
    delete missing.verificationMaterial.timestampVerificationData;
    expect(() =>
      new Verifier(toTrustMaterial(TrustedRoot.fromJSON(upstreamRoot))).verify(
        toSignedEntity(bundleFromJSON(missing)),
      ),
    ).toThrow();
  });
  test.each([
    "SAN",
    "issuer",
    "OID",
    "CA",
    "CT log",
    "Rekor",
    "promise",
    "proof",
    "signature",
  ])("retained research refuses mismatched or missing %s", (change) => {
    const bundle = structuredClone(retained),
      root = structuredClone(roots),
      selected = publisher();
    switch (change) {
      case "SAN":
        selected.policy.subjectAlternativeName = san.replace(
          "codex/scan-keyless-contract-smoke",
          "main",
        );
        break;
      case "issuer":
        selected.policy.issuer = "https://example.invalid";
        break;
      case "OID":
        selected.policy.requiredCertificateExtensions[0]!.valueDerBase64 =
          der("0").toString("base64");
        break;
      case "CA":
        root.certificateAuthorities = [];
        break;
      case "CT log":
        root.ctlogs = [];
        break;
      case "Rekor":
        root.tlogs = [];
        break;
      case "promise":
        delete bundle.verificationMaterial.tlogEntries![0]!.inclusionPromise;
        break;
      case "proof":
        delete bundle.verificationMaterial.tlogEntries![0]!.inclusionProof;
        break;
      case "signature":
        bundle.dsseEnvelope.signatures[0]!.sig = Buffer.alloc(72).toString("base64");
        break;
    }
    expect(() => verifyResearch(bundle, root, selected)).toThrow();
  });
  test("the product rejects the retained research predicate even though its crypto verifies", async () => {
    const reportBytes = Buffer.from(
      '{"schema":"urn:aihq:research:keyless-smoke:1.0.0","synthetic":true}',
    );
    const hash = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
    const artifact: Artifact = {
      schema: "urn:aihq:scan:artifact:1.0.0",
      scanId: `scan:sha256:${hash(Buffer.concat([Buffer.from("aih.scan.report.v1\0"), reportBytes]))}`,
      report: {
        schema: "urn:aihq:research:keyless-smoke:1.0.0",
        mediaType: "application/json",
        sha256: hash(reportBytes),
        byteLength: reportBytes.length,
        bytesBase64: reportBytes.toString("base64"),
      },
      annexes: [],
    };
    await expect(
      attachAttestation({ bytes: canonicalBytes(artifact), bundle: retained }),
    ).rejects.toMatchObject({ code: "invalid-input", reason: "byte-mismatch" });
    expect(
      await authenticateArtifact({
        bytes: canonicalBytes({ ...artifact, attestation: retained }),
        expectedScanId: artifact.scanId,
        trust: { keys: [], publishers: [publisher()] },
      }),
    ).toMatchObject({ status: "unverifiable", reason: "byte-mismatch" });
  });
});

describe("product certificate profile refuses before promotion", () => {
  async function detached() {
    const prepared = await prepareArtifact({ report: emptyReport(), annexes: [] });
    const bundle = structuredClone(retained);
    bundle.dsseEnvelope.payload = Buffer.from(JSON.stringify(prepared.statement)).toString(
      "base64",
    );
    return { prepared, bundle };
  }
  test("attachment accepts only bindings; selected public roots cannot rescue a changed signed payload", async () => {
    const { prepared, bundle } = await detached();
    const attached = await attachAttestation({ bytes: prepared.bytes, bundle });
    expect(
      await authenticateArtifact({
        bytes: attached.bytes,
        expectedScanId: prepared.scanId,
        trust: { keys: [], publishers: [publisher()] },
      }),
    ).toMatchObject({ status: "unverifiable", reason: "invalid-signature" });
  });
  test.each([
    "union",
    "chain",
    "missing promise",
    "missing proof",
    "unwitnessed 0.0.2",
    "uint64 number",
    "unsafe time",
  ])("the bundle refuses %s before upstream parsing", async (change) => {
    const { prepared, bundle } = await detached();
    const material = bundle.verificationMaterial as Record<string, unknown>;
    const entry = bundle.verificationMaterial.tlogEntries![0]!;
    switch (change) {
      case "union":
        material.publicKey = { hint: "test" };
        break;
      case "chain":
        material.x509CertificateChain = { certificates: [material.certificate] };
        break;
      case "missing promise":
        delete entry.inclusionPromise;
        break;
      case "missing proof":
        delete entry.inclusionProof;
        break;
      case "unwitnessed 0.0.2":
        entry.kindVersion = { kind: "dsse", version: "0.0.2" };
        break;
      case "uint64 number":
        entry.logIndex = 9007199254740992;
        break;
      case "unsafe time":
        entry.integratedTime = "18446744073709551615";
        break;
    }
    await expect(attachAttestation({ bytes: prepared.bytes, bundle })).rejects.toMatchObject({
      code: "invalid-input",
    });
  });
  test("historical uint64 indices remain exact decimal strings at attachment", async () => {
    const { prepared, bundle } = await detached();
    bundle.verificationMaterial.tlogEntries![0]!.logIndex = "18446744073709551615";
    const attached = await attachAttestation({ bytes: prepared.bytes, bundle });
    expect(attached.artifact.attestation!.verificationMaterial.tlogEntries![0]!.logIndex).toBe(
      "18446744073709551615",
    );
  });
  test("publisher and root ceilings, conflicting OIDs and malformed DER never become absent trust", async () => {
    const { prepared, bundle } = await detached();
    const attached = await attachAttestation({ bytes: prepared.bytes, bundle });
    const malformed = publisher();
    malformed.policy.requiredCertificateExtensions.push(
      malformed.policy.requiredCertificateExtensions[0]!,
    );
    const oversized = publisher();
    oversized.trustedRoot.tlogs = Array.from({ length: 65 }, () => (roots.tlogs as unknown[])[0]);
    const bad = publisher();
    bad.policy.requiredCertificateExtensions[0]!.oid = [3, 0];
    for (const [publishers, reason] of [
      [Array.from({ length: 33 }, publisher), "resource-limit"],
      [[oversized], "resource-limit"],
      [[malformed], "malformed"],
      [[bad], "malformed"],
    ] as const) {
      expect(
        await authenticateArtifact({
          bytes: attached.bytes,
          expectedScanId: prepared.scanId,
          trust: { keys: [], publishers: [...publishers] },
        }),
      ).toMatchObject({ status: "unverifiable", reason });
    }
  });
  test("offline certificate verification performs no fetch or root refresh", async () => {
    const { prepared, bundle } = await detached();
    const attached = await attachAttestation({ bytes: prepared.bytes, bundle });
    const blocked = () => {
      throw new Error("No network permitted");
    };
    const guards = [
      vi.spyOn(globalThis, "fetch").mockImplementation(blocked),
      vi.spyOn(http, "request").mockImplementation(blocked),
      vi.spyOn(http, "get").mockImplementation(blocked),
      vi.spyOn(https, "request").mockImplementation(blocked),
      vi.spyOn(https, "get").mockImplementation(blocked),
      vi.spyOn(net, "connect").mockImplementation(blocked),
      vi.spyOn(net, "createConnection").mockImplementation(blocked),
      vi.spyOn(net.Socket.prototype, "connect").mockImplementation(blocked),
      vi.spyOn(tls, "connect").mockImplementation(blocked),
      vi.spyOn(dns, "lookup").mockImplementation(blocked),
      vi.spyOn(dns, "resolve").mockImplementation(blocked),
      vi.spyOn(dns.promises, "lookup").mockImplementation(blocked),
      vi.spyOn(dns.promises, "resolve").mockImplementation(blocked),
    ];
    syncBuiltinESMExports();
    try {
      expect(
        await authenticateArtifact({
          bytes: attached.bytes,
          expectedScanId: prepared.scanId,
          trust: { keys: [], publishers: [publisher()] },
        }),
      ).toMatchObject({ status: "unverifiable", reason: "invalid-signature" });
      expect(verifyResearch().identity?.subjectAlternativeName).toBe(san);
      for (const guard of guards) expect(guard).not.toHaveBeenCalled();
    } finally {
      for (const guard of guards) guard.mockRestore();
      syncBuiltinESMExports();
    }
  });
});
