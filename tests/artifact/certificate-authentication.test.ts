import { X509Certificate } from "node:crypto";
import dns from "node:dns";
import http from "node:http";
import https from "node:https";
import { syncBuiltinESMExports } from "node:module";
import net from "node:net";
import tls from "node:tls";
import { expect, test, vi } from "vitest";
import type { VerificationPublisher } from "../../src/artifact/types.js";
import { canonicalBytes } from "../../src/assessment/json.js";
import { authenticateArtifact } from "../../src/public/host.js";
import { readArtifact } from "../../src/public/read.js";
import { syntheticKeyless, utf8Der } from "./synthetic-keyless.js";

type Fixture = Awaited<ReturnType<typeof syntheticKeyless>>;
const authenticate = (fixture: Fixture, publishers: VerificationPublisher[]) =>
  authenticateArtifact({
    bytes: fixture.attached.bytes,
    expectedScanId: fixture.prepared.scanId,
    trust: { keys: [], publishers },
  });
const expiredPolicy = (fixture: Fixture) => {
  const old = structuredClone(fixture.publisher);
  old.trustedRoot.ctlogs = [];
  return old;
};

test("the product authenticates TEST ONLY DSSE 0.0.2 with a real RFC3161 timestamp bound to signature bytes", async () => {
  const fixture = await syntheticKeyless("0.0.2");
  expect(fixture.bundle.verificationMaterial.tlogEntries![0]!.kindVersion).toEqual({
    kind: "dsse",
    version: "0.0.2",
  });
  expect(fixture.bundle.verificationMaterial.tlogEntries![0]!.inclusionPromise).toBeUndefined();
  expect(Date.parse(new X509Certificate(fixture.certificate).validTo)).toBeLessThan(Date.now());
  expect(fixture.prepared.artifact.annexes[0]?.byteLength).toBeGreaterThan(0);
  expect(await authenticate(fixture, [fixture.publisher])).toEqual({
    scanId: fixture.prepared.scanId,
    status: "authenticated",
    producerIdentity: fixture.publisher.identity,
    reportRead: "not-requested",
  });
});

test.each([
  "missing",
  "wrong imprint",
  "outside leaf validity",
  "unselected TSA",
  "corrupt TSA signature",
])("DSSE 0.0.2 refuses a %s timestamp witness through the product API", async (change) => {
  const fixture = await syntheticKeyless("0.0.2");
  const artifact = structuredClone(fixture.attached.artifact);
  const publisher = structuredClone(fixture.publisher);
  if (change === "missing")
    delete artifact.attestation!.verificationMaterial.timestampVerificationData;
  if (change === "unselected TSA") publisher.trustedRoot.timestampAuthorities = [];
  const timestamp = (
    artifact.attestation!.verificationMaterial.timestampVerificationData as
      | {
          rfc3161Timestamps: { signedTimestamp: string }[];
        }
      | undefined
  )?.rfc3161Timestamps[0];
  if (timestamp) {
    if (change === "wrong imprint")
      timestamp.signedTimestamp = fixture.timestamps!.wrongImprintTimestamp;
    if (change === "outside leaf validity")
      timestamp.signedTimestamp = fixture.timestamps!.outsideLeafValidityTimestamp;
    if (change === "corrupt TSA signature") {
      const token = Buffer.from(timestamp.signedTimestamp, "base64");
      token[token.length - 1] = token[token.length - 1]! ^ 1;
      timestamp.signedTimestamp = token.toString("base64");
    }
  }
  expect(
    await authenticateArtifact({
      bytes: canonicalBytes(artifact),
      expectedScanId: fixture.prepared.scanId,
      trust: { keys: [], publishers: [publisher] },
    }),
  ).toMatchObject({
    status: "unverifiable",
    reason: change === "missing" ? "malformed" : "invalid-signature",
  });
});

test("the product authenticates a TEST ONLY expired certificate with real CT/Rekor witnesses and a nonempty annex", async () => {
  const fixture = await syntheticKeyless();
  expect(Date.parse(new X509Certificate(fixture.certificate).validTo)).toBeLessThan(Date.now());
  expect(fixture.prepared.artifact.annexes[0]?.byteLength).toBeGreaterThan(0);
  expect(Buffer.from(fixture.bundle.dsseEnvelope.payload, "base64")).toEqual(fixture.payload);
  expect(await readArtifact(fixture.attached.bytes)).toMatchObject({
    status: "read",
    authenticity: "unchecked",
  });
  expect(
    await authenticateArtifact({
      bytes: fixture.attached.bytes,
      expectedScanId: fixture.prepared.scanId,
      trust: { keys: [], publishers: [fixture.publisher] },
    }),
  ).toEqual({
    scanId: fixture.prepared.scanId,
    status: "authenticated",
    producerIdentity: fixture.publisher.identity,
    reportRead: "not-requested",
  });
});

test("equivalent historical policies consolidate; a failed old root cannot hide a valid identity", async () => {
  const fixture = await syntheticKeyless();
  const historical = structuredClone(fixture.publisher);
  historical.policy.requiredCertificateExtensions = [];
  for (const publishers of [
    [expiredPolicy(fixture), historical, fixture.publisher],
    [fixture.publisher, historical, expiredPolicy(fixture)],
  ]) {
    expect(await authenticate(fixture, publishers)).toMatchObject({
      status: "authenticated",
      producerIdentity: fixture.publisher.identity,
    });
  }
});

test("different successfully verified producer identities are ambiguous in either order", async () => {
  const fixture = await syntheticKeyless();
  const conflicting = structuredClone(fixture.publisher);
  conflicting.identity = "TEST-ONLY-different-publisher";
  for (const publishers of [
    [fixture.publisher, conflicting],
    [conflicting, fixture.publisher],
  ]) {
    expect(await authenticate(fixture, publishers)).toMatchObject({
      status: "unverifiable",
      reason: "unknown-producer",
    });
  }
});

test.each([
  "SAN metacharacter",
  "issuer",
  "OID value",
  "missing OID",
])("valid synthetic cryptography cannot override a mismatching %s policy", async (change) => {
  const fixture = await syntheticKeyless();
  const mismatched = structuredClone(fixture.publisher);
  if (change === "SAN metacharacter")
    mismatched.policy.subjectAlternativeName = mismatched.policy.subjectAlternativeName.replace(
      "+literal",
      ".literal",
    );
  if (change === "issuer") mismatched.policy.issuer = "https://other.test.invalid";
  if (change === "OID value")
    mismatched.policy.requiredCertificateExtensions[0]!.valueDerBase64 = utf8Der(
      "TEST-ONLY-other-repository",
    ).toString("base64");
  if (change === "missing OID")
    mismatched.policy.requiredCertificateExtensions[0]!.oid = [1, 3, 6, 1, 4, 1, 57264, 1, 17];
  expect(await authenticate(fixture, [mismatched])).toMatchObject({
    status: "unverifiable",
    reason: "unknown-producer",
  });
});

test("an unrelated failed historical root does not overwrite a verified identity-policy refusal", async () => {
  const fixture = await syntheticKeyless();
  const mismatched = structuredClone(fixture.publisher);
  mismatched.policy.issuer = "https://other.test.invalid";
  for (const publishers of [
    [mismatched, expiredPolicy(fixture)],
    [expiredPolicy(fixture), mismatched],
  ]) {
    expect(await authenticate(fixture, publishers)).toMatchObject({
      status: "unverifiable",
      reason: "unknown-producer",
    });
  }
});

test.each([
  "CA",
  "CT",
  "Rekor",
  "promise",
  "proof",
  "signature",
])("the full product path refuses missing or corrupted synthetic %s", async (change) => {
  const fixture = await syntheticKeyless();
  const publisher = structuredClone(fixture.publisher);
  const artifact = structuredClone(fixture.attached.artifact);
  const entry = artifact.attestation!.verificationMaterial.tlogEntries![0]!;
  if (change === "CA") publisher.trustedRoot.certificateAuthorities = [];
  if (change === "CT") publisher.trustedRoot.ctlogs = [];
  if (change === "Rekor") publisher.trustedRoot.tlogs = [];
  if (change === "promise")
    (entry.inclusionPromise as Record<string, unknown>).signedEntryTimestamp =
      Buffer.alloc(72).toString("base64");
  if (change === "proof") {
    const checkpoint = (entry.inclusionProof as { checkpoint: { envelope: string } }).checkpoint;
    checkpoint.envelope = checkpoint.envelope.replace("\n1\n", "\n2\n");
  }
  if (change === "signature")
    artifact.attestation!.dsseEnvelope.signatures[0]!.sig = Buffer.alloc(72).toString("base64");
  expect(
    await authenticateArtifact({
      bytes: canonicalBytes(artifact),
      expectedScanId: fixture.prepared.scanId,
      trust: { keys: [], publishers: [publisher] },
    }),
  ).toMatchObject({ status: "unverifiable", reason: "invalid-signature" });
});

test("the certificate profile binds the original statement bytes and nonempty annex bytes", async () => {
  const fixture = await syntheticKeyless();
  const rewritten = structuredClone(fixture.attached.artifact);
  rewritten.attestation!.dsseEnvelope.payload = Buffer.from(
    JSON.stringify(fixture.prepared.statement),
  ).toString("base64");
  expect(
    await authenticateArtifact({
      bytes: canonicalBytes(rewritten),
      expectedScanId: fixture.prepared.scanId,
      trust: { keys: [], publishers: [fixture.publisher] },
    }),
  ).toMatchObject({ status: "unverifiable", reason: "invalid-signature" });
  const tampered = structuredClone(fixture.attached.artifact);
  const annex = Buffer.from(tampered.annexes[0]!.bytesBase64, "base64");
  annex[0] = annex[0]! ^ 1;
  tampered.annexes[0]!.bytesBase64 = annex.toString("base64");
  expect(
    await authenticateArtifact({
      bytes: canonicalBytes(tampered),
      expectedScanId: fixture.prepared.scanId,
      trust: { keys: [], publishers: [fixture.publisher] },
    }),
  ).toMatchObject({ status: "unverifiable", reason: "byte-mismatch" });
});

test("successful product certificate authentication and historical consolidation perform no network calls", async () => {
  const fixture = await syntheticKeyless();
  const timestampFixture = await syntheticKeyless("0.0.2");
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
    expect(await authenticate(fixture, [fixture.publisher])).toMatchObject({
      status: "authenticated",
    });
    expect(
      await authenticate(fixture, [
        expiredPolicy(fixture),
        fixture.publisher,
        structuredClone(fixture.publisher),
      ]),
    ).toMatchObject({ status: "authenticated", producerIdentity: fixture.publisher.identity });
    expect(await authenticate(timestampFixture, [timestampFixture.publisher])).toMatchObject({
      status: "authenticated",
      producerIdentity: timestampFixture.publisher.identity,
    });
    for (const guard of guards) expect(guard).not.toHaveBeenCalled();
  } finally {
    for (const guard of guards) guard.mockRestore();
    syncBuiltinESMExports();
  }
});
