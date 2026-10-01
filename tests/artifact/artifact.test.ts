import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, test } from "vitest";
import {
  attachAttestation,
  authenticateArtifact,
  prepareArtifact,
  signArtifact,
} from "../../src/public/host.js";
import { readArtifact } from "../../src/public/read.js";
import { emptyReport } from "../assessment/fixtures.js";

const hash = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const opaqueReport = Buffer.from('{"schema":"urn:example:report:2.0.0"}');
const scanId = `scan:sha256:${hash(Buffer.concat([Buffer.from("aih.scan.report.v1\0"), opaqueReport]))}`;
const canonical = (value: unknown): string => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
};
function opaqueFixture() {
  const annex = Buffer.from("nonempty independent annex\n");
  const descriptor = {
    id: "annex.raw",
    mediaType: "text/plain",
    sha256: hash(annex),
    byteLength: annex.length,
  };
  const artifact = {
    schema: "urn:aihq:scan:artifact:1.0.0",
    scanId,
    report: {
      schema: "urn:example:report:2.0.0",
      mediaType: "application/json",
      sha256: hash(opaqueReport),
      byteLength: opaqueReport.length,
      bytesBase64: opaqueReport.toString("base64"),
    },
    annexes: [{ ...descriptor, bytesBase64: annex.toString("base64") }],
  };
  const statement = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "scan-report", digest: { sha256: hash(opaqueReport) } }],
    predicateType: "urn:aihq:scan:artifact-attestation:1.0.0",
    predicate: {
      scanId,
      reportSchema: artifact.report.schema,
      reportByteLength: opaqueReport.length,
      annexManifestSha256: hash(Buffer.from(canonical([descriptor]))),
    },
  };
  const keyId = `ed25519:${"0".repeat(64)}`;
  const bundle = {
    mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
    verificationMaterial: { publicKey: { hint: keyId }, tlogEntries: [] },
    dsseEnvelope: {
      payloadType: "application/vnd.in-toto+json",
      payload: Buffer.from(JSON.stringify(statement)).toString("base64"),
      signatures: [{ keyid: keyId, sig: Buffer.alloc(64).toString("base64") }],
    },
  };
  return { artifact, statement, bundle, bytes: Buffer.from(canonical(artifact)), scanId };
}

describe("portable artifact attachment", () => {
  test("a reader refuses a transport schema descriptor that disagrees with the decoded report schema", async () => {
    const fixture = opaqueFixture();
    fixture.artifact.report.schema = "urn:aihq:scan:report:1.0.0";
    expect(await readArtifact(Buffer.from(canonical(fixture.artifact)))).toMatchObject({
      status: "invalid",
    });
  });
  test("an unsupported bundle content case reports unsupported-artifact", async () => {
    const fixture = opaqueFixture();
    const bundle = {
      mediaType: fixture.bundle.mediaType,
      verificationMaterial: fixture.bundle.verificationMaterial,
      messageSignature: { signature: "AA==" },
    };
    await expect(attachAttestation({ bytes: fixture.bytes, bundle })).rejects.toMatchObject({
      code: "unsupported-artifact",
    });
  });
  test("attachment binds a nonempty annex without claiming producer authenticity", async () => {
    const fixture = opaqueFixture();
    const attached = await attachAttestation({ bytes: fixture.bytes, bundle: fixture.bundle });
    expect(attached.scanId).toBe(fixture.scanId);
    expect(attached.artifact.attestation).toEqual(fixture.bundle);
    expect(
      await authenticateArtifact({
        bytes: attached.bytes,
        expectedScanId: fixture.scanId,
        trust: { keys: [], publishers: [] },
      }),
    ).toMatchObject({ status: "unverifiable", reason: "untrusted-key" });
    await expect(
      attachAttestation({ bytes: attached.bytes, bundle: fixture.bundle }),
    ).rejects.toMatchObject({ code: "already-attested" });
  });
});

function organizationKey(identity = "test-organization") {
  const key = generateKeyPairSync("ed25519");
  const spki = key.publicKey.export({ type: "spki", format: "der" });
  const keyId = `ed25519:${hash(spki)}`;
  return {
    ...key,
    keyId,
    record: { identity, keyId, publicKeySpkiBase64: spki.toString("base64") },
  };
}
function supportedFixture() {
  const report = emptyReport();
  const annex = Buffer.from("nonempty raw detector evidence\n");
  report.annexes = [
    { id: "annex.raw", mediaType: "text/plain", sha256: hash(annex), byteLength: annex.length },
  ];
  return { report, annexes: [{ id: "annex.raw", bytes: annex }] };
}

describe("local independent organization authentication", () => {
  test("authentication snapshots independently selected trust before any asynchronous byte validation", async () => {
    const key = organizationKey("initially-selected-identity");
    const signed = await signArtifact({
      ...supportedFixture(),
      signer: { keyId: key.keyId, privateKey: key.privateKey },
    });
    const trust = { keys: [key.record], publishers: [] };
    const authentication = authenticateArtifact({
      bytes: signed.bytes,
      expectedScanId: signed.scanId,
      trust,
    });
    key.record.identity = "mutated-after-entry";
    trust.keys.length = 0;
    expect(await authentication).toMatchObject({
      status: "authenticated",
      producerIdentity: "initially-selected-identity",
      keyId: key.keyId,
    });
  });
  test("a partial report with a nonempty annex remains readable, signable and immutable across new signatures", async () => {
    const fixture = supportedFixture();
    const prepared = await prepareArtifact(fixture);
    expect(prepared.artifact.attestation).toBeUndefined();
    expect(prepared.statement).toMatchObject({
      predicateType: "urn:aihq:scan:artifact-attestation:1.0.0",
      predicate: { scanId: prepared.scanId, reportByteLength: prepared.artifact.report.byteLength },
    });
    const first = organizationKey("retained-organization");
    const rotated = organizationKey("current-organization");
    const signed = await signArtifact({
      ...fixture,
      signer: { keyId: first.keyId, privateKey: first.privateKey },
    });
    const resigned = await signArtifact({
      ...fixture,
      signer: { keyId: rotated.keyId, privateKey: rotated.privateKey },
    });
    expect(resigned.scanId).toBe(signed.scanId);
    expect(signed.scanId).toBe(prepared.scanId);
    expect(await readArtifact(signed.bytes)).toMatchObject({
      status: "read",
      authenticity: "unchecked",
      annexBytes: "checked",
      report: { completion: "partial" },
    });
    const input = {
      bytes: signed.bytes,
      expectedScanId: signed.scanId,
      trust: { keys: [first.record, rotated.record], publishers: [] },
    };
    expect(await authenticateArtifact(input)).toMatchObject({
      status: "authenticated",
      producerIdentity: "retained-organization",
      keyId: first.keyId,
    });
    expect(await authenticateArtifact(input)).toMatchObject({ status: "authenticated" });
    expect(
      await authenticateArtifact({ ...input, trust: { keys: [rotated.record], publishers: [] } }),
    ).toMatchObject({ status: "unverifiable", reason: "untrusted-key" });
  });
  test("original noncanonical statement ordering and whitespace are verified as the signed bytes", async () => {
    const fixture = opaqueFixture();
    const key = organizationKey();
    const payload = Buffer.from(JSON.stringify(fixture.statement, null, 2));
    const pae = Buffer.concat([
      Buffer.from(`DSSEv1 28 application/vnd.in-toto+json ${payload.length} `),
      payload,
    ]);
    const bundle = {
      ...fixture.bundle,
      verificationMaterial: { publicKey: { hint: key.keyId }, tlogEntries: [] },
      dsseEnvelope: {
        ...fixture.bundle.dsseEnvelope,
        payload: payload.toString("base64"),
        signatures: [{ keyid: key.keyId, sig: sign(null, pae, key.privateKey).toString("base64") }],
      },
    };
    const attached = await attachAttestation({ bytes: fixture.bytes, bundle });
    expect(
      await authenticateArtifact({
        bytes: attached.bytes,
        expectedScanId: attached.scanId,
        trust: { keys: [key.record], publishers: [] },
      }),
    ).toMatchObject({ status: "authenticated", producerIdentity: key.record.identity });
    expect(await readArtifact(attached.bytes)).toEqual({
      status: "unsupported-report",
      scanId: attached.scanId,
      reportSchema: "urn:example:report:2.0.0",
    });
  });
  test("a signature made without the DSSE PAE is refused under an independently trusted key", async () => {
    const fixture = opaqueFixture();
    const key = organizationKey();
    const payload = Buffer.from(JSON.stringify(fixture.statement));
    fixture.bundle.verificationMaterial.publicKey.hint = key.keyId;
    fixture.bundle.dsseEnvelope.signatures = [
      { keyid: key.keyId, sig: sign(null, payload, key.privateKey).toString("base64") },
    ];
    const attached = await attachAttestation({ bytes: fixture.bytes, bundle: fixture.bundle });
    expect(
      await authenticateArtifact({
        bytes: attached.bytes,
        expectedScanId: attached.scanId,
        trust: { keys: [key.record], publishers: [] },
      }),
    ).toMatchObject({ status: "unverifiable", reason: "invalid-signature" });
  });
  test("preparation refuses unsupported details and missing, extra, duplicate or changed annex records", async () => {
    const fixture = supportedFixture();
    for (const annexes of [
      [],
      [...fixture.annexes, ...fixture.annexes],
      [{ id: "annex.extra", bytes: Buffer.from("extra") }],
      [{ id: "annex.raw", bytes: Buffer.from("changed") }],
    ]) {
      await expect(prepareArtifact({ report: fixture.report, annexes })).rejects.toMatchObject({
        code: "invalid-input",
      });
    }
    await expect(
      prepareArtifact({
        ...fixture,
        report: {
          ...fixture.report,
          schema: "urn:example:report:2.0.0",
        } as unknown as typeof fixture.report,
      }),
    ).rejects.toMatchObject({ code: "invalid-input" });
  });
  test("local signing requires the matching explicit private Ed25519 KeyObject", async () => {
    const fixture = supportedFixture();
    const key = organizationKey();
    const other = organizationKey();
    const ec = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    for (const signer of [
      { keyId: key.keyId, privateKey: key.publicKey },
      { keyId: key.keyId, privateKey: other.privateKey },
      { keyId: key.keyId, privateKey: ec.privateKey },
    ]) {
      await expect(signArtifact({ ...fixture, signer })).rejects.toMatchObject({
        code: "invalid-input",
        message: "Scan artifact invalid-input.",
      });
    }
  });
  test("changed annex bytes, manifest descriptors, report digests and expected ID cannot authenticate", async () => {
    const key = organizationKey();
    const signed = await signArtifact({
      ...supportedFixture(),
      signer: { keyId: key.keyId, privateKey: key.privateKey },
    });
    const trust = { keys: [key.record], publishers: [] };
    expect(
      await authenticateArtifact({
        bytes: signed.bytes,
        expectedScanId: `scan:sha256:${"0".repeat(64)}`,
        trust,
      }),
    ).toMatchObject({ status: "unverifiable", reason: "id-mismatch" });
    for (const mutate of [
      (artifact: typeof signed.artifact) => {
        artifact.annexes[0]!.bytesBase64 = Buffer.from("tampered").toString("base64");
      },
      (artifact: typeof signed.artifact) => {
        artifact.annexes[0]!.mediaType = "text/changed";
      },
      (artifact: typeof signed.artifact) => {
        artifact.report.sha256 = "0".repeat(64);
      },
      (artifact: typeof signed.artifact) => {
        artifact.annexes = [];
      },
    ]) {
      const artifact = structuredClone(signed.artifact);
      mutate(artifact);
      expect(
        await authenticateArtifact({
          bytes: Buffer.from(canonical(artifact)),
          expectedScanId: signed.scanId,
          trust,
        }),
      ).toMatchObject({ status: "unverifiable", reason: "byte-mismatch" });
    }
  });
  test("trust is explicit, closed, bounded and fingerprint checked before verification", async () => {
    const key = organizationKey();
    const signed = await signArtifact({
      ...supportedFixture(),
      signer: { keyId: key.keyId, privateKey: key.privateKey },
    });
    for (const trust of [
      { keys: [key.record, key.record], publishers: [] },
      { keys: [{ ...key.record, keyId: `ed25519:${"0".repeat(64)}` }], publishers: [] },
      { keys: [{ ...key.record, identity: "e\u0301" }], publishers: [] },
      { keys: [], publishers: [], ambientKeys: [] },
    ]) {
      expect(
        await authenticateArtifact({ bytes: signed.bytes, expectedScanId: signed.scanId, trust }),
      ).toMatchObject({ status: "unverifiable", reason: "malformed" });
    }
    expect(
      await authenticateArtifact({
        bytes: signed.bytes,
        expectedScanId: signed.scanId,
        trust: { keys: Array.from({ length: 129 }, () => key.record), publishers: [] },
      }),
    ).toMatchObject({ status: "unverifiable", reason: "resource-limit" });
  });
  test("accessor control fields are rejected without evaluating caller code", async () => {
    const fixture = opaqueFixture();
    let reads = 0;
    Object.defineProperty(fixture.bundle, "mediaType", {
      enumerable: true,
      get() {
        reads++;
        return "application/vnd.dev.sigstore.bundle.v0.3+json";
      },
    });
    await expect(
      attachAttestation({ bytes: fixture.bytes, bundle: fixture.bundle }),
    ).rejects.toMatchObject({ code: "invalid-input" });
    expect(reads).toBe(0);
  });
});

describe("strict attachment refusal", () => {
  test.each([
    [
      "payload type",
      (f: ReturnType<typeof opaqueFixture>) => {
        f.bundle.dsseEnvelope.payloadType = "application/json";
      },
    ],
    [
      "wrong hint",
      (f: ReturnType<typeof opaqueFixture>) => {
        f.bundle.verificationMaterial.publicKey.hint = `ed25519:${"1".repeat(64)}`;
      },
    ],
    [
      "short signature",
      (f: ReturnType<typeof opaqueFixture>) => {
        f.bundle.dsseEnvelope.signatures[0]!.sig = "AA==";
      },
    ],
    [
      "extra signature",
      (f: ReturnType<typeof opaqueFixture>) => {
        f.bundle.dsseEnvelope.signatures.push(f.bundle.dsseEnvelope.signatures[0]!);
      },
    ],
    [
      "noncanonical padding",
      (f: ReturnType<typeof opaqueFixture>) => {
        f.bundle.dsseEnvelope.signatures[0]!.sig = "AB==";
      },
    ],
    [
      "wrong subject",
      (f: ReturnType<typeof opaqueFixture>) => {
        f.statement.subject[0]!.name = "another";
        f.bundle.dsseEnvelope.payload = Buffer.from(JSON.stringify(f.statement)).toString("base64");
      },
    ],
    [
      "wrong report length",
      (f: ReturnType<typeof opaqueFixture>) => {
        f.statement.predicate.reportByteLength++;
        f.bundle.dsseEnvelope.payload = Buffer.from(JSON.stringify(f.statement)).toString("base64");
      },
    ],
    [
      "duplicate statement field",
      (f: ReturnType<typeof opaqueFixture>) => {
        f.bundle.dsseEnvelope.payload = Buffer.from(
          JSON.stringify(f.statement).replace('"_type":', '"_type":"duplicate","_type":'),
        ).toString("base64");
      },
    ],
    [
      "unsafe number token",
      (f: ReturnType<typeof opaqueFixture>) => {
        f.bundle.dsseEnvelope.payload = Buffer.from(
          JSON.stringify(f.statement).replace(
            String(f.statement.predicate.reportByteLength),
            "9007199254740993",
          ),
        ).toString("base64");
      },
    ],
    [
      "malformed UTF8",
      (f: ReturnType<typeof opaqueFixture>) => {
        f.bundle.dsseEnvelope.payload = Buffer.from([0xc0, 0xaf]).toString("base64");
      },
    ],
  ])("%s cannot enter a complete artifact", async (_name, mutate) => {
    const fixture = opaqueFixture();
    mutate(fixture);
    await expect(
      attachAttestation({ bytes: fixture.bytes, bundle: fixture.bundle }),
    ).rejects.toMatchObject({ code: "invalid-input" });
  });
  test("statement and native byte bounds return finite resource-limit errors", async () => {
    const fixture = opaqueFixture();
    fixture.bundle.dsseEnvelope.payload = Buffer.alloc(128 * 1024 + 1).toString("base64");
    await expect(
      attachAttestation({ bytes: fixture.bytes, bundle: fixture.bundle }),
    ).rejects.toMatchObject({ code: "resource-limit", message: "Scan artifact resource-limit." });
    const supported = supportedFixture();
    await expect(
      prepareArtifact({
        report: supported.report,
        annexes: [{ id: "annex.raw", bytes: Buffer.alloc(16 * 1024 * 1024 + 1) }],
      }),
    ).rejects.toMatchObject({ code: "resource-limit" });
  });
});
