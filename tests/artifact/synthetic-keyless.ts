// TEST ONLY. Ephemeral local keys and a private CA/log universe are never
// production roots or evidence. This encoder creates fixtures, not a verifier.
import { createHash, generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import type { SigstoreBundle, VerificationPublisher } from "../../src/artifact/types.js";
import { attachAttestation, prepareArtifact } from "../../src/public/host.js";
import { emptyReport } from "../assessment/fixtures.js";

const hash = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest();
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64");
const concat = (...bytes: Uint8Array[]) => Buffer.concat(bytes);
const uint = (value: number | bigint, width: number) => {
  const result = Buffer.alloc(width);
  let remainder = BigInt(value);
  for (let index = width - 1; index >= 0; index--) {
    result[index] = Number(remainder & 255n);
    remainder >>= 8n;
  }
  return result;
};
const der = (tag: number, ...content: Uint8Array[]) => {
  const value = concat(...content);
  const length =
    value.length < 128
      ? uint(value.length, 1)
      : value.length < 256
        ? concat(uint(0x81, 1), uint(value.length, 1))
        : concat(uint(0x82, 1), uint(value.length, 2));
  return concat(uint(tag, 1), length, value);
};
const sequence = (...content: Uint8Array[]) => der(0x30, ...content);
export const utf8Der = (value: string) => der(12, Buffer.from(value));
const oid = (...arcs: number[]) => {
  const encoded = [arcs[0]! * 40 + arcs[1]!];
  for (const arc of arcs.slice(2)) {
    const parts = [arc & 127];
    let rest = Math.floor(arc / 128);
    while (rest > 0) {
      parts.unshift((rest & 127) | 128);
      rest = Math.floor(rest / 128);
    }
    encoded.push(...parts);
  }
  return der(6, Buffer.from(encoded));
};
const extension = (arcs: number[], value: Uint8Array, critical = false) =>
  sequence(oid(...arcs), ...(critical ? [der(1, Buffer.from([255]))] : []), der(4, value));
const name = (value: string) => sequence(der(0x31, sequence(oid(2, 5, 4, 3), utf8Der(value))));
const algorithm = sequence(oid(1, 2, 840, 10045, 4, 3, 2));
const ec = () => generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const spki = (key: KeyObject) => key.export({ type: "spki", format: "der" });
const signedCertificate = (tbs: Buffer, key: KeyObject) =>
  sequence(tbs, algorithm, der(3, Buffer.from([0]), sign("sha256", tbs, key)));
const validity = (start: string, end: string) =>
  sequence(der(23, Buffer.from(start)), der(23, Buffer.from(end)));
const tbs = (
  issuer: Buffer,
  subject: Buffer,
  key: KeyObject,
  dates: Buffer,
  extensions: Buffer[],
) =>
  sequence(
    der(0xa0, der(2, Buffer.from([2]))),
    der(2, Buffer.from([1])),
    algorithm,
    issuer,
    dates,
    subject,
    spki(key),
    der(0xa3, sequence(...extensions)),
  );
// Only ASCII object keys, strings and safe integers occur in the log fixture.
const canonical = (value: unknown): string => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object")
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`)
      .join(",")}}`;
  return JSON.stringify(value);
};

// RFC3161 TimeStampResp containing CMS SignedData. All keys stay in this local
// test helper; consumers receive only signed tokens and public certificates.
function syntheticTimestamps(signature: Buffer) {
  const ca = ec(),
    signer = ec();
  const caName = name("TEST ONLY timestamp CA");
  const dates = validity("100101000000Z", "400101000000Z");
  const caCertificate = signedCertificate(
    tbs(caName, caName, ca.publicKey, dates, [
      extension([2, 5, 29, 19], sequence(der(1, Buffer.from([255]))), true),
    ]),
    ca.privateKey,
  );
  const signerCertificate = signedCertificate(
    tbs(caName, name("TEST ONLY timestamp signer"), signer.publicKey, dates, [
      extension([2, 5, 29, 19], sequence()),
      extension([2, 5, 29, 15], der(3, Buffer.from([7, 128])), true),
      extension([2, 5, 29, 37], sequence(oid(1, 3, 6, 1, 5, 5, 7, 3, 8)), true),
    ]),
    ca.privateKey,
  );
  const digestAlgorithm = sequence(oid(2, 16, 840, 1, 101, 3, 4, 2, 1));
  const tstOid = oid(1, 2, 840, 113549, 1, 9, 16, 1, 4);
  const token = (data: Buffer, genTime: string) => {
    const info = sequence(
      der(2, Buffer.from([1])),
      oid(1, 3, 6, 1, 4, 1, 57264, 999),
      sequence(digestAlgorithm, der(4, hash(data))),
      der(2, Buffer.from([1])),
      der(24, Buffer.from(genTime)),
    );
    const attributes = [
      sequence(oid(1, 2, 840, 113549, 1, 9, 3), der(0x31, tstOid)),
      sequence(oid(1, 2, 840, 113549, 1, 9, 4), der(0x31, der(4, hash(info)))),
      // ESS SigningCertificateV2 binds the TSA signer certificate (SHA-256 default).
      sequence(
        oid(1, 2, 840, 113549, 1, 9, 16, 2, 47),
        der(0x31, sequence(sequence(sequence(der(4, hash(signerCertificate)))))),
      ),
    ].sort(Buffer.compare);
    const signerInfo = sequence(
      der(2, Buffer.from([1])),
      sequence(caName, der(2, Buffer.from([1]))),
      digestAlgorithm,
      der(0xa0, ...attributes),
      algorithm,
      der(4, sign("sha256", der(0x31, ...attributes), signer.privateKey)),
    );
    const signedData = sequence(
      der(2, Buffer.from([3])),
      der(0x31, digestAlgorithm),
      sequence(tstOid, der(0xa0, der(4, info))),
      der(0xa0, signerCertificate, caCertificate),
      der(0x31, signerInfo),
    );
    return sequence(
      sequence(der(2, Buffer.from([0]))),
      sequence(oid(1, 2, 840, 113549, 1, 7, 2), der(0xa0, signedData)),
    );
  };
  return {
    signedTimestamp: b64(token(signature, "20200601000000Z")),
    wrongImprintTimestamp: b64(token(Buffer.alloc(signature.length), "20200601000000Z")),
    outsideLeafValidityTimestamp: b64(token(signature, "20220601000000Z")),
    authority: {
      uri: "https://tsa.test.invalid",
      certChain: {
        certificates: [{ rawBytes: b64(signerCertificate) }, { rawBytes: b64(caCertificate) }],
      },
      validFor: { start: "2010-01-01T00:00:00Z", end: "2040-01-01T00:00:00Z" },
    },
  };
}

export async function syntheticKeyless(version: "0.0.1" | "0.0.2" = "0.0.1") {
  const ca = ec(),
    leaf = ec(),
    ct = ec(),
    rekor = ec();
  const caName = name("TEST ONLY ephemeral CA");
  const caCertificate = signedCertificate(
    tbs(caName, caName, ca.publicKey, validity("100101000000Z", "400101000000Z"), [
      extension([2, 5, 29, 19], sequence(der(1, Buffer.from([255]))), true),
    ]),
    ca.privateKey,
  );
  const san = "https://test.invalid/workflows/test.v1+literal@refs/heads/test";
  const issuer = "https://issuer.test.invalid";
  const requiredOid = [1, 3, 6, 1, 4, 1, 57264, 1, 15];
  const leafExtensions = [
    extension([2, 5, 29, 17], sequence(der(0x86, Buffer.from(san)))),
    extension([1, 3, 6, 1, 4, 1, 57264, 1, 8], utf8Der(issuer)),
    extension(requiredOid, utf8Der("TEST-ONLY-repository")),
  ];
  const leafTbs = (extensions: Buffer[]) =>
    tbs(
      caName,
      name("TEST ONLY leaf"),
      leaf.publicKey,
      validity("200101000000Z", "210101000000Z"),
      extensions,
    );
  const witnessed = Date.parse("2020-06-01T00:00:00Z");
  const beforeSct = leafTbs(leafExtensions);
  const precert = concat(hash(spki(ca.publicKey)), uint(beforeSct.length, 3), beforeSct);
  const sctData = concat(Buffer.from([0, 0]), uint(witnessed, 8), uint(1, 2), precert, uint(0, 2));
  const sctSignature = sign("sha256", sctData, ct.privateKey);
  const sct = concat(
    Buffer.from([0]),
    hash(spki(ct.publicKey)),
    uint(witnessed, 8),
    uint(0, 2),
    Buffer.from([4, 3]),
    uint(sctSignature.length, 2),
    sctSignature,
  );
  const sctList = concat(uint(sct.length + 2, 2), uint(sct.length, 2), sct);
  const certificate = signedCertificate(
    leafTbs([...leafExtensions, extension([1, 3, 6, 1, 4, 1, 11129, 2, 4, 2], der(4, sctList))]),
    ca.privateKey,
  );

  const annex = Buffer.from("TEST ONLY nonempty local certificate annex\n");
  const report = emptyReport();
  report.annexes = [
    {
      id: "annex.test_only",
      mediaType: "text/plain",
      byteLength: annex.length,
      sha256: hash(annex).toString("hex"),
    },
  ];
  const prepared = await prepareArtifact({
    report,
    annexes: [{ id: "annex.test_only", bytes: annex }],
  });
  // Deliberately retain ordinary statement ordering and whitespace, not C(statement).
  const payload = Buffer.from(JSON.stringify(prepared.statement, null, 2));
  const payloadType = "application/vnd.in-toto+json";
  const pae = concat(
    Buffer.from(`DSSEv1 ${Buffer.byteLength(payloadType)} ${payloadType} ${payload.length} `),
    payload,
  );
  const signature = sign("sha256", pae, leaf.privateKey);
  const body = Buffer.from(
    canonical({
      apiVersion: version,
      kind: "dsse",
      spec:
        version === "0.0.1"
          ? {
              payloadHash: { algorithm: "sha256", value: hash(payload).toString("hex") },
              signatures: [{ signature: b64(signature), verifier: b64(certificate) }],
            }
          : {
              dsseV002: {
                payloadHash: { algorithm: "SHA2_256", digest: b64(hash(payload)) },
                signatures: [
                  {
                    content: b64(signature),
                    verifier: {
                      keyDetails: "PKIX_ECDSA_P256_SHA_256",
                      x509Certificate: { rawBytes: b64(certificate) },
                    },
                  },
                ],
              },
            },
    }),
  );
  const logId = hash(spki(rekor.publicKey));
  const set = Buffer.from(
    canonical({
      body: b64(body),
      integratedTime: witnessed / 1000,
      logIndex: 0,
      logID: logId.toString("hex"),
    }),
  );
  const rootHash = hash(concat(Buffer.from([0]), body));
  const note = `rekor.test.invalid\n1\n${b64(rootHash)}\n`;
  const checkpoint = `${note}\n— rekor.test.invalid ${b64(
    concat(logId.subarray(0, 4), sign("sha256", Buffer.from(note), rekor.privateKey)),
  )}\n`;
  const bundle: SigstoreBundle = {
    mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
    verificationMaterial: {
      certificate: { rawBytes: b64(certificate) },
      tlogEntries: [
        {
          logIndex: "0",
          logId: { keyId: b64(logId) },
          kindVersion: { kind: "dsse", version },
          ...(version === "0.0.1"
            ? {
                integratedTime: String(witnessed / 1000),
                inclusionPromise: {
                  signedEntryTimestamp: b64(sign("sha256", set, rekor.privateKey)),
                },
              }
            : {}),
          canonicalizedBody: b64(body),
          inclusionProof: {
            logIndex: "0",
            treeSize: "1",
            rootHash: b64(rootHash),
            hashes: [],
            checkpoint: { envelope: checkpoint },
          },
        },
      ],
    },
    dsseEnvelope: { payloadType, payload: b64(payload), signatures: [{ sig: b64(signature) }] },
  };
  const validFor = { start: "2010-01-01T00:00:00Z", end: "2040-01-01T00:00:00Z" };
  const log = (key: KeyObject, baseUrl: string) => ({
    baseUrl,
    hashAlgorithm: "SHA2_256",
    publicKey: { rawBytes: b64(spki(key)), keyDetails: "PKIX_ECDSA_P256_SHA_256", validFor },
    logId: { keyId: b64(hash(spki(key))) },
  });
  const publisher: VerificationPublisher = {
    profile: "sigstore-public",
    identity: "TEST-ONLY-local-publisher",
    purposes: ["scan-report"],
    trustedRoot: {
      mediaType: "application/vnd.dev.sigstore.trustedroot.v0.2+json",
      certificateAuthorities: [
        {
          uri: "https://ca.test.invalid",
          certChain: { certificates: [{ rawBytes: b64(caCertificate) }] },
          validFor,
        },
      ],
      ctlogs: [log(ct.publicKey, "https://ct.test.invalid")],
      tlogs: [log(rekor.publicKey, "https://rekor.test.invalid")],
      timestampAuthorities: [],
    },
    policy: {
      issuer,
      subjectAlternativeName: san,
      requiredCertificateExtensions: [
        { oid: requiredOid, valueDerBase64: b64(utf8Der("TEST-ONLY-repository")) },
      ],
    },
  };
  const timestamps = version === "0.0.2" ? syntheticTimestamps(signature) : undefined;
  if (timestamps) {
    bundle.verificationMaterial.timestampVerificationData = {
      rfc3161Timestamps: [{ signedTimestamp: timestamps.signedTimestamp }],
    };
    publisher.trustedRoot.timestampAuthorities = [timestamps.authority];
  }
  const attached = await attachAttestation({ bytes: prepared.bytes, bundle });
  return { prepared, attached, bundle, publisher, certificate, payload, timestamps };
}
