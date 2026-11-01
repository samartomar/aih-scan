// TEST ONLY. A private, offline Sigstore-like universe (Fulcio-style P-384 CA chain, P-256
// CT log, Rekor v1 P-256 log, Rekor v2 Ed25519 log, P-384 timestamp authority) used to build
// `aih-sigstore-keyless/1` evidence for host, CLI and browser-realm tests. Its keys and roots
// are never production trust. This module encodes fixtures; it never verifies anything.
import { createHash, generateKeyPairSync, type KeyObject, sign } from "node:crypto";

const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest();
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64");
const concat = (...parts: Uint8Array[]) => Buffer.concat(parts);
const uint = (value: number | bigint, width: number) => {
  const out = Buffer.alloc(width);
  let rest = BigInt(value);
  for (let index = width - 1; index >= 0; index -= 1) {
    out[index] = Number(rest & 255n);
    rest >>= 8n;
  }
  return out;
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
const seq = (...content: Uint8Array[]) => der(0x30, ...content);
const set = (...content: Uint8Array[]) => der(0x31, ...content);
const utf8String = (value: string) => der(0x0c, Buffer.from(value));
const integer = (value: number) => der(2, value < 128 ? Buffer.from([value]) : uint(value, 4));
const oid = (dotted: string) => {
  const arcs = dotted.split(".").map(Number);
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
const extension = (id: string, value: Uint8Array, critical = false) =>
  seq(oid(id), ...(critical ? [der(1, Buffer.from([255]))] : []), der(4, value));
const name = (common: string) => seq(set(seq(oid("2.5.4.3"), utf8String(common))));
const utcTime = (ms: number) => {
  const iso = new Date(ms).toISOString();
  return der(
    0x17,
    Buffer.from(
      `${iso.slice(2, 4)}${iso.slice(5, 7)}${iso.slice(8, 10)}${iso.slice(11, 13)}${iso.slice(14, 16)}${iso.slice(17, 19)}Z`,
    ),
  );
};
const generalizedTime = (ms: number) => {
  const iso = new Date(ms).toISOString();
  return der(
    0x18,
    Buffer.from(
      `${iso.slice(0, 4)}${iso.slice(5, 7)}${iso.slice(8, 10)}${iso.slice(11, 13)}${iso.slice(14, 16)}${iso.slice(17, 19)}Z`,
    ),
  );
};

const ECDSA_SHA256 = "1.2.840.10045.4.3.2";
const ECDSA_SHA384 = "1.2.840.10045.4.3.3";
type Ec = { publicKey: KeyObject; privateKey: KeyObject };
export const p256 = (): Ec => generateKeyPairSync("ec", { namedCurve: "prime256v1" });
export const p384 = (): Ec => generateKeyPairSync("ec", { namedCurve: "secp384r1" });
const ed25519 = (): Ec => generateKeyPairSync("ed25519");
export const spkiOf = (key: KeyObject) => key.export({ type: "spki", format: "der" });
const hashOfKey = (key: KeyObject) =>
  key.asymmetricKeyDetails?.namedCurve === "secp384r1" ? "sha384" : "sha256";
const algorithmOf = (key: KeyObject) =>
  seq(oid(hashOfKey(key) === "sha384" ? ECDSA_SHA384 : ECDSA_SHA256));

function certificate(options: {
  issuer: Buffer;
  subject: Buffer;
  publicKey: Buffer;
  signer: KeyObject;
  notBefore: number;
  notAfter: number;
  extensions: Buffer[];
  serial?: number;
}): { tbs: Buffer; raw: Buffer } {
  const algorithm = algorithmOf(options.signer);
  const tbs = seq(
    der(0xa0, integer(2)),
    integer(options.serial ?? 1),
    algorithm,
    options.issuer,
    seq(utcTime(options.notBefore), utcTime(options.notAfter)),
    options.subject,
    options.publicKey,
    der(0xa3, seq(...options.extensions)),
  );
  const raw = seq(
    tbs,
    algorithm,
    der(3, Buffer.from([0]), sign(hashOfKey(options.signer), tbs, options.signer)),
  );
  return { tbs, raw };
}

const caExtensions = (pathLength: number) => [
  extension("2.5.29.19", seq(der(1, Buffer.from([255])), integer(pathLength)), true),
  extension("2.5.29.15", der(3, Buffer.from([1, 0x06])), true),
];

const canonical = (value: unknown): string => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object")
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`)
      .join(",")}}`;
  return JSON.stringify(value);
};

const pem = (raw: Uint8Array) =>
  `-----BEGIN CERTIFICATE-----\n${b64(raw)
    .match(/.{1,64}/g)!
    .join("\n")}\n-----END CERTIFICATE-----\n`;

export const TEST_ISSUER = "https://issuer.test.invalid";
export const signerA = {
  issuer: TEST_ISSUER,
  subject: "https://test.invalid/signer-a@refs/heads/main",
};
export const signerB = {
  issuer: TEST_ISSUER,
  subject: "https://test.invalid/signer-b@refs/heads/main",
};
export const REPOSITORY_OID = "1.3.6.1.4.1.57264.1.15";

const VALID_FOR = { start: "2020-01-01T00:00:00Z", end: "2030-01-01T00:00:00Z" };
export const LEAF_NOT_BEFORE = Date.parse("2025-06-01T00:00:00Z");
export const LEAF_NOT_AFTER = Date.parse("2025-06-01T00:10:00Z");
export const SIGNED_AT = Date.parse("2025-06-01T00:05:00Z");

export interface LeafOptions {
  readonly issuer?: string;
  readonly subject?: string;
  readonly repository?: string;
  readonly notBefore?: number;
  readonly notAfter?: number;
  /** Omit the embedded SCT. */
  readonly noSct?: boolean;
  /** Sign the SCT with another key while naming the selected CT log. */
  readonly sctKey?: KeyObject;
  /** Issue under another (unselected) CA. */
  readonly ca?: Ec;
  readonly codeSigning?: boolean;
}

export interface LogOptions {
  readonly integratedTime?: number;
  /** Sign the SET over different content. */
  readonly badSet?: boolean;
  /** Break the inclusion proof. */
  readonly badProof?: boolean;
  /** Sign the checkpoint with another key. */
  readonly badCheckpoint?: boolean;
  /** Omit the inclusion proof. */
  readonly noProof?: boolean;
  /** Omit the SET (as Rekor v2). */
  readonly noSet?: boolean;
}

export type Universe = ReturnType<typeof universe>;

/** Creates a fresh universe of ephemeral keys. */
export function universe() {
  const fulcioRoot = p384();
  const fulcioIntermediate = p384();
  const ct = p256();
  const rekor = p256();
  const rekorV2 = ed25519();
  const tsaRoot = p384();
  const tsaSigner = p384();
  const otherCa = p384();

  const rootName = name("TEST ONLY fulcio root");
  const intermediateName = name("TEST ONLY fulcio intermediate");
  const caStart = Date.parse("2020-01-01T00:00:00Z");
  const caEnd = Date.parse("2030-01-01T00:00:00Z");
  const rootCertificate = certificate({
    issuer: rootName,
    subject: rootName,
    publicKey: spkiOf(fulcioRoot.publicKey),
    signer: fulcioRoot.privateKey,
    notBefore: caStart,
    notAfter: caEnd,
    extensions: caExtensions(1),
  }).raw;
  const intermediateCertificate = certificate({
    issuer: rootName,
    subject: intermediateName,
    publicKey: spkiOf(fulcioIntermediate.publicKey),
    signer: fulcioRoot.privateKey,
    notBefore: caStart,
    notAfter: caEnd,
    extensions: caExtensions(0),
    serial: 2,
  }).raw;
  const otherName = name("TEST ONLY unselected CA");
  const otherCertificate = certificate({
    issuer: otherName,
    subject: otherName,
    publicKey: spkiOf(otherCa.publicKey),
    signer: otherCa.privateKey,
    notBefore: caStart,
    notAfter: caEnd,
    extensions: caExtensions(1),
  }).raw;

  const tsaRootName = name("TEST ONLY timestamp root");
  const tsaRootCertificate = certificate({
    issuer: tsaRootName,
    subject: tsaRootName,
    publicKey: spkiOf(tsaRoot.publicKey),
    signer: tsaRoot.privateKey,
    notBefore: caStart,
    notAfter: caEnd,
    extensions: caExtensions(0),
  }).raw;
  const tsaSignerCertificate = certificate({
    issuer: tsaRootName,
    subject: name("TEST ONLY timestamp signer"),
    publicKey: spkiOf(tsaSigner.publicKey),
    signer: tsaRoot.privateKey,
    notBefore: caStart,
    notAfter: caEnd,
    serial: 7,
    extensions: [
      extension("2.5.29.19", seq()),
      extension("2.5.29.15", der(3, Buffer.from([7, 0x80])), true),
      extension("2.5.29.37", seq(oid("1.3.6.1.5.5.7.3.8")), true),
    ],
  }).raw;

  /** Issues a Fulcio-style leaf for `publicKey` (SPKI DER) with an embedded SCT. */
  function issueLeaf(publicKey: Buffer, options: LeafOptions = {}): Buffer {
    const ca = options.ca ?? fulcioIntermediate;
    const caName = options.ca === undefined ? intermediateName : otherName;
    const extensions = [
      extension("2.5.29.15", der(3, Buffer.from([7, 0x80])), true),
      extension(
        "2.5.29.37",
        seq(oid(options.codeSigning === false ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.3")),
      ),
      extension("2.5.29.17", seq(der(0x86, Buffer.from(options.subject ?? signerA.subject))), true),
      extension("1.3.6.1.4.1.57264.1.8", utf8String(options.issuer ?? signerA.issuer)),
      extension(REPOSITORY_OID, utf8String(options.repository ?? "TEST-ONLY-1")),
    ];
    const notBefore = options.notBefore ?? LEAF_NOT_BEFORE;
    const notAfter = options.notAfter ?? LEAF_NOT_AFTER;
    const base = {
      issuer: caName,
      subject: seq(),
      publicKey,
      signer: ca.privateKey,
      notBefore,
      notAfter,
      serial: 9,
    };
    if (options.noSct) return certificate({ ...base, extensions }).raw;
    const precert = certificate({ ...base, extensions }).tbs;
    const caKey = options.ca === undefined ? fulcioIntermediate.publicKey : options.ca.publicKey;
    const time = notBefore;
    const signed = concat(
      Buffer.from([0, 0]),
      uint(time, 8),
      uint(1, 2),
      sha256(spkiOf(caKey)),
      uint(precert.length, 3),
      precert,
      uint(0, 2),
    );
    const signature = sign("sha256", signed, options.sctKey ?? ct.privateKey);
    const sct = concat(
      Buffer.from([0]),
      sha256(spkiOf(ct.publicKey)),
      uint(time, 8),
      uint(0, 2),
      Buffer.from([4, 3]),
      uint(signature.length, 2),
      signature,
    );
    const list = concat(uint(sct.length + 2, 2), uint(sct.length, 2), sct);
    return certificate({
      ...base,
      extensions: [...extensions, extension("1.3.6.1.4.1.11129.2.4.2", der(4, list))],
    }).raw;
  }

  const leafHash = (body: Uint8Array) => sha256(concat(Buffer.from([0]), body));
  const nodeHash = (left: Uint8Array, right: Uint8Array) =>
    sha256(concat(Buffer.from([1]), left, right));

  function proofFor(
    body: Buffer,
    origin: string,
    key: KeyObject,
    logId: Buffer,
    options: LogOptions,
  ) {
    // Tree of three leaves; the entry is leaf 1.
    const before = leafHash(Buffer.from("TEST ONLY leaf 0"));
    const after = leafHash(Buffer.from("TEST ONLY leaf 2"));
    const root = nodeHash(nodeHash(before, leafHash(body)), after);
    const note = `${origin}\n3\n${b64(root)}\n`;
    const noteSigner = options.badCheckpoint ? p256().privateKey : key;
    const noteSignature =
      key.asymmetricKeyType === "ed25519" && !options.badCheckpoint
        ? sign(null, Buffer.from(note), noteSigner)
        : sign("sha256", Buffer.from(note), noteSigner);
    return {
      logIndex: "1",
      treeSize: "3",
      rootHash: b64(root),
      hashes: [b64(options.badProof ? sha256(Buffer.from("x")) : before), b64(after)],
      checkpoint: {
        envelope: `${note}\n— ${origin} ${b64(concat(logId.subarray(0, 4), noteSignature))}\n`,
      },
    };
  }

  const rekorLogId = sha256(spkiOf(rekor.publicKey));
  const rekorV2LogId = sha256(spkiOf(rekorV2.publicKey));

  /** A Rekor v1 hashedrekord 0.0.1 entry with SET and inclusion proof. */
  function logV1(body: Buffer, options: LogOptions = {}) {
    const integratedTime = Math.floor((options.integratedTime ?? SIGNED_AT) / 1000);
    const payload = canonical({
      body: b64(options.badSet ? Buffer.from("{}") : body),
      integratedTime,
      logIndex: 1,
      logID: rekorLogId.toString("hex"),
    });
    return {
      logIndex: "1",
      logId: { keyId: b64(rekorLogId) },
      kindVersion: { kind: "hashedrekord", version: "0.0.1" },
      integratedTime: String(integratedTime),
      ...(options.noSet
        ? {}
        : {
            inclusionPromise: {
              signedEntryTimestamp: b64(sign("sha256", Buffer.from(payload), rekor.privateKey)),
            },
          }),
      ...(options.noProof
        ? {}
        : {
            inclusionProof: proofFor(
              body,
              "rekor.test.invalid",
              rekor.privateKey,
              rekorLogId,
              options,
            ),
          }),
      canonicalizedBody: b64(body),
    };
  }

  /** A Rekor v2 hashedrekord 0.0.2 entry: Ed25519 checkpoint, no SET. */
  function logV2(body: Buffer, options: LogOptions = {}) {
    return {
      logIndex: "1",
      logId: { keyId: b64(rekorV2LogId) },
      kindVersion: { kind: "hashedrekord", version: "0.0.2" },
      inclusionProof: proofFor(
        body,
        "rekor-v2.test.invalid",
        rekorV2.privateKey,
        rekorV2LogId,
        options,
      ),
      canonicalizedBody: b64(body),
    };
  }

  /** An RFC 3161 TimeStampResp over `data` (P-384 TSA, SHA-384 CMS signature, SHA-256 imprint). */
  function timestamp(data: Uint8Array, genTime = SIGNED_AT): Buffer {
    const tstOid = oid("1.2.840.113549.1.9.16.1.4");
    const sha256Algorithm = seq(oid("2.16.840.1.101.3.4.2.1"));
    const sha384Algorithm = seq(oid("2.16.840.1.101.3.4.2.2"));
    const info = seq(
      integer(1),
      oid("1.3.6.1.4.1.57264.999"),
      seq(sha256Algorithm, der(4, sha256(data))),
      integer(5),
      generalizedTime(genTime),
    );
    const attributes = [
      seq(oid("1.2.840.113549.1.9.3"), set(tstOid)),
      seq(oid("1.2.840.113549.1.9.4"), set(der(4, createHash("sha384").update(info).digest()))),
    ].sort(Buffer.compare);
    const signerInfo = seq(
      integer(1),
      seq(tsaRootName, integer(7)),
      sha384Algorithm,
      der(0xa0, ...attributes),
      seq(oid(ECDSA_SHA384)),
      der(4, sign("sha384", set(...attributes), tsaSigner.privateKey)),
    );
    const signedData = seq(
      integer(3),
      set(sha384Algorithm),
      seq(tstOid, der(0xa0, der(4, info))),
      der(0xa0, tsaSignerCertificate, tsaRootCertificate),
      set(signerInfo),
    );
    return seq(seq(integer(0)), seq(oid("1.2.840.113549.1.7.2"), der(0xa0, signedData)));
  }

  const log = (
    key: KeyObject,
    baseUrl: string,
    details: string,
    validFor: object = VALID_FOR,
    logIdKey = key,
  ) => ({
    baseUrl,
    hashAlgorithm: "SHA2_256",
    publicKey: { rawBytes: b64(spkiOf(key)), keyDetails: details, validFor },
    logId: { keyId: b64(sha256(spkiOf(logIdKey))) },
  });

  /** The universe's trusted root, with optional substitutions for negative cases. */
  function trustedRoot(
    options: {
      caValidFor?: object;
      ctKey?: KeyObject;
      rekorKey?: KeyObject;
      noTsa?: boolean;
      cas?: unknown[];
      ctlogs?: unknown[];
      tlogs?: unknown[];
    } = {},
  ) {
    return {
      mediaType: "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
      tlogs: options.tlogs ?? [
        log(
          options.rekorKey ?? rekor.publicKey,
          "https://rekor.test.invalid",
          "PKIX_ECDSA_P256_SHA_256",
          VALID_FOR,
          rekor.publicKey,
        ),
        log(rekorV2.publicKey, "https://rekor-v2.test.invalid", "PKIX_ED25519"),
      ],
      certificateAuthorities: options.cas ?? [
        {
          subject: { commonName: "TEST ONLY fulcio" },
          uri: "https://fulcio.test.invalid",
          certChain: {
            certificates: [
              { rawBytes: b64(intermediateCertificate) },
              { rawBytes: b64(rootCertificate) },
            ],
          },
          validFor: options.caValidFor ?? VALID_FOR,
        },
      ],
      ctlogs: options.ctlogs ?? [
        log(
          options.ctKey ?? ct.publicKey,
          "https://ct.test.invalid",
          "PKIX_ECDSA_P256_SHA_256",
          VALID_FOR,
          ct.publicKey,
        ),
      ],
      timestampAuthorities: options.noTsa
        ? []
        : [
            {
              subject: { commonName: "TEST ONLY timestamp" },
              uri: "https://tsa.test.invalid",
              certChain: {
                certificates: [
                  { rawBytes: b64(tsaSignerCertificate) },
                  { rawBytes: b64(tsaRootCertificate) },
                ],
              },
              validFor: VALID_FOR,
            },
          ],
    };
  }

  /** The hashedrekord body Rekor v1 records. */
  const bodyV1 = (digest: Uint8Array, signature: Uint8Array, certificateDer: Uint8Array) =>
    Buffer.from(
      canonical({
        apiVersion: "0.0.1",
        kind: "hashedrekord",
        spec: {
          data: { hash: { algorithm: "sha256", value: Buffer.from(digest).toString("hex") } },
          signature: {
            content: b64(signature),
            publicKey: { content: b64(Buffer.from(pem(certificateDer))) },
          },
        },
      }),
    );
  const bodyV2 = (digest: Uint8Array, signature: Uint8Array, certificateDer: Uint8Array) =>
    Buffer.from(
      canonical({
        apiVersion: "0.0.2",
        kind: "hashedrekord",
        spec: {
          hashedRekordV002: {
            data: { algorithm: "SHA2_256", digest: b64(digest) },
            signature: {
              content: b64(signature),
              verifier: {
                keyDetails: "PKIX_ECDSA_P256_SHA_256",
                x509Certificate: { rawBytes: b64(certificateDer) },
              },
            },
          },
        },
      }),
    );

  return {
    issueLeaf,
    logV1,
    logV2,
    timestamp,
    trustedRoot,
    bodyV1,
    bodyV2,
    pem,
    keys: { ct, rekor, rekorV2, otherCa },
    otherCaCertificate: otherCertificate,
  };
}

export interface SignOptions {
  readonly rekor?: "v1" | "v2" | "v1+tsa";
  readonly leaf?: LeafOptions;
  readonly log?: LogOptions;
  /** Record a log body for other bytes/certificate/signature. */
  readonly body?: "other-digest" | "other-certificate" | "other-signature";
  readonly timestampFor?: "other-data";
  readonly genTime?: number;
  readonly key?: Ec;
}

/** Signs `bytes` as `aih-scan sign` would and returns the v0.3 messageSignature bundle. */
export function signedBundle(world: Universe, bytes: Uint8Array, options: SignOptions = {}) {
  const key = options.key ?? p256();
  const certificateDer = world.issueLeaf(spkiOf(key.publicKey), options.leaf);
  const signature = sign("sha256", bytes, key.privateKey);
  const digest = sha256(bytes);
  const bodyDigest = options.body === "other-digest" ? sha256(Buffer.from("other")) : digest;
  const bodySignature =
    options.body === "other-signature"
      ? sign("sha256", Buffer.from("other"), key.privateKey)
      : signature;
  const bodyCertificate =
    options.body === "other-certificate"
      ? world.issueLeaf(spkiOf(p256().publicKey), options.leaf)
      : certificateDer;
  const mode = options.rekor ?? "v1";
  const entry =
    mode === "v2"
      ? world.logV2(world.bodyV2(bodyDigest, bodySignature, bodyCertificate), options.log)
      : world.logV1(world.bodyV1(bodyDigest, bodySignature, bodyCertificate), options.log);
  const stamped = mode === "v2" || mode === "v1+tsa";
  return {
    mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
    verificationMaterial: {
      certificate: { rawBytes: b64(certificateDer) },
      tlogEntries: [entry],
      ...(stamped
        ? {
            timestampVerificationData: {
              rfc3161Timestamps: [
                {
                  signedTimestamp: b64(
                    world.timestamp(
                      options.timestampFor === "other-data"
                        ? Buffer.alloc(signature.length)
                        : signature,
                      options.genTime,
                    ),
                  ),
                },
              ],
            },
          }
        : {}),
    },
    messageSignature: {
      messageDigest: { algorithm: "SHA2_256", digest: b64(digest) },
      signature: b64(signature),
    },
  };
}
