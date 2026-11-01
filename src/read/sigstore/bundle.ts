/**
 * Reads a Sigstore bundle under the `aih-sigstore-keyless/1` profile: media type
 * `application/vnd.dev.sigstore.bundle.v0.3+json`, an X.509 `certificate` and a
 * `messageSignature` with a SHA2_256 digest. Every other evidence form is refused explicitly.
 */
import { base64Decode, utf8Text } from "./bytes.js";

export const BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json";
const BUNDLE_FAMILY =
  /^application\/vnd\.dev\.sigstore\.bundle(?:\+json;version=\d+\.\d+|\.v\d+\.\d+\+json)$/;

export interface InclusionProof {
  readonly logIndex: bigint;
  readonly treeSize: bigint;
  readonly rootHash: Uint8Array;
  readonly hashes: readonly Uint8Array[];
  readonly checkpoint: string;
}

export interface TlogEntry {
  readonly logIndex: bigint;
  readonly logId: Uint8Array;
  readonly kind: string;
  readonly version: string;
  readonly integratedTime: bigint | undefined;
  readonly signedEntryTimestamp: Uint8Array | undefined;
  readonly body: Uint8Array;
  readonly proof: InclusionProof | undefined;
}

export interface KeylessBundle {
  readonly certificate: Uint8Array;
  readonly digest: Uint8Array;
  readonly signature: Uint8Array;
  readonly tlogEntries: readonly TlogEntry[];
  readonly timestamps: readonly Uint8Array[];
}

export class BundleProblem extends Error {
  constructor(
    readonly status: "invalid" | "refused" | "unsupported-version",
    readonly reason: string,
    detail: string,
  ) {
    super(detail);
  }
}

const invalid = (detail: string): never => {
  throw new BundleProblem("invalid", "bundle", detail);
};
const unsupportedProfile = (detail: string): never => {
  throw new BundleProblem("refused", "unsupported-profile", detail);
};

const MAX_ENTRIES = 8;
const MAX_HASHES = 64;

const objectOf = (value: unknown, label: string): Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : invalid(`${label} must be an object`);

const bytesOf = (value: unknown, label: string, max = 1024 * 1024): Uint8Array =>
  base64Decode(value, max) ?? invalid(`${label} must be base64`);

function int64(value: unknown, label: string): bigint {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === "string" && /^(0|[1-9]\d{0,18})$/.test(value)) return BigInt(value);
  return invalid(`${label} must be a non-negative integer`);
}

function arrayOf(value: unknown, label: string, max: number): unknown[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > max)
    return invalid(`${label} must be an array of at most ${max}`);
  return value;
}

function entryOf(value: unknown, index: number): TlogEntry {
  const label = `tlogEntries[${index}]`;
  const entry = objectOf(value, label);
  const kindVersion = objectOf(entry.kindVersion, `${label}.kindVersion`);
  if (typeof kindVersion.kind !== "string" || typeof kindVersion.version !== "string")
    invalid(`${label}.kindVersion`);
  const promise =
    entry.inclusionPromise === undefined
      ? undefined
      : objectOf(entry.inclusionPromise, `${label}.inclusionPromise`);
  let proof: InclusionProof | undefined;
  if (entry.inclusionProof !== undefined) {
    const raw = objectOf(entry.inclusionProof, `${label}.inclusionProof`);
    const checkpoint = objectOf(raw.checkpoint, `${label}.inclusionProof.checkpoint`).envelope;
    if (typeof checkpoint !== "string" || checkpoint.length > 64 * 1024)
      invalid(`${label} checkpoint`);
    proof = Object.freeze({
      logIndex: int64(raw.logIndex, `${label}.inclusionProof.logIndex`),
      treeSize: int64(raw.treeSize, `${label}.inclusionProof.treeSize`),
      rootHash: bytesOf(raw.rootHash, `${label}.inclusionProof.rootHash`),
      hashes: Object.freeze(
        arrayOf(raw.hashes, `${label}.inclusionProof.hashes`, MAX_HASHES).map((hash, position) =>
          bytesOf(hash, `${label}.inclusionProof.hashes[${position}]`),
        ),
      ),
      checkpoint: checkpoint as string,
    });
  }
  return Object.freeze({
    logIndex: int64(entry.logIndex, `${label}.logIndex`),
    logId: bytesOf(objectOf(entry.logId, `${label}.logId`).keyId, `${label}.logId.keyId`),
    kind: kindVersion.kind as string,
    version: kindVersion.version as string,
    integratedTime:
      entry.integratedTime === undefined
        ? undefined
        : int64(entry.integratedTime, `${label}.integratedTime`),
    signedEntryTimestamp:
      promise === undefined
        ? undefined
        : bytesOf(promise.signedEntryTimestamp, `${label}.signedEntryTimestamp`),
    body: bytesOf(entry.canonicalizedBody, `${label}.canonicalizedBody`, 4 * 1024 * 1024),
    proof,
  });
}

/** Parses bundle JSON bytes or an already-parsed bundle object. Throws `BundleProblem` only. */
export function parseBundle(value: unknown): KeylessBundle {
  let document = value;
  if (value instanceof Uint8Array || (ArrayBuffer.isView(value) && !(value instanceof DataView))) {
    const bytes = value as Uint8Array;
    if (bytes.length > 8 * 1024 * 1024) invalid("the bundle is too large");
    const text = utf8Text(bytes);
    if (text === undefined) return invalid("the bundle is not UTF-8 JSON");
    try {
      document = JSON.parse(text);
    } catch {
      return invalid("the bundle is not JSON");
    }
  }
  const bundle = objectOf(document, "bundle");
  if (bundle.mediaType !== BUNDLE_MEDIA_TYPE) {
    if (typeof bundle.mediaType === "string" && BUNDLE_FAMILY.test(bundle.mediaType))
      throw new BundleProblem(
        "unsupported-version",
        "unsupported-version",
        `bundle media type ${bundle.mediaType} is not supported; expected ${BUNDLE_MEDIA_TYPE}`,
      );
    invalid("bundle.mediaType is not a Sigstore bundle media type");
  }
  const material = objectOf(bundle.verificationMaterial, "bundle.verificationMaterial");
  if (bundle.dsseEnvelope !== undefined)
    unsupportedProfile("DSSE attestations are not accepted by aih-sigstore-keyless/1");
  if (material.publicKey !== undefined)
    unsupportedProfile("bare public-key signatures are not accepted by aih-sigstore-keyless/1");
  if (material.x509CertificateChain !== undefined || material.certificate === undefined)
    unsupportedProfile("aih-sigstore-keyless/1 requires a single X.509 signing certificate");
  if (bundle.messageSignature === undefined)
    unsupportedProfile("aih-sigstore-keyless/1 requires a messageSignature");
  const signature = objectOf(bundle.messageSignature, "bundle.messageSignature");
  const messageDigest = objectOf(signature.messageDigest, "bundle.messageSignature.messageDigest");
  if (messageDigest.algorithm !== "SHA2_256")
    throw new BundleProblem(
      "refused",
      "unsupported-algorithm",
      "aih-sigstore-keyless/1 requires a SHA2_256 message digest",
    );
  const timestamps = material.timestampVerificationData
    ? arrayOf(
        objectOf(material.timestampVerificationData, "timestampVerificationData").rfc3161Timestamps,
        "rfc3161Timestamps",
        MAX_ENTRIES,
      ).map((entry, index) =>
        bytesOf(
          objectOf(entry, "rfc3161 timestamp").signedTimestamp,
          `rfc3161Timestamps[${index}]`,
        ),
      )
    : [];
  return Object.freeze({
    certificate: bytesOf(
      objectOf(material.certificate, "certificate").rawBytes,
      "certificate.rawBytes",
    ),
    digest: bytesOf(messageDigest.digest, "messageDigest.digest"),
    signature: bytesOf(signature.signature, "messageSignature.signature"),
    tlogEntries: Object.freeze(
      arrayOf(material.tlogEntries, "tlogEntries", MAX_ENTRIES).map(entryOf),
    ),
    timestamps: Object.freeze(timestamps),
  });
}
