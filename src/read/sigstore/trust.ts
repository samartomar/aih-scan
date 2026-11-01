/**
 * Reads caller-selected (or the shipped) Sigstore trusted-root material. Malformed trust data
 * is a `TrustProblem` with status `invalid`; well-formed material that leaves no usable CA,
 * certificate-transparency log or transparency log is `trust-data-unavailable`.
 */
import { base64Decode, EvidenceError } from "./bytes.js";
import { type PublicKey, publicKeyOf } from "./crypto.js";
import { type Certificate, parseCertificate } from "./x509.js";

export const TRUSTED_ROOT_MEDIA_TYPES = Object.freeze([
  "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
  "application/vnd.dev.sigstore.trustedroot.v0.2+json",
]);

export interface ValidFor {
  readonly start: number;
  readonly end: number;
}

export interface LogKey {
  readonly baseUrl: string;
  readonly logId: Uint8Array;
  readonly key: PublicKey;
  readonly validFor: ValidFor;
}

export interface CertificateAuthority {
  /** Leaf-first chain as published in the trusted root (CA: intermediate…root; TSA: signer…root). */
  readonly certificates: readonly Certificate[];
  readonly validFor: ValidFor;
}

export interface TrustMaterial {
  readonly certificateAuthorities: readonly CertificateAuthority[];
  readonly tlogs: readonly LogKey[];
  readonly ctlogs: readonly LogKey[];
  readonly timestampAuthorities: readonly CertificateAuthority[];
}

export class TrustProblem extends Error {
  constructor(
    readonly status: "invalid" | "refused",
    readonly reason: string,
    detail: string,
  ) {
    super(detail);
  }
}

const malformed = (detail: string): never => {
  throw new TrustProblem("invalid", "trusted-root", detail);
};

const MAX_ENTRIES = 64;
const MAX_CHAIN = 8;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;

const objectOf = (value: unknown, label: string): Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : malformed(`${label} must be an object`);

function arrayOf(value: unknown, label: string): unknown[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) return malformed(`${label} must be an array`);
  if (value.length > MAX_ENTRIES) return malformed(`${label} has too many entries`);
  return value;
}

function timeOf(value: unknown, label: string): number {
  if (typeof value !== "string" || !RFC3339.test(value))
    return malformed(`${label} must be an RFC 3339 time`);
  const time = Date.parse(value);
  return Number.isFinite(time) ? time : malformed(`${label} must be an RFC 3339 time`);
}

function validForOf(value: unknown, label: string): ValidFor {
  if (value === undefined) return Object.freeze({ start: 0, end: Number.POSITIVE_INFINITY });
  const range = objectOf(value, label);
  // An absent start (allowed by the protobuf schema) means valid from the epoch.
  const start = range.start === undefined ? 0 : timeOf(range.start, `${label}.start`);
  const end =
    range.end === undefined ? Number.POSITIVE_INFINITY : timeOf(range.end, `${label}.end`);
  if (end < start) malformed(`${label} ends before it starts`);
  return Object.freeze({ start, end });
}

function bytesOf(value: unknown, label: string): Uint8Array {
  return base64Decode(value, 1024 * 1024) ?? malformed(`${label} must be base64`);
}

const SUPPORTED_LOG_KEYS = new Set(["PKIX_ECDSA_P256_SHA_256", "PKIX_ED25519"]);

function logKeys(value: unknown, label: string): LogKey[] {
  const out: LogKey[] = [];
  for (const [index, entry] of arrayOf(value, label).entries()) {
    const log = objectOf(entry, `${label}[${index}]`);
    const publicKey = objectOf(log.publicKey, `${label}[${index}].publicKey`);
    const logId = bytesOf(
      objectOf(log.logId, `${label}[${index}].logId`).keyId,
      `${label}[${index}].logId.keyId`,
    );
    if (logId.length !== 32) malformed(`${label}[${index}].logId.keyId must be 32 bytes`);
    const baseUrl =
      typeof log.baseUrl === "string" ? log.baseUrl : malformed(`${label}[${index}].baseUrl`);
    const validFor = validForOf(publicKey.validFor, `${label}[${index}].publicKey.validFor`);
    if (typeof publicKey.keyDetails !== "string")
      malformed(`${label}[${index}].publicKey.keyDetails`);
    const raw = bytesOf(publicKey.rawBytes, `${label}[${index}].publicKey.rawBytes`);
    // Keys of other types cannot be used by this profile; they are not selected.
    if (!SUPPORTED_LOG_KEYS.has(publicKey.keyDetails as string)) continue;
    let key: PublicKey;
    try {
      key = publicKeyOf(raw);
    } catch (error) {
      if (error instanceof EvidenceError && error.reason === "unsupported-algorithm") continue;
      return malformed(`${label}[${index}].publicKey.rawBytes is not a public key`);
    }
    const expected = publicKey.keyDetails === "PKIX_ED25519" ? "ed25519" : "ecdsa-p256";
    if (key.kind !== expected)
      malformed(`${label}[${index}].publicKey does not match its keyDetails`);
    out.push(Object.freeze({ baseUrl, logId, key, validFor }));
  }
  return out;
}

function authorities(value: unknown, label: string): CertificateAuthority[] {
  const out: CertificateAuthority[] = [];
  for (const [index, entry] of arrayOf(value, label).entries()) {
    const authority = objectOf(entry, `${label}[${index}]`);
    const chain = arrayOf(
      objectOf(authority.certChain, `${label}[${index}].certChain`).certificates,
      "certificates",
    );
    if (chain.length === 0 || chain.length > MAX_CHAIN)
      malformed(`${label}[${index}] needs 1-${MAX_CHAIN} certificates`);
    const validFor = validForOf(authority.validFor, `${label}[${index}].validFor`);
    const certificates: Certificate[] = [];
    let usable = true;
    for (const [position, certificate] of chain.entries()) {
      const raw = bytesOf(
        objectOf(certificate, "certificate").rawBytes,
        `${label}[${index}] certificate ${position}`,
      );
      try {
        certificates.push(parseCertificate(raw));
      } catch (error) {
        if (error instanceof EvidenceError && error.reason === "unsupported-algorithm") {
          usable = false;
          continue;
        }
        return malformed(`${label}[${index}] certificate ${position} is not a certificate`);
      }
    }
    if (usable) out.push(Object.freeze({ certificates: Object.freeze(certificates), validFor }));
  }
  return out;
}

/**
 * Parses a trusted root (`TrustedRoot` protobuf JSON). Throws `TrustProblem` only; callers turn
 * it into a returned result.
 */
export function parseTrustedRoot(value: unknown): TrustMaterial {
  const root = objectOf(value, "trustedRoot");
  if (typeof root.mediaType !== "string" || !TRUSTED_ROOT_MEDIA_TYPES.includes(root.mediaType))
    malformed("trustedRoot.mediaType is not a supported Sigstore trusted-root media type");
  const material = Object.freeze({
    certificateAuthorities: Object.freeze(
      authorities(root.certificateAuthorities, "certificateAuthorities"),
    ),
    tlogs: Object.freeze(logKeys(root.tlogs, "tlogs")),
    ctlogs: Object.freeze(logKeys(root.ctlogs, "ctlogs")),
    timestampAuthorities: Object.freeze(
      authorities(root.timestampAuthorities, "timestampAuthorities"),
    ),
  });
  if (
    material.certificateAuthorities.length === 0 ||
    material.tlogs.length === 0 ||
    material.ctlogs.length === 0
  )
    throw new TrustProblem(
      "refused",
      "trust-data-unavailable",
      "the selected trust material has no usable certificate authority, transparency log or certificate-transparency log",
    );
  return material;
}

export const covers = (range: ValidFor, time: number) => range.start <= time && time <= range.end;
