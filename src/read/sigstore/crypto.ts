/**
 * WebCrypto primitives for the `aih-sigstore-keyless/1` profile. Exactly these combinations are
 * supported (published in `/contracts` as `verification.algorithms`): ECDSA on P-256 or P-384
 * with SHA-256, SHA-384 or SHA-512 as the evidence names it, and Ed25519. The signing key of the
 * signed bytes is further restricted to P-256 with SHA-256 by the profile. Anything else is
 * refused as an unsupported algorithm.
 */
import { EvidenceError, fail } from "./bytes.js";
import { bitStringBytes, expectTag, integerBytes, oidOf, parseDer, TAG } from "./der.js";

export type HashName = "SHA-256" | "SHA-384" | "SHA-512";
export type KeyKind = "ecdsa-p256" | "ecdsa-p384" | "ed25519";

export interface PublicKey {
  readonly kind: KeyKind;
  readonly spki: Uint8Array;
}

const OID = Object.freeze({
  ecPublicKey: "1.2.840.10045.2.1",
  p256: "1.2.840.10045.3.1.7",
  p384: "1.3.132.0.34",
  ed25519: "1.3.101.112",
  sha256: "2.16.840.1.101.3.4.2.1",
  sha384: "2.16.840.1.101.3.4.2.2",
  sha512: "2.16.840.1.101.3.4.2.3",
  ecdsaSha256: "1.2.840.10045.4.3.2",
  ecdsaSha384: "1.2.840.10045.4.3.3",
  ecdsaSha512: "1.2.840.10045.4.3.4",
});

const unsupported = (detail: string): never => {
  throw new EvidenceError("unsupported-algorithm", detail);
};

const subtle = (): SubtleCrypto => {
  const value = (globalThis as { crypto?: Crypto }).crypto?.subtle;
  if (value === undefined) throw new TypeError("WebCrypto is unavailable");
  return value;
};

const view = (bytes: Uint8Array) => bytes as Uint8Array<ArrayBuffer>;

export async function digest(name: HashName, bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle().digest(name, view(bytes)));
}

export const sha256 = (bytes: Uint8Array) => digest("SHA-256", bytes);

/** Hash named by a digest-algorithm OID (sha256/384/512), or undefined. */
export function hashOfOid(oid: string): HashName | undefined {
  if (oid === OID.sha256) return "SHA-256";
  if (oid === OID.sha384) return "SHA-384";
  if (oid === OID.sha512) return "SHA-512";
  return undefined;
}

/** Hash of an ECDSA signature-algorithm OID, or undefined. */
export const ecPublicKeyOid = OID.ecPublicKey;

export function ecdsaHashOfOid(oid: string): HashName | undefined {
  if (oid === OID.ecdsaSha256) return "SHA-256";
  if (oid === OID.ecdsaSha384) return "SHA-384";
  if (oid === OID.ecdsaSha512) return "SHA-512";
  return undefined;
}

/** Parses a SubjectPublicKeyInfo of a supported key type. */
export function publicKeyOf(spki: Uint8Array): PublicKey {
  const root = expectTag(parseDer(spki), TAG.sequence, "public key");
  const algorithm = expectTag(root.children[0], TAG.sequence, "public key algorithm");
  const algorithmOid = oidOf(algorithm.children[0]);
  bitStringBytes(root.children[1]);
  if (algorithmOid === OID.ed25519) return Object.freeze({ kind: "ed25519", spki });
  if (algorithmOid !== OID.ecPublicKey) return unsupported(`public key algorithm ${algorithmOid}`);
  const curve = oidOf(algorithm.children[1]);
  if (curve === OID.p256) return Object.freeze({ kind: "ecdsa-p256", spki });
  if (curve === OID.p384) return Object.freeze({ kind: "ecdsa-p384", spki });
  return unsupported(`elliptic curve ${curve}`);
}

/** Converts a DER ECDSA-Sig-Value to IEEE P1363 r||s. */
export function rawEcdsaSignature(der: Uint8Array, size: number): Uint8Array {
  const node = expectTag(parseDer(der), TAG.sequence, "ECDSA signature");
  if (node.children.length !== 2) fail("malformed ECDSA signature");
  const out = new Uint8Array(size * 2);
  for (const [index, child] of node.children.entries()) {
    const value = integerBytes(child);
    if (value.length > size) fail("malformed ECDSA signature");
    out.set(value, index * size + (size - value.length));
  }
  return out;
}

/**
 * Verifies `signature` over `data` with `key`. ECDSA signatures are DER and take SHA-256,
 * SHA-384 or SHA-512 as named by the evidence; Ed25519 takes no hash.
 * Returns false for a well-formed signature that does not verify.
 */
export async function verifySignature(
  key: PublicKey,
  hash: HashName | undefined,
  signature: Uint8Array,
  data: Uint8Array,
): Promise<boolean> {
  if (key.kind === "ed25519") {
    if (hash !== undefined) unsupported("Ed25519 takes no separate hash");
    if (signature.length !== 64) return false;
    const imported = await subtle().importKey("spki", view(key.spki), { name: "Ed25519" }, false, [
      "verify",
    ]);
    return subtle().verify({ name: "Ed25519" }, imported, view(signature), view(data));
  }
  if (hash === undefined) unsupported(`ECDSA ${key.kind} needs a hash`);
  const size = key.kind === "ecdsa-p256" ? 32 : 48;
  let raw: Uint8Array;
  try {
    raw = rawEcdsaSignature(signature, size);
  } catch {
    return false;
  }
  const imported = await subtle().importKey(
    "spki",
    view(key.spki),
    { name: "ECDSA", namedCurve: key.kind === "ecdsa-p256" ? "P-256" : "P-384" },
    false,
    ["verify"],
  );
  return subtle().verify(
    { name: "ECDSA", hash: hash as HashName },
    imported,
    view(raw),
    view(data),
  );
}
