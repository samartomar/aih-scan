/**
 * Minimal X.509 certificate reader for Sigstore evidence: names (as exact DER), validity,
 * key, extensions, SAN and Fulcio identity extensions. Adapted from the structure of
 * @sigstore/core's x509 module (Apache-2.0, The Sigstore Authors) over Uint8Array.
 */
import { EvidenceError, equalBytes, fail, utf8Text } from "./bytes.js";
import {
  ecdsaHashOfOid,
  type HashName,
  type PublicKey,
  publicKeyOf,
  verifySignature,
} from "./crypto.js";
import {
  bitStringBytes,
  type Der,
  encode,
  expectTag,
  integerBytes,
  oidOf,
  parseDer,
  smallInteger,
  TAG,
  timeOf,
} from "./der.js";

export const EXTENSION = Object.freeze({
  basicConstraints: "2.5.29.19",
  keyUsage: "2.5.29.15",
  extKeyUsage: "2.5.29.37",
  subjectAltName: "2.5.29.17",
  sct: "1.3.6.1.4.1.11129.2.4.2",
  fulcioIssuerV1: "1.3.6.1.4.1.57264.1.1",
  fulcioIssuerV2: "1.3.6.1.4.1.57264.1.8",
});
export const EKU = Object.freeze({
  codeSigning: "1.3.6.1.5.5.7.3.3",
  timeStamping: "1.3.6.1.5.5.7.3.8",
});

export interface Extension {
  readonly oid: string;
  readonly critical: boolean;
  /** The extnValue OCTET STRING content (the DER-encoded extension value). */
  readonly value: Uint8Array;
  readonly node: Der;
}

export interface Certificate {
  readonly raw: Uint8Array;
  readonly tbs: Der;
  readonly serial: Uint8Array;
  readonly issuer: Uint8Array;
  readonly subject: Uint8Array;
  readonly notBefore: number;
  readonly notAfter: number;
  readonly key: PublicKey;
  readonly spki: Uint8Array;
  readonly signatureHash: HashName;
  readonly signature: Uint8Array;
  readonly extensions: readonly Extension[];
}

export function parseCertificate(raw: Uint8Array): Certificate {
  const root = expectTag(parseDer(raw), TAG.sequence, "certificate");
  if (root.children.length !== 3) fail("malformed certificate");
  const tbs = expectTag(root.children[0], TAG.sequence, "TBS certificate");
  const algorithm = expectTag(root.children[1], TAG.sequence, "certificate signature algorithm");
  const signatureOid = oidOf(algorithm.children[0]);
  const signatureHash = ecdsaHashOfOid(signatureOid);
  if (signatureHash === undefined)
    throw new EvidenceError(
      "unsupported-algorithm",
      `certificate signature algorithm ${signatureOid}`,
    );
  const signature = bitStringBytes(root.children[2]);
  const fields = [...tbs.children];
  let index = 0;
  if (fields[0]?.tag === 0xa0) {
    if (smallInteger(fields[0].children[0]) !== 2) fail("only X.509 v3 certificates are supported");
    index += 1;
  } else fail("only X.509 v3 certificates are supported");
  const serial = integerBytes(fields[index++]);
  const innerAlgorithm = expectTag(fields[index++], TAG.sequence, "TBS signature algorithm");
  if (!equalBytes(innerAlgorithm.raw, algorithm.raw))
    fail("certificate signature algorithms differ");
  const issuer = expectTag(fields[index++], TAG.sequence, "issuer").raw;
  const validity = expectTag(fields[index++], TAG.sequence, "validity");
  const subject = expectTag(fields[index++], TAG.sequence, "subject").raw;
  const spki = expectTag(fields[index++], TAG.sequence, "subject public key").raw;
  const extensions: Extension[] = [];
  for (; index < fields.length; index += 1) {
    const field = fields[index] as Der;
    if (field.tag === 0x81 || field.tag === 0x82) continue;
    if (field.tag !== 0xa3) fail("malformed TBS certificate");
    const list = expectTag(field.children[0], TAG.sequence, "extensions");
    for (const entry of list.children) {
      const parts = expectTag(entry, TAG.sequence, "extension").children;
      const oid = oidOf(parts[0]);
      const critical = parts.length === 3;
      if (critical && (parts[1]?.tag !== TAG.boolean || parts[1].value[0] !== 0xff))
        fail("malformed extension");
      const value = expectTag(parts[parts.length - 1], TAG.octetString, "extension value").value;
      if (extensions.some((existing) => existing.oid === oid))
        fail("duplicate certificate extension");
      extensions.push(Object.freeze({ oid, critical, value, node: entry }));
    }
  }
  const key = publicKeyOf(spki);
  return Object.freeze({
    raw,
    tbs,
    serial,
    issuer,
    subject,
    notBefore: timeOf(validity.children[0]),
    notAfter: timeOf(validity.children[1]),
    key,
    spki,
    signatureHash,
    signature,
    extensions: Object.freeze(extensions),
  });
}

export const extensionOf = (certificate: Certificate, oid: string) =>
  certificate.extensions.find((extension) => extension.oid === oid);

export function isCa(certificate: Certificate): { ca: boolean; pathLength?: number } {
  const extension = extensionOf(certificate, EXTENSION.basicConstraints);
  if (extension === undefined) return { ca: false };
  const node = expectTag(parseDer(extension.value), TAG.sequence, "basic constraints");
  const [first, second] = node.children;
  const ca = first?.tag === TAG.boolean && first.value[0] === 0xff;
  const lengthNode = first?.tag === TAG.integer ? first : second;
  return lengthNode === undefined ? { ca } : { ca, pathLength: smallInteger(lengthNode) };
}

/** Key usage bits as a number with bit 0 = digitalSignature … bit 5 = keyCertSign; undefined if absent. */
export function keyUsage(certificate: Certificate): number | undefined {
  const extension = extensionOf(certificate, EXTENSION.keyUsage);
  if (extension === undefined) return undefined;
  const node = expectTag(parseDer(extension.value), TAG.bitString, "key usage");
  let bits = 0;
  for (let index = 1; index < node.value.length && index < 3; index += 1) {
    const byte = node.value[index] as number;
    for (let bit = 0; bit < 8; bit += 1)
      if (byte & (0x80 >> bit)) bits |= 1 << ((index - 1) * 8 + bit);
  }
  return bits;
}

export const KEY_USAGE = Object.freeze({ digitalSignature: 1, keyCertSign: 1 << 5 });

export function extendedKeyUsages(certificate: Certificate): readonly string[] {
  const extension = extensionOf(certificate, EXTENSION.extKeyUsage);
  if (extension === undefined) return [];
  return expectTag(parseDer(extension.value), TAG.sequence, "extended key usage").children.map(
    oidOf,
  );
}

/** The single URI or email SAN of a Fulcio leaf. */
export function subjectAlternativeName(certificate: Certificate): string | undefined {
  const extension = extensionOf(certificate, EXTENSION.subjectAltName);
  if (extension === undefined) return undefined;
  const names = expectTag(
    parseDer(extension.value),
    TAG.sequence,
    "subject alternative name",
  ).children;
  const values = names
    .filter((name) => name.tag === 0x86 || name.tag === 0x81)
    .map((name) => utf8Text(name.value));
  if (values.length !== 1 || values[0] === undefined) return undefined;
  return values[0];
}

/** Text of a Fulcio extension: V2 extensions are DER UTF8String; V1 extensions are raw text. */
export function fulcioText(certificate: Certificate, oid: string): string | undefined {
  const extension = extensionOf(certificate, oid);
  if (extension === undefined) return undefined;
  try {
    const node = parseDer(extension.value);
    if (node.tag === TAG.utf8String) return utf8Text(node.value);
  } catch {
    // V1 extensions hold the raw value.
  }
  return utf8Text(extension.value);
}

export function oidIssuer(certificate: Certificate): string | undefined {
  if (extensionOf(certificate, EXTENSION.fulcioIssuerV2) !== undefined) {
    const node = parseDer((extensionOf(certificate, EXTENSION.fulcioIssuerV2) as Extension).value);
    return node.tag === TAG.utf8String ? utf8Text(node.value) : undefined;
  }
  const v1 = extensionOf(certificate, EXTENSION.fulcioIssuerV1);
  return v1 === undefined ? undefined : utf8Text(v1.value);
}

/** Whether `issuer` signed `certificate` (name chaining plus signature). */
export async function issuedBy(certificate: Certificate, issuer: Certificate): Promise<boolean> {
  if (!equalBytes(certificate.issuer, issuer.subject)) return false;
  return verifySignature(
    issuer.key,
    certificate.signatureHash,
    certificate.signature,
    certificate.tbs.raw,
  );
}

/** The TBS certificate re-encoded without the embedded SCT extension (RFC 6962 precertificate TBS). */
export function precertificateTbs(certificate: Certificate): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const field of certificate.tbs.children) {
    if (field.tag !== 0xa3) {
      parts.push(field.raw);
      continue;
    }
    const list = field.children[0] as Der;
    const kept = list.children.filter((entry) => oidOf(entry.children[0]) !== EXTENSION.sct);
    parts.push(encode(0xa3, encode(TAG.sequence, ...kept.map((entry) => entry.raw))));
  }
  return encode(TAG.sequence, ...parts);
}
