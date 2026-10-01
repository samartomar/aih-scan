import { createHash, createPublicKey, type KeyObject } from "node:crypto";
import { PublicKeyDetails } from "@sigstore/protobuf-specs";
import { canonicalBytes, strictParse } from "../assessment/json.js";
import type { AuthenticationTrust } from "./types.js";
import {
  array,
  artifactLimits,
  boundedJson,
  decoded,
  integer,
  invalid,
  object,
  text,
} from "./validation.js";

export function keyFingerprint(key: KeyObject): string {
  const bytes = key.export({ type: "spki", format: "der" });
  return `ed25519:${createHash("sha256").update(bytes).digest("hex")}`;
}
function timeRange(value: unknown): void {
  const range = object(value, ["start"], ["end"]);
  const timestamps = [range.start, ...(range.end === undefined ? [] : [range.end])];
  for (const value of timestamps) {
    const timestamp = text(value, 64);
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(timestamp)) invalid();
    const date = Date.parse(timestamp);
    if (!Number.isSafeInteger(date)) invalid();
    const normalized = timestamp.includes(".")
      ? timestamp.replace(
          /\.(\d{1,3})Z$/,
          (_match, fraction: string) => `.${fraction.padEnd(3, "0")}Z`,
        )
      : timestamp.replace(/Z$/, ".000Z");
    if (new Date(date).toISOString() !== normalized) invalid();
  }
  if (
    range.end !== undefined &&
    Date.parse(range.end as string) < Date.parse(range.start as string)
  )
    invalid();
}
function logAuthority(value: unknown): void {
  const log = object(
    value,
    ["baseUrl", "hashAlgorithm", "publicKey", "logId"],
    ["checkpointKeyId", "operator"],
  );
  text(log.baseUrl, 2048);
  if (log.hashAlgorithm !== "SHA2_256") invalid();
  decoded(object(log.logId, ["keyId"]).keyId, 32, 32);
  if (log.checkpointKeyId !== undefined)
    decoded(object(log.checkpointKeyId, ["keyId"]).keyId, 4, 4);
  if (log.operator !== undefined) text(log.operator);
  const key = object(log.publicKey, ["rawBytes", "keyDetails", "validFor"]);
  if (decoded(key.rawBytes, 4096).length === 0) invalid();
  if (
    typeof key.keyDetails !== "string" ||
    !Object.hasOwn(PublicKeyDetails, key.keyDetails) ||
    key.keyDetails === "PUBLIC_KEY_DETAILS_UNSPECIFIED"
  )
    invalid();
  timeRange(key.validFor);
}
function certificateAuthority(value: unknown): void {
  const ca = object(value, ["uri", "certChain", "validFor"], ["subject", "operator"]);
  text(ca.uri, 2048);
  if (ca.subject !== undefined) {
    const subject = object(ca.subject, [], ["organization", "commonName"]);
    for (const value of Object.values(subject)) text(value);
  }
  if (ca.operator !== undefined) text(ca.operator);
  timeRange(ca.validFor);
  const certificates = array(object(ca.certChain, ["certificates"]).certificates, 8);
  if (certificates.length === 0) invalid();
  for (const certificate of certificates) {
    if (
      decoded(object(certificate, ["rawBytes"]).rawBytes, artifactLimits.certificate).length === 0
    )
      invalid();
  }
}
function trustedRoot(value: unknown): void {
  const root = object(
    value,
    ["mediaType"],
    ["tlogs", "ctlogs", "certificateAuthorities", "timestampAuthorities"],
  );
  if (
    ![
      "application/vnd.dev.sigstore.trustedroot.v0.2+json",
      "application/vnd.dev.sigstore.trustedroot.v0.1+json",
      "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
    ].includes(root.mediaType as string)
  )
    invalid();
  for (const category of ["tlogs", "ctlogs"] as const) {
    for (const log of array(root[category] ?? [], 64)) logAuthority(log);
  }
  for (const category of ["certificateAuthorities", "timestampAuthorities"] as const) {
    for (const ca of array(root[category] ?? [], 64)) certificateAuthority(ca);
  }
}
export interface SelectedTrust {
  trust: AuthenticationTrust;
  keys: Map<string, KeyObject>;
}
export function selectTrust(value: unknown): SelectedTrust {
  const trust = object(value, ["keys", "publishers"]);
  const keys = array(trust.keys, 128);
  const publishers = array(trust.publishers, 32);
  const seenKeys = new Set<string>();
  // Structural and byte ceilings precede DER parsing. Trusted inputs can also
  // arrive from an untrusted configuration transport, so validate them equally.
  for (const value of keys) {
    const key = object(value, ["identity", "keyId", "publicKeySpkiBase64"]);
    text(key.identity);
    const keyId = text(key.keyId);
    if (!/^ed25519:[0-9a-f]{64}$/.test(keyId) || seenKeys.has(keyId)) invalid();
    seenKeys.add(keyId);
    decoded(key.publicKeySpkiBase64, 4096);
  }
  for (const value of publishers) {
    const publisher = object(value, ["profile", "identity", "purposes", "trustedRoot", "policy"]);
    if (publisher.profile !== "sigstore-public") invalid();
    text(publisher.identity);
    const purposes = array(publisher.purposes, 1);
    if (purposes.length !== 1 || purposes[0] !== "scan-report") invalid();
    trustedRoot(publisher.trustedRoot);
    const policy = object(publisher.policy, [
      "issuer",
      "subjectAlternativeName",
      "requiredCertificateExtensions",
    ]);
    text(policy.issuer, 2048);
    text(policy.subjectAlternativeName, 2048);
    const seenOids = new Set<string>();
    for (const value of array(policy.requiredCertificateExtensions, 16)) {
      const extension = object(value, ["oid", "valueDerBase64"]);
      const oid = array(extension.oid, 32);
      if (oid.length < 2) invalid();
      for (const arc of oid) integer(arc, 4294967295);
      if ((oid[0] as number) > 2 || ((oid[0] as number) < 2 && (oid[1] as number) > 39)) invalid();
      const id = oid.join(".");
      if (seenOids.has(id)) invalid();
      seenOids.add(id);
      decoded(extension.valueDerBase64, 4096);
    }
  }
  boundedJson(trust, artifactLimits.trust);
  // Do not carry references to mutable caller-selected identities/policies/root
  // material across the subsequent asynchronous artifact byte checks.
  const snapshot = strictParse(
    canonicalBytes(trust),
    "selected trust",
    artifactLimits.trust,
  ) as AuthenticationTrust;
  const parsedKeys = new Map<string, KeyObject>();
  for (const value of snapshot.keys) {
    const key = value as AuthenticationTrust["keys"][number];
    try {
      const publicKey = createPublicKey({
        key: Buffer.from(decoded(key.publicKeySpkiBase64, 4096)),
        type: "spki",
        format: "der",
      });
      if (publicKey.asymmetricKeyType !== "ed25519" || keyFingerprint(publicKey) !== key.keyId)
        invalid();
      parsedKeys.set(key.keyId, publicKey);
    } catch {
      invalid();
    }
  }
  return { trust: snapshot, keys: parsedKeys };
}
