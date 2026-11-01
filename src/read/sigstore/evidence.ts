/**
 * Offline verification of one `aih-sigstore-keyless/1` signing event against selected trust
 * material: exact-byte signature, Fulcio chain, SCT, transparency-log body binding, inclusion
 * proof and signed checkpoint, and authenticated signing time (Rekor SET or RFC 3161).
 * Follows the verification rules of sigstore-js (@sigstore/verify, Apache-2.0, The Sigstore
 * Authors), ported to Uint8Array and WebCrypto. Throws `EvidenceError` on any failure.
 */

import type { KeylessBundle, TlogEntry } from "./bundle.js";
import {
  base64Decode,
  base64Encode,
  concat,
  EvidenceError,
  equalBytes,
  fail,
  hexDecode,
  hexOf,
  pemCertificate,
  uintOf,
  utf8,
  utf8Text,
} from "./bytes.js";
import {
  digest,
  ecdsaHashOfOid,
  ecPublicKeyOid,
  type HashName,
  hashOfOid,
  sha256,
  verifySignature,
} from "./crypto.js";
import {
  type Der,
  expectTag,
  integerBytes,
  oidOf,
  parseDer,
  smallInteger,
  TAG,
  timeOf,
} from "./der.js";
import { type CertificateAuthority, covers, type LogKey, type TrustMaterial } from "./trust.js";
import {
  type Certificate,
  EKU,
  EXTENSION,
  extendedKeyUsages,
  extensionOf,
  isCa,
  issuedBy,
  KEY_USAGE,
  keyUsage,
  oidIssuer,
  parseCertificate,
  precertificateTbs,
  subjectAlternativeName,
} from "./x509.js";

export interface VerifiedSigner {
  readonly issuer: string;
  readonly subject: string;
  readonly certificate: Certificate;
  /** Authenticated signing times (ms since the epoch). */
  readonly signedAt: readonly number[];
}

const validAt = (certificate: Certificate, time: number) =>
  certificate.notBefore <= time && time <= certificate.notAfter;

/** Builds and verifies a chain from `leaf` to a self-signed certificate of one authority. */
export async function verifyChain(
  leaf: Certificate,
  authorities: readonly CertificateAuthority[],
  time: number,
): Promise<Certificate[]> {
  for (const authority of authorities) {
    if (!covers(authority.validFor, time)) continue;
    const path = await chainWithin(leaf, authority.certificates);
    if (path === undefined) continue;
    if (!path.every((certificate) => validAt(certificate, time))) continue;
    return path;
  }
  return fail(
    "the certificate does not chain to selected trust material valid at the signing time",
  );
}

async function chainWithin(
  leaf: Certificate,
  trusted: readonly Certificate[],
): Promise<Certificate[] | undefined> {
  const path = [leaf];
  let current = leaf;
  for (let depth = 0; depth <= trusted.length; depth += 1) {
    const selfSigned = equalBytes(current.subject, current.issuer);
    if (selfSigned && current !== leaf) {
      if (!(await issuedBy(current, current))) return undefined;
      return checkPath(path) ? path : undefined;
    }
    let next: Certificate | undefined;
    for (const candidate of trusted)
      if (
        candidate !== current &&
        !equalBytes(candidate.raw, current.raw) &&
        (await issuedBy(current, candidate))
      ) {
        next = candidate;
        break;
      }
    if (next === undefined) return undefined;
    path.push(next);
    current = next;
  }
  return undefined;
}

function checkPath(path: readonly Certificate[]): boolean {
  for (let index = 1; index < path.length; index += 1) {
    const certificate = path[index] as Certificate;
    const constraints = isCa(certificate);
    if (!constraints.ca) return false;
    const usage = keyUsage(certificate);
    if (usage !== undefined && (usage & KEY_USAGE.keyCertSign) === 0) return false;
    if (constraints.pathLength !== undefined && constraints.pathLength < index - 1) return false;
  }
  return true;
}

// --- Certificate transparency -------------------------------------------------------------

interface Sct {
  readonly version: number;
  readonly logId: Uint8Array;
  readonly timestamp: Uint8Array;
  readonly extensions: Uint8Array;
  readonly hash: HashName | undefined;
  readonly signatureAlgorithm: number;
  readonly signature: Uint8Array;
}

function readScts(leaf: Certificate): Sct[] {
  const extension = extensionOf(leaf, EXTENSION.sct);
  if (extension === undefined) return [];
  const list = expectTag(parseDer(extension.value), TAG.octetString, "SCT list").value;
  const u16 = (offset: number) => ((list[offset] as number) << 8) | (list[offset + 1] as number);
  if (list.length < 2 || u16(0) !== list.length - 2) fail("malformed SCT list");
  const out: Sct[] = [];
  let offset = 2;
  while (offset < list.length) {
    if (offset + 2 > list.length) fail("malformed SCT list");
    const length = u16(offset);
    const end = offset + 2 + length;
    if (end > list.length || length < 47) fail("malformed SCT");
    const sct = list.subarray(offset + 2, end);
    const extensionsLength = ((sct[41] as number) << 8) | (sct[42] as number);
    const after = 43 + extensionsLength;
    if (after + 4 > sct.length) fail("malformed SCT");
    const signatureLength = ((sct[after + 2] as number) << 8) | (sct[after + 3] as number);
    if (after + 4 + signatureLength !== sct.length) fail("malformed SCT");
    const hashCode = sct[after] as number;
    out.push({
      version: sct[0] as number,
      logId: sct.subarray(1, 33),
      timestamp: sct.subarray(33, 41),
      extensions: sct.subarray(43, after),
      hash:
        hashCode === 4
          ? "SHA-256"
          : hashCode === 5
            ? "SHA-384"
            : hashCode === 6
              ? "SHA-512"
              : undefined,
      signatureAlgorithm: sct[after + 1] as number,
      signature: sct.subarray(after + 4),
    });
    offset = end;
  }
  return out;
}

/** Number of embedded SCTs verified by a selected CT log valid at the SCT time. */
export async function verifyScts(
  leaf: Certificate,
  issuer: Certificate,
  ctlogs: readonly LogKey[],
): Promise<number> {
  const scts = readScts(leaf);
  if (scts.length === 0) return 0;
  const tbs = precertificateTbs(leaf);
  const length = Uint8Array.of(
    (tbs.length >> 16) & 0xff,
    (tbs.length >> 8) & 0xff,
    tbs.length & 0xff,
  );
  const preCert = concat(await sha256(issuer.spki), length, tbs);
  let verified = 0;
  for (const sct of scts) {
    const time = Number(uintOf(sct.timestamp));
    const logs = ctlogs.filter(
      (log) => equalBytes(log.logId, sct.logId) && covers(log.validFor, time),
    );
    if (logs.length === 0) continue;
    if (sct.version !== 0 || sct.signatureAlgorithm !== 3 || sct.hash === undefined)
      throw new EvidenceError("unsupported-algorithm", "unsupported SCT version or algorithm");
    const extensionsLength = Uint8Array.of(
      sct.extensions.length >> 8,
      sct.extensions.length & 0xff,
    );
    const signed = concat(
      Uint8Array.of(sct.version, 0),
      sct.timestamp,
      Uint8Array.of(0, 1),
      preCert,
      extensionsLength,
      sct.extensions,
    );
    let ok = false;
    for (const log of logs)
      if (await verifySignature(log.key, sct.hash, sct.signature, signed)) ok = true;
    if (!ok) fail("an SCT from a selected log does not verify");
    verified += 1;
  }
  return verified;
}

// --- Transparency log ----------------------------------------------------------------------

const hashLeaf = (body: Uint8Array) => sha256(concat(Uint8Array.of(0), body));
const hashChildren = (left: Uint8Array, right: Uint8Array) =>
  sha256(concat(Uint8Array.of(1), left, right));
const bitLength = (value: bigint) => (value === 0n ? 0 : value.toString(2).length);
const onesCount = (value: bigint) => [...value.toString(2)].filter((bit) => bit === "1").length;

/** RFC 6962 / RFC 9162 inclusion proof of `body` at `index` in a tree of `size` leaves. */
export async function merkleRoot(
  body: Uint8Array,
  index: bigint,
  size: bigint,
  hashes: readonly Uint8Array[],
): Promise<Uint8Array> {
  if (index < 0n || index >= size) return fail("inclusion proof index is outside the tree");
  const inner = bitLength(index ^ (size - 1n));
  const border = onesCount(index >> BigInt(inner));
  if (hashes.length !== inner + border)
    return fail("inclusion proof has the wrong number of hashes");
  let node = await hashLeaf(body);
  for (const [position, hash] of hashes.entries()) {
    if (hash.length !== 32) fail("inclusion proof hash is not 32 bytes");
    if (position < inner)
      node =
        (index >> BigInt(position)) & 1n
          ? await hashChildren(hash, node)
          : await hashChildren(node, hash);
    else node = await hashChildren(hash, node);
  }
  return node;
}

interface Checkpoint {
  readonly origin: string;
  readonly size: bigint;
  readonly root: Uint8Array;
}

/** Verifies a signed-note checkpoint with a selected log key; returns its parsed body. */
export async function verifyCheckpoint(envelope: string, log: LogKey): Promise<Checkpoint> {
  const split = envelope.indexOf("\n\n");
  if (split < 0) return fail("checkpoint has no signature separator");
  const note = envelope.slice(0, split + 1);
  const lines = note.slice(0, -1).split("\n");
  if (lines.length < 3) return fail("checkpoint has too few lines");
  if (!/^(0|[1-9]\d{0,18})$/.test(lines[1] as string)) return fail("checkpoint size is malformed");
  const root = base64Decode(lines[2]);
  if (root === undefined || root.length !== 32) return fail("checkpoint root is malformed");
  const signatures = envelope.slice(split + 2);
  const pattern = /^— (\S+) (\S+)\n/gmu;
  let host: string;
  try {
    host = new URL(log.baseUrl).host;
  } catch {
    host = log.baseUrl;
  }
  let verified = false;
  for (const match of signatures.matchAll(pattern)) {
    const name = match[1] as string;
    const bytes = base64Decode(match[2]);
    if (bytes === undefined || bytes.length < 5) continue;
    if (!equalBytes(bytes.subarray(0, 4), log.logId.subarray(0, 4))) continue;
    if (name !== host && !log.baseUrl.includes(name)) continue;
    const hash = log.key.kind === "ed25519" ? undefined : "SHA-256";
    if (await verifySignature(log.key, hash, bytes.subarray(4), utf8(note))) verified = true;
  }
  if (!verified) return fail("checkpoint signature does not verify with the selected log key");
  return { origin: lines[0] as string, size: BigInt(lines[1] as string), root };
}

function jsonOf(bytes: Uint8Array): Record<string, unknown> {
  const text = utf8Text(bytes);
  if (text === undefined) return fail("log entry body is not UTF-8");
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return fail("log entry body is not JSON");
  }
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return fail("log entry body is not an object");
  return value as Record<string, unknown>;
}

const field = (value: unknown, ...path: string[]): unknown => {
  let current = value;
  for (const key of path) {
    if (typeof current !== "object" || current === null || Array.isArray(current)) return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return current;
};

/** Binds a hashedrekord body (0.0.1 or 0.0.2) to the digest, certificate and signature. */
export function verifyBody(
  entry: TlogEntry,
  bundleDigest: Uint8Array,
  certificate: Uint8Array,
  signature: Uint8Array,
): void {
  const body = jsonOf(entry.body);
  if (entry.kind !== "hashedrekord")
    fail(`log entry kind ${entry.kind} does not bind a message signature`);
  if (body.kind !== entry.kind || body.apiVersion !== entry.version)
    fail("log entry kind/version mismatch");
  const same = (value: Uint8Array | undefined, expected: Uint8Array) =>
    value !== undefined && equalBytes(value, expected);
  if (entry.version === "0.0.1") {
    if (field(body, "spec", "data", "hash", "algorithm") !== "sha256")
      fail("log entry digest algorithm");
    if (!same(hexDecode(field(body, "spec", "data", "hash", "value")), bundleDigest))
      fail("log entry digest differs");
    if (!same(base64Decode(field(body, "spec", "signature", "content")), signature))
      fail("log entry signature differs");
    const key = base64Decode(field(body, "spec", "signature", "publicKey", "content"));
    const pem = key === undefined ? undefined : utf8Text(key);
    const der = pem === undefined ? undefined : pemCertificate(pem);
    if (!same(der, certificate)) fail("log entry certificate differs");
    return;
  }
  if (entry.version === "0.0.2") {
    const spec = field(body, "spec", "hashedRekordV002");
    if (field(spec, "data", "algorithm") !== "SHA2_256") fail("log entry digest algorithm");
    if (!same(base64Decode(field(spec, "data", "digest")), bundleDigest))
      fail("log entry digest differs");
    if (!same(base64Decode(field(spec, "signature", "content")), signature))
      fail("log entry signature differs");
    const details = field(spec, "signature", "verifier", "keyDetails");
    if (details !== undefined && details !== "PKIX_ECDSA_P256_SHA_256")
      fail("log entry key details differ");
    if (
      !same(
        base64Decode(field(spec, "signature", "verifier", "x509Certificate", "rawBytes")),
        certificate,
      )
    )
      fail("log entry certificate differs");
    return;
  }
  fail(`hashedrekord version ${entry.version} is not supported`);
}

/**
 * Verifies a log entry's inclusion proof and signed checkpoint, and its SET when present.
 * Returns the selected log and the SET-authenticated integrated time (ms) if any.
 */
export async function verifyInclusion(
  entry: TlogEntry,
  tlogs: readonly LogKey[],
): Promise<{ log: LogKey; integratedTime: number | undefined }> {
  const candidates = tlogs.filter((log) => equalBytes(log.logId, entry.logId));
  if (candidates.length === 0) return fail("the log entry is not from a selected transparency log");
  if (entry.proof === undefined) return fail("the log entry has no inclusion proof");
  const proof = entry.proof;
  for (const log of candidates) {
    try {
      const checkpoint = await verifyCheckpoint(proof.checkpoint, log);
      if (checkpoint.size !== proof.treeSize || !equalBytes(checkpoint.root, proof.rootHash))
        fail("checkpoint does not match the inclusion proof");
      const root = await merkleRoot(entry.body, proof.logIndex, proof.treeSize, proof.hashes);
      if (!equalBytes(root, proof.rootHash))
        fail("inclusion proof does not reproduce the root hash");
      let integratedTime: number | undefined;
      if (entry.signedEntryTimestamp !== undefined) {
        if (entry.integratedTime === undefined)
          fail("signed entry timestamp without integrated time");
        const time = entry.integratedTime as bigint;
        if (time > 253402300799n) fail("integrated time is out of range");
        if (entry.logIndex > BigInt(Number.MAX_SAFE_INTEGER)) fail("log index is out of range");
        const payload = `{"body":${JSON.stringify(base64Encode(entry.body))},"integratedTime":${time},"logID":${JSON.stringify(hexOf(entry.logId))},"logIndex":${entry.logIndex}}`;
        const hash = log.key.kind === "ed25519" ? undefined : "SHA-256";
        if (!(await verifySignature(log.key, hash, entry.signedEntryTimestamp, utf8(payload))))
          fail("signed entry timestamp does not verify");
        integratedTime = Number(time) * 1000;
        if (!covers(log.validFor, integratedTime)) fail("log key not valid at the integrated time");
      }
      return { log, integratedTime };
    } catch (error) {
      if (
        candidates.length === 1 ||
        !(error instanceof EvidenceError) ||
        error.reason !== "invalid-signature"
      )
        throw error;
    }
  }
  return fail("the log entry does not verify with a selected log key");
}

// --- RFC 3161 timestamps -------------------------------------------------------------------

const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const OID_TST_INFO = "1.2.840.113549.1.9.16.1.4";
const OID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
const OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";

/** Verifies an RFC 3161 TimeStampResp over `data` with selected TSA material; returns genTime (ms). */
export async function verifyTimestamp(
  token: Uint8Array,
  data: Uint8Array,
  authorities: readonly CertificateAuthority[],
): Promise<number> {
  const response = expectTag(parseDer(token), TAG.sequence, "timestamp response");
  const status = smallInteger(
    expectTag(response.children[0], TAG.sequence, "PKIStatusInfo").children[0],
  );
  if (status !== 0 && status !== 1) fail("timestamp was not granted");
  const contentInfo = expectTag(response.children[1], TAG.sequence, "timestamp token");
  if (oidOf(contentInfo.children[0]) !== OID_SIGNED_DATA) fail("timestamp token is not SignedData");
  const signedData = expectTag(
    expectTag(contentInfo.children[1], 0xa0, "SignedData").children[0],
    TAG.sequence,
    "SignedData",
  );
  const parts = signedData.children;
  const encapsulated = expectTag(parts[2], TAG.sequence, "encapsulated content");
  if (oidOf(encapsulated.children[0]) !== OID_TST_INFO) fail("timestamp content is not TSTInfo");
  const tstInfoBytes = expectTag(
    expectTag(encapsulated.children[1], 0xa0, "TSTInfo").children[0],
    TAG.octetString,
    "TSTInfo",
  ).value;
  const signerInfos = expectTag(parts[parts.length - 1], TAG.set, "signer infos");
  if (signerInfos.children.length !== 1) fail("timestamp must have exactly one signer");
  const signerInfo = expectTag(signerInfos.children[0], TAG.sequence, "signer info").children;
  const sid = expectTag(signerInfo[1], TAG.sequence, "signer identifier");
  const sidIssuer = expectTag(sid.children[0], TAG.sequence, "signer issuer").raw;
  const sidSerial = integerBytes(sid.children[1]);
  const digestOid = oidOf(expectTag(signerInfo[2], TAG.sequence, "digest algorithm").children[0]);
  const signerHash = hashOfOid(digestOid);
  if (signerHash === undefined)
    throw new EvidenceError("unsupported-algorithm", `timestamp digest ${digestOid}`);
  const signedAttributes = expectTag(signerInfo[3], 0xa0, "signed attributes");
  const signatureOid = oidOf(
    expectTag(signerInfo[4], TAG.sequence, "signature algorithm").children[0],
  );
  const signatureHash = signatureOid === ecPublicKeyOid ? signerHash : ecdsaHashOfOid(signatureOid);
  if (signatureHash === undefined)
    throw new EvidenceError(
      "unsupported-algorithm",
      `timestamp signature algorithm ${signatureOid}`,
    );
  const signatureValue = expectTag(signerInfo[5], TAG.octetString, "signature").value;

  const attribute = (oid: string): Der | undefined =>
    signedAttributes.children.find((entry) => oidOf(entry.children[0]) === oid)?.children[1]
      ?.children[0];
  if (oidOf(attribute(OID_CONTENT_TYPE)) !== OID_TST_INFO) fail("timestamp content-type attribute");
  const messageDigest = expectTag(
    attribute(OID_MESSAGE_DIGEST),
    TAG.octetString,
    "message digest",
  ).value;
  if (!equalBytes(messageDigest, await digest(signerHash, tstInfoBytes)))
    fail("timestamp message digest differs");

  const tstInfo = expectTag(parseDer(tstInfoBytes), TAG.sequence, "TSTInfo").children;
  const imprint = expectTag(tstInfo[2], TAG.sequence, "message imprint");
  const imprintOid = oidOf(
    expectTag(imprint.children[0], TAG.sequence, "imprint algorithm").children[0],
  );
  const imprintHash = hashOfOid(imprintOid);
  if (imprintHash === undefined)
    throw new EvidenceError("unsupported-algorithm", `timestamp imprint ${imprintOid}`);
  const imprintValue = expectTag(imprint.children[1], TAG.octetString, "imprint").value;
  if (!equalBytes(imprintValue, await digest(imprintHash, data)))
    fail("timestamp does not cover this signature");
  const genTime = timeOf(expectTag(tstInfo[4], TAG.generalizedTime, "genTime"));

  const signed = new Uint8Array(signedAttributes.raw);
  signed[0] = TAG.set;
  for (const authority of authorities) {
    const [signer, ...rest] = authority.certificates;
    if (
      signer === undefined ||
      !equalBytes(signer.serial, sidSerial) ||
      !equalBytes(signer.issuer, sidIssuer)
    )
      continue;
    if (!covers(authority.validFor, genTime)) continue;
    if (!extendedKeyUsages(signer).includes(EKU.timeStamping)) continue;
    const path = rest.length === 0 ? undefined : await chainWithin(signer, rest);
    if (path === undefined || !path.every((certificate) => validAt(certificate, genTime))) continue;
    if (await verifySignature(signer.key, signatureHash, signatureValue, signed)) return genTime;
  }
  return fail("timestamp is not signed by selected timestamp-authority material");
}

// --- The signing event ---------------------------------------------------------------------

/**
 * Verifies that `bytes` were signed under the profile and selected trust material. Returns the
 * signer's identity (OIDC issuer, certificate SAN) and authenticated signing times.
 */
export async function verifyKeyless(
  bytes: Uint8Array,
  bundle: KeylessBundle,
  trust: TrustMaterial,
): Promise<VerifiedSigner> {
  const leaf = parseCertificate(bundle.certificate);
  if (leaf.key.kind !== "ecdsa-p256")
    throw new EvidenceError("unsupported-algorithm", "the signing key must be ECDSA P-256");
  const actual = await sha256(bytes);
  if (!equalBytes(actual, bundle.digest))
    fail("the signed digest does not match the supplied bytes");
  if (!(await verifySignature(leaf.key, "SHA-256", bundle.signature, bytes)))
    fail("the signature does not verify over the supplied bytes");

  if (bundle.tlogEntries.length === 0) fail("the bundle has no transparency-log entry");
  const times: number[] = [];
  const logs: LogKey[] = [];
  for (const entry of bundle.tlogEntries) {
    verifyBody(entry, bundle.digest, bundle.certificate, bundle.signature);
    const { log, integratedTime } = await verifyInclusion(entry, trust.tlogs);
    logs.push(log);
    if (integratedTime !== undefined) times.push(integratedTime);
  }
  for (const token of bundle.timestamps)
    times.push(await verifyTimestamp(token, bundle.signature, trust.timestampAuthorities));
  if (times.length === 0) fail("no authenticated signing time");
  for (const log of logs)
    if (!times.every((time) => covers(log.validFor, time)))
      fail("the log key is not valid at the signing time");

  let issuer: Certificate | undefined;
  for (const time of times) {
    if (!validAt(leaf, time))
      fail("the signing time is outside the signing certificate's validity");
    const path = await verifyChain(leaf, trust.certificateAuthorities, time);
    issuer = path[1];
  }
  if (issuer === undefined) return fail("the signing certificate has no issuer");
  if ((await verifyScts(leaf, issuer, trust.ctlogs)) < 1)
    fail("no valid certificate-transparency SCT");

  if (!extendedKeyUsages(leaf).includes(EKU.codeSigning))
    fail("the signing certificate lacks code signing usage");
  const usage = keyUsage(leaf);
  if (usage !== undefined && (usage & KEY_USAGE.digitalSignature) === 0)
    fail("the signing certificate lacks digital signature usage");
  const oidcIssuer = oidIssuer(leaf);
  const subject = subjectAlternativeName(leaf);
  if (oidcIssuer === undefined || subject === undefined)
    fail("the signing certificate has no Fulcio identity");
  return Object.freeze({
    issuer: oidcIssuer as string,
    subject: subject as string,
    certificate: leaf,
    signedAt: Object.freeze([...times]),
  });
}
