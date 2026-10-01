import { canonicalBytes, strictParse } from "../assessment/json.js";
import type { ArtifactStatement, SigstoreBundle, ValidatedArtifact } from "./types.js";
import {
  array,
  artifactLimits,
  boundedJson,
  decoded,
  equalBytes,
  integer,
  invalid,
  object,
  text,
  uint64,
  unsupported,
} from "./validation.js";

export const bundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json" as const;
export const payloadType = "application/vnd.in-toto+json";

export function validateBundle(value: unknown): { bundle: SigstoreBundle; payload: Uint8Array } {
  // Bound untrusted fields before protobuf conversion, ASN.1 or crypto work.
  const format = object(
    value,
    ["mediaType"],
    ["verificationMaterial", "dsseEnvelope", "messageSignature"],
  );
  if (format.mediaType !== bundleMediaType || Object.hasOwn(format, "messageSignature"))
    unsupported();
  const b = object(value, ["mediaType", "verificationMaterial", "dsseEnvelope"]);
  if (b.mediaType !== bundleMediaType) unsupported();
  const envelope = object(b.dsseEnvelope, ["payloadType", "payload", "signatures"]);
  if (envelope.payloadType !== payloadType) invalid();
  const payload = decoded(envelope.payload, artifactLimits.statement);
  const signatures = array(envelope.signatures);
  if (signatures.length !== 1) invalid();
  const signature = object(signatures[0], ["sig"], ["keyid"]);
  const signatureBytes = decoded(signature.sig, artifactLimits.signature);
  if (signatureBytes.length === 0) invalid();
  if (signature.keyid !== undefined) text(signature.keyid, 256, true);
  const material = object(
    b.verificationMaterial,
    [],
    ["certificate", "publicKey", "tlogEntries", "timestampVerificationData"],
  );
  const hasCertificate = Object.hasOwn(material, "certificate");
  const hasKey = Object.hasOwn(material, "publicKey");
  if (hasCertificate === hasKey) invalid();
  const logs = material.tlogEntries === undefined ? [] : array(material.tlogEntries, 4);
  let timestamps: unknown[] = [];
  if (material.timestampVerificationData !== undefined) {
    const time = object(material.timestampVerificationData, [], ["rfc3161Timestamps"]);
    timestamps = time.rfc3161Timestamps === undefined ? [] : array(time.rfc3161Timestamps, 4);
    for (const timestamp of timestamps)
      decoded(object(timestamp, ["signedTimestamp"]).signedTimestamp, 64 * 1024);
  }
  if (hasKey) {
    const key = object(material.publicKey, ["hint"]);
    const hint = text(key.hint);
    if (
      !/^ed25519:[0-9a-f]{64}$/.test(hint) ||
      signature.keyid !== hint ||
      signatureBytes.length !== 64 ||
      logs.length !== 0 ||
      timestamps.length !== 0
    )
      invalid();
  } else {
    const cert = object(material.certificate, ["rawBytes"]);
    if (decoded(cert.rawBytes, artifactLimits.certificate).length === 0) invalid();
    if (signature.keyid !== undefined && signature.keyid !== "") invalid();
    if (logs.length === 0) invalid();
    for (const log of logs) {
      const entry = object(
        log,
        ["logIndex", "logId", "kindVersion", "canonicalizedBody", "inclusionProof"],
        ["integratedTime", "inclusionPromise"],
      );
      uint64(entry.logIndex);
      decoded(object(entry.logId, ["keyId"]).keyId, 32, 32);
      const kind = object(entry.kindVersion, ["kind", "version"]);
      if (kind.kind !== "dsse" || (kind.version !== "0.0.1" && kind.version !== "0.0.2"))
        unsupported();
      if (entry.integratedTime !== undefined) uint64(entry.integratedTime, true);
      decoded(entry.canonicalizedBody, 256 * 1024);
      const proof = object(entry.inclusionProof, [
        "logIndex",
        "rootHash",
        "treeSize",
        "hashes",
        "checkpoint",
      ]);
      uint64(proof.logIndex);
      uint64(proof.treeSize);
      if (
        BigInt(proof.treeSize as string) === 0n ||
        BigInt(proof.logIndex as string) >= BigInt(proof.treeSize as string)
      )
        invalid();
      decoded(proof.rootHash, 32, 32);
      for (const hash of array(proof.hashes, 64)) decoded(hash, 32, 32);
      text(object(proof.checkpoint, ["envelope"]).envelope, 16 * 1024);
      if (entry.inclusionPromise !== undefined) {
        decoded(
          object(entry.inclusionPromise, ["signedEntryTimestamp"]).signedEntryTimestamp,
          artifactLimits.signature,
        );
      }
      if (
        kind.version === "0.0.1" &&
        (entry.inclusionPromise === undefined ||
          entry.integratedTime === undefined ||
          entry.integratedTime === "0")
      )
        invalid();
      if (kind.version === "0.0.2" && timestamps.length === 0) invalid();
    }
  }
  boundedJson(b, artifactLimits.attestation);
  return { bundle: b as unknown as SigstoreBundle, payload };
}

export function statementFor(validated: ValidatedArtifact): ArtifactStatement {
  const { artifact, annexManifestSha256 } = validated;
  return {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "scan-report", digest: { sha256: artifact.report.sha256 } }],
    predicateType: "urn:aihq:scan:artifact-attestation:1.0.0",
    predicate: {
      scanId: artifact.scanId,
      reportSchema: artifact.report.schema,
      reportByteLength: artifact.report.byteLength,
      annexManifestSha256,
    },
  };
}
export function validateStatement(payload: Uint8Array, validated: ValidatedArtifact): void {
  const s = object(strictParse(payload, "statement", artifactLimits.statement), [
    "_type",
    "subject",
    "predicateType",
    "predicate",
  ]);
  const subjects = array(s.subject, 1);
  if (subjects.length !== 1) invalid();
  const subject = object(subjects[0], ["name", "digest"]);
  object(subject.digest, ["sha256"]);
  const predicate = object(s.predicate, [
    "scanId",
    "reportSchema",
    "reportByteLength",
    "annexManifestSha256",
  ]);
  integer(predicate.reportByteLength);
  if (!equalBytes(canonicalBytes(s), canonicalBytes(statementFor(validated))))
    invalid("byte-mismatch");
}
