import type { AnnexDescriptor, ReportBody } from "../assessment/types.js";

export type { AnnexDescriptor } from "../assessment/types.js";
export interface ArtifactAnnex extends AnnexDescriptor {
  bytesBase64: string;
}
export interface Artifact {
  schema: "urn:aihq:scan:artifact:1.0.0";
  scanId: string;
  report: {
    schema: string;
    mediaType: "application/json";
    sha256: string;
    byteLength: number;
    bytesBase64: string;
  };
  annexes: ArtifactAnnex[];
  attestation?: SigstoreBundle;
}
export interface ArtifactStatement {
  _type: "https://in-toto.io/Statement/v1";
  subject: [{ name: "scan-report"; digest: { sha256: string } }];
  predicateType: "urn:aihq:scan:artifact-attestation:1.0.0";
  predicate: {
    scanId: string;
    reportSchema: string;
    reportByteLength: number;
    annexManifestSha256: string;
  };
}
// Wire protocol members are validated against the upstream bundle field definitions
// before conversion. The nested witness records remain upstream JSON data.
export interface SigstoreBundle {
  mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json";
  verificationMaterial: {
    certificate?: { rawBytes: string };
    publicKey?: { hint: string };
    tlogEntries?: Record<string, unknown>[];
    timestampVerificationData?: { rfc3161Timestamps?: { signedTimestamp: string }[] };
  };
  dsseEnvelope: {
    payloadType: string;
    payload: string;
    signatures: { keyid?: string; sig: string }[];
  };
}
export interface ArtifactResult {
  scanId: string;
  artifact: Artifact;
  bytes: Uint8Array;
}
export interface PreparedArtifact extends ArtifactResult {
  statement: ArtifactStatement;
}
export interface PrepareArtifactInput {
  report: ReportBody;
  annexes: { id: string; bytes: Uint8Array }[];
}
export interface VerificationKey {
  identity: string;
  keyId: string;
  publicKeySpkiBase64: string;
}
export interface VerificationPublisher {
  profile: "sigstore-public";
  identity: string;
  purposes: ["scan-report"];
  trustedRoot: Record<string, unknown>;
  policy: {
    issuer: string;
    subjectAlternativeName: string;
    requiredCertificateExtensions: { oid: number[]; valueDerBase64: string }[];
  };
}
export interface AuthenticationTrust {
  keys: VerificationKey[];
  publishers: VerificationPublisher[];
}
export type AssociationReason =
  | "not-supplied"
  | "not-requested"
  | "unavailable"
  | "unsupported-artifact"
  | "malformed"
  | "id-mismatch"
  | "byte-mismatch"
  | "unsigned"
  | "unknown-producer"
  | "untrusted-key"
  | "invalid-signature"
  | "resource-limit";
export interface AssociationResult {
  scanId?: string;
  status: "skipped" | "authenticated" | "unverifiable";
  reason?: AssociationReason;
  producerIdentity?: string;
  keyId?: string;
  reportRead?: "supported" | "unsupported" | "not-requested";
}
export type ReadArtifactResult =
  | {
      status: "read";
      scanId: string;
      report: ReportBody;
      authenticity: "unchecked";
      annexBytes: "checked";
    }
  | { status: "unsupported-report"; scanId: string; reportSchema: string }
  | { status: "invalid"; diagnostics: { code: string; detail: string }[] };
export interface ValidatedArtifact {
  artifact: Artifact;
  reportBytes: Uint8Array;
  annexManifestSha256: string;
}
