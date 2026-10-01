import { createPublicKey, KeyObject, sign, X509Certificate } from "node:crypto";
import { bundleFromJSON } from "@sigstore/bundle";
import { TrustedRoot } from "@sigstore/protobuf-specs";
import { PolicyError, toSignedEntity, toTrustMaterial, Verifier } from "@sigstore/verify";
import { base64Encode, canonicalBytes, scanIdFor, sha256 } from "../assessment/json.js";
import { validateReport } from "../assessment/report.js";
import {
  bundleMediaType,
  payloadType,
  statementFor,
  validateBundle,
  validateStatement,
} from "./bundle.js";
import { validateArtifact } from "./read.js";
import { keyFingerprint, selectTrust } from "./trust.js";
import type {
  Artifact,
  ArtifactResult,
  AssociationReason,
  AssociationResult,
  AuthenticationTrust,
  PrepareArtifactInput,
  PreparedArtifact,
  SigstoreBundle,
} from "./types.js";
import {
  ArtifactError,
  array,
  artifactLimits,
  decoded,
  invalid,
  limited,
  object,
  text,
  validScanId,
} from "./validation.js";

export interface SignArtifactInput extends PrepareArtifactInput {
  signer: { keyId: string; privateKey: KeyObject };
}

function constructionError(error: unknown): never {
  if (error instanceof ArtifactError) throw error;
  if (error instanceof Error && "code" in error && error.code === "resource-limit") limited();
  invalid();
}
export async function prepareArtifact(input: PrepareArtifactInput): Promise<PreparedArtifact> {
  try {
    const supplied = object(input, ["report", "annexes"]);
    const report = await validateReport(supplied.report);
    const reportBytes = canonicalBytes(report);
    if (reportBytes.length > artifactLimits.report) limited();
    const records = array(supplied.annexes);
    const byId = new Map<string, Uint8Array>();
    let total = reportBytes.length;
    for (const value of records) {
      const annex = object(value, ["id", "bytes"]);
      const id = text(annex.id);
      if (byId.has(id) || !(annex.bytes instanceof Uint8Array)) invalid();
      if (annex.bytes.length > artifactLimits.annex) limited();
      total += annex.bytes.length;
      if (total > artifactLimits.decoded) limited();
      byId.set(id, new Uint8Array(annex.bytes));
    }
    if (byId.size !== report.annexes.length) invalid();
    const annexes: Artifact["annexes"] = [];
    for (const descriptor of report.annexes) {
      const bytes = byId.get(descriptor.id);
      if (
        !bytes ||
        bytes.length !== descriptor.byteLength ||
        (await sha256(bytes)) !== descriptor.sha256
      )
        invalid("byte-mismatch");
      annexes.push({ ...descriptor, bytesBase64: base64Encode(bytes) });
    }
    const scanId = await scanIdFor(reportBytes);
    const artifact: Artifact = {
      schema: "urn:aihq:scan:artifact:1.0.0",
      scanId,
      report: {
        schema: report.schema,
        mediaType: "application/json",
        sha256: await sha256(reportBytes),
        byteLength: reportBytes.length,
        bytesBase64: base64Encode(reportBytes),
      },
      annexes,
    };
    const bytes = canonicalBytes(artifact);
    const validated = await validateArtifact(bytes);
    return { scanId, artifact, bytes, statement: statementFor(validated) };
  } catch (error) {
    constructionError(error);
  }
}
export async function attachAttestation(input: {
  bytes: Uint8Array;
  bundle: unknown;
}): Promise<ArtifactResult> {
  try {
    const supplied = object(input, ["bytes", "bundle"]);
    const validated = await validateArtifact(supplied.bytes as Uint8Array);
    if (validated.artifact.attestation !== undefined) throw new ArtifactError("already-attested");
    const { bundle, payload } = validateBundle(supplied.bundle);
    validateStatement(payload, validated);
    const artifact = { ...validated.artifact, attestation: bundle };
    const bytes = canonicalBytes(artifact);
    if (bytes.length > artifactLimits.artifact) limited();
    return { scanId: artifact.scanId, artifact, bytes };
  } catch (error) {
    constructionError(error);
  }
}
export async function signArtifact(input: SignArtifactInput): Promise<ArtifactResult> {
  try {
    const supplied = object(input, ["report", "annexes", "signer"]);
    const signer = object(supplied.signer, ["keyId", "privateKey"]);
    if (
      !(signer.privateKey instanceof KeyObject) ||
      signer.privateKey.type !== "private" ||
      signer.privateKey.asymmetricKeyType !== "ed25519"
    )
      invalid();
    const keyId = text(signer.keyId);
    const publicKey = createPublicKey(signer.privateKey.export({ type: "pkcs8", format: "pem" }));
    if (keyFingerprint(publicKey) !== keyId) invalid();
    const prepared = await prepareArtifact({ report: input.report, annexes: input.annexes });
    const payload = canonicalBytes(prepared.statement);
    const prefix = Buffer.from(
      `DSSEv1 ${Buffer.byteLength(payloadType)} ${payloadType} ${payload.length} `,
    );
    let signature: Buffer;
    try {
      signature = sign(null, Buffer.concat([prefix, Buffer.from(payload)]), signer.privateKey);
    } catch {
      throw new ArtifactError("signing-failed");
    }
    const bundle: SigstoreBundle = {
      mediaType: bundleMediaType,
      verificationMaterial: { publicKey: { hint: keyId }, tlogEntries: [] },
      dsseEnvelope: {
        payloadType,
        payload: base64Encode(payload),
        signatures: [{ keyid: keyId, sig: base64Encode(signature) }],
      },
    };
    return await attachAttestation({ bytes: prepared.bytes, bundle });
  } catch (error) {
    constructionError(error);
  }
}

export async function authenticateArtifact(input: {
  bytes: Uint8Array;
  expectedScanId: string;
  trust: AuthenticationTrust;
}): Promise<AssociationResult> {
  let scanId: string | undefined;
  const refuse = (reason: AssociationReason): AssociationResult => ({
    ...(scanId ? { scanId } : {}),
    status: "unverifiable",
    reason,
  });
  try {
    const supplied = object(input, ["bytes", "expectedScanId", "trust"]);
    const expectedScanId = validScanId(supplied.expectedScanId);
    // Bound and validate selected trust before touching certificates in a bundle.
    const selected = selectTrust(supplied.trust);
    const validated = await validateArtifact(supplied.bytes as Uint8Array);
    scanId = validated.artifact.scanId;
    if (scanId !== expectedScanId) return refuse("id-mismatch");
    const bundle = validated.artifact.attestation;
    if (!bundle) return refuse("unsigned");
    const { bundle: boundedBundle } = validateBundle(bundle);
    const entity = toSignedEntity(bundleFromJSON(boundedBundle));
    if (boundedBundle.verificationMaterial.publicKey) {
      const hint = boundedBundle.verificationMaterial.publicKey.hint;
      const key = selected.keys.get(hint);
      const record = selected.trust.keys.find((value) => value.keyId === hint);
      if (!key || !record) return refuse("untrusted-key");
      try {
        const trust = toTrustMaterial(TrustedRoot.fromJSON({}), (selectedHint) => {
          if (selectedHint !== hint) invalid();
          return { publicKey: key, validFor: () => true };
        });
        new Verifier(trust, { tlogThreshold: 0, ctlogThreshold: 0, timestampThreshold: 0 }).verify(
          entity,
        );
      } catch {
        return refuse("invalid-signature");
      }
      return {
        scanId,
        status: "authenticated",
        producerIdentity: record.identity,
        keyId: hint,
        reportRead: "not-requested",
      };
    }
    const certBytes = decoded(
      boundedBundle.verificationMaterial.certificate?.rawBytes,
      artifactLimits.certificate,
    );
    const certificate = new X509Certificate(certBytes);
    if (
      certificate.publicKey.asymmetricKeyType !== "ec" ||
      certificate.publicKey.asymmetricKeyDetails?.namedCurve !== "prime256v1"
    )
      return refuse("invalid-signature");
    if (selected.trust.publishers.length === 0) return refuse("unknown-producer");
    const matches = new Set<string>();
    let failure: AssociationReason = "unknown-producer";
    for (const publisher of selected.trust.publishers) {
      try {
        const verifier = new Verifier(
          toTrustMaterial(TrustedRoot.fromJSON(publisher.trustedRoot)),
          { tlogThreshold: 1, ctlogThreshold: 1, timestampThreshold: 1 },
        );
        // Upstream treats even strings as patterns. Escape our validated literal
        // policy internally, then also compare the verified identity literally.
        const exactSan = new RegExp(
          `^${publisher.policy.subjectAlternativeName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`,
        );
        const signer = verifier.verify(entity, {
          subjectAlternativeName: exactSan,
          extensions: { issuer: publisher.policy.issuer },
          oids: publisher.policy.requiredCertificateExtensions.map((extension) => ({
            oid: { id: extension.oid },
            value: Buffer.from(decoded(extension.valueDerBase64, 4096)),
          })),
        });
        if (
          signer.identity?.subjectAlternativeName !== publisher.policy.subjectAlternativeName ||
          signer.identity?.extensions?.issuer !== publisher.policy.issuer
        )
          continue;
        matches.add(publisher.identity);
      } catch (error) {
        if (!(error instanceof PolicyError)) failure = "invalid-signature";
      }
    }
    if (matches.size === 1)
      return {
        scanId,
        status: "authenticated",
        producerIdentity: [...matches][0],
        reportRead: "not-requested",
      };
    return refuse(matches.size > 1 ? "unknown-producer" : failure);
  } catch (error) {
    if (error instanceof ArtifactError) return refuse(error.reason);
    if (error instanceof Error && "code" in error && error.code === "resource-limit")
      return refuse("resource-limit");
    return refuse("malformed");
  }
}
