import { z } from "zod";
import { canonicalStrictJsonBytesV1, codeUnitCompare } from "./contract/strict-json-v1.js";
import {
  assertCompleteScanAnnexArtifactsV2,
  isVerifiedScanAttestationV2,
  type ScanAnnexArtifactV2,
  type VerifiedScanAttestationV2,
} from "./observation/scan-attestation-v2.js";

/**
 * Public, Scan-owned reading of genuine existing result and annex records.
 *
 * Scan owns detector and result facts. This reader normalizes only the facts an
 * already-verified `ScanAttestationV2` actually declares, reusing Scan's existing
 * validators so nothing here can accept evidence the verifier rejected.
 *
 * Honesty rules enforced by construction:
 *
 * - only a value produced by `verifyScanAttestationV2` is accepted; a structurally
 *   identical object literal is refused, so a caller cannot forge facts;
 * - detector output bytes (SARIF and the raw OCI annex) are exposed as digest-bound
 *   references and are never parsed, so no severity, message or location is
 *   synthesized from them;
 * - facts the attestation does not state are reported in `gaps`, not defaulted;
 * - a scanner result never carries qualification, approval, installation,
 *   observation or effect authority, and this reader executes nothing.
 */

/** Format of the normalized record returned by this reader. */
export const SCAN_RESULT_RECORD_FORMAT_V1 = "aih-scan-result-record";
export const SCAN_RESULT_RECORD_VERSION_V1 = 1;
export const SCAN_RESULT_SUBJECT_NAME_V1 = "source-tree";

const SHA256_HEX = /^[0-9a-f]{64}$/;

export type ScanResultReadStatusV1 = "available" | "unverified" | "invalid-input";

/** A fact the attestation genuinely declares, or a gap naming why it does not. */
export type ScanResultGapKindV1 =
  | "sarif-not-interpreted"
  | "finding-message-and-location-not-read-from-annex"
  | "severity-not-declared-by-attestation"
  | "annex-and-signing-states-are-declared-not-verified"
  | "no-effect-or-qualification-authority"
  | "ci-claim-set-not-restated";

export interface ScanResultGapV1 {
  readonly kind: ScanResultGapKindV1;
  readonly detail: string;
}

export interface ScanResultObservationV1 {
  readonly rawOccurrenceFingerprint: string;
  readonly multiplicity: number;
}

export interface ScanResultRecordV1 {
  readonly format: typeof SCAN_RESULT_RECORD_FORMAT_V1;
  readonly version: typeof SCAN_RESULT_RECORD_VERSION_V1;
  /** The exact bytes that were scanned, as a bare 64-hex digest. */
  readonly subject: { readonly name: typeof SCAN_RESULT_SUBJECT_NAME_V1; readonly sha256: string };
  readonly signer: {
    readonly identity: string;
    readonly class: "test-ephemeral" | "organization";
    readonly keyId: string;
  };
  readonly replayIdentity: string;
  /**
   * Exactly the claim facts the verifier exposes. The wider CI claim set
   * (repository, workflow, ref, commit, environment, run id) is checked during
   * verification but is not part of the public verified facts, so it is not
   * restated here as though this reader had read it.
   */
  readonly claims: {
    readonly signedAt: string;
    readonly expiresAt: string;
    readonly origin: "signer-asserted";
    readonly provenance: "none";
  };
  /** The exact Core contract this attestation was produced against. */
  readonly coreContract: {
    readonly commit: string;
    readonly decisionSchemaSha256: string;
  };
  readonly run: {
    readonly state: "succeeded" | "failed" | "refused";
    readonly cleanupOutcome: "completed";
    /** Signer-asserted provenance only; this transport carries none. */
    readonly provenance: "none";
  };
  readonly platform: { readonly os: "linux"; readonly architecture: "amd64" };
  readonly coverage: {
    readonly kind: "selected-closure";
    readonly sha256: string;
    readonly complete: true;
  };
  readonly detector: {
    readonly id: string;
    readonly adapterCapability: "cisco-oci-v1";
    readonly analyzerIdentity: string;
    readonly oci: {
      readonly logicalReference: string;
      readonly manifestDigestSha256: string;
      readonly configDigestSha256: string;
    };
    readonly adapter: { readonly identity: string; readonly sha256: string };
    readonly observationConfigurationSha256: string;
    readonly executionProfileSha256: string;
    readonly supportedPlatform: { readonly os: "linux"; readonly architecture: "amd64" };
    readonly sourceSealV1: {
      readonly protocol: "SourceSealV1";
      readonly sourceTreeSha256: string;
      readonly selectedClosureSha256: string;
      readonly sealedSnapshotSha256: string;
    };
    readonly observationCoverage: readonly {
      readonly coverageKind: "selected-closure" | "source-tree";
      readonly coverageSha256: string;
    }[];
  };
  readonly observations: readonly ScanResultObservationV1[];
  /** Individual finding records: an occurrence fingerprint and its multiplicity only. */
  readonly findings: readonly ScanResultObservationV1[];
  readonly evidenceBindings: {
    readonly scannerManifestSha256: string;
    readonly scannerManifestEntrySha256: string;
    readonly runtimeSha256: string;
    readonly configurationSha256: string;
    readonly observationKeySha256: string;
    readonly observationSetSha256: string;
    readonly payloadSha256: string;
    readonly evidenceDigestSha256: string;
    readonly candidateSha256: string;
    readonly sarifSha256: string;
    readonly sarifState: "digest-bound-unverified";
    readonly sbom: {
      readonly mediaType: "application/spdx+json";
      readonly sha256: string;
      readonly state: "digest-bound-unverified";
    };
    readonly provenance: {
      readonly mediaType: "application/vnd.in-toto+json";
      readonly sha256: string;
      readonly state: "digest-bound-unverified";
    };
    readonly brokerIdentity: string;
    readonly brokerEnforcementState: "unverified";
    readonly brokerPolicyDigestSha256: string;
    readonly brokerAppliedFactsSha256: string;
  };
  /** Digest-bound annex references. Bytes are returned only when the caller supplied them. */
  readonly annexes: readonly {
    readonly descriptorId: string;
    readonly sha256: string;
    readonly byteLength: number;
    readonly state: "digest-bound";
    readonly bytes?: Uint8Array;
  }[];
  readonly gaps: readonly ScanResultGapV1[];
}

export type ScanResultReadV1 =
  | { readonly status: "available"; readonly result: ScanResultRecordV1 }
  | { readonly status: "unverified" }
  | { readonly status: "invalid-input"; readonly reason: string };

/**
 * The scanned-content binding Core needs to prove that the evidence it was handed
 * describes the content its governance subject names.
 *
 * This closes the gap where a caller-selected `subjectDigest` was the only link:
 * the digest below comes from the verified attestation itself, never from a caller.
 */
export type ScanResultSubjectBindingV1 =
  | {
      readonly status: "bound";
      readonly subjectName: typeof SCAN_RESULT_SUBJECT_NAME_V1;
      readonly subjectSha256: string;
    }
  | { readonly status: "unverified" };

export interface ReadScanResultSubjectBindingV1Request {
  readonly verified: unknown;
}

export interface ReadScanResultRecordV1Request {
  readonly verified: unknown;
  /** Optional: when supplied, every annex must match the verified descriptors. */
  readonly annexArtifacts?: readonly ScanAnnexArtifactV2[];
  /** Optional: when supplied, must be this attestation's canonical envelope bytes. */
  readonly envelopeBytes?: Uint8Array;
}

const gap = (kind: ScanResultGapKindV1, detail: string): ScanResultGapV1 => ({ kind, detail });

const GAPS: readonly ScanResultGapV1[] = Object.freeze([
  gap(
    "sarif-not-interpreted",
    "The broker SARIF document is bound by digest only. Scan does not parse it here, so no rule, severity, message or location is derived from it.",
  ),
  gap(
    "finding-message-and-location-not-read-from-annex",
    "Per-finding message and location live in the digest-bound raw annex bytes. Read the annex yourself if you need them; this reader will not guess them.",
  ),
  gap(
    "severity-not-declared-by-attestation",
    "The attestation declares occurrence fingerprints and multiplicity, not severity. Absent severity is reported as absent, never defaulted.",
  ),
  gap(
    "annex-and-signing-states-are-declared-not-verified",
    "SBOM, provenance and broker enforcement are digest-bound and unverified as declared by the attestation. Detection also needs a separately verified organisation attestation and enrolment.",
  ),
  gap(
    "no-effect-or-qualification-authority",
    "A scanner result is evidence only. It grants no qualification, approval, installation, observation or effect authority.",
  ),
  gap(
    "ci-claim-set-not-restated",
    "The verifier checks the full CI claim set but publishes only signedAt/expiresAt. Repository, workflow, ref, commit, environment and run identity are therefore not restated here.",
  ),
]);

function freeze<T>(value: T): T {
  return Object.freeze(value);
}

export function readScanResultSubjectBindingV1(
  request: ReadScanResultSubjectBindingV1Request,
): ScanResultSubjectBindingV1 {
  const unverified = freeze({ status: "unverified" as const });
  if (typeof request !== "object" || request === null) return unverified;
  const value = (request as { verified?: unknown }).verified;
  // Only a value minted by verifyScanAttestationV2 may supply a binding.
  if (!isVerifiedScanAttestationV2(value)) return unverified;
  const subject = (value as VerifiedScanAttestationV2).facts.subject;
  if (subject.name !== SCAN_RESULT_SUBJECT_NAME_V1) return unverified;
  if (!SHA256_HEX.test(subject.sha256)) return unverified;
  return freeze({
    status: "bound" as const,
    subjectName: SCAN_RESULT_SUBJECT_NAME_V1,
    subjectSha256: subject.sha256,
  });
}

function invalid(reason: string): ScanResultReadV1 {
  return freeze({ status: "invalid-input" as const, reason });
}

/**
 * Normalizes one already-verified `ScanAttestationV2` into a result record.
 *
 * Returns typed absence for anything that is not verified, and `invalid-input`
 * when supplied annex bytes or envelope bytes contradict the verified value.
 */
export function readScanResultRecordV1(request: ReadScanResultRecordV1Request): ScanResultReadV1 {
  if (typeof request !== "object" || request === null) {
    return freeze({ status: "unverified" as const });
  }
  const { verified } = request;
  if (!isVerifiedScanAttestationV2(verified)) {
    return freeze({ status: "unverified" as const });
  }
  const facts = (verified as VerifiedScanAttestationV2).facts;

  if (request.annexArtifacts !== undefined) {
    if (!Array.isArray(request.annexArtifacts)) return invalid("annex artifacts");
    try {
      assertCompleteScanAnnexArtifactsV2(facts.annexDescriptors, [...request.annexArtifacts]);
    } catch {
      return invalid("annex artifacts do not match the verified descriptors");
    }
  }

  if (request.envelopeBytes !== undefined) {
    if (!(request.envelopeBytes instanceof Uint8Array)) return invalid("envelope bytes");
    // The canonical candidate bytes are recomputable from the verified facts, so a
    // caller cannot substitute unrelated envelope bytes for this attestation.
    try {
      parseEnvelopeCandidateSha256(request.envelopeBytes);
    } catch {
      return invalid("envelope bytes are not a ScanAttestationV2 envelope");
    }
    const candidateDigest = parseEnvelopeCandidateSha256(request.envelopeBytes);
    if (candidateDigest !== facts.candidateSha256) {
      return invalid("envelope bytes describe a different candidate");
    }
  }

  const detector = facts.scanner.detector;
  const annexBytes = new Map<string, Uint8Array>();
  for (const artifact of request.annexArtifacts ?? []) {
    annexBytes.set(artifact.descriptorId, artifact.bytes);
  }

  const observations: ScanResultObservationV1[] = detector.observation.facts.map((fact) => ({
    rawOccurrenceFingerprint: fact.rawOccurrenceFingerprint,
    multiplicity: fact.multiplicity,
  }));

  const result: ScanResultRecordV1 = {
    format: SCAN_RESULT_RECORD_FORMAT_V1,
    version: SCAN_RESULT_RECORD_VERSION_V1,
    subject: freeze({ name: SCAN_RESULT_SUBJECT_NAME_V1, sha256: facts.subject.sha256 }),
    signer: freeze({
      identity: facts.signer.identity,
      class: facts.signer.class,
      keyId: facts.signer.keyId,
    }),
    replayIdentity: facts.replayIdentity,
    claims: freeze({
      signedAt: facts.claims.signedAt,
      expiresAt: facts.claims.expiresAt,
      origin: "signer-asserted" as const,
      provenance: "none" as const,
    }),
    coreContract: freeze({
      commit: facts.coreContract.commit,
      decisionSchemaSha256: facts.coreContract.decisionSchemaSha256,
    }),
    run: freeze({
      state: facts.scan.outcome,
      cleanupOutcome: facts.cleanup.outcome,
      provenance: facts.provenance,
    }),
    platform: freeze({ os: facts.platform.os, architecture: facts.platform.architecture }),
    coverage: freeze({
      kind: facts.coverage.kind,
      sha256: facts.coverage.sha256,
      complete: facts.coverage.complete,
    }),
    detector: freeze({
      id: detector.detectorId,
      adapterCapability: detector.adapterCapability,
      analyzerIdentity: detector.analyzerIdentity,
      oci: freeze({
        logicalReference: detector.oci.logicalReference,
        manifestDigestSha256: detector.oci.manifestDigestSha256,
        configDigestSha256: detector.oci.configDigestSha256,
      }),
      adapter: freeze({ identity: detector.adapter.identity, sha256: detector.adapter.sha256 }),
      observationConfigurationSha256: detector.observationConfigurationSha256,
      executionProfileSha256: detector.executionProfileSha256,
      supportedPlatform: freeze({
        os: detector.supportedPlatform.os,
        architecture: detector.supportedPlatform.architecture,
      }),
      sourceSealV1: freeze({ ...detector.sourceSealV1 }),
      observationCoverage: freeze(
        detector.observation.coverage.map((entry) => freeze({ ...entry })),
      ),
    }),
    observations: freeze(observations),
    findings: freeze(observations.map((observation) => freeze({ ...observation }))),
    evidenceBindings: freeze({
      scannerManifestSha256: facts.scanner.manifestSha256,
      scannerManifestEntrySha256: detector.scannerManifestEntrySha256,
      runtimeSha256: facts.scanner.runtimeSha256,
      configurationSha256: facts.scanner.configurationSha256,
      observationKeySha256: facts.observation.keySha256,
      observationSetSha256: facts.observation.setSha256,
      payloadSha256: facts.payloadSha256,
      evidenceDigestSha256: facts.evidenceDigestSha256,
      candidateSha256: facts.candidateSha256,
      sarifSha256: detector.broker.sarifSha256,
      // The attestation binds the SARIF by digest and declares no interpretation.
      sarifState: "digest-bound-unverified",
      sbom: freeze({
        mediaType: detector.sbom.mediaType,
        sha256: detector.sbom.sha256,
        state: detector.sbom.state,
      }),
      provenance: freeze({
        mediaType: detector.provenance.mediaType,
        sha256: detector.provenance.sha256,
        state: detector.provenance.state,
      }),
      brokerIdentity: detector.broker.identity,
      brokerEnforcementState: detector.broker.enforcementState,
      brokerPolicyDigestSha256: detector.broker.policyDigestSha256,
      brokerAppliedFactsSha256: detector.broker.appliedFactsSha256,
    }),
    annexes: freeze(
      [...facts.annexDescriptors]
        .sort((left, right) => codeUnitCompare(left.descriptorId, right.descriptorId))
        .map((descriptor) => {
          const bytes = annexBytes.get(descriptor.descriptorId);
          return freeze({
            descriptorId: descriptor.descriptorId,
            sha256: descriptor.sha256,
            byteLength: descriptor.byteLength,
            state: "digest-bound" as const,
            ...(bytes === undefined ? {} : { bytes }),
          });
        }),
    ),
    gaps: GAPS,
  };

  return freeze({ status: "available" as const, result: freeze(result) });
}

const envelopeSchema = z
  .object({
    payloadType: z.literal("application/vnd.in-toto+json"),
    payload: z.string(),
  })
  .passthrough();

const statementSchema = z
  .object({
    predicate: z
      .object({
        candidate: z.object({ sha256: z.string().regex(SHA256_HEX) }).strict(),
      })
      .passthrough(),
  })
  .passthrough();

/** Reads only the candidate digest a canonical envelope commits to; nothing else is trusted. */
function parseEnvelopeCandidateSha256(bytes: Uint8Array): string {
  const text = Buffer.from(bytes).toString("utf8");
  if (!Buffer.from(text, "utf8").equals(Buffer.from(bytes))) throw new TypeError("utf8");
  const envelope = envelopeSchema.parse(JSON.parse(text));
  const payloadBytes = Buffer.from(envelope.payload, "base64");
  const canonicalPayload = canonicalStrictJsonBytesV1(JSON.parse(payloadBytes.toString("utf8")));
  if (!canonicalPayload.equals(payloadBytes)) throw new TypeError("noncanonical payload");
  const statement = statementSchema.parse(JSON.parse(payloadBytes.toString("utf8")));
  return statement.predicate.candidate.sha256;
}
