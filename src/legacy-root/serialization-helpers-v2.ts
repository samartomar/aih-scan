// Deprecated root bindings for low-level serialization helpers.
//
// These helpers were exported from the `@aihq/scan` root in 0.4.0. They are
// internal serialization details with no supported use outside Scan, and stay on
// the root only for compatibility. Each binding is the same function the internal
// implementation uses, so behavior is unchanged.
import { canonicalCoreOrganizationEvidenceEnvelopeV1Bytes as coreEnvelopeBytes } from "../core/organization-evidence-envelope-v1.js";
import {
  assertCompleteScanAnnexArtifactsV2 as assertAnnexes,
  canonicalScanAttestationEnvelopeBytesV2 as attestationEnvelopeBytes,
  canonicalScanCandidateBytesV2 as candidateBytes,
  canonicalDssePaeV2 as dssePae,
  isVerifiedScanAttestationV2 as isVerified,
  ed25519KeyIdV2 as keyId,
  canonicalSourceSealsV2Bytes as sourceSealsBytes,
} from "../observation/scan-attestation-v2.js";
import { canonicalDetectorRegistrationV1Bytes as registrationBytes } from "../registration/detector-registration-v1.js";

/**
 * @deprecated Internal serialization helper; no supported use outside Scan;
 * scheduled for removal with the legacy root window.
 */
export const assertCompleteScanAnnexArtifactsV2: typeof assertAnnexes = assertAnnexes;

/**
 * @deprecated Internal serialization helper; no supported use outside Scan;
 * scheduled for removal with the legacy root window.
 */
export const canonicalDssePaeV2: typeof dssePae = dssePae;

/**
 * @deprecated Internal serialization helper; no supported use outside Scan;
 * scheduled for removal with the legacy root window.
 */
export const canonicalScanAttestationEnvelopeBytesV2: typeof attestationEnvelopeBytes =
  attestationEnvelopeBytes;

/**
 * @deprecated Internal serialization helper; no supported use outside Scan;
 * scheduled for removal with the legacy root window.
 */
export const canonicalScanCandidateBytesV2: typeof candidateBytes = candidateBytes;

/**
 * @deprecated Internal serialization helper; no supported use outside Scan;
 * scheduled for removal with the legacy root window.
 */
export const canonicalSourceSealsV2Bytes: typeof sourceSealsBytes = sourceSealsBytes;

/**
 * @deprecated Internal serialization helper; no supported use outside Scan;
 * scheduled for removal with the legacy root window.
 */
export const ed25519KeyIdV2: typeof keyId = keyId;

/**
 * @deprecated Internal serialization helper; no supported use outside Scan;
 * scheduled for removal with the legacy root window.
 */
export const isVerifiedScanAttestationV2: typeof isVerified = isVerified;

/**
 * @deprecated Internal serialization helper; no supported use outside Scan;
 * scheduled for removal with the legacy root window.
 */
export const canonicalCoreOrganizationEvidenceEnvelopeV1Bytes: typeof coreEnvelopeBytes =
  coreEnvelopeBytes;

/**
 * @deprecated Internal serialization helper; no supported use outside Scan;
 * scheduled for removal with the legacy root window.
 */
export const canonicalDetectorRegistrationV1Bytes: typeof registrationBytes = registrationBytes;
