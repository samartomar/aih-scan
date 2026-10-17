// Deprecated root bindings for retired baseline production.
//
// New baseline production is retired. These names stay on the `@aihq/scan` root
// only for compatibility while existing callers migrate. Each binding is the same
// function or value the internal implementation uses, so behavior is unchanged.
// Historical baseline readers and verifiers are not deprecated and are exported
// directly from src/index.ts.
import {
  canonicalBaselineVetAttestationEnvelopeV1Bytes as attestationEnvelopeBytes,
  signBaselineVetBundleV1 as signBundle,
} from "../baseline/attestation-v1.js";
import {
  BASELINE_ANALYZERS_V1 as analyzers,
  createBaselineVetRequestV1 as createRequest,
  canonicalBaselineVetReceiptV1Bytes as receiptBytes,
  canonicalBaselineVetRequestV1Bytes as requestBytes,
} from "../baseline/batch-v1.js";
import {
  createBaselineVetDiscoveryV1 as createDiscovery,
  createBaselineVetPublicationV1 as createPublication,
  canonicalBaselineVetDiscoveryV1Bytes as discoveryBytes,
  canonicalBaselineVetPublicationV1Bytes as publicationBytes,
} from "../baseline/publication-v1.js";

/**
 * @deprecated New baseline production is retired. Run assessments with `runScan`
 * from `@aihq/scan/host`; read historical baseline evidence with the retained root
 * readers.
 */
export const BASELINE_ANALYZERS_V1: typeof analyzers = analyzers;

/**
 * @deprecated New baseline production is retired. Run assessments with `runScan`
 * from `@aihq/scan/host`; read historical requests with `parseBaselineVetRequestV1Json`.
 */
export const createBaselineVetRequestV1: typeof createRequest = createRequest;

/**
 * @deprecated New baseline production is retired. Run assessments with `runScan`
 * from `@aihq/scan/host`; read historical requests with `parseBaselineVetRequestV1Json`.
 */
export const canonicalBaselineVetRequestV1Bytes: typeof requestBytes = requestBytes;

/**
 * @deprecated New baseline production is retired. Run assessments with `runScan`
 * from `@aihq/scan/host`; read historical receipts with `parseBaselineVetReceiptV1Json`.
 */
export const canonicalBaselineVetReceiptV1Bytes: typeof receiptBytes = receiptBytes;

/**
 * @deprecated New baseline production is retired. Sign new evidence with
 * `prepareArtifact` and `signArtifact` from `@aihq/scan/host`; verify historical
 * baseline attestations with `verifyBaselineVetAttestationV1`.
 */
export const signBaselineVetBundleV1: typeof signBundle = signBundle;

/**
 * @deprecated New baseline production is retired. Sign new evidence with
 * `prepareArtifact` and `signArtifact` from `@aihq/scan/host`; read historical
 * envelopes with `parseBaselineVetAttestationEnvelopeV1Json`.
 */
export const canonicalBaselineVetAttestationEnvelopeV1Bytes: typeof attestationEnvelopeBytes =
  attestationEnvelopeBytes;

/**
 * @deprecated New baseline production is retired. Publish new evidence as a
 * portable artifact from `prepareArtifact` in `@aihq/scan/host`; read historical
 * publications with `parseBaselineVetPublicationV1Json`.
 */
export const createBaselineVetPublicationV1: typeof createPublication = createPublication;

/**
 * @deprecated New baseline production is retired. Publish new evidence as a
 * portable artifact from `prepareArtifact` in `@aihq/scan/host`; read historical
 * publications with `parseBaselineVetPublicationV1Json`.
 */
export const canonicalBaselineVetPublicationV1Bytes: typeof publicationBytes = publicationBytes;

/**
 * @deprecated New baseline production is retired. Publish new evidence as a
 * portable artifact from `prepareArtifact` in `@aihq/scan/host`; resolve historical
 * discoveries with `parseBaselineVetDiscoveryV1Json` and `resolveBaselineVetDiscoveryV1`.
 */
export const createBaselineVetDiscoveryV1: typeof createDiscovery = createDiscovery;

/**
 * @deprecated New baseline production is retired. Publish new evidence as a
 * portable artifact from `prepareArtifact` in `@aihq/scan/host`; resolve historical
 * discoveries with `parseBaselineVetDiscoveryV1Json` and `resolveBaselineVetDiscoveryV1`.
 */
export const canonicalBaselineVetDiscoveryV1Bytes: typeof discoveryBytes = discoveryBytes;
