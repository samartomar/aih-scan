/**
 * The offline verification profile `aih-sigstore-keyless/1` (published contract data): the
 * supported evidence form and algorithms, the pinned public trust snapshot shipped in this
 * package with its provenance and SHA-256, and the documented default publishing identity.
 */

/** A caller-selected signer: OIDC issuer and exact certificate subject (SAN), plus optional
 * Fulcio certificate extensions (dotted OID → exact text value) that must also match. */
export interface AllowedSigner {
  /** The caller's attribution label reported back as `signer.identity`; it creates no trust. */
  readonly identity: string;
  readonly issuer: string;
  readonly subject: string;
  readonly extensions?: Readonly<Record<string, string>>;
}

const PUBLISHER_URI =
  "https://github.com/samartomar/aih-scan/.github/workflows/scan-report-publisher.yml@refs/heads/main";

/**
 * The documented default publishing identity: the Scan report publisher workflow on `main` of
 * `samartomar/aih-scan` (repository ID 1336836161, owner ID 9993940), signed through GitHub
 * Actions OIDC, with the complete documented certificate policy. A signer list passed by the
 * caller replaces it; an empty list trusts nobody.
 */
export const defaultSigners: readonly AllowedSigner[] = Object.freeze([
  Object.freeze({
    identity: "aihq-scan-production",
    issuer: "https://token.actions.githubusercontent.com",
    subject: PUBLISHER_URI,
    extensions: Object.freeze({
      "1.3.6.1.4.1.57264.1.9": PUBLISHER_URI,
      "1.3.6.1.4.1.57264.1.11": "github-hosted",
      "1.3.6.1.4.1.57264.1.12": "https://github.com/samartomar/aih-scan",
      "1.3.6.1.4.1.57264.1.14": "refs/heads/main",
      "1.3.6.1.4.1.57264.1.15": "1336836161",
      "1.3.6.1.4.1.57264.1.16": "https://github.com/samartomar",
      "1.3.6.1.4.1.57264.1.17": "9993940",
      "1.3.6.1.4.1.57264.1.18": PUBLISHER_URI,
      "1.3.6.1.4.1.57264.1.20": "workflow_dispatch",
      "1.3.6.1.4.1.57264.1.22": "public",
    }),
  }),
]);

export const verification = Object.freeze({
  profile: "aih-sigstore-keyless/1",
  bundle: Object.freeze({
    mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
    verificationMaterial: "certificate",
    content: "messageSignature",
    messageDigest: "SHA2_256",
    signingKey: "ECDSA P-256 with SHA-256 (DER signature) over the exact supplied bytes",
    refused: Object.freeze([
      "dsseEnvelope",
      "publicKey",
      "x509CertificateChain",
      "other bundle media types",
    ]),
  }),
  encodings: Object.freeze({
    bundle: "Sigstore bundle protobuf JSON (base64 bytes, decimal int64 strings)",
    trustedRoot: Object.freeze([
      "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
      "application/vnd.dev.sigstore.trustedroot.v0.2+json",
    ]),
    certificates: "X.509 v3 DER",
    tlogBodies: Object.freeze(["hashedrekord 0.0.1 (Rekor v1)", "hashedrekord 0.0.2 (Rekor v2)"]),
    timestamps: "RFC 3161 TimeStampResp with CMS SignedData/TSTInfo",
  }),
  algorithms: Object.freeze({
    signingCertificate: "ECDSA P-256 / SHA-256",
    certificateChains:
      "ECDSA P-256 or P-384 with SHA-256, SHA-384 or SHA-512 (as the certificate names)",
    certificateTransparency: "ECDSA P-256 / SHA-256 SCTs (RFC 6962), log id = SHA-256 of the key",
    transparencyLogs: Object.freeze([
      "PKIX_ECDSA_P256_SHA_256 (signed entry timestamp and checkpoint)",
      "PKIX_ED25519 (checkpoint)",
    ]),
    merkleTree: "RFC 6962 SHA-256 inclusion proofs",
    timestampAuthorities:
      "ECDSA P-256 or P-384 with SHA-256, SHA-384 or SHA-512; imprint SHA-256/384/512",
    unsupported: "refused with reason unsupported-algorithm",
  }),
  rules: Object.freeze([
    "fresh SHA-256 of the supplied bytes equals the bundle's message digest and the signature verifies",
    "the signing certificate chains to a selected Fulcio CA valid at every authenticated signing time",
    "at least one embedded SCT verifies under a selected CT log",
    "every transparency-log entry binds the digest, certificate and signature and has a verified inclusion proof and signed checkpoint",
    "at least one authenticated signing time (Rekor signed entry timestamp or RFC 3161) within the certificate's validity",
    "certificates and proofs inside a bundle are evidence, never trust anchors; no network access",
  ]),
  trustSnapshot: Object.freeze({
    description: "Sigstore public-good instance trusted root",
    source: "https://tuf-repo-cdn.sigstore.dev",
    obtainedThrough:
      "authenticated TUF update from the embedded bootstrap root (sigstore-python 4.5.1, python-tuf 7.0.1)",
    target: "trusted_root.json",
    rootVersion: 16,
    targetsVersion: 14,
    snapshotVersion: 166,
    timestampVersion: 823,
    fetchedAt: "2026-11-01",
    mediaType: "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
    length: 6787,
    sha256: "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66",
    note: "authenticates evidence under this material only; no live revocation, freshness or withdrawal discovery",
  }),
});

export type Verification = typeof verification;
