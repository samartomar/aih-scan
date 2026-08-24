import { createHash } from "node:crypto";
import { z } from "zod";
import {
  canonicalStrictJsonBytesV1,
  codeUnitCompare,
  deepFreezeStrictJsonV1,
} from "../contract/strict-json-v1.js";
import {
  isVerifiedScanAttestationV2,
  type VerifiedScanAttestationV2,
} from "../observation/scan-attestation-v2.js";

const subjectDigest = z.string().regex(/^sha256:[0-9a-f]{64}$/);
const envelopeSchema = z
  .object({
    format: z.literal("aih-organization-evidence"),
    version: z.literal(1),
    subjectDigest,
    evidence: z
      .object({
        kind: z.literal("scan-attestation-v2"),
        id: z.literal("scanner-evidence-v2"),
        summary: z.literal(
          "Verified scanner evidence only; not qualification, admission, approval, finding disposition, or effect authority.",
        ),
        payloadDigest: subjectDigest,
        artifactDigests: z.array(subjectDigest).min(1).max(16),
      })
      .strict(),
    attestor: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9:._@/-]{0,255}$/),
    issuedAt: z.string(),
    notBefore: z.string(),
    expiresAt: z.string(),
  })
  .strict();

export type CoreOrganizationEvidenceEnvelopeV1 = Readonly<z.infer<typeof envelopeSchema>>;
const projected = new WeakMap<object, Buffer>();

function fail(reason: string): never {
  throw new TypeError(`invalid Core organization evidence projection: ${reason}`);
}
function ownData(value: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor))
    fail(`${key} must be own enumerable data`);
  return descriptor.value;
}
function exactInput(value: unknown): {
  verified: VerifiedScanAttestationV2;
  subjectDigest: string;
} {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail("input object");
  if (
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.getOwnPropertySymbols(value).length > 0
  )
    fail("input plain data");
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== 2 ||
    keys.some((key) => typeof key !== "string" || (key !== "verified" && key !== "subjectDigest"))
  )
    fail("input fields");
  const verified = ownData(value, "verified");
  const digest = ownData(value, "subjectDigest");
  if (!isVerifiedScanAttestationV2(verified)) fail("verified attestation custody");
  if (!subjectDigest.safeParse(digest).success) fail("Core subject digest");
  return { verified, subjectDigest: digest as string };
}
function prefixed(value: string): string {
  if (!/^[0-9a-f]{64}$/.test(value)) fail("verified digest");
  return `sha256:${value}`;
}
function deterministicAttestor(verified: VerifiedScanAttestationV2): string {
  const signer = verified.facts.signer;
  return `scanner:${createHash("sha256")
    .update(
      canonicalStrictJsonBytesV1({
        domain: "aih.scan-to-core-organization-evidence-v1.attestor",
        signer: { identity: signer.identity, class: signer.class, keyId: signer.keyId },
      }),
    )
    .digest("hex")}`;
}
function artifactDigests(verified: VerifiedScanAttestationV2): string[] {
  const facts = verified.facts;
  const values = [
    prefixed(facts.evidenceDigestSha256),
    prefixed(facts.candidateSha256),
    prefixed(facts.payloadSha256),
    prefixed(facts.subject.sha256),
    prefixed(facts.sourceSeals.before.sourceTreeSha256),
    prefixed(facts.sourceSeals.before.selectedClosureSha256),
    prefixed(facts.sourceSeals.before.sealedSnapshotSha256),
    ...facts.annexDescriptors.map((annex) => prefixed(annex.sha256)),
  ];
  return [...new Set(values)].sort(codeUnitCompare);
}

/**
 * Creates Core-owned evidence bytes only from an already verified V2 attestation.
 * This is evidence projection, not a decision, qualification, approval, or effect.
 */
export function projectVerifiedScanAttestationToCoreEvidenceEnvelopeV1(
  value: unknown,
): CoreOrganizationEvidenceEnvelopeV1 {
  const input = exactInput(value);
  const facts = input.verified.facts;
  if (facts.signer.class !== "organization") fail("organization signer required");
  if (facts.scan.outcome !== "succeeded") fail("successful scan required");
  const result = deepFreezeStrictJsonV1(
    envelopeSchema.parse({
      format: "aih-organization-evidence",
      version: 1,
      subjectDigest: input.subjectDigest,
      evidence: {
        kind: "scan-attestation-v2",
        id: "scanner-evidence-v2",
        summary:
          "Verified scanner evidence only; not qualification, admission, approval, finding disposition, or effect authority.",
        payloadDigest: prefixed(facts.payloadSha256),
        artifactDigests: artifactDigests(input.verified),
      },
      attestor: deterministicAttestor(input.verified),
      issuedAt: facts.claims.signedAt,
      notBefore: facts.claims.signedAt,
      expiresAt: facts.claims.expiresAt,
    }),
  );
  projected.set(result, canonicalStrictJsonBytesV1(result));
  return result;
}

/** Returns the canonical Core schema-compatible bytes for a custody-projected envelope only. */
export function canonicalCoreOrganizationEvidenceEnvelopeV1Bytes(
  value: CoreOrganizationEvidenceEnvelopeV1,
): Buffer {
  if (typeof value !== "object" || value === null) fail("envelope object");
  const bytes = projected.get(value);
  if (bytes === undefined) fail("projected envelope custody");
  return Buffer.from(bytes);
}
