import { createHash, KeyObject, sign as signDetached, verify as verifyDetached } from "node:crypto";
import { z } from "zod";
import {
  assertStrictJsonValueV1,
  canonicalStrictJsonBytesV1,
  deepFreezeStrictJsonV1,
  parseStrictJsonObjectV1,
} from "../contract/strict-json-v1.js";
import { canonicalDssePaeV2, ed25519KeyIdV2 } from "../observation/scan-attestation-v2.js";
import {
  type BaselineVetBatchResultV1,
  type BaselineVetRequestV1,
  canonicalBaselineVetRequestV1Bytes,
  verifyBaselineVetReceiptV1,
} from "./batch-v1.js";

const sha256 = z.string().regex(/^[0-9a-f]{64}$/);
const receiptReplayBinding = z.object({ requestSha256: sha256, receiptSha256: sha256 }).strict();
const keyId = z.string().regex(/^ed25519:[0-9a-f]{64}$/);
const identity = z
  .string()
  .min(1)
  .max(256)
  .regex(/^[A-Za-z0-9][A-Za-z0-9@/.:_-]*$/);
const signer = z
  .object({
    identity,
    class: z.enum(["test-ephemeral", "organization"]),
    keyId,
  })
  .strict();
const claims = z
  .object({
    signedAt: z.string(),
    expiresAt: z.string(),
  })
  .strict();
const statement = z
  .object({
    _type: z.literal("https://in-toto.io/Statement/v1"),
    subject: z
      .array(
        z
          .object({
            name: z.literal("baseline-vet-receipt"),
            digest: z.object({ sha256 }).strict(),
          })
          .strict(),
      )
      .length(1),
    predicateType: z.literal("https://aih.dev/BaselineVetAttestationV1"),
    predicate: z
      .object({
        protocol: z.literal("BaselineVetAttestationV1"),
        requestSha256: sha256,
        receiptSha256: sha256,
        signer,
        claims: claims
          .extend({
            origin: z.literal("signer-asserted"),
            provenance: z.literal("none"),
          })
          .strict(),
      })
      .strict(),
  })
  .strict();
const envelope = z
  .object({
    payloadType: z.literal("application/vnd.in-toto+json"),
    payload: z.string(),
    signatures: z.array(z.object({ keyid: keyId, sig: z.string() }).strict()).length(1),
  })
  .strict();

export type BaselineVetTrustRootV1 = Readonly<{
  identity: string;
  class: "test-ephemeral" | "organization";
  keyId: string;
  publicKey: KeyObject;
}>;
export type SignedBaselineVetAttestationV1 = Readonly<{
  protocol: "BaselineVetAttestationV1";
  envelope: Readonly<z.infer<typeof envelope>>;
  payloadSha256: string;
  evidenceDigestSha256: string;
}>;
export type VerifiedBaselineVetAttestationV1 = Readonly<{
  facts: Readonly<{
    protocol: "BaselineVetAttestationV1";
    envelopeValid: true;
    authority: "none";
    provenance: "none";
    requestSha256: string;
    receiptSha256: string;
    payloadSha256: string;
    evidenceDigestSha256: string;
    signer: Readonly<z.infer<typeof signer>>;
    claims: Readonly<z.infer<typeof claims>>;
    annexesComplete: true;
  }>;
}>;

const signed = new WeakMap<object, Buffer>();

function fail(reason: string): never {
  throw new TypeError(`invalid BaselineVetAttestationV1: ${reason}`);
}
function digest(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}
function ownData(value: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !("value" in descriptor)) fail(`${key} must be own data`);
  return descriptor.value;
}
function exactKeys(value: object, allowed: readonly string[], label: string): void {
  if (Object.getPrototypeOf(value) !== Object.prototype) fail(`${label} plain data`);
  const keys = Reflect.ownKeys(value);
  if (keys.length !== allowed.length || allowed.some((key) => !keys.includes(key)))
    fail(`${label} fields`);
  for (const key of allowed) ownData(value, key);
}
function canonicalBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}
function decodeBase64(value: string, label: string, maximum = 2 * 1024 * 1024): Buffer {
  if (
    value.length === 0 ||
    value.length % 4 !== 0 ||
    value.length > Math.ceil(maximum / 3) * 4 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
  )
    fail(`${label} base64`);
  const bytes = Buffer.from(value, "base64");
  if (bytes.byteLength > maximum || canonicalBase64(bytes) !== value) fail(`${label} base64`);
  return bytes;
}
function exactTime(value: string, label: string): number {
  if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value)) fail(`${label} time`);
  const epoch = Date.parse(value);
  if (!Number.isFinite(epoch) || new Date(epoch).toISOString() !== value) fail(`${label} time`);
  return epoch;
}
function parsedClaims(value: unknown): z.infer<typeof claims> {
  assertStrictJsonValueV1(value, "baseline attestation claims");
  const parsed = claims.parse(structuredClone(value));
  const signedAt = exactTime(parsed.signedAt, "signedAt");
  const expiresAt = exactTime(parsed.expiresAt, "expiresAt");
  if (expiresAt <= signedAt || expiresAt - signedAt > 24 * 60 * 60 * 1000) fail("claims expiry");
  return parsed;
}
function parsedReceiptBindings(value: unknown) {
  assertStrictJsonValueV1(value, "seen receipt bindings");
  return z.array(receiptReplayBinding).max(10_000).parse(structuredClone(value));
}
function assertComplete(
  request: BaselineVetRequestV1,
  result: BaselineVetBatchResultV1,
  seenReceiptBindings: readonly z.infer<typeof receiptReplayBinding>[] = [],
): void {
  canonicalBaselineVetRequestV1Bytes(request);
  if (verifyBaselineVetReceiptV1(request, result, seenReceiptBindings).kind !== "complete")
    fail("receipt and annex verification");
}

export function signBaselineVetBundleV1(value: unknown): SignedBaselineVetAttestationV1 {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail("sign input");
  exactKeys(value, ["request", "result", "signer", "claims"], "sign input");
  const request = ownData(value, "request") as BaselineVetRequestV1;
  const result = ownData(value, "result") as BaselineVetBatchResultV1;
  assertComplete(request, result);
  const rawSigner = ownData(value, "signer");
  if (typeof rawSigner !== "object" || rawSigner === null || Array.isArray(rawSigner))
    fail("signer object");
  exactKeys(rawSigner, ["identity", "class", "keyId", "privateKey"], "signer");
  const parsedSigner = signer.parse({
    identity: ownData(rawSigner, "identity"),
    class: ownData(rawSigner, "class"),
    keyId: ownData(rawSigner, "keyId"),
  });
  const privateKey = ownData(rawSigner, "privateKey");
  if (
    !(privateKey instanceof KeyObject) ||
    privateKey.type !== "private" ||
    privateKey.asymmetricKeyType !== "ed25519"
  )
    fail("Ed25519 private key");
  if (ed25519KeyIdV2(privateKey) !== parsedSigner.keyId) fail("signer key fingerprint");
  const parsedClaim = parsedClaims(ownData(value, "claims"));
  const payload = canonicalStrictJsonBytesV1(
    statement.parse({
      _type: "https://in-toto.io/Statement/v1",
      subject: [{ name: "baseline-vet-receipt", digest: { sha256: result.receipt.receiptSha256 } }],
      predicateType: "https://aih.dev/BaselineVetAttestationV1",
      predicate: {
        protocol: "BaselineVetAttestationV1",
        requestSha256: request.requestSha256,
        receiptSha256: result.receipt.receiptSha256,
        signer: parsedSigner,
        claims: { ...parsedClaim, origin: "signer-asserted", provenance: "none" },
      },
    }),
  );
  const signature = signDetached(
    null,
    canonicalDssePaeV2("application/vnd.in-toto+json", payload),
    privateKey,
  );
  if (signature.byteLength !== 64) fail("signature length");
  const parsedEnvelope = envelope.parse({
    payloadType: "application/vnd.in-toto+json",
    payload: canonicalBase64(payload),
    signatures: [{ keyid: parsedSigner.keyId, sig: canonicalBase64(signature) }],
  });
  const resultValue = deepFreezeStrictJsonV1({
    protocol: "BaselineVetAttestationV1" as const,
    envelope: parsedEnvelope,
    payloadSha256: digest(payload),
    evidenceDigestSha256: digest(canonicalStrictJsonBytesV1(parsedEnvelope)),
  });
  signed.set(resultValue, canonicalStrictJsonBytesV1(parsedEnvelope));
  return resultValue;
}

export function canonicalBaselineVetAttestationEnvelopeV1Bytes(
  value: SignedBaselineVetAttestationV1,
): Buffer {
  const bytes = typeof value === "object" && value !== null ? signed.get(value) : undefined;
  if (bytes === undefined) fail("signed evidence custody");
  return Buffer.from(bytes);
}

function parseEnvelope(value: unknown): {
  envelope: z.infer<typeof envelope>;
  statement: z.infer<typeof statement>;
  payload: Buffer;
  payloadSha256: string;
  evidenceDigestSha256: string;
} {
  assertStrictJsonValueV1(value, "baseline attestation envelope");
  const parsedEnvelope = envelope.parse(structuredClone(value));
  const payload = decodeBase64(parsedEnvelope.payload, "payload");
  const payloadObject = parseStrictJsonObjectV1(payload.toString("utf8"), "baseline statement");
  if (!canonicalStrictJsonBytesV1(payloadObject).equals(payload)) fail("payload canonical wire");
  return {
    envelope: parsedEnvelope,
    statement: statement.parse(payloadObject),
    payload,
    payloadSha256: digest(payload),
    evidenceDigestSha256: digest(canonicalStrictJsonBytesV1(parsedEnvelope)),
  };
}

export function parseBaselineVetAttestationEnvelopeV1Json(
  text: string,
): Readonly<z.infer<typeof envelope>> {
  const parsed = parseEnvelope(parseStrictJsonObjectV1(text, "BaselineVetAttestationV1 envelope"));
  if (!Buffer.from(text, "utf8").equals(canonicalStrictJsonBytesV1(parsed.envelope)))
    fail("envelope canonical wire");
  return deepFreezeStrictJsonV1(parsed.envelope);
}

export function verifyBaselineVetAttestationV1(value: unknown): VerifiedBaselineVetAttestationV1 {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail("verify input");
  exactKeys(
    value,
    [
      "envelope",
      "request",
      "result",
      "roots",
      "expected",
      "seenEvidenceDigests",
      "seenReceiptBindings",
    ],
    "verify input",
  );
  const request = ownData(value, "request") as BaselineVetRequestV1;
  const result = ownData(value, "result") as BaselineVetBatchResultV1;
  const seenReceiptBindings = parsedReceiptBindings(ownData(value, "seenReceiptBindings"));
  assertComplete(request, result, seenReceiptBindings);
  const parsed = parseEnvelope(ownData(value, "envelope"));
  if (
    parsed.statement.subject[0]?.digest.sha256 !== result.receipt.receiptSha256 ||
    parsed.statement.predicate.requestSha256 !== request.requestSha256 ||
    parsed.statement.predicate.receiptSha256 !== result.receipt.receiptSha256
  )
    fail("request or receipt binding");
  const expectedValue = ownData(value, "expected");
  if (typeof expectedValue !== "object" || expectedValue === null || Array.isArray(expectedValue))
    fail("expected object");
  exactKeys(expectedValue, ["now", "signer"], "expected");
  const now = ownData(expectedValue, "now");
  const expectedSigner = signer.parse(ownData(expectedValue, "signer"));
  if (typeof now !== "string") fail("expected now");
  const signedAt = exactTime(parsed.statement.predicate.claims.signedAt, "signedAt");
  const expiresAt = exactTime(parsed.statement.predicate.claims.expiresAt, "expiresAt");
  const nowEpoch = exactTime(now, "now");
  if (expiresAt <= signedAt || expiresAt - signedAt > 24 * 60 * 60 * 1000) fail("claims expiry");
  if (nowEpoch < signedAt || nowEpoch > expiresAt) fail("evidence freshness");
  if (
    canonicalStrictJsonBytesV1(expectedSigner).compare(
      canonicalStrictJsonBytesV1(parsed.statement.predicate.signer),
    ) !== 0
  )
    fail("expected signer");
  const roots = ownData(value, "roots");
  if (!Array.isArray(roots) || roots.length === 0 || roots.length > 64) fail("roots");
  const matching = roots.filter((root) => {
    if (typeof root !== "object" || root === null || Array.isArray(root)) fail("root object");
    exactKeys(root, ["identity", "class", "keyId", "publicKey"], "root");
    return (
      ownData(root, "identity") === expectedSigner.identity &&
      ownData(root, "class") === expectedSigner.class &&
      ownData(root, "keyId") === expectedSigner.keyId
    );
  }) as BaselineVetTrustRootV1[];
  if (matching.length !== 1) fail("trusted signer root");
  const root = matching[0] as BaselineVetTrustRootV1;
  if (
    !(root.publicKey instanceof KeyObject) ||
    root.publicKey.type !== "public" ||
    root.publicKey.asymmetricKeyType !== "ed25519" ||
    ed25519KeyIdV2(root.publicKey) !== expectedSigner.keyId
  )
    fail("trusted public key");
  const signatureValue = parsed.envelope.signatures[0];
  if (signatureValue?.keyid !== expectedSigner.keyId) fail("signature key");
  const signature = decodeBase64(signatureValue.sig, "signature", 64);
  if (
    signature.byteLength !== 64 ||
    !verifyDetached(
      null,
      canonicalDssePaeV2(parsed.envelope.payloadType, parsed.payload),
      root.publicKey,
      signature,
    )
  )
    fail("signature");
  const seen = ownData(value, "seenEvidenceDigests");
  assertStrictJsonValueV1(seen, "seen evidence digests");
  const parsedSeen = z.array(sha256).max(10_000).parse(structuredClone(seen));
  if (new Set(parsedSeen).size !== parsedSeen.length) fail("duplicate replay entry");
  if (parsedSeen.includes(parsed.evidenceDigestSha256)) fail("replayed evidence");
  return deepFreezeStrictJsonV1({
    facts: {
      protocol: "BaselineVetAttestationV1" as const,
      envelopeValid: true as const,
      authority: "none" as const,
      provenance: "none" as const,
      requestSha256: request.requestSha256,
      receiptSha256: result.receipt.receiptSha256,
      payloadSha256: parsed.payloadSha256,
      evidenceDigestSha256: parsed.evidenceDigestSha256,
      signer: expectedSigner,
      claims: {
        signedAt: parsed.statement.predicate.claims.signedAt,
        expiresAt: parsed.statement.predicate.claims.expiresAt,
      },
      annexesComplete: true as const,
    },
  });
}
