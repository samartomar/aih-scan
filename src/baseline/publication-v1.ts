import { createHash, createPublicKey, type KeyObject } from "node:crypto";
import { z } from "zod";
import {
  assertStrictJsonValueV1,
  canonicalStrictJsonBytesV1,
  canonicalStrictJsonSha256V1,
  deepFreezeStrictJsonV1,
  parseStrictJsonObjectV1,
} from "../contract/strict-json-v1.js";
import { ed25519KeyIdV2 } from "../observation/scan-attestation-v2.js";
import {
  type BaselineVetTrustRootV1,
  parseBaselineVetAttestationEnvelopeV1Json,
  type SignedBaselineVetAttestationV1,
  verifyBaselineVetAttestationV1,
} from "./attestation-v1.js";
import {
  type BaselineVetBatchResultV1,
  type BaselineVetRequestV1,
  canonicalBaselineVetReceiptV1Bytes,
  canonicalBaselineVetRequestV1Bytes,
  parseBaselineVetReceiptV1Json,
  parseBaselineVetRequestV1Json,
  verifyBaselineVetReceiptV1,
} from "./batch-v1.js";

const SHA256 = /^[0-9a-f]{64}$/;
const MAX_ANNEX_BYTES = 16 * 1024 * 1024;
const MAX_PUBLICATION_BYTES = 96 * 1024 * 1024;
const MAX_DISCOVERY_BYTES = 8 * 1024;
const MAX_BASE64_LENGTH = Math.ceil(MAX_ANNEX_BYTES / 3) * 4;

const annexWire = z
  .object({
    path: z.string().min(1).max(1_024),
    bytesBase64: z.string().min(4).max(MAX_BASE64_LENGTH),
  })
  .strict();

const signerWire = z
  .object({
    identity: z
      .string()
      .min(1)
      .max(256)
      .regex(/^[A-Za-z0-9][A-Za-z0-9@/.:_-]*$/),
    class: z.enum(["test-ephemeral", "organization"]),
    keyId: z.string().regex(/^ed25519:[0-9a-f]{64}$/),
  })
  .strict();

const verificationWire = z
  .object({
    root: signerWire.extend({ publicKeySpkiBase64: z.string().min(4).max(1_024) }).strict(),
    expected: z.object({ now: z.string(), signer: signerWire }).strict(),
  })
  .strict();

const publicationWire = z
  .object({
    protocol: z.literal("BaselineVetPublicationV1"),
    request: z.record(z.string(), z.unknown()),
    receipt: z.record(z.string(), z.unknown()),
    annexes: z.array(annexWire).min(1).max(4),
    envelope: z.record(z.string(), z.unknown()),
    verification: verificationWire,
  })
  .strict();

const discoveryWire = z
  .object({
    protocol: z.literal("BaselineVetDiscoveryV1"),
    authority: z.literal("none"),
    requestSha256: z.string().regex(SHA256),
    receiptSha256: z.string().regex(SHA256),
    evidenceDigestSha256: z.string().regex(SHA256),
    publicationSha256: z.string().regex(SHA256),
    locator: z.string().min(1).max(2_048),
  })
  .strict();

type PortableVerificationV1 = Readonly<{
  root: Readonly<z.infer<typeof verificationWire>["root"]>;
  expected: Readonly<z.infer<typeof verificationWire>["expected"]>;
}>;

export type BaselineVetPublicationV1 = Readonly<{
  protocol: "BaselineVetPublicationV1";
  request: BaselineVetRequestV1;
  receipt: BaselineVetBatchResultV1["receipt"];
  annexes: readonly Readonly<{ path: string; bytesBase64: string }>[];
  envelope: SignedBaselineVetAttestationV1["envelope"];
  verification: PortableVerificationV1;
}>;
export type BaselineVetDiscoveryV1 = Readonly<z.infer<typeof discoveryWire>>;

function fail(reason: string): never {
  throw new TypeError(`invalid baseline publication: ${reason}`);
}

function digest(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function canonicalJson(value: unknown): string {
  return canonicalStrictJsonBytesV1(value).toString("utf8");
}

function decodeCanonicalBase64(value: string): Buffer {
  if (
    value.length === 0 ||
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
  )
    fail("annex base64");
  const bytes = Buffer.from(value, "base64");
  if (
    bytes.byteLength === 0 ||
    bytes.byteLength > MAX_ANNEX_BYTES ||
    bytes.toString("base64") !== value
  )
    fail("annex base64");
  return bytes;
}

function portableRoot(value: z.infer<typeof verificationWire>["root"]): BaselineVetTrustRootV1 {
  const bytes = decodeCanonicalBase64(value.publicKeySpkiBase64);
  let publicKey: KeyObject;
  try {
    publicKey = createPublicKey({ key: bytes, format: "der", type: "spki" });
  } catch {
    return fail("verification public key");
  }
  if (
    publicKey.asymmetricKeyType !== "ed25519" ||
    ed25519KeyIdV2(publicKey) !== value.keyId ||
    !Buffer.from(publicKey.export({ format: "der", type: "spki" })).equals(bytes)
  )
    fail("verification public key");
  return Object.freeze({
    identity: value.identity,
    class: value.class,
    keyId: value.keyId,
    publicKey,
  });
}

function safeLocator(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return fail("locator");
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.port !== "" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.hostname === "" ||
    parsed.href !== value
  )
    fail("locator");
  return value;
}

function normalizePublication(value: unknown): BaselineVetPublicationV1 {
  assertStrictJsonValueV1(value, "BaselineVetPublicationV1");
  const parsed = publicationWire.parse(structuredClone(value));
  const request = parseBaselineVetRequestV1Json(canonicalJson(parsed.request));
  const receipt = parseBaselineVetReceiptV1Json(canonicalJson(parsed.receipt));
  const envelope = parseBaselineVetAttestationEnvelopeV1Json(canonicalJson(parsed.envelope));
  portableRoot(parsed.verification.root);
  const annexArtifacts = parsed.annexes.map((annex) => ({
    path: annex.path,
    bytes: decodeCanonicalBase64(annex.bytesBase64),
  }));
  const result = { receipt, annexArtifacts };
  if (verifyBaselineVetReceiptV1(request, result, []).kind !== "complete")
    fail("receipt or annex binding");
  const expectedPaths = receipt.observations.map((observation) => observation.annex.path);
  if (
    parsed.annexes.length !== expectedPaths.length ||
    parsed.annexes.some((annex, index) => annex.path !== expectedPaths[index])
  )
    fail("annex order");
  return deepFreezeStrictJsonV1({
    protocol: "BaselineVetPublicationV1" as const,
    request,
    receipt,
    annexes: parsed.annexes.map((annex) => ({
      path: annex.path,
      bytesBase64: annex.bytesBase64,
    })),
    envelope,
    verification: {
      root: parsed.verification.root,
      expected: parsed.verification.expected,
    },
  }) as BaselineVetPublicationV1;
}

export function createBaselineVetPublicationV1(input: {
  readonly request: BaselineVetRequestV1;
  readonly result: BaselineVetBatchResultV1;
  readonly envelope: unknown;
  readonly roots: readonly BaselineVetTrustRootV1[];
  readonly expected: {
    readonly now: string;
    readonly signer: {
      readonly identity: string;
      readonly class: "test-ephemeral" | "organization";
      readonly keyId: string;
    };
  };
  readonly seenEvidenceDigests: readonly string[];
  readonly seenReceiptBindings: readonly Readonly<{
    requestSha256: string;
    receiptSha256: string;
  }>[];
}): BaselineVetPublicationV1 {
  verifyBaselineVetAttestationV1(input);
  const matchingRoot = input.roots.find(
    (root) =>
      root.identity === input.expected.signer.identity &&
      root.class === input.expected.signer.class &&
      root.keyId === input.expected.signer.keyId,
  );
  if (matchingRoot === undefined) fail("verification root");
  const byPath = new Map(input.result.annexArtifacts.map((annex) => [annex.path, annex.bytes]));
  return normalizePublication({
    protocol: "BaselineVetPublicationV1",
    request: JSON.parse(canonicalBaselineVetRequestV1Bytes(input.request).toString("utf8")),
    receipt: JSON.parse(canonicalBaselineVetReceiptV1Bytes(input.result.receipt).toString("utf8")),
    annexes: input.result.receipt.observations.map((observation) => {
      const bytes = byPath.get(observation.annex.path);
      if (bytes === undefined) fail(`missing annex ${observation.analyzer}`);
      return { path: observation.annex.path, bytesBase64: bytes.toString("base64") };
    }),
    envelope: input.envelope,
    verification: {
      root: {
        identity: matchingRoot.identity,
        class: matchingRoot.class,
        keyId: matchingRoot.keyId,
        publicKeySpkiBase64: Buffer.from(
          matchingRoot.publicKey.export({ format: "der", type: "spki" }),
        ).toString("base64"),
      },
      expected: input.expected,
    },
  });
}

export function canonicalBaselineVetPublicationV1Bytes(value: BaselineVetPublicationV1): Buffer {
  return canonicalStrictJsonBytesV1(normalizePublication(value));
}

export function parseBaselineVetPublicationV1Json(text: string): BaselineVetPublicationV1 {
  if (
    Buffer.byteLength(text, "utf8") === 0 ||
    Buffer.byteLength(text, "utf8") > MAX_PUBLICATION_BYTES
  )
    fail("publication size");
  const parsed = normalizePublication(parseStrictJsonObjectV1(text, "BaselineVetPublicationV1"));
  if (!Buffer.from(text, "utf8").equals(canonicalStrictJsonBytesV1(parsed)))
    fail("publication canonical wire");
  return parsed;
}

export function baselineVetPublicationResultV1(publication: BaselineVetPublicationV1): Readonly<{
  request: BaselineVetRequestV1;
  result: BaselineVetBatchResultV1;
  envelope: BaselineVetPublicationV1["envelope"];
  roots: readonly BaselineVetTrustRootV1[];
  expected: BaselineVetPublicationV1["verification"]["expected"];
}> {
  const parsed = normalizePublication(publication);
  return Object.freeze({
    request: parsed.request as BaselineVetRequestV1,
    result: Object.freeze({
      receipt: parsed.receipt,
      annexArtifacts: Object.freeze(
        parsed.annexes.map((annex) => ({
          path: annex.path,
          bytes: decodeCanonicalBase64(annex.bytesBase64),
        })),
      ),
    }),
    envelope: parsed.envelope,
    roots: Object.freeze([portableRoot(parsed.verification.root)]),
    expected: parsed.verification.expected,
  });
}

function normalizeDiscovery(value: unknown): BaselineVetDiscoveryV1 {
  assertStrictJsonValueV1(value, "BaselineVetDiscoveryV1");
  const parsed = discoveryWire.parse(structuredClone(value));
  safeLocator(parsed.locator);
  return deepFreezeStrictJsonV1(parsed);
}

export function createBaselineVetDiscoveryV1(input: {
  readonly publication: BaselineVetPublicationV1;
  readonly locator: string;
}): BaselineVetDiscoveryV1 {
  const publication = normalizePublication(input.publication);
  const publicationBytes = canonicalStrictJsonBytesV1(publication);
  return normalizeDiscovery({
    protocol: "BaselineVetDiscoveryV1",
    authority: "none",
    requestSha256: publication.request.requestSha256,
    receiptSha256: publication.receipt.receiptSha256,
    evidenceDigestSha256: canonicalStrictJsonSha256V1(publication.envelope),
    publicationSha256: digest(publicationBytes),
    locator: safeLocator(input.locator),
  });
}

export function canonicalBaselineVetDiscoveryV1Bytes(value: BaselineVetDiscoveryV1): Buffer {
  return canonicalStrictJsonBytesV1(normalizeDiscovery(value));
}

export function parseBaselineVetDiscoveryV1Json(text: string): BaselineVetDiscoveryV1 {
  if (
    Buffer.byteLength(text, "utf8") === 0 ||
    Buffer.byteLength(text, "utf8") > MAX_DISCOVERY_BYTES
  )
    fail("discovery size");
  const parsed = normalizeDiscovery(parseStrictJsonObjectV1(text, "BaselineVetDiscoveryV1"));
  if (!Buffer.from(text, "utf8").equals(canonicalStrictJsonBytesV1(parsed)))
    fail("discovery canonical wire");
  return parsed;
}

export function resolveBaselineVetDiscoveryV1(input: {
  readonly discovery: BaselineVetDiscoveryV1;
  readonly publicationBytes: Uint8Array;
  readonly expectedRequestSha256: string;
}): BaselineVetPublicationV1 {
  const discovery = normalizeDiscovery(input.discovery);
  if (!SHA256.test(input.expectedRequestSha256)) fail("expected request digest");
  if (discovery.requestSha256 !== input.expectedRequestSha256) fail("request digest");
  if (digest(input.publicationBytes) !== discovery.publicationSha256) fail("publication digest");
  const publication = parseBaselineVetPublicationV1Json(
    Buffer.from(input.publicationBytes).toString("utf8"),
  );
  if (
    publication.request.requestSha256 !== discovery.requestSha256 ||
    publication.receipt.receiptSha256 !== discovery.receiptSha256 ||
    canonicalStrictJsonSha256V1(publication.envelope) !== discovery.evidenceDigestSha256
  )
    fail("discovery binding");
  return publication;
}
