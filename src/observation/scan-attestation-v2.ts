import {
  createHash,
  createPublicKey,
  KeyObject,
  sign as signDetached,
  verify as verifyDetached,
} from "node:crypto";
import { z } from "zod";
import {
  assertStrictJsonValueV1,
  canonicalStrictJsonBytesV1,
  codeUnitCompare,
  deepFreezeStrictJsonV1,
  parseStrictJsonObjectV1,
} from "../contract/strict-json-v1.js";
import {
  AI_HARNESS_DECISION_V2_SCHEMA_SHA256,
  AI_HARNESS_STRICT_V2_COMMIT,
} from "../core/core-contract-lock-v2.js";
import { createObservationKeyV1, createObservationSetV1 } from "./observation-evidence-v1.js";
import { createScannerManifestV1 } from "./scanner-manifest-v1.js";
import { sourceSealV2Schema, validateSourceSealV2 } from "./source-seal-v2.js";

const sha256 = z.string().regex(/^[0-9a-f]{64}$/);
const sourceSeal = sourceSealV2Schema;
const sourceSealV1 = z
  .object({
    protocol: z.literal("SourceSealV1"),
    sourceTreeSha256: sha256,
    selectedClosureSha256: sha256,
    sealedSnapshotSha256: sha256,
  })
  .strict();
const rawFact = z
  .object({
    rawOccurrenceFingerprint: z.string().regex(/^raw-occurrence-v1:[0-9a-f]{64}$/),
    multiplicity: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  })
  .strict();
const rawCoverage = z
  .object({
    coverageKind: z.enum(["selected-closure", "source-tree"]),
    coverageSha256: sha256,
  })
  .strict();
const ciscoScanner = z
  .object({
    detectorId: z.literal("detector.cisco"),
    analyzerIdentity: z.string().regex(/^native\.[a-f0-9]{12}$/),
    oci: z
      .object({
        logicalReference: z.string().regex(/^[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}$/),
        manifestDigestSha256: z.string().regex(/^sha256:[a-f0-9]{64}$/),
        configDigestSha256: z.string().regex(/^sha256:[a-f0-9]{64}$/),
      })
      .strict(),
    adapter: z.object({ identity: z.string().regex(/^adapter\.[a-f0-9]{12}$/), sha256 }).strict(),
    observationConfigurationSha256: sha256,
    executionProfileSha256: sha256,
    supportedPlatform: z
      .object({ os: z.literal("linux"), architecture: z.literal("amd64") })
      .strict(),
    sbom: z
      .object({
        mediaType: z.literal("application/spdx+json"),
        sha256,
        state: z.literal("digest-bound-unverified"),
      })
      .strict(),
    provenance: z
      .object({
        mediaType: z.literal("application/vnd.in-toto+json"),
        sha256,
        state: z.literal("digest-bound-unverified"),
      })
      .strict(),
    scannerManifestEntrySha256: sha256,
    sourceSealV1,
    platform: z
      .object({
        os: z.literal("linux"),
        architecture: z.literal("amd64"),
        relevantFactsSha256: sha256,
      })
      .strict(),
    observation: z
      .object({
        keySha256: sha256,
        setSha256: sha256,
        facts: z.array(rawFact).max(4096),
        coverage: z.array(rawCoverage).min(1).max(2),
      })
      .strict(),
    broker: z
      .object({
        identity: z.string().regex(/^broker\.[a-f0-9]{12}$/),
        sarifSha256: sha256,
        enforcementState: z.literal("unverified"),
        policyDigestSha256: sha256,
        appliedFactsSha256: sha256,
      })
      .strict(),
  })
  .strict()
  .superRefine((value, context) => {
    if (!value.oci.logicalReference.endsWith(`@${value.oci.manifestDigestSha256}`))
      context.addIssue({
        code: "custom",
        message: "OCI reference manifest binding",
        path: ["oci"],
      });
    if (
      new Set(value.observation.coverage.map((entry) => entry.coverageKind)).size !==
      value.observation.coverage.length
    )
      context.addIssue({
        code: "custom",
        message: "duplicate raw coverage",
        path: ["observation", "coverage"],
      });
  });
const subject = z
  .object({ name: z.literal("source-tree"), digest: z.object({ sha256 }).strict() })
  .strict();
const candidateInput = z
  .object({
    protocol: z.literal("ScanCandidateV2"),
    coreContract: z
      .object({
        commit: z.literal(AI_HARNESS_STRICT_V2_COMMIT),
        decisionSchemaSha256: z.literal(AI_HARNESS_DECISION_V2_SCHEMA_SHA256),
      })
      .strict(),
    subject,
    sourceSeals: z.object({ before: sourceSeal, after: sourceSeal }).strict(),
    observation: z.object({ keySha256: sha256, setSha256: sha256 }).strict(),
    scanner: z
      .object({
        manifestSha256: sha256,
        runtimeSha256: sha256,
        configurationSha256: sha256,
        cisco: ciscoScanner,
      })
      .strict(),
    platform: z.object({ os: z.literal("linux"), architecture: z.literal("amd64") }).strict(),
    coverage: z
      .object({ kind: z.literal("selected-closure"), sha256, complete: z.literal(true) })
      .strict(),
    annexes: z
      .array(
        z
          .object({
            descriptorId: z.string().regex(/^annex\.[a-z0-9][a-z0-9.-]*$/),
            sha256,
            byteLength: z
              .number()
              .int()
              .positive()
              .max(16 * 1024 * 1024),
          })
          .strict(),
      )
      .max(128),
    cleanup: z.object({ outcome: z.literal("completed") }).strict(),
    scan: z.object({ outcome: z.enum(["succeeded", "failed", "refused"]) }).strict(),
  })
  .strict();
const claimsSchema = z
  .object({
    repository: z.string().regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/),
    workflow: z.string().regex(/^\.github\/workflows\/[A-Za-z0-9_.-]+\.ya?ml$/),
    issuer: z.string().url().max(512),
    sourceRef: z.string().regex(/^refs\/(heads|tags)\/[A-Za-z0-9._/-]{1,256}$/),
    commit: z.string().regex(/^[0-9a-f]{40}$/),
    environment: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/),
    runId: z.string().regex(/^[1-9][0-9]{0,19}$/),
    runAttempt: z.number().int().positive().max(1000),
    signedAt: z.string(),
    expiresAt: z.string(),
  })
  .strict();
const signerSchema = z
  .object({
    identity: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/),
    class: z.enum(["test-ephemeral", "organization"]),
    keyId: z.string().regex(/^ed25519:[0-9a-f]{64}$/),
  })
  .strict();
const signatureSchema = z.object({ keyid: signerSchema.shape.keyId, sig: z.string() }).strict();
const envelopeSchema = z
  .object({
    payloadType: z.literal("application/vnd.in-toto+json"),
    payload: z.string(),
    signatures: z.array(signatureSchema).length(1),
  })
  .strict();
const statementSchema = z
  .object({
    _type: z.literal("https://in-toto.io/Statement/v1"),
    subject: z.array(subject).length(1),
    predicateType: z.literal("https://aih.dev/ScanAttestationV2"),
    predicate: z
      .object({
        protocol: z.literal("ScanAttestationV2"),
        candidate: z.object({ sha256 }).strict(),
        coreContract: candidateInput.shape.coreContract,
        sourceSeals: candidateInput.shape.sourceSeals,
        observation: candidateInput.shape.observation,
        scanner: candidateInput.shape.scanner,
        platform: candidateInput.shape.platform,
        coverage: candidateInput.shape.coverage,
        annexes: candidateInput.shape.annexes,
        cleanup: candidateInput.shape.cleanup,
        scan: candidateInput.shape.scan,
        signer: signerSchema,
        claims: claimsSchema
          .extend({ origin: z.literal("signer-asserted"), provenance: z.literal("none") })
          .strict(),
      })
      .strict(),
  })
  .strict();

type CandidateWire = z.infer<typeof candidateInput> & { readonly candidateSha256: string };
type Statement = z.infer<typeof statementSchema>;
type Envelope = z.infer<typeof envelopeSchema>;
export interface ScanCandidateV2 extends Readonly<CandidateWire> {}
export type ScanAnnexArtifactV2 = Readonly<{ descriptorId: string; bytes: Uint8Array }>;
export interface SignedScanAttestationV2 {
  readonly protocol: "ScanAttestationV2";
  readonly envelope: Readonly<Envelope>;
  readonly payloadSha256: string;
  readonly evidenceDigestSha256: string;
}
export type ScanTrustRootV2 = Readonly<{
  identity: string;
  class: "test-ephemeral" | "organization";
  keyId: string;
  publicKey: KeyObject;
}>;
export interface VerifiedScanAttestationV2 {
  readonly facts: Readonly<{
    envelopeValid: true;
    signer: Readonly<{ identity: string; class: "test-ephemeral" | "organization"; keyId: string }>;
    signerAssertedClaimsMatchPolicy: true;
    provenance: "none";
    scan: Readonly<{ outcome: "succeeded" | "failed" | "refused" }>;
    replayIdentity: string;
    payloadSha256: string;
    evidenceDigestSha256: string;
    subject: Readonly<{ name: "source-tree"; sha256: string }>;
    coreContract: Readonly<{ commit: string; decisionSchemaSha256: string }>;
    observation: Readonly<{ keySha256: string; setSha256: string }>;
    scanner: Readonly<CandidateWire["scanner"]>;
    platform: Readonly<{ os: "linux"; architecture: "amd64" }>;
    coverage: Readonly<{ kind: "selected-closure"; sha256: string; complete: true }>;
    cleanup: Readonly<{ outcome: "completed" }>;
    annexesComplete: true;
    annexDescriptors: readonly Readonly<{
      descriptorId: string;
      sha256: string;
      byteLength: number;
    }>[];
  }>;
}

const candidates = new WeakMap<object, Buffer>();
const signed = new WeakMap<object, Buffer>();
const verified = new WeakSet<object>();

function fail(reason: string): never {
  throw new TypeError(`invalid ScanAttestationV2: ${reason}`);
}
function digest(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}
function keyIdFor(key: KeyObject): string {
  if (key.asymmetricKeyType !== "ed25519") fail("Ed25519 key");
  const publicKey = key.type === "private" ? createPublicKey(key as never) : key;
  if (publicKey.type !== "public") fail("Ed25519 public key");
  return `ed25519:${digest(publicKey.export({ type: "spki", format: "der" }))}`;
}
export function ed25519KeyIdV2(key: KeyObject): string {
  return keyIdFor(key);
}
function canonicalBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}
function decodeBase64(value: string, label: string, maxBytes = 2 * 1024 * 1024): Buffer {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > Math.ceil(maxBytes / 3) * 4 ||
    value.length % 4 !== 0
  )
    fail(`${label} base64 bounds`);
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))
    fail(`${label} base64 grammar`);
  const bytes = Buffer.from(value, "base64");
  if (bytes.byteLength > maxBytes || canonicalBase64(bytes) !== value)
    fail(`${label} canonical base64`);
  return bytes;
}
function exactTime(value: string, label: string): number {
  if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value)) fail(`${label} time grammar`);
  const epoch = Date.parse(value);
  if (!Number.isFinite(epoch) || new Date(epoch).toISOString() !== value)
    fail(`${label} time value`);
  return epoch;
}
function sameSeal(left: z.infer<typeof sourceSeal>, right: z.infer<typeof sourceSeal>): boolean {
  return canonicalStrictJsonBytesV1(left).equals(canonicalStrictJsonBytesV1(right));
}
function validateCiscoIdentityBindings(
  scanner: z.infer<typeof candidateInput>["scanner"],
  observation: z.infer<typeof candidateInput>["observation"],
): void {
  const cisco = scanner.cisco;
  const manifest = createScannerManifestV1({
    protocol: "ScannerManifestV1",
    detectors: [
      {
        detectorId: cisco.detectorId,
        analyzerIdentity: cisco.analyzerIdentity,
        ociImage: {
          reference: cisco.oci.logicalReference,
          sha256: cisco.oci.manifestDigestSha256.slice("sha256:".length),
        },
        adapter: cisco.adapter,
        observationConfigurationSha256: cisco.observationConfigurationSha256,
        executionProfileSha256: cisco.executionProfileSha256,
        supportedPlatforms: [cisco.supportedPlatform],
        sbom: { mediaType: cisco.sbom.mediaType, sha256: cisco.sbom.sha256 },
        provenance: { mediaType: cisco.provenance.mediaType, sha256: cisco.provenance.sha256 },
      },
    ],
  });
  const detector = manifest.detectors[0] ?? fail("Cisco scanner manifest entry");
  if (
    manifest.scannerManifestSha256 !== scanner.manifestSha256 ||
    detector.scannerManifestEntrySha256 !== cisco.scannerManifestEntrySha256
  )
    fail("Cisco scanner manifest binding");
  const expectedRelevantFacts = digest(
    canonicalStrictJsonBytesV1({
      domain: "aih.cisco.oci-candidate.relevant-facts-v1",
      sourceSeal: cisco.sourceSealV1,
    }),
  );
  if (cisco.platform.relevantFactsSha256 !== expectedRelevantFacts)
    fail("Cisco relevant facts binding");
  const observationKeyInput = {
    protocol: "ObservationKeyV1" as const,
    sourceSeal: cisco.sourceSealV1,
    nativeAnalyzerIdentity: cisco.analyzerIdentity,
    observationConfigurationSha256: cisco.observationConfigurationSha256,
    platform: cisco.platform,
    scannerManifestEntrySha256: cisco.scannerManifestEntrySha256,
  };
  const observationKey = createObservationKeyV1(observationKeyInput);
  const observationSet = createObservationSetV1({
    protocol: "ObservationSetV1",
    observationKey: observationKeyInput,
    facts: cisco.observation.facts,
    coverage: cisco.observation.coverage,
  });
  if (
    observationKey.observationKeySha256 !== cisco.observation.keySha256 ||
    observationSet.observationSetSha256 !== cisco.observation.setSha256 ||
    observation.keySha256 !== observationKey.observationKeySha256 ||
    observation.setSha256 !== observationSet.observationSetSha256 ||
    !canonicalStrictJsonBytesV1(observationSet.facts).equals(
      canonicalStrictJsonBytesV1(cisco.observation.facts),
    ) ||
    !canonicalStrictJsonBytesV1(observationSet.coverage).equals(
      canonicalStrictJsonBytesV1(cisco.observation.coverage),
    )
  )
    fail("Cisco observation identity binding");
  const appliedFactsSha256 = digest(
    canonicalStrictJsonBytesV1({
      domain: "aih.cisco.oci-candidate.applied-facts-v1",
      facts: cisco.observation.facts,
      coverage: cisco.observation.coverage,
    }),
  );
  if (cisco.broker.appliedFactsSha256 !== appliedFactsSha256) fail("Cisco broker facts binding");
  const policyDigestSha256 = digest(
    canonicalStrictJsonBytesV1({
      domain: "aih.cisco.oci-candidate.broker-binding-v1",
      brokerIdentity: cisco.broker.identity,
      scannerManifestEntrySha256: cisco.scannerManifestEntrySha256,
      sarifSha256: cisco.broker.sarifSha256,
    }),
  );
  if (cisco.broker.policyDigestSha256 !== policyDigestSha256) fail("Cisco broker policy binding");
  const runtimeSha256 = digest(
    canonicalStrictJsonBytesV1({ domain: "aih.cisco.capture-v2.runtime", detector }),
  );
  if (scanner.runtimeSha256 !== runtimeSha256) fail("Cisco runtime identity binding");
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
function sortedAnnexes(
  values: z.infer<typeof candidateInput>["annexes"],
): z.infer<typeof candidateInput>["annexes"] {
  const seen = new Set<string>();
  for (const value of values) {
    if (seen.has(value.descriptorId)) fail("duplicate annex descriptor");
    seen.add(value.descriptorId);
  }
  return [...values].sort((left, right) => codeUnitCompare(left.descriptorId, right.descriptorId));
}
export function assertCompleteScanAnnexArtifactsV2(
  descriptors: z.infer<typeof candidateInput>["annexes"],
  value: unknown,
): z.infer<typeof candidateInput>["annexes"] {
  if (!Array.isArray(value) || value.length !== descriptors.length) fail("annex artifact set");
  const supplied = new Map<string, { bytes: Uint8Array }>();
  for (const item of value) {
    if (typeof item !== "object" || item === null || Array.isArray(item))
      fail("annex artifact object");
    exactKeys(item, ["descriptorId", "bytes"], "annex artifact");
    const descriptorId = ownData(item, "descriptorId"),
      bytes = ownData(item, "bytes");
    if (
      typeof descriptorId !== "string" ||
      !(Buffer.isBuffer(bytes) || bytes instanceof Uint8Array) ||
      bytes.byteLength > 16 * 1024 * 1024 ||
      supplied.has(descriptorId)
    )
      fail("annex artifact fields");
    supplied.set(descriptorId, { bytes });
  }
  for (const descriptor of descriptors) {
    const artifact = supplied.get(descriptor.descriptorId);
    if (
      artifact === undefined ||
      artifact.bytes.byteLength !== descriptor.byteLength ||
      digest(artifact.bytes) !== descriptor.sha256
    )
      fail("annex artifact binding");
  }
  return descriptors;
}

/** Source-seal V2 bytes use strict JSON and code-unit sorted object keys. */
export function canonicalSourceSealsV2Bytes(value: unknown): Buffer {
  assertStrictJsonValueV1(value, "ScanAttestationV2 source seals");
  const parsed = candidateInput.shape.sourceSeals.parse(structuredClone(value));
  return canonicalStrictJsonBytesV1({
    before: validateSourceSealV2(parsed.before),
    after: validateSourceSealV2(parsed.after),
  });
}
export function createScanCandidateV2(value: unknown): ScanCandidateV2 {
  assertStrictJsonValueV1(value, "ScanCandidateV2 candidate");
  const parsed = candidateInput.parse(structuredClone(value));
  const sourceSeals = {
    before: validateSourceSealV2(parsed.sourceSeals.before),
    after: validateSourceSealV2(parsed.sourceSeals.after),
  };
  const normalizedParsed = { ...parsed, sourceSeals };
  if (!sameSeal(sourceSeals.before, sourceSeals.after)) fail("source seal TOCTOU mismatch");
  if (
    parsed.subject.digest.sha256 !== sourceSeals.before.sourceTreeSha256 ||
    parsed.subject.digest.sha256 !== sourceSeals.after.sourceTreeSha256
  )
    fail("subject source seal binding");
  if (parsed.coverage.sha256 !== sourceSeals.before.selectedClosureSha256)
    fail("coverage selected closure binding");
  validateCiscoIdentityBindings(parsed.scanner, parsed.observation);
  if (
    parsed.observation.keySha256 !== parsed.scanner.cisco.observation.keySha256 ||
    parsed.observation.setSha256 !== parsed.scanner.cisco.observation.setSha256 ||
    parsed.scanner.configurationSha256 !== parsed.scanner.cisco.observationConfigurationSha256 ||
    parsed.platform.os !== parsed.scanner.cisco.supportedPlatform.os ||
    parsed.platform.architecture !== parsed.scanner.cisco.supportedPlatform.architecture
  )
    fail("Cisco identity binding");
  const expectedAnnexes = new Map(parsed.annexes.map((annex) => [annex.descriptorId, annex]));
  if (
    expectedAnnexes.size !== 3 ||
    expectedAnnexes.get("annex.cisco-raw") === undefined ||
    expectedAnnexes.get("annex.sbom")?.sha256 !== parsed.scanner.cisco.sbom.sha256 ||
    expectedAnnexes.get("annex.provenance")?.sha256 !== parsed.scanner.cisco.provenance.sha256
  )
    fail("Cisco annex identity binding");
  const normalized = { ...normalizedParsed, annexes: sortedAnnexes(parsed.annexes) };
  const result = deepFreezeStrictJsonV1({
    ...normalized,
    candidateSha256: digest(
      canonicalStrictJsonBytesV1({ domain: "aih.scan-candidate-v2", candidate: normalized }),
    ),
  });
  candidates.set(result, canonicalStrictJsonBytesV1(result));
  return result;
}
export function canonicalScanCandidateBytesV2(value: ScanCandidateV2): Buffer {
  if (typeof value !== "object" || value === null) fail("candidate object");
  const bytes = candidates.get(value);
  if (bytes === undefined) fail("candidate requires validated custody");
  return Buffer.from(bytes);
}
export function parseScanCandidateV2Json(text: string): ScanCandidateV2 {
  const parsed = parseStrictJsonObjectV1(text, "ScanCandidateV2 candidate");
  const candidateSha256 = parsed.candidateSha256;
  if (typeof candidateSha256 !== "string" || !/^[0-9a-f]{64}$/.test(candidateSha256))
    fail("candidate digest");
  const { candidateSha256: _candidateSha256, ...input } = parsed;
  const candidate = createScanCandidateV2(input);
  if (candidate.candidateSha256 !== candidateSha256) fail("candidate digest binding");
  if (!Buffer.from(text, "utf8").equals(canonicalScanCandidateBytesV2(candidate)))
    fail("noncanonical candidate");
  return candidate;
}
function candidateBytes(value: unknown): Buffer {
  if (typeof value !== "object" || value === null) fail("candidate object");
  const bytes = candidates.get(value);
  if (bytes === undefined) fail("candidate requires validated custody");
  return bytes;
}
function parseClaims(value: unknown): z.infer<typeof claimsSchema> {
  assertStrictJsonValueV1(value, "ScanAttestationV2 claims");
  const parsed = claimsSchema.parse(structuredClone(value));
  const signedAt = exactTime(parsed.signedAt, "signedAt");
  if (
    exactTime(parsed.expiresAt, "expiresAt") <= signedAt ||
    exactTime(parsed.expiresAt, "expiresAt") - signedAt > 24 * 60 * 60 * 1000
  )
    fail("claims expiry");
  return parsed;
}
export function canonicalDssePaeV2(payloadType: string, payload: Uint8Array): Buffer {
  if (payloadType !== "application/vnd.in-toto+json") fail("payload type");
  if (
    !(Buffer.isBuffer(payload) || payload instanceof Uint8Array) ||
    payload.byteLength === 0 ||
    payload.byteLength > 2 * 1024 * 1024
  )
    fail("payload bytes");
  return Buffer.concat([
    Buffer.from(
      `DSSEv1 ${Buffer.byteLength(payloadType)} ${payloadType} ${payload.byteLength} `,
      "ascii",
    ),
    Buffer.from(payload),
  ]);
}
export function signScanCandidateV2(value: unknown): SignedScanAttestationV2 {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    fail("sign input object");
  exactKeys(value, ["candidate", "signer", "claims", "annexArtifacts"], "sign input");
  const candidate = ownData(value, "candidate");
  candidateBytes(candidate);
  const rawSigner = ownData(value, "signer");
  if (typeof rawSigner !== "object" || rawSigner === null || Array.isArray(rawSigner))
    fail("signer object");
  exactKeys(rawSigner, ["identity", "class", "keyId", "privateKey"], "signer");
  const signer = signerSchema.parse({
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
  if (signer.keyId !== keyIdFor(privateKey)) fail("signer keyId fingerprint");
  const claims = parseClaims(ownData(value, "claims"));
  const candidateWire = candidate as ScanCandidateV2;
  assertCompleteScanAnnexArtifactsV2(candidateWire.annexes, ownData(value, "annexArtifacts"));
  const statement: Statement = statementSchema.parse({
    _type: "https://in-toto.io/Statement/v1",
    subject: [candidateWire.subject],
    predicateType: "https://aih.dev/ScanAttestationV2",
    predicate: {
      protocol: "ScanAttestationV2",
      candidate: { sha256: candidateWire.candidateSha256 },
      coreContract: candidateWire.coreContract,
      sourceSeals: candidateWire.sourceSeals,
      observation: candidateWire.observation,
      scanner: candidateWire.scanner,
      platform: candidateWire.platform,
      coverage: candidateWire.coverage,
      annexes: candidateWire.annexes,
      cleanup: candidateWire.cleanup,
      scan: candidateWire.scan,
      signer,
      claims: { ...claims, origin: "signer-asserted", provenance: "none" },
    },
  });
  const payload = canonicalStrictJsonBytesV1(statement);
  const signature = signDetached(
    null,
    canonicalDssePaeV2("application/vnd.in-toto+json", payload),
    privateKey,
  );
  if (signature.byteLength !== 64) fail("Ed25519 signature length");
  const envelope = envelopeSchema.parse({
    payloadType: "application/vnd.in-toto+json",
    payload: canonicalBase64(payload),
    signatures: [{ keyid: signer.keyId, sig: canonicalBase64(signature) }],
  });
  const result = deepFreezeStrictJsonV1({
    protocol: "ScanAttestationV2" as const,
    envelope,
    payloadSha256: digest(payload),
    evidenceDigestSha256: digest(canonicalStrictJsonBytesV1(envelope)),
  });
  signed.set(result, canonicalStrictJsonBytesV1(result));
  return result;
}
export function canonicalScanAttestationEnvelopeBytesV2(value: SignedScanAttestationV2): Buffer {
  if (typeof value !== "object" || value === null) fail("signed evidence object");
  const bytes = signed.get(value);
  if (bytes === undefined) fail("canonical envelope requires signed custody");
  return canonicalStrictJsonBytesV1(value.envelope);
}
function parseEnvelope(value: unknown): {
  envelope: Envelope;
  statement: Statement;
  payload: Buffer;
  payloadSha256: string;
  evidenceDigestSha256: string;
} {
  const raw =
    typeof value === "object" && value !== null && "envelope" in value
      ? (value as { envelope: unknown }).envelope
      : value;
  assertStrictJsonValueV1(raw, "ScanAttestationV2 envelope");
  const envelope = envelopeSchema.parse(structuredClone(raw));
  const payload = decodeBase64(envelope.payload, "payload");
  let parsedPayload: Record<string, unknown>;
  try {
    parsedPayload = parseStrictJsonObjectV1(payload.toString("utf8"), "ScanAttestationV2 payload");
  } catch {
    fail("payload JSON");
  }
  if (!canonicalStrictJsonBytesV1(parsedPayload).equals(payload)) fail("noncanonical payload");
  const statement = statementSchema.parse(parsedPayload);
  const sourceSeals = {
    before: validateSourceSealV2(statement.predicate.sourceSeals.before),
    after: validateSourceSealV2(statement.predicate.sourceSeals.after),
  };
  const candidate = statement.predicate.candidate.sha256;
  const rebuiltCandidate = digest(
    canonicalStrictJsonBytesV1({
      domain: "aih.scan-candidate-v2",
      candidate: {
        protocol: "ScanCandidateV2",
        coreContract: statement.predicate.coreContract,
        subject: statement.subject[0],
        sourceSeals,
        observation: statement.predicate.observation,
        scanner: statement.predicate.scanner,
        platform: statement.predicate.platform,
        coverage: statement.predicate.coverage,
        annexes: sortedAnnexes(statement.predicate.annexes),
        cleanup: statement.predicate.cleanup,
        scan: statement.predicate.scan,
      },
    }),
  );
  if (candidate !== rebuiltCandidate) fail("candidate digest binding");
  if (!sameSeal(sourceSeals.before, sourceSeals.after)) fail("source seal TOCTOU mismatch");
  if (
    statement.subject[0]?.digest.sha256 !== sourceSeals.before.sourceTreeSha256 ||
    statement.predicate.coverage.sha256 !== sourceSeals.before.selectedClosureSha256
  )
    fail("subject or coverage source seal binding");
  return {
    envelope,
    statement,
    payload,
    payloadSha256: digest(payload),
    evidenceDigestSha256: digest(canonicalStrictJsonBytesV1(envelope)),
  };
}
export function parseScanAttestationEnvelopeV2Json(text: string): Readonly<Envelope> {
  const raw = parseStrictJsonObjectV1(text, "ScanAttestationV2 envelope");
  const parsed = parseEnvelope(raw);
  if (!Buffer.from(text, "utf8").equals(canonicalStrictJsonBytesV1(parsed.envelope)))
    fail("noncanonical envelope");
  return deepFreezeStrictJsonV1(parsed.envelope);
}
function parseExpected(value: unknown): z.infer<typeof claimsSchema> & {
  now: string;
  subjectSha256: string;
  signer: z.infer<typeof signerSchema>;
} {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail("expected policy");
  exactKeys(
    value,
    [...Object.keys(claimsSchema.shape), "now", "subjectSha256", "signer"],
    "expected policy",
  );
  const claims = parseClaims(
    Object.fromEntries(Object.keys(claimsSchema.shape).map((key) => [key, ownData(value, key)])),
  );
  const now = ownData(value, "now");
  const subjectSha256 = ownData(value, "subjectSha256");
  const rawSigner = ownData(value, "signer");
  if (typeof now !== "string" || !sha256.safeParse(subjectSha256).success) fail("expected values");
  if (typeof rawSigner !== "object" || rawSigner === null || Array.isArray(rawSigner))
    fail("expected signer object");
  exactKeys(rawSigner, ["identity", "class", "keyId"], "expected signer");
  const signer = signerSchema.parse({
    identity: ownData(rawSigner, "identity"),
    class: ownData(rawSigner, "class"),
    keyId: ownData(rawSigner, "keyId"),
  });
  return {
    ...claims,
    now,
    subjectSha256: subjectSha256 as string,
    signer,
  };
}
export function verifyScanAttestationV2(value: unknown): VerifiedScanAttestationV2 {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    fail("verify input object");
  const raw = value as object;
  const allowed = [
    "envelope",
    "candidate",
    "roots",
    "expected",
    "seenReplayIdentities",
    "annexArtifacts",
  ];
  if (
    Object.getPrototypeOf(raw) !== Object.prototype ||
    Object.getOwnPropertySymbols(raw).length > 0 ||
    Object.keys(raw).some((key) => !allowed.includes(key)) ||
    !["envelope", "candidate", "roots", "expected", "annexArtifacts"].every((key) =>
      Object.hasOwn(raw, key),
    )
  )
    fail("verify input fields");
  const parsed = parseEnvelope(ownData(raw, "envelope"));
  const bundledCandidate = ownData(raw, "candidate");
  if (
    typeof bundledCandidate !== "object" ||
    bundledCandidate === null ||
    candidateBytes(bundledCandidate) === undefined ||
    (bundledCandidate as ScanCandidateV2).candidateSha256 !==
      parsed.statement.predicate.candidate.sha256
  )
    fail("detached candidate binding");
  const annexDescriptors = assertCompleteScanAnnexArtifactsV2(
    parsed.statement.predicate.annexes,
    ownData(raw, "annexArtifacts"),
  );
  const expected = parseExpected(ownData(raw, "expected"));
  const now = exactTime(expected.now, "now");
  const claims = parsed.statement.predicate.claims;
  if (
    now < exactTime(claims.signedAt, "signedAt") ||
    now >= exactTime(claims.expiresAt, "expiresAt")
  )
    fail("evidence time window");
  for (const key of Object.keys(claimsSchema.shape) as (keyof z.infer<typeof claimsSchema>)[])
    if (claims[key] !== expected[key]) fail(`claim mismatch ${key}`);
  if (parsed.statement.subject[0]?.digest.sha256 !== expected.subjectSha256)
    fail("Core subject digest mismatch");
  const signer = parsed.statement.predicate.signer;
  if (
    signer.identity !== expected.signer.identity ||
    signer.class !== expected.signer.class ||
    signer.keyId !== expected.signer.keyId
  )
    fail("expected signer mismatch");
  const roots = ownData(raw, "roots");
  if (!Array.isArray(roots) || roots.length === 0 || roots.length > 64) fail("trust roots");
  const parsedRoots = roots.map((entry) => {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry))
      fail("trust root object");
    exactKeys(entry, ["identity", "class", "keyId", "publicKey"], "trust root");
    const parsedRoot = signerSchema.parse({
      identity: ownData(entry, "identity"),
      class: ownData(entry, "class"),
      keyId: ownData(entry, "keyId"),
    });
    const publicKey = ownData(entry, "publicKey");
    if (
      !(publicKey instanceof KeyObject) ||
      publicKey.type !== "public" ||
      publicKey.asymmetricKeyType !== "ed25519"
    )
      fail("Ed25519 trust root");
    if (parsedRoot.keyId !== keyIdFor(publicKey)) fail("trust root keyId fingerprint");
    return { ...parsedRoot, publicKey };
  });
  const rootKeys = new Set<string>();
  const rootIdentityClasses = new Map<string, string>();
  for (const entry of parsedRoots) {
    if (rootKeys.has(entry.keyId)) fail("duplicate trust root key");
    const existingClass = rootIdentityClasses.get(entry.identity);
    if (existingClass !== undefined && existingClass !== entry.class)
      fail("trust root identity class conflict");
    rootKeys.add(entry.keyId);
    rootIdentityClasses.set(entry.identity, entry.class);
  }
  const root = parsedRoots.find(
    (entry) =>
      entry.identity === signer.identity &&
      entry.class === signer.class &&
      entry.keyId === signer.keyId,
  );
  if (root === undefined) fail("unknown signer root");
  const rootKey = root.publicKey;
  const signature = decodeBase64(parsed.envelope.signatures[0]?.sig ?? "", "signature", 64);
  if (
    signature.byteLength !== 64 ||
    parsed.envelope.signatures[0]?.keyid !== signer.keyId ||
    !verifyDetached(
      null,
      canonicalDssePaeV2(parsed.envelope.payloadType, parsed.payload),
      rootKey,
      signature,
    )
  )
    fail("signature verification");
  const replayIdentity = `${signer.identity}|${parsed.payloadSha256}`;
  const seen = Object.hasOwn(raw, "seenReplayIdentities")
    ? ownData(raw, "seenReplayIdentities")
    : [];
  if (
    !Array.isArray(seen) ||
    seen.length > 100_000 ||
    seen.some((entry) => typeof entry !== "string")
  )
    fail("replay identities");
  if (seen.includes(replayIdentity)) fail("replayed evidence");
  const result = deepFreezeStrictJsonV1({
    facts: {
      envelopeValid: true as const,
      signer: { identity: signer.identity, class: signer.class, keyId: signer.keyId },
      signerAssertedClaimsMatchPolicy: true as const,
      provenance: "none" as const,
      scan: { outcome: parsed.statement.predicate.scan.outcome },
      replayIdentity,
      payloadSha256: parsed.payloadSha256,
      evidenceDigestSha256: parsed.evidenceDigestSha256,
      subject: {
        name: "source-tree" as const,
        sha256: parsed.statement.subject[0]?.digest.sha256 ?? fail("subject"),
      },
      coreContract: parsed.statement.predicate.coreContract,
      observation: parsed.statement.predicate.observation,
      scanner: parsed.statement.predicate.scanner,
      platform: parsed.statement.predicate.platform,
      coverage: parsed.statement.predicate.coverage,
      cleanup: parsed.statement.predicate.cleanup,
      annexesComplete: true as const,
      annexDescriptors,
    },
  });
  verified.add(result);
  return result;
}
export function isVerifiedScanAttestationV2(value: unknown): value is VerifiedScanAttestationV2 {
  return typeof value === "object" && value !== null && verified.has(value);
}
