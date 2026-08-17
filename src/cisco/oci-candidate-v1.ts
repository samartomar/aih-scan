import { createHash } from "node:crypto";
import { z } from "zod";
import {
  assertStrictJsonValueV1,
  canonicalStrictJsonBytesV1,
  canonicalStrictJsonSha256V1,
  codeUnitCompare,
  deepFreezeStrictJsonV1,
  parseStrictJsonObjectV1,
} from "../contract/strict-json-v1.js";
import {
  createEvidenceAnnexV1,
  createObservationKeyV1,
  createObservationSetV1,
  parseEvidenceAnnexV1Json,
  verifyEvidenceAnnexBytesV1,
} from "../observation/observation-evidence-v1.js";
import {
  createScanAttestationV1,
  parseScanAttestationV1Json,
} from "../observation/scan-attestation-v1.js";
import { createScannerManifestV1 } from "../observation/scanner-manifest-v1.js";
import {
  type CiscoOciLayoutV1,
  isCiscoOciLayoutV1,
  parseCiscoOciLayoutV1,
} from "./oci-layout-v1.js";

const MAX_PAYLOAD_BYTES = 16 * 1024 * 1024;
// Two maximum binary payloads expand to less than 45 MiB in Base64; the remaining
// 3 MiB covers the immutable candidate envelope without admitting unbounded JSON.
const MAX_CANDIDATE_JSON_BYTES = 48 * 1024 * 1024;
// This textual ceiling is checked before decode. The decoded payload ceiling remains
// authoritative, so a syntactically valid but oversized Base64 value never allocates.
const MAX_BASE64_PAYLOAD_CHARS = 32 * 1024 * 1024;
const base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const base64Characters = /^[A-Za-z0-9+/]*$(?![\s\S])/;
const fields = [
  "protocol",
  "layout",
  "brokerResult",
  "runtime",
  "annexPayloads",
  "broker",
] as const;
const sha256 = z.string().regex(/^[a-f0-9]{64}$/);
const runtimeSchema = z
  .object({
    detectorId: z.literal("detector.cisco"),
    analyzerIdentity: z.string().regex(/^native\.[a-f0-9]{12}$/),
    ociImage: z.object({ reference: z.string(), sha256 }).strict(),
    adapter: z.object({ identity: z.string().regex(/^adapter\.[a-f0-9]{12}$/), sha256 }).strict(),
    observationConfigurationSha256: sha256,
    executionProfileSha256: sha256,
    supportedPlatforms: z
      .array(z.object({ os: z.literal("linux"), architecture: z.literal("amd64") }).strict())
      .length(1),
    sbom: z.object({ mediaType: z.literal("application/spdx+json"), sha256 }).strict(),
    provenance: z.object({ mediaType: z.literal("application/vnd.in-toto+json"), sha256 }).strict(),
  })
  .strict();
const brokerSchema = z.object({ identity: z.string().regex(/^broker\.[a-f0-9]{12}$/) }).strict();
const outputSchema = z
  .object({
    protocol: z.literal("CiscoOciCandidateV1"),
    layout: z.object({}).passthrough(),
    scannerManifest: z.object({}).passthrough(),
    observationKey: z.object({}).passthrough(),
    observationSet: z.object({}).passthrough(),
    evidenceAnnex: z.object({}).passthrough(),
    annexPayloads: z
      .array(z.object({ descriptorId: z.string(), payload: z.string() }).strict())
      .min(1)
      .max(128),
    attestation: z.object({}).passthrough(),
    validationState: z.literal("cryptographically-unverified"),
  })
  .strict();

type Runtime = {
  detectorId: "detector.cisco";
  analyzerIdentity: string;
  ociImage: { reference: string; sha256: string };
  adapter: { identity: string; sha256: string };
  observationConfigurationSha256: string;
  executionProfileSha256: string;
  supportedPlatforms: { os: "linux"; architecture: "amd64" }[];
  sbom: { mediaType: "application/spdx+json"; sha256: string };
  provenance: { mediaType: "application/vnd.in-toto+json"; sha256: string };
};
type BrokerIdentity = { identity: string };
type Payload = { readonly descriptorId: "annex.sbom" | "annex.provenance"; readonly bytes: Buffer };
type BrokerData = {
  readonly protocol: unknown;
  readonly observationScope: unknown;
  readonly validationState: unknown;
  readonly manifestDigestSha256: unknown;
  readonly configDigestSha256: unknown;
  readonly logicalReference: unknown;
  readonly platform: unknown;
  readonly sourceSeal: unknown;
  readonly sarifSha256: unknown;
  readonly facts: unknown;
  readonly coverage: unknown;
  readonly evidenceAnnex: object;
  readonly annexBytes: Buffer;
  readonly cleanup: unknown;
};
type CandidateWire = {
  protocol: "CiscoOciCandidateV1";
  layout: Record<string, unknown>;
  scannerManifest: Record<string, unknown>;
  observationKey: Record<string, unknown>;
  observationSet: Record<string, unknown>;
  evidenceAnnex: Record<string, unknown>;
  annexPayloads: { descriptorId: string; payload: string }[];
  attestation: Record<string, unknown>;
  validationState: "cryptographically-unverified";
};
type Candidate = Readonly<Record<string, unknown>>;
const candidates = new WeakMap<object, Buffer>();

const fail = (message: string): never => {
  throw new TypeError(`invalid Cisco OCI candidate V1: ${message}`);
};
const decodeCanonicalBase64Payload = (payload: string): Buffer => {
  if (payload.length > MAX_BASE64_PAYLOAD_CHARS) fail("candidate payload encoded size");
  if (payload.length % 4 !== 0) fail("candidate payload base64 grammar");
  const padding = payload.endsWith("==") ? 2 : payload.endsWith("=") ? 1 : 0;
  const contentLength = payload.length - padding;
  if (
    !base64Characters.test(payload.slice(0, contentLength)) ||
    payload.slice(contentLength) !== "=".repeat(padding)
  )
    fail("candidate payload base64 grammar");
  const decodedSize = (payload.length / 4) * 3 - padding;
  if (decodedSize > MAX_PAYLOAD_BYTES) fail("candidate payload decoded size");
  if (
    (padding === 2 && (base64Alphabet.indexOf(payload.at(-3) ?? "") & 0x0f) !== 0) ||
    (padding === 1 && (base64Alphabet.indexOf(payload.at(-2) ?? "") & 0x03) !== 0)
  )
    fail("candidate payload base64 grammar");
  const bytes = Buffer.from(payload, "base64");
  if (bytes.length !== decodedSize) fail("candidate payload base64 grammar");
  return bytes;
};
const ownData = (value: object, key: string): unknown => {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !("value" in descriptor))
    fail(`${key} must be an own data property`);
  return (descriptor as PropertyDescriptor & { value: unknown }).value;
};
const plain = (
  value: unknown,
  expected: readonly string[],
  label: string,
): Record<string, unknown> => {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.getOwnPropertySymbols(value).length !== 0
  )
    fail(`${label} object`);
  const object = value as object;
  const keys = Object.keys(object);
  if (keys.length !== expected.length || expected.some((key) => !Object.hasOwn(object, key)))
    fail(`${label} fields`);
  for (const key of keys) ownData(object, key);
  return object as Record<string, unknown>;
};
const deeplyFrozen = (value: unknown, seen = new WeakSet<object>()): boolean => {
  if (value === null || typeof value !== "object" || Buffer.isBuffer(value)) return true;
  if (seen.has(value)) return true;
  if (!Object.isFrozen(value)) return false;
  seen.add(value);
  for (const key of Object.keys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      !deeplyFrozen(descriptor.value, seen)
    )
      return false;
  }
  return true;
};
const hash = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const same = (left: unknown, right: unknown) =>
  canonicalStrictJsonBytesV1(left).equals(canonicalStrictJsonBytesV1(right));

function parsePayloads(value: unknown, runtime: Runtime) {
  if (
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    value.length !== 2
  )
    fail("annex payloads");
  const payloads: Payload[] = (value as unknown[]).map((entry) => {
    const parsed = plain(entry, ["descriptorId", "bytes"], "annex payload");
    const descriptorId = ownData(parsed, "descriptorId");
    const bytes = ownData(parsed, "bytes");
    if (
      (descriptorId !== "annex.sbom" && descriptorId !== "annex.provenance") ||
      !Buffer.isBuffer(bytes) ||
      bytes.length === 0 ||
      bytes.length > MAX_PAYLOAD_BYTES
    )
      fail("annex payload");
    return {
      descriptorId: descriptorId as Payload["descriptorId"],
      bytes: Buffer.from(bytes as Buffer),
    };
  });
  if (new Set(payloads.map((payload) => payload.descriptorId)).size !== payloads.length)
    fail("duplicate annex payload");
  const sbom = payloads.find((payload) => payload.descriptorId === "annex.sbom");
  const provenance = payloads.find((payload) => payload.descriptorId === "annex.provenance");
  if (
    sbom === undefined ||
    provenance === undefined ||
    hash(sbom.bytes) !== runtime.sbom.sha256 ||
    hash(provenance.bytes) !== runtime.provenance.sha256
  )
    fail("annex payload digest");
  return payloads;
}

function parseBroker(value: unknown, layout: CiscoOciLayoutV1): BrokerData {
  const broker = plain(
    value,
    [
      "protocol",
      "observationScope",
      "validationState",
      "manifestDigestSha256",
      "configDigestSha256",
      "logicalReference",
      "platform",
      "sourceSeal",
      "sarifSha256",
      "facts",
      "coverage",
      "evidenceAnnex",
      "annexBytes",
      "cleanup",
    ],
    "broker result",
  );
  if (!deeplyFrozen(broker)) fail("genuine frozen broker result");
  const annexBytes = ownData(broker, "annexBytes");
  if (
    !Buffer.isBuffer(annexBytes) ||
    annexBytes.length === 0 ||
    annexBytes.length > MAX_PAYLOAD_BYTES
  )
    fail("broker annex bytes");
  const evidenceAnnex = ownData(broker, "evidenceAnnex");
  if (typeof evidenceAnnex !== "object" || evidenceAnnex === null) fail("broker evidence annex");
  try {
    if (
      verifyEvidenceAnnexBytesV1({
        annex: evidenceAnnex as never,
        descriptors: [{ descriptorId: "annex.cisco-raw", bytes: annexBytes as Buffer }],
      }).kind !== "complete"
    )
      fail("broker annex bytes");
  } catch {
    fail("branded broker evidence annex");
  }
  const data: BrokerData = {
    protocol: ownData(broker, "protocol"),
    observationScope: ownData(broker, "observationScope"),
    validationState: ownData(broker, "validationState"),
    manifestDigestSha256: ownData(broker, "manifestDigestSha256"),
    configDigestSha256: ownData(broker, "configDigestSha256"),
    logicalReference: ownData(broker, "logicalReference"),
    platform: ownData(broker, "platform"),
    sourceSeal: ownData(broker, "sourceSeal"),
    sarifSha256: ownData(broker, "sarifSha256"),
    facts: ownData(broker, "facts"),
    coverage: ownData(broker, "coverage"),
    evidenceAnnex: evidenceAnnex as object,
    annexBytes: Buffer.from(annexBytes as Buffer),
    cleanup: ownData(broker, "cleanup"),
  };
  try {
    const { annexBytes: _annexBytes, ...strictData } = data;
    assertStrictJsonValueV1(strictData, "Cisco OCI candidate broker result");
  } catch {
    fail("broker result data");
  }
  if (
    data.protocol !== "CiscoOciBrokerV1" ||
    data.observationScope !== "candidate" ||
    data.validationState !== "cryptographically-unverified" ||
    data.manifestDigestSha256 !== layout.manifestDigestSha256 ||
    data.configDigestSha256 !== layout.configDigestSha256 ||
    data.logicalReference !== layout.logicalReference ||
    !same(data.platform, { os: "linux", architecture: "amd64" }) ||
    data.cleanup === null ||
    !same(data.cleanup, { kind: "clean" })
  )
    fail("broker result binding");
  return data;
}

function sourceSeal(value: unknown) {
  const key = createObservationKeyV1({
    protocol: "ObservationKeyV1",
    sourceSeal: value,
    nativeAnalyzerIdentity: "native.000000000000",
    observationConfigurationSha256: "0".repeat(64),
    platform: { os: "linux", architecture: "amd64", relevantFactsSha256: "0".repeat(64) },
    scannerManifestEntrySha256: "0".repeat(64),
  });
  return key.sourceSeal;
}

function build(
  layout: CiscoOciLayoutV1,
  brokerResult: BrokerData,
  runtime: Runtime,
  payloads: readonly Payload[],
  broker: BrokerIdentity,
) {
  const seal = sourceSeal(brokerResult.sourceSeal);
  const brokerFacts = brokerResult.facts;
  const brokerCoverage = brokerResult.coverage;
  if (!Array.isArray(brokerFacts) || !Array.isArray(brokerCoverage))
    fail("broker facts or coverage");
  const facts = (brokerFacts as unknown[]).map((fact) => {
    assertStrictJsonValueV1(fact, "broker fact");
    if (typeof fact !== "object" || fact === null || Array.isArray(fact)) fail("broker fact");
    return {
      rawOccurrenceFingerprint: ownData(fact as object, "rawOccurrenceFingerprint"),
      multiplicity: ownData(fact as object, "multiplicity"),
    };
  });
  const coverage = (brokerCoverage as unknown[]).map((entry) => {
    const value = plain(entry, ["coverageKind", "coverageSha256"], "broker coverage");
    return {
      coverageKind: ownData(value, "coverageKind"),
      coverageSha256: ownData(value, "coverageSha256"),
    };
  });
  const appliedFactsSha256 = canonicalStrictJsonSha256V1({
    domain: "aih.cisco.oci-candidate.applied-facts-v1",
    facts,
    coverage,
  });
  const relevantFactsSha256 = canonicalStrictJsonSha256V1({
    domain: "aih.cisco.oci-candidate.relevant-facts-v1",
    sourceSeal: seal,
  });
  const scannerManifest = createScannerManifestV1({
    protocol: "ScannerManifestV1",
    detectors: [
      {
        detectorId: runtime.detectorId,
        analyzerIdentity: runtime.analyzerIdentity,
        ociImage: runtime.ociImage,
        adapter: runtime.adapter,
        observationConfigurationSha256: runtime.observationConfigurationSha256,
        executionProfileSha256: runtime.executionProfileSha256,
        supportedPlatforms: runtime.supportedPlatforms,
        sbom: runtime.sbom,
        provenance: runtime.provenance,
      },
    ],
  });
  const detector = scannerManifest.detectors.find((entry) => entry.detectorId === "detector.cisco");
  const scannerManifestEntry = detector ?? fail("Cisco scanner manifest entry");
  const observationKeyInput = {
    protocol: "ObservationKeyV1" as const,
    sourceSeal: seal,
    nativeAnalyzerIdentity: runtime.analyzerIdentity,
    observationConfigurationSha256: runtime.observationConfigurationSha256,
    platform: { os: "linux" as const, architecture: "amd64" as const, relevantFactsSha256 },
    scannerManifestEntrySha256: scannerManifestEntry.scannerManifestEntrySha256,
  };
  const observationKey = createObservationKeyV1(observationKeyInput);
  const observationSet = createObservationSetV1({
    protocol: "ObservationSetV1",
    observationKey: observationKeyInput,
    facts,
    coverage,
  });
  const rawPayload = {
    descriptorId: "annex.cisco-raw",
    bytes: Buffer.from(brokerResult.annexBytes),
  };
  const allPayloads = [rawPayload, ...payloads].sort((left, right) =>
    codeUnitCompare(left.descriptorId, right.descriptorId),
  );
  const evidenceAnnex = createEvidenceAnnexV1({
    protocol: "EvidenceAnnexV1",
    descriptors: allPayloads.map((payload) => ({
      descriptorId: payload.descriptorId,
      mediaType:
        payload.descriptorId === "annex.sbom" ? "application/spdx+json" : "application/json",
      sha256: hash(payload.bytes),
      byteLength: payload.bytes.length,
      uri:
        payload.descriptorId === "annex.cisco-raw"
          ? "annex/cisco-raw.json"
          : payload.descriptorId === "annex.sbom"
            ? "annex/sbom.spdx.json"
            : "annex/provenance.json",
    })),
  });
  if (
    verifyEvidenceAnnexBytesV1({ annex: evidenceAnnex, descriptors: allPayloads }).kind !==
    "complete"
  )
    fail("candidate annex bytes");
  const policyDigestSha256 = canonicalStrictJsonSha256V1({
    domain: "aih.cisco.oci-candidate.broker-binding-v1",
    brokerIdentity: broker.identity,
    scannerManifestEntrySha256: scannerManifestEntry.scannerManifestEntrySha256,
    sarifSha256: brokerResult.sarifSha256,
  });
  const attestation = createScanAttestationV1({
    protocol: "ScanAttestationV1",
    sourceTarget: { name: "source-tree", sha256: seal.sourceTreeSha256 },
    scannerManifestSha256: scannerManifest.scannerManifestSha256,
    observations: [
      {
        detectorId: "detector.cisco",
        observationKeySha256: observationKey.observationKeySha256,
        observationSetSha256: observationSet.observationSetSha256,
      },
    ],
    brokerEnforcement: {
      protocol: "BrokerEnforcementBindingV1",
      brokerIdentity: broker.identity,
      policyDigestSha256,
      appliedFactsSha256,
      enforcementState: "unverified",
    },
    cleanup: { outcome: "completed" },
    annexDescriptors: evidenceAnnex.descriptors,
  });
  return {
    protocol: "CiscoOciCandidateV1" as const,
    layout,
    scannerManifest,
    observationKey,
    observationSet,
    evidenceAnnex,
    annexPayloads: allPayloads.map((payload) => ({
      descriptorId: payload.descriptorId,
      payload: payload.bytes.toString("base64"),
    })),
    attestation,
    validationState: "cryptographically-unverified" as const,
  };
}

function store(value: Candidate): Candidate {
  const frozen = deepFreezeStrictJsonV1(value);
  candidates.set(frozen, canonicalStrictJsonBytesV1(frozen));
  return frozen;
}

// biome-ignore lint/suspicious/noExplicitAny: this internal contract composes multiple branded projections.
export function createCiscoOciCandidateV1(input: unknown): any {
  const value = plain(input, fields, "candidate input");
  const layoutValue = ownData(value, "layout");
  if (!isCiscoOciLayoutV1(layoutValue)) fail("branded OCI layout");
  const layout = layoutValue as CiscoOciLayoutV1;
  const runtimeValue = ownData(value, "runtime");
  assertStrictJsonValueV1(runtimeValue, "candidate runtime");
  const runtime = runtimeSchema.parse(runtimeValue) as unknown as Runtime;
  const brokerIdentityValue = ownData(value, "broker");
  assertStrictJsonValueV1(brokerIdentityValue, "candidate broker");
  const broker = brokerSchema.parse(brokerIdentityValue) as unknown as BrokerIdentity;
  if (
    runtime.ociImage.reference !== layout.logicalReference ||
    runtime.ociImage.sha256 !== layout.manifestDigestSha256.slice("sha256:".length)
  )
    fail("runtime OCI identity");
  const brokerResult = parseBroker(ownData(value, "brokerResult"), layout);
  const payloads = parsePayloads(ownData(value, "annexPayloads"), runtime);
  return store(build(layout, brokerResult, runtime, payloads, broker));
}

function inputWithoutHash(
  value: Record<string, unknown>,
  hashField: string,
): Record<string, unknown> {
  const clone = structuredClone(value);
  delete clone[hashField];
  return clone;
}

export function parseCiscoOciCandidateV1Json(text: string): Candidate {
  if (Buffer.byteLength(text, "utf8") > MAX_CANDIDATE_JSON_BYTES)
    fail("candidate JSON exceeds bounded size");
  const parsed = outputSchema.parse(
    parseStrictJsonObjectV1(text, "Cisco OCI candidate"),
  ) as unknown as CandidateWire;
  const layout = parseCiscoOciLayoutV1(canonicalStrictJsonBytesV1(parsed.layout));
  const manifestValue = parsed.scannerManifest as Record<string, unknown>;
  const detectorValues = (manifestValue.detectors as Record<string, unknown>[]).map((entry) =>
    inputWithoutHash(entry, "scannerManifestEntrySha256"),
  );
  const scannerManifest = createScannerManifestV1({
    protocol: "ScannerManifestV1",
    detectors: detectorValues,
  });
  if (!same(scannerManifest, manifestValue)) fail("scanner manifest canonical binding");
  const observationKeyValue = parsed.observationKey as Record<string, unknown>;
  const observationKey = createObservationKeyV1(
    inputWithoutHash(observationKeyValue, "observationKeySha256"),
  );
  if (!same(observationKey, observationKeyValue)) fail("observation key canonical binding");
  const observationSetValue = parsed.observationSet as Record<string, unknown>;
  const observationSet = createObservationSetV1({
    ...inputWithoutHash(observationSetValue, "observationSetSha256"),
    observationKey: inputWithoutHash(
      observationSetValue.observationKey as Record<string, unknown>,
      "observationKeySha256",
    ),
  });
  if (!same(observationSet, observationSetValue)) fail("observation set canonical binding");
  const evidenceAnnex = parseEvidenceAnnexV1Json(
    JSON.stringify(
      inputWithoutHash(parsed.evidenceAnnex as Record<string, unknown>, "evidenceAnnexSha256"),
    ),
  );
  if (!same(evidenceAnnex, parsed.evidenceAnnex)) fail("evidence annex canonical binding");
  const attestation = parseScanAttestationV1Json(JSON.stringify(parsed.attestation));
  if (!same(attestation.statement.predicate.annexDescriptors, evidenceAnnex.descriptors))
    fail("candidate attestation annex binding");
  const payloads = parsed.annexPayloads.map((entry) => {
    const bytes = decodeCanonicalBase64Payload(entry.payload);
    return { descriptorId: entry.descriptorId, bytes };
  });
  if (
    verifyEvidenceAnnexBytesV1({ annex: evidenceAnnex, descriptors: payloads }).kind !== "complete"
  )
    fail("candidate payload digest");
  const ciscoDetector = scannerManifest.detectors[0] ?? fail("candidate Cisco detector missing");
  const sbomDescriptor = evidenceAnnex.descriptors.find(
    (descriptor) => descriptor.descriptorId === "annex.sbom",
  );
  const provenanceDescriptor = evidenceAnnex.descriptors.find(
    (descriptor) => descriptor.descriptorId === "annex.provenance",
  );
  if (scannerManifest.detectors.length !== 1) fail("candidate Cisco detector cardinality");
  if (
    ciscoDetector.detectorId !== "detector.cisco" ||
    ciscoDetector.ociImage.reference !== layout.logicalReference ||
    ciscoDetector.ociImage.sha256 !== layout.manifestDigestSha256.slice("sha256:".length) ||
    sbomDescriptor === undefined ||
    ciscoDetector.sbom.sha256 !== sbomDescriptor.sha256 ||
    provenanceDescriptor === undefined ||
    ciscoDetector.provenance.sha256 !== provenanceDescriptor.sha256
  )
    fail("candidate runtime evidence binding");
  if (
    scannerManifest.scannerManifestSha256 !==
      attestation.statement.predicate.scannerManifestSha256 ||
    observationKey.scannerManifestEntrySha256 !== ciscoDetector.scannerManifestEntrySha256 ||
    observationSet.observationKey.observationKeySha256 !== observationKey.observationKeySha256 ||
    attestation.statement.subject[0]?.digest.sha256 !== observationKey.sourceSeal.sourceTreeSha256
  )
    fail("candidate cross binding");
  const attestedObservations = attestation.statement.predicate.observations;
  const attestedCisco = attestedObservations[0];
  if (
    attestedObservations.length !== 1 ||
    attestedCisco === undefined ||
    attestedCisco.detectorId !== "detector.cisco" ||
    attestedCisco.observationKeySha256 !== observationKey.observationKeySha256 ||
    attestedCisco.observationSetSha256 !== observationSet.observationSetSha256
  )
    fail("candidate attestation observation binding");
  const appliedFactsSha256 = canonicalStrictJsonSha256V1({
    domain: "aih.cisco.oci-candidate.applied-facts-v1",
    facts: observationSet.facts,
    coverage: observationSet.coverage,
  });
  if (attestation.statement.predicate.brokerEnforcement.appliedFactsSha256 !== appliedFactsSha256)
    fail("candidate applied facts binding");
  return store({
    protocol: "CiscoOciCandidateV1",
    layout,
    scannerManifest,
    observationKey,
    observationSet,
    evidenceAnnex,
    annexPayloads: payloads.map((payload) => ({
      descriptorId: payload.descriptorId,
      payload: payload.bytes.toString("base64"),
    })),
    attestation,
    validationState: "cryptographically-unverified",
  });
}

export function canonicalCiscoOciCandidateBytesV1(value: Candidate): Buffer {
  const bytes = typeof value === "object" && value !== null ? candidates.get(value) : undefined;
  return Buffer.from(bytes ?? fail("canonical bytes require a branded candidate"));
}
