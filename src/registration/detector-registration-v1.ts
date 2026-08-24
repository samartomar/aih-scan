import { z } from "zod";
import {
  assertStrictJsonValueV1,
  canonicalStrictJsonBytesV1,
  canonicalStrictJsonSha256V1,
  codeUnitCompare,
  deepFreezeStrictJsonV1,
  parseStrictJsonObjectV1,
} from "../contract/strict-json-v1.js";
import { createScannerManifestV1 } from "../observation/scanner-manifest-v1.js";

const sha256 = z.string().regex(/^[0-9a-f]{64}$/, "must be a lowercase SHA-256 digest");
const maxRegistrationBytes = 512 * 1024;
const platform = z.object({ os: z.literal("linux"), architecture: z.literal("amd64") }).strict();
const immutableOci = z
  .object({ reference: z.string().min(1).max(1024), sha256 })
  .strict()
  .superRefine((value, context) => {
    const match = /^([a-z0-9][a-z0-9._-]*(?:\/[a-z0-9][a-z0-9._-]*)+)@sha256:([0-9a-f]{64})$/.exec(
      value.reference,
    );
    if (match === null || match[2] !== value.sha256)
      context.addIssue({ code: "custom", message: "immutable OCI reference binding" });
  });
const detector = z
  .object({
    detectorId: z
      .string()
      .max(128)
      .regex(/^detector\.[a-z0-9][a-z0-9.-]*$/),
    analyzerIdentity: z.string().regex(/^native\.[0-9a-f]{12}$/),
    ociImage: immutableOci,
    adapter: z.object({ identity: z.string().regex(/^adapter\.[0-9a-f]{12}$/), sha256 }).strict(),
    observationConfigurationSha256: sha256,
    executionProfileSha256: sha256,
    supportedPlatforms: z.array(platform).length(1),
    sbom: z.object({ mediaType: z.literal("application/spdx+json"), sha256 }).strict(),
    provenance: z.object({ mediaType: z.literal("application/vnd.in-toto+json"), sha256 }).strict(),
  })
  .strict();
const registrationInput = z
  .object({
    detector,
    runtime: z
      .object({
        sourceReference: z.string().min(1).max(1024),
        sourceSha256: sha256,
        configSha256: sha256,
      })
      .strict(),
    adapterCapability: z.literal("cisco-oci-v1"),
    broker: z
      .object({
        identity: z.string().regex(/^broker\.[0-9a-f]{12}$/),
        capability: z.literal("cisco-oci-v1"),
      })
      .strict(),
  })
  .strict()
  .superRefine((value, context) => {
    const source = immutableOci.safeParse({
      reference: value.runtime.sourceReference,
      sha256: value.runtime.sourceSha256,
    });
    if (!source.success)
      context.addIssue({ code: "custom", message: "runtime source immutable reference" });
    if (
      value.detector.ociImage.reference !== value.runtime.sourceReference ||
      value.detector.ociImage.sha256 !== value.runtime.sourceSha256
    )
      context.addIssue({ code: "custom", message: "detector runtime source binding" });
    if (value.adapterCapability !== value.broker.capability)
      context.addIssue({ code: "custom", message: "adapter broker capability binding" });
  });
const input = z
  .object({
    protocol: z.literal("DetectorRegistrationV1"),
    registrations: z.array(registrationInput).min(1).max(128),
  })
  .strict();
const wireDetector = detector.extend({ scannerManifestEntrySha256: sha256 }).strict();
const wireRegistration = registrationInput
  .safeExtend({ detector: wireDetector, registrationEntrySha256: sha256 })
  .strict();
const wire = z
  .object({
    protocol: z.literal("DetectorRegistrationV1"),
    registrations: z.array(wireRegistration).min(1).max(128),
    registrationSha256: sha256,
  })
  .strict();

type RegisteredDetector = z.infer<typeof detector> & {
  readonly scannerManifestEntrySha256: string;
};
export type DetectorRegistrationEntryV1 = Readonly<
  Omit<z.infer<typeof registrationInput>, "detector"> & {
    readonly detector: RegisteredDetector;
    readonly registrationEntrySha256: string;
  }
>;
export interface DetectorRegistrationV1 {
  readonly protocol: "DetectorRegistrationV1";
  readonly registrations: readonly DetectorRegistrationEntryV1[];
  readonly registrationSha256: string;
}

const registrations = new WeakMap<object, Buffer>();
function fail(reason: string): never {
  throw new TypeError(`invalid DetectorRegistrationV1: ${reason}`);
}
function assertUnique(values: readonly string[], label: string): void {
  const seen = new Set<string>();
  for (const value of values) {
    if (seen.has(value)) fail(`duplicate or ambiguous ${label}: ${value}`);
    seen.add(value);
  }
}
function entry(value: z.infer<typeof registrationInput>): DetectorRegistrationEntryV1 {
  const manifest = createScannerManifestV1({
    protocol: "ScannerManifestV1",
    detectors: [value.detector],
  });
  const manifestEntry = manifest.detectors[0] ?? fail("detector manifest entry");
  const normalizedDetector = {
    ...value.detector,
    scannerManifestEntrySha256: manifestEntry.scannerManifestEntrySha256,
  };
  return {
    ...value,
    detector: normalizedDetector,
    registrationEntrySha256: canonicalStrictJsonSha256V1({
      domain: "aih.detector-registration-v1.entry",
      registration: { ...value, detector: normalizedDetector },
    }),
  };
}
function authoringInput(value: DetectorRegistrationV1): z.input<typeof input> {
  return {
    protocol: value.protocol,
    registrations: value.registrations.map(
      ({ registrationEntrySha256: _entry, detector, ...entry }) => {
        const { scannerManifestEntrySha256: _manifestEntry, ...detectorInput } = detector;
        return { ...entry, detector: detectorInput };
      },
    ),
  };
}
function store(value: DetectorRegistrationV1): DetectorRegistrationV1 {
  const bytes = canonicalStrictJsonBytesV1(value);
  if (bytes.byteLength > maxRegistrationBytes) fail("canonical bytes bounds");
  registrations.set(value, bytes);
  return value;
}
export function createDetectorRegistrationV1(value: unknown): DetectorRegistrationV1 {
  assertStrictJsonValueV1(value, "detector registration");
  const parsed = input.parse(structuredClone(value));
  assertUnique(
    parsed.registrations.map((item) => item.detector.detectorId),
    "detector ID",
  );
  if (parsed.registrations.some((item) => item.detector.detectorId === "detector.cisco"))
    fail("reserved detector ID");
  const normalized = parsed.registrations
    .map(entry)
    .sort((left, right) => codeUnitCompare(left.detector.detectorId, right.detector.detectorId));
  const result = deepFreezeStrictJsonV1({
    protocol: parsed.protocol,
    registrations: normalized,
    registrationSha256: canonicalStrictJsonSha256V1({
      domain: "aih.detector-registration-v1.aggregate",
      protocol: parsed.protocol,
      registrations: normalized,
    }),
  });
  return store(result);
}
export function parseDetectorRegistrationV1Json(text: string): DetectorRegistrationV1 {
  if (Buffer.byteLength(text, "utf8") > maxRegistrationBytes) fail("canonical bytes bounds");
  const parsed = wire.parse(parseStrictJsonObjectV1(text, "detector registration"));
  const result = createDetectorRegistrationV1(authoringInput(parsed));
  if (!Buffer.from(text, "utf8").equals(canonicalDetectorRegistrationV1Bytes(result)))
    fail("canonical wire binding");
  return result;
}
export function canonicalDetectorRegistrationV1Bytes(value: DetectorRegistrationV1): Buffer {
  const bytes = typeof value === "object" && value !== null ? registrations.get(value) : undefined;
  if (bytes === undefined) fail("canonical bytes require a validated registration");
  return Buffer.from(bytes);
}
