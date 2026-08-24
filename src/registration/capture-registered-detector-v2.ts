import { type CiscoCaptureV2, captureRegisteredCiscoOciCandidateV2 } from "../cisco/capture-v2.js";
import { parseCiscoOciLayoutV1 } from "../cisco/oci-layout-v1.js";
import {
  canonicalStrictJsonBytesV1,
  canonicalStrictJsonSha256V1,
} from "../contract/strict-json-v1.js";
import { createScanCandidateV2 } from "../observation/scan-attestation-v2.js";
import { createScannerManifestV1 } from "../observation/scanner-manifest-v1.js";
import {
  canonicalDetectorRegistrationV1Bytes,
  createDetectorRegistrationV1,
  type DetectorRegistrationV1,
} from "./detector-registration-v1.js";

function fail(reason: string): never {
  throw new TypeError(`invalid registered detector capture: ${reason}`);
}
function ownData(value: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !("value" in descriptor)) fail(`${key} must be own data`);
  return descriptor.value;
}
function exactInput(value: object, fields: readonly string[]): void {
  if (
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.getOwnPropertySymbols(value).length !== 0 ||
    Object.keys(value).length !== fields.length ||
    fields.some((field) => !Object.hasOwn(value, field))
  )
    fail("input fields");
  for (const field of fields) ownData(value, field);
}
function registrationInput(value: DetectorRegistrationV1): Record<string, unknown> {
  return {
    protocol: value.protocol,
    registrations: value.registrations.map(
      ({ registrationEntrySha256: _entry, detector, ...entry }) => {
        const { scannerManifestEntrySha256: _detectorEntry, ...detectorInput } = detector;
        return { ...entry, detector: detectorInput };
      },
    ),
  };
}
function runtimeInput(
  value: DetectorRegistrationV1["registrations"][number]["detector"],
): Record<string, unknown> {
  const { scannerManifestEntrySha256: _entry, ...runtime } = value;
  return runtime;
}
function sameRegistration(left: DetectorRegistrationV1, right: DetectorRegistrationV1): boolean {
  return canonicalDetectorRegistrationV1Bytes(left).equals(
    canonicalDetectorRegistrationV1Bytes(right),
  );
}

/** Dispatches only the named detector registration through a bounded built-in adapter. */
export async function captureRegisteredDetectorCandidateV2(
  value: unknown,
): Promise<CiscoCaptureV2> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail("input object");
  exactInput(value, [
    "registration",
    "detectorId",
    "layout",
    "sourceRoot",
    "selectedClosurePaths",
    "annexPayloads",
    "runner",
  ]);
  const registration = createDetectorRegistrationV1(ownData(value, "registration"));
  const detectorId = ownData(value, "detectorId");
  const layoutInput = ownData(value, "layout");
  const sourceRoot = ownData(value, "sourceRoot");
  const selectedClosurePaths = ownData(value, "selectedClosurePaths");
  const annexPayloads = ownData(value, "annexPayloads");
  const runner = ownData(value, "runner");
  if (
    typeof detectorId !== "string" ||
    typeof sourceRoot !== "string" ||
    !Array.isArray(selectedClosurePaths) ||
    typeof runner !== "function"
  )
    fail("input values");
  const selected = registration.registrations.find(
    (entry) => entry.detector.detectorId === detectorId,
  );
  if (selected === undefined) fail("unregistered detector");
  if (
    selected.adapterCapability !== "cisco-oci-v1" ||
    selected.broker.capability !== "cisco-oci-v1" ||
    selected.detector.supportedPlatforms.length !== 1 ||
    selected.detector.supportedPlatforms[0]?.os !== "linux" ||
    selected.detector.supportedPlatforms[0]?.architecture !== "amd64"
  )
    fail("unsupported registered adapter or platform");
  const layout = parseCiscoOciLayoutV1(canonicalStrictJsonBytesV1(layoutInput));
  if (
    layout.logicalReference !== selected.runtime.sourceReference ||
    layout.manifestDigestSha256 !== `sha256:${selected.runtime.sourceSha256}` ||
    layout.configDigestSha256 !== `sha256:${selected.runtime.configSha256}`
  )
    fail("registered runtime substitution");
  const scannerManifest = createScannerManifestV1({
    protocol: "ScannerManifestV1",
    detectors: registration.registrations.map((entry) => runtimeInput(entry.detector)),
  });
  const beforeRegistration = canonicalDetectorRegistrationV1Bytes(registration);
  const registrationEvidence = {
    detectorId,
    adapterCapability: selected.adapterCapability,
    value: registrationInput(registration),
    scannerManifestSha256: scannerManifest.scannerManifestSha256,
    runtimeSha256: canonicalStrictJsonSha256V1({
      domain: "aih.registered-detector-capture-v1.runtime",
      registrationSha256: registration.registrationSha256,
      detectorId,
    }),
  } as const;
  const captured = await captureRegisteredCiscoOciCandidateV2(
    {
      layout: layoutInput,
      sourceRoot,
      selectedClosurePaths,
      runtime: runtimeInput(selected.detector),
      annexPayloads,
      broker: { identity: selected.broker.identity },
      runner,
    },
    registrationEvidence,
  );
  const reobservedRegistration = createDetectorRegistrationV1(registrationInput(registration));
  if (!beforeRegistration.equals(canonicalDetectorRegistrationV1Bytes(reobservedRegistration)))
    fail("registration changed during capture");
  if (!sameRegistration(registration, reobservedRegistration)) fail("registration re-observation");
  const candidateWire = structuredClone(captured.candidate) as Record<string, unknown>;
  delete candidateWire.candidateSha256;
  const scanner = candidateWire.scanner;
  if (typeof scanner !== "object" || scanner === null || Array.isArray(scanner))
    fail("adapter candidate scanner");
  candidateWire.scanner = {
    ...(scanner as Record<string, unknown>),
    manifestSha256: scannerManifest.scannerManifestSha256,
    runtimeSha256: registrationEvidence.runtimeSha256,
    registration: {
      detectorId: registrationEvidence.detectorId,
      adapterCapability: registrationEvidence.adapterCapability,
      value: registrationEvidence.value,
    },
  };
  return {
    candidate: createScanCandidateV2(candidateWire),
    annexArtifacts: captured.annexArtifacts,
  };
}
