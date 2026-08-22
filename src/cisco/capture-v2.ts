import {
  canonicalStrictJsonBytesV1,
  canonicalStrictJsonSha256V1,
} from "../contract/strict-json-v1.js";
import { createScanCandidateV2, type ScanCandidateV2 } from "../observation/scan-attestation-v2.js";
import { sealSourceV2 } from "../observation/source-seal-v2.js";
import { executeCiscoOciBrokerV1 } from "./oci-broker-v1.js";
import { createCiscoOciCandidateV1 } from "./oci-candidate-v1.js";
import { parseCiscoOciLayoutV1 } from "./oci-layout-v1.js";

function fail(reason: string): never {
  throw new TypeError(`invalid Cisco V2 capture: ${reason}`);
}
function sameSeal(
  left: { sourceTreeSha256: string; selectedClosureSha256: string; sealedSnapshotSha256: string },
  right: { sourceTreeSha256: string; selectedClosureSha256: string; sealedSnapshotSha256: string },
): boolean {
  return (
    left.sourceTreeSha256 === right.sourceTreeSha256 &&
    left.selectedClosureSha256 === right.selectedClosureSha256 &&
    left.sealedSnapshotSha256 === right.sealedSnapshotSha256
  );
}
export interface CiscoCaptureV2 {
  readonly candidate: ScanCandidateV2;
  readonly annexArtifacts: readonly { readonly descriptorId: string; readonly bytes: Buffer }[];
}
/** Executes only the registered Cisco OCI broker and promotes its exact internal evidence bindings. */
export async function captureCiscoOciCandidateV2(value: unknown): Promise<CiscoCaptureV2> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail("input object");
  const input = value as Record<string, unknown>;
  const fields = [
    "layout",
    "sourceRoot",
    "selectedClosurePaths",
    "runtime",
    "annexPayloads",
    "broker",
    "runner",
  ];
  if (
    Object.getPrototypeOf(input) !== Object.prototype ||
    Object.keys(input).length !== fields.length ||
    fields.some((field) => !Object.hasOwn(input, field))
  )
    fail("input fields");
  if (
    typeof input.sourceRoot !== "string" ||
    !Array.isArray(input.selectedClosurePaths) ||
    typeof input.runner !== "function"
  )
    fail("input values");
  const layout = parseCiscoOciLayoutV1(canonicalStrictJsonBytesV1(input.layout));
  const before = sealSourceV2({
    sourceRoot: input.sourceRoot,
    selectedClosurePaths: input.selectedClosurePaths,
  });
  const result = await executeCiscoOciBrokerV1({
    protocol: "CiscoOciBrokerV1",
    layout,
    sourceRoot: input.sourceRoot,
    selectedClosurePaths: input.selectedClosurePaths,
    host: { os: "linux", architecture: "amd64" },
    runner: input.runner,
  });
  const after = sealSourceV2({
    sourceRoot: input.sourceRoot,
    selectedClosurePaths: input.selectedClosurePaths,
  });
  if (!sameSeal(before, after)) fail("source changed during capture");
  if (typeof result !== "object" || result === null) fail("broker result");
  const internal = createCiscoOciCandidateV1({
    protocol: "CiscoOciCandidateV1",
    layout,
    brokerResult: result,
    runtime: input.runtime,
    annexPayloads: input.annexPayloads,
    broker: input.broker,
  });
  const detector = internal.scannerManifest.detectors[0];
  if (
    detector === undefined ||
    internal.attestation.statement.predicate.cleanup.outcome !== "completed"
  )
    fail("internal candidate binding");
  const annexArtifacts = internal.annexPayloads.map(
    (item: { descriptorId: string; payload: string }) => ({
      descriptorId: item.descriptorId,
      bytes: Buffer.from(item.payload, "base64"),
    }),
  );
  const candidate = createScanCandidateV2({
    protocol: "ScanCandidateV2",
    coreContract: {
      commit: "e27a55dcebb635c8298aa4fd6fd871f59089bcf7",
      decisionSchemaSha256: "27295aee8d8be333abe2c73adc72884b534b1c9980a9b7a39d12be8d34c5caff",
    },
    subject: { name: "source-tree", digest: { sha256: before.sourceTreeSha256 } },
    sourceSeals: { before, after },
    observation: {
      keySha256: internal.observationKey.observationKeySha256,
      setSha256: internal.observationSet.observationSetSha256,
    },
    scanner: {
      manifestSha256: internal.scannerManifest.scannerManifestSha256,
      runtimeSha256: canonicalStrictJsonSha256V1({
        domain: "aih.cisco.capture-v2.runtime",
        detector,
      }),
      configurationSha256: detector.observationConfigurationSha256,
    },
    platform: { os: "linux", architecture: "amd64" },
    coverage: { kind: "selected-closure", sha256: before.selectedClosureSha256, complete: true },
    annexes: internal.evidenceAnnex.descriptors.map((value: unknown) => {
      if (typeof value !== "object" || value === null || Array.isArray(value))
        fail("broker annex descriptor");
      const descriptor = value as Record<string, unknown>;
      return {
        descriptorId: descriptor.descriptorId,
        sha256: descriptor.sha256,
        byteLength: descriptor.byteLength,
      };
    }),
    cleanup: internal.attestation.statement.predicate.cleanup,
    scan: { outcome: "succeeded" },
  });
  return { candidate, annexArtifacts };
}
