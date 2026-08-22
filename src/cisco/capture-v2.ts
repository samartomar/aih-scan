import {
  canonicalStrictJsonBytesV1,
  canonicalStrictJsonSha256V1,
} from "../contract/strict-json-v1.js";
import { describeNativeObservationSourceV1 } from "../observation/native-observation-v1.js";
import { createScanCandidateV2, type ScanCandidateV2 } from "../observation/scan-attestation-v2.js";
import { sealSourceV2 } from "../observation/source-seal-v2.js";
import { executeCiscoOciBrokerV1 } from "./oci-broker-v1.js";
import { createCiscoOciCandidateV1 } from "./oci-candidate-v1.js";
import { parseCiscoOciLayoutV1 } from "./oci-layout-v1.js";

function fail(reason: string): never {
  throw new TypeError(`invalid Cisco V2 capture: ${reason}`);
}
function ownData(value: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !("value" in descriptor)) fail(`${key} must be own data`);
  return descriptor.value;
}
function exactInput(value: object, fields: readonly string[]): void {
  if (
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.getOwnPropertySymbols(value).length > 0
  )
    fail("input plain data");
  const keys = Object.keys(value);
  if (keys.length !== fields.length || fields.some((field) => !keys.includes(field)))
    fail("input fields");
  for (const field of fields) ownData(value, field);
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
function sameV1Seal(
  left: { sourceTreeSha256: string; selectedClosureSha256: string; sealedSnapshotSha256: string },
  right: { sourceTreeSha256: string; selectedClosureSha256: string; sealedSnapshotSha256: string },
): boolean {
  return sameSeal(left, right);
}
function crossCheckSourceInventories(
  v2: {
    entries: readonly {
      kind: "file" | "directory";
      path: string;
      sha256?: string;
      byteLength?: number;
    }[];
    selectedFiles: readonly { path: string; sha256: string; byteLength: number }[];
  },
  v1: {
    sourceFiles: readonly { path: string; sha256: string; bytes: number }[];
    selectedClosureFiles: readonly { path: string; sha256: string; bytes: number }[];
  },
): void {
  const v2Files = v2.entries.filter(
    (entry): entry is { kind: "file"; path: string; sha256: string; byteLength: number } =>
      entry.kind === "file" &&
      typeof entry.sha256 === "string" &&
      typeof entry.byteLength === "number",
  );
  const sameFiles = (
    left: readonly { path: string; sha256: string; byteLength: number }[],
    right: readonly { path: string; sha256: string; bytes: number }[],
  ) => {
    if (left.length !== right.length) return false;
    const byPath = new Map(right.map((entry) => [entry.path, entry]));
    return (
      byPath.size === right.length &&
      left.every((entry) => {
        const paired = byPath.get(entry.path);
        return (
          paired !== undefined &&
          paired.sha256 === entry.sha256 &&
          paired.bytes === entry.byteLength
        );
      })
    );
  };
  if (!sameFiles(v2Files, v1.sourceFiles) || !sameFiles(v2.selectedFiles, v1.selectedClosureFiles))
    fail("V1/V2 source inventory binding");
}
export interface CiscoCaptureV2 {
  readonly candidate: ScanCandidateV2;
  readonly annexArtifacts: readonly { readonly descriptorId: string; readonly bytes: Buffer }[];
}
/** Executes only the registered Cisco OCI broker and promotes its exact internal evidence bindings. */
export async function captureCiscoOciCandidateV2(value: unknown): Promise<CiscoCaptureV2> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail("input object");
  const input = value;
  const fields = [
    "layout",
    "sourceRoot",
    "selectedClosurePaths",
    "runtime",
    "annexPayloads",
    "broker",
    "runner",
  ];
  exactInput(input, fields);
  const layoutInput = ownData(input, "layout");
  const sourceRoot = ownData(input, "sourceRoot");
  const selectedClosurePaths = ownData(input, "selectedClosurePaths");
  const runtime = ownData(input, "runtime");
  const annexPayloads = ownData(input, "annexPayloads");
  const broker = ownData(input, "broker");
  const runner = ownData(input, "runner");
  if (
    typeof sourceRoot !== "string" ||
    !Array.isArray(selectedClosurePaths) ||
    typeof runner !== "function"
  )
    fail("input values");
  const layout = parseCiscoOciLayoutV1(canonicalStrictJsonBytesV1(layoutInput));
  const before = sealSourceV2({
    sourceRoot,
    selectedClosurePaths,
  });
  const beforeV1 = describeNativeObservationSourceV1({
    sourceRoot,
    selectedClosurePaths,
  });
  crossCheckSourceInventories(before, beforeV1);
  const result = await executeCiscoOciBrokerV1({
    protocol: "CiscoOciBrokerV1",
    layout,
    sourceRoot,
    selectedClosurePaths,
    host: { os: "linux", architecture: "amd64" },
    runner,
  });
  if (typeof result !== "object" || result === null) fail("broker result");
  const after = sealSourceV2({
    sourceRoot,
    selectedClosurePaths,
  });
  const afterV1 = describeNativeObservationSourceV1({
    sourceRoot,
    selectedClosurePaths,
  });
  crossCheckSourceInventories(after, afterV1);
  if (!sameSeal(before, after)) fail("source changed during capture");
  if (!sameV1Seal(beforeV1, afterV1) || !sameV1Seal(beforeV1, result.sourceSeal as never))
    fail("V1 source changed during capture");
  const internal = createCiscoOciCandidateV1({
    protocol: "CiscoOciCandidateV1",
    layout,
    brokerResult: result,
    runtime,
    annexPayloads,
    broker,
  });
  const detector = internal.scannerManifest.detectors[0];
  if (
    detector === undefined ||
    internal.attestation.statement.predicate.cleanup.outcome !== "completed"
  )
    fail("internal candidate binding");
  if (!sameV1Seal(beforeV1, internal.observationKey.sourceSeal))
    fail("internal source seal binding");
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
      cisco: {
        detectorId: detector.detectorId,
        analyzerIdentity: detector.analyzerIdentity,
        oci: {
          logicalReference: internal.layout.logicalReference,
          manifestDigestSha256: internal.layout.manifestDigestSha256,
          configDigestSha256: internal.layout.configDigestSha256,
        },
        adapter: detector.adapter,
        observationConfigurationSha256: detector.observationConfigurationSha256,
        executionProfileSha256: detector.executionProfileSha256,
        supportedPlatform: detector.supportedPlatforms[0],
        sbom: { ...detector.sbom, state: "digest-bound-unverified" },
        provenance: { ...detector.provenance, state: "digest-bound-unverified" },
        scannerManifestEntrySha256: detector.scannerManifestEntrySha256,
        sourceSealV1: internal.observationKey.sourceSeal,
        platform: internal.observationKey.platform,
        observation: {
          keySha256: internal.observationKey.observationKeySha256,
          setSha256: internal.observationSet.observationSetSha256,
          facts: internal.observationSet.facts,
          coverage: internal.observationSet.coverage,
        },
        broker: {
          identity: internal.attestation.statement.predicate.brokerEnforcement.brokerIdentity,
          sarifSha256: result.sarifSha256,
          enforcementState:
            internal.attestation.statement.predicate.brokerEnforcement.enforcementState,
          policyDigestSha256:
            internal.attestation.statement.predicate.brokerEnforcement.policyDigestSha256,
          appliedFactsSha256:
            internal.attestation.statement.predicate.brokerEnforcement.appliedFactsSha256,
        },
      },
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
