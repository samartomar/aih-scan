import { canonicalStrictJsonSha256V1 } from "../contract/strict-json-v1.js";
import { createScanCandidateV2, type ScanCandidateV2 } from "../observation/scan-attestation-v2.js";
import { sealSourceV2 } from "../observation/source-seal-v2.js";
import { executeCiscoOciBrokerV1 } from "./oci-broker-v1.js";
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
/** Executes only the registered Cisco OCI broker against an explicit source target. */
export async function captureCiscoOciCandidateV2(value: unknown): Promise<ScanCandidateV2> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail("input object");
  const input = value as Record<string, unknown>;
  const fields = ["layout", "sourceRoot", "selectedClosurePaths", "runner"];
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
  const layout = parseCiscoOciLayoutV1(input.layout);
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
  const broker = result as Record<string, unknown>;
  if (
    broker.cleanup === undefined ||
    broker.coverage === undefined ||
    broker.evidenceAnnex === undefined ||
    !Array.isArray(broker.facts)
  )
    fail("broker result shape");
  const annex = broker.evidenceAnnex as { descriptors?: unknown };
  if (!Array.isArray(annex.descriptors)) fail("broker annex");
  return createScanCandidateV2({
    protocol: "ScanCandidateV2",
    coreContract: {
      commit: "e27a55dcebb635c8298aa4fd6fd871f59089bcf7",
      decisionSchemaSha256: "27295aee8d8be333abe2c73adc72884b534b1c9980a9b7a39d12be8d34c5caff",
    },
    subject: { name: "source-tree", digest: { sha256: before.sourceTreeSha256 } },
    sourceSeals: { before, run: before, after },
    observation: {
      keySha256: canonicalStrictJsonSha256V1({
        domain: "aih.cisco.capture-v2.key",
        facts: broker.facts,
      }),
      setSha256: canonicalStrictJsonSha256V1({
        domain: "aih.cisco.capture-v2.set",
        facts: broker.facts,
        coverage: broker.coverage,
      }),
    },
    scanner: {
      manifestSha256: layout.manifestDigestSha256.slice(7),
      runtimeSha256: layout.configDigestSha256.slice(7),
      configurationSha256: layout.configDigestSha256.slice(7),
    },
    platform: { os: "linux", architecture: "amd64" },
    coverage: { kind: "selected-closure", sha256: before.selectedClosureSha256, complete: true },
    annexes: annex.descriptors.map((value) => {
      if (typeof value !== "object" || value === null || Array.isArray(value))
        fail("broker annex descriptor");
      const descriptor = value as Record<string, unknown>;
      return {
        descriptorId: descriptor.descriptorId,
        sha256: descriptor.sha256,
        byteLength: descriptor.byteLength,
      };
    }),
    cleanup: { outcome: "completed" },
    scan: { outcome: "succeeded" },
  });
}
