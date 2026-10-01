export type { SignArtifactInput } from "../artifact/host.js";
export {
  attachAttestation,
  authenticateArtifact,
  prepareArtifact,
  signArtifact,
} from "../artifact/host.js";
export type * from "../artifact/types.js";
export type { RetainedObservationsV1 } from "../assessment/reuse.js";
export { createRetainedObservationsV1 } from "../assessment/reuse.js";
export type { RunScanOptions } from "../assessment/run.js";
export { runScan } from "../assessment/run.js";
export type { ScanRequest, ScanRunResult } from "../assessment/types.js";
export { compareMaterialInventories } from "../material-change/compare.js";
export { deliverMaterialChange } from "../material-change/delivery.js";
export type * from "../material-change/delivery-types.js";
export type * from "../material-change/types.js";
