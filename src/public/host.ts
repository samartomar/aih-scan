export type { SignArtifactInput } from "../artifact/host.js";
export {
  attachAttestation,
  authenticateArtifact,
  prepareArtifact,
  signArtifact,
} from "../artifact/host.js";
export type * from "../artifact/types.js";
export type { RunScanOptions } from "../assessment/run.js";
export { runScan } from "../assessment/run.js";
export type { ScanRequest, ScanRunResult } from "../assessment/types.js";
