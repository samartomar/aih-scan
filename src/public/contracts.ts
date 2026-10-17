import { schemas } from "../assessment/types.js";
import { packageIdentity } from "./package-identity.js";

export type {
  Artifact,
  ArtifactAnnex,
  ArtifactResult,
  ArtifactStatement,
  AssociationResult,
  AuthenticationTrust,
  ReadArtifactResult,
  SigstoreBundle,
} from "../artifact/types.js";
export type { DetectorDefinitionV1 } from "../assessment/detector-definition.js";
export * from "../assessment/types.js";
export type * from "../material-change/types.js";
export const contractSupport = Object.freeze({
  schema: "urn:aihq:package-support:1.0.0",
  package: packageIdentity,
  contracts: Object.freeze([
    {
      id: "urn:aihq:scan:detector-definition:1.0.0",
      role: "accepts",
      schemaExport: "@aihq/scan/schemas/detector-definition/1.0.0.json",
    },
    { id: schemas.request, role: "accepts", schemaExport: "@aihq/scan/schemas/request/1.0.0.json" },
    {
      id: schemas.runResult,
      role: "produces",
      schemaExport: "@aihq/scan/schemas/run-result/1.0.0.json",
    },
    { id: schemas.report, role: "both", schemaExport: "@aihq/scan/schemas/report/1.0.0.json" },
    { id: schemas.artifact, role: "both", schemaExport: "@aihq/scan/schemas/artifact/1.0.0.json" },
    {
      id: schemas.evidenceAssociation,
      role: "accepts",
      schemaExport: "@aihq/scan/schemas/evidence-association/1.0.0.json",
    },
    {
      id: schemas.materialChange,
      role: "both",
      schemaExport: "@aihq/scan/schemas/material-change/1.0.0.json",
    },
  ]),
  entries: Object.freeze([
    { export: "@aihq/scan/contracts", runtime: "portable", status: "current" },
    { export: "@aihq/scan/read", runtime: "portable", status: "current" },
    { export: "@aihq/scan/host", runtime: "node", nodeRange: ">=24.15.0 <25", status: "current" },
    {
      export: "@aihq/scan",
      runtime: "node",
      nodeRange: ">=24.15.0 <25",
      status: "compatibility-only",
      // Each operation group of the legacy root, its status and the current
      // operation that replaces it for new work (null when nothing replaces it).
      operations: Object.freeze([
        { group: "v2-evidence-readers", status: "compatibility-only", use: "@aihq/scan/read" },
        { group: "baseline-evidence-readers", status: "compatibility-only", use: null },
        { group: "detector-execution", status: "compatibility-only", use: "@aihq/scan/host" },
        { group: "v2-capture-and-signing", status: "compatibility-only", use: "@aihq/scan/host" },
        { group: "legacy-core-evidence", status: "compatibility-only", use: null },
        { group: "baseline-production", status: "deprecated", use: "@aihq/scan/host" },
        { group: "v2-internal-helpers", status: "deprecated", use: null },
      ]),
    },
  ]),
});
