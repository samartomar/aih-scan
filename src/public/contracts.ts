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
export * from "../assessment/types.js";
export type * from "../material-change/types.js";
export const contractSupport = Object.freeze({
  schema: "urn:aihq:package-support:1.0.0",
  package: packageIdentity,
  contracts: Object.freeze([
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
    { export: "@aihq/scan/contracts", runtime: "portable" },
    { export: "@aihq/scan/read", runtime: "portable" },
    { export: "@aihq/scan/host", runtime: "node", nodeRange: ">=24.15.0 <25" },
  ]),
});
