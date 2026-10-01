import type { Diagnostic, Digest, Json, ScanId, schemas } from "../assessment/types.js";

export interface MaterialItem {
  itemId: string;
  paths: { path: string; sha256: Digest }[];
  /** Installation-relevant JSON explicitly declared by the material owner. */
  metadata: Json;
}
export interface MaterialInventory {
  scanId: ScanId;
  projection: "aih-material-v1";
  complete: boolean;
  uncomparedItemIds?: string[];
  items: MaterialItem[];
}
export interface CompareMaterialInventoriesInput {
  sourceId: string;
  before: MaterialInventory | null;
  after: MaterialInventory;
}
export interface MaterialChangeEntry {
  itemId: string;
  kind: "added" | "removed" | "modified";
  beforeSha256: Digest | null;
  afterSha256: Digest | null;
}
export interface MaterialChange {
  schema: typeof schemas.materialChange;
  sourceId: string;
  materialProjection: "aih-material-v1";
  beforeScanId: ScanId | null;
  afterScanId: ScanId;
  inventory: { beforeComplete: boolean; afterComplete: boolean; uncomparedItemIds: string[] };
  changes: MaterialChangeEntry[];
  diagnostics: Diagnostic[];
}
export type MaterialComparisonResult =
  | { status: "compared"; materialChange: MaterialChange }
  | { status: "diagnostic"; diagnostics: Diagnostic[] };
