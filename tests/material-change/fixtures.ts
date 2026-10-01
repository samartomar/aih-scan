import type { Json } from "../../src/assessment/types.js";

export const sourceId = "https://github.com/example/skills";
export const scanA = `scan:sha256:${"a".repeat(64)}` as const;
export const scanB = `scan:sha256:${"b".repeat(64)}` as const;
export const hex = (character: string) => character.repeat(64);

export interface FixtureItem {
  itemId: string;
  paths: { path: string; sha256: string }[];
  metadata: Json;
}
export interface FixtureInventory {
  scanId: string;
  projection: string;
  complete: boolean;
  uncomparedItemIds?: string[];
  items: FixtureItem[];
}

export function item(
  itemId: string,
  digest: string,
  metadata: Json = { install: "copy" },
): FixtureItem {
  return { itemId, paths: [{ path: `${itemId}/SKILL.md`, sha256: hex(digest) }], metadata };
}
export function inventory(
  scanId: string,
  items: FixtureItem[],
  overrides: Partial<FixtureInventory> = {},
): FixtureInventory {
  return { scanId, projection: "aih-material-v1", complete: true, items, ...overrides };
}
