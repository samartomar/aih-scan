import { canonicalBytes, fail, sha256 } from "../assessment/json.js";
import type { MaterialChange, MaterialChangeEntry } from "./types.js";
import { parseMaterialChange, parseMaterialChangeEntry } from "./validation.js";

export async function identityForChange(
  summary: MaterialChange,
  entry: MaterialChangeEntry,
): Promise<{ changeId: `change:sha256:${string}`; itemKey: string }> {
  const parsed = parseMaterialChange(summary),
    change = parseMaterialChangeEntry(entry);
  if (
    !parsed.changes.some(
      (candidate) =>
        candidate.itemId === change.itemId &&
        candidate.kind === change.kind &&
        candidate.beforeSha256 === change.beforeSha256 &&
        candidate.afterSha256 === change.afterSha256,
    )
  )
    fail("The material change entry must belong to the supplied summary.");
  const changeId = `change:sha256:${await sha256(
    canonicalBytes({
      domain: "aih.scan.material-change.v1",
      sourceId: parsed.sourceId,
      materialProjection: parsed.materialProjection,
      ...change,
    }),
  )}` as const;
  const itemKey = await sha256(
    canonicalBytes({
      domain: "aih.scan.material-item.v1",
      sourceId: parsed.sourceId,
      itemId: change.itemId,
    }),
  );
  return { changeId, itemKey };
}
