import { canonicalBytes, errorDiagnostic, sha256 } from "../assessment/json.js";
import { codeUnitCompare } from "../assessment/strict-json.js";
import { type Diagnostic, schemas } from "../assessment/types.js";
import type {
  CompareMaterialInventoriesInput,
  MaterialChangeEntry,
  MaterialComparisonResult,
  MaterialItem,
} from "./types.js";
import { parseMaterialChange, parseMaterialComparison } from "./validation.js";

async function digest(item: MaterialItem): Promise<string> {
  return sha256(
    canonicalBytes({
      paths: [...item.paths].sort((a, b) => codeUnitCompare(a.path, b.path)),
      metadata: item.metadata,
    }),
  );
}
export async function compareMaterialInventories(
  input: CompareMaterialInventoriesInput,
): Promise<MaterialComparisonResult> {
  try {
    const { sourceId, before, after } = parseMaterialComparison(input);
    const previous = new Map(
      await Promise.all(
        (before?.items ?? []).map(async (item) => [item.itemId, await digest(item)] as const),
      ),
    );
    const current = new Map(
      await Promise.all(
        after.items.map(async (item) => [item.itemId, await digest(item)] as const),
      ),
    );
    const changes: MaterialChangeEntry[] = [];
    const uncompared = new Set([
      ...(before?.uncomparedItemIds ?? []),
      ...(after.uncomparedItemIds ?? []),
    ]);
    const diagnostics: Diagnostic[] = [];
    if ((before !== null && !before.complete) || !after.complete)
      diagnostics.push({
        code: "incomplete-inventory",
        detail: "Incomplete inventory does not establish absent material.",
      });
    if (uncompared.size)
      diagnostics.push({
        code: "uncompared-items",
        detail: "Some material items could not be compared reliably.",
      });
    for (const itemId of [...new Set([...previous.keys(), ...current.keys()])].sort(
      codeUnitCompare,
    )) {
      const beforeSha256 = previous.get(itemId) ?? null;
      const afterSha256 = current.get(itemId) ?? null;
      if (uncompared.has(itemId)) continue;
      if (
        (afterSha256 === null && (!before?.complete || !after.complete)) ||
        (beforeSha256 === null && before !== null && !before.complete)
      ) {
        uncompared.add(itemId);
        continue;
      }
      if (beforeSha256 === afterSha256) continue;
      changes.push({
        itemId,
        kind: beforeSha256 === null ? "added" : afterSha256 === null ? "removed" : "modified",
        beforeSha256,
        afterSha256,
      });
    }
    return {
      status: "compared",
      materialChange: parseMaterialChange({
        schema: schemas.materialChange,
        sourceId,
        materialProjection: "aih-material-v1",
        beforeScanId: before?.scanId ?? null,
        afterScanId: after.scanId,
        inventory: {
          beforeComplete: before?.complete ?? false,
          afterComplete: after.complete,
          uncomparedItemIds: [...uncompared].sort(codeUnitCompare),
        },
        changes,
        diagnostics,
      }),
    };
  } catch (error) {
    return { status: "diagnostic", diagnostics: [errorDiagnostic(error)] };
  }
}
