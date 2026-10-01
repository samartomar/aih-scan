import { fail } from "./json.js";
import type { CaptureEntry, ObservationInput } from "./types.js";

/**
 * Binding inspectors read a selected inventory. Other current adapters can inspect
 * unselected source facts, so their complete relevant input remains the whole tree.
 */
export function observationScope(
  detectorId: string,
  entries: CaptureEntry[],
  selectedPaths: string[],
): Pick<ObservationInput, "scopeKind" | "entries"> {
  if (detectorId !== "detector.aih-binding-gate") return { scopeKind: "source-tree", entries };

  const byPath = new Map(entries.map((entry) => [entry.path, entry]));
  const relevant = new Set<string>();
  const pending = [...selectedPaths];
  while (pending.length) {
    const path = pending.pop()!;
    if (relevant.has(path)) continue;
    const entry = byPath.get(path);
    if (!entry) fail("Selected detector input is absent from the captured source");
    relevant.add(path);
    const separator = path.lastIndexOf("/");
    if (separator !== -1) pending.push(path.slice(0, separator));
    // Preserve the supported entry contract and the exact bytes reached through
    // each selected link, including the target's captured directory ancestry.
    if ("target" in entry) pending.push(entry.target);
  }
  return {
    scopeKind: "selected-closure",
    entries: entries.filter((entry) => relevant.has(entry.path)),
  };
}
