import { z } from "zod";
import { bound, ContractError, canonicalBytes, fail, strictParse } from "../assessment/json.js";
import {
  diagnosticShape,
  digestShape,
  pathShape,
  repositoryShape,
  scanIdShape,
} from "../assessment/shapes.js";
import { codeUnitCompare, deepFreezeStrictJsonV1 } from "../assessment/strict-json.js";
import type {
  CompareMaterialInventoriesInput,
  MaterialChange,
  MaterialChangeEntry,
} from "./types.js";

const sourceIdShape = z.union([
  z.string().regex(/^local:[A-Za-z0-9][A-Za-z0-9._-]{0,249}$/),
  repositoryShape.refine((value) => {
    const url = new URL(value);
    return (
      url.href === value &&
      url.pathname !== "/" &&
      !value.endsWith("/") &&
      !value.endsWith(".git") &&
      !url.pathname.includes("%") &&
      pathShape.safeParse(url.pathname.slice(1)).success
    );
  }, "canonical repository URL"),
]);
const inventoryShape = z
  .object({
    scanId: scanIdShape,
    projection: z.literal("aih-material-v1"),
    complete: z.boolean(),
    uncomparedItemIds: z.array(pathShape).max(4096).optional(),
    items: z
      .array(
        z
          .object({
            itemId: pathShape,
            paths: z.array(z.object({ path: pathShape, sha256: digestShape }).strict()).max(4096),
            metadata: z.json(),
          })
          .strict(),
      )
      .max(4096),
  })
  .strict();
const comparisonShape = z
  .object({ sourceId: sourceIdShape, before: inventoryShape.nullable(), after: inventoryShape })
  .strict();
const changeShape = z
  .object({
    itemId: pathShape,
    kind: z.enum(["added", "removed", "modified"]),
    beforeSha256: digestShape.nullable(),
    afterSha256: digestShape.nullable(),
  })
  .strict();
const summaryShape = z
  .object({
    schema: z.literal("urn:aihq:scan:material-change:1.0.0"),
    sourceId: sourceIdShape,
    materialProjection: z.literal("aih-material-v1"),
    beforeScanId: scanIdShape.nullable(),
    afterScanId: scanIdShape,
    inventory: z
      .object({
        beforeComplete: z.boolean(),
        afterComplete: z.boolean(),
        uncomparedItemIds: z.array(pathShape).max(4096),
      })
      .strict(),
    changes: z.array(changeShape).max(4096),
    diagnostics: z.array(diagnosticShape).max(4096),
  })
  .strict();

/** Bound descriptor-only traversal before canonicalization or schema parsing. */
function checkBounds(value: unknown): void {
  const pending: { value: unknown; depth: number }[] = [{ value, depth: 0 }];
  let nodes = 0,
    bytes = 0;
  const text = (value: string) => {
    bound(value.length <= 2 * 1024 * 1024, "material text", 2 * 1024 * 1024);
    bytes += new TextEncoder().encode(value).byteLength;
    bound(bytes <= 2 * 1024 * 1024, "material text", 2 * 1024 * 1024);
  };
  while (pending.length) {
    const next = pending.pop();
    if (!next) continue;
    bound(++nodes <= 100000, "material JSON nodes", 100000);
    bound(next.depth <= 32, "material JSON nesting", 32);
    if (typeof next.value === "string") text(next.value);
    if (next.value === null || typeof next.value !== "object") continue;
    const keys = Reflect.ownKeys(next.value);
    bound(keys.length + nodes + pending.length <= 100000, "material JSON nodes", 100000);
    const array = Array.isArray(next.value);
    const prototype = Object.getPrototypeOf(next.value);
    if (
      array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null
    )
      fail("Material data requires plain JSON objects and arrays.");
    if (Array.isArray(next.value))
      bound(next.value.length <= 100000, "material array length", 100000);
    for (const key of keys) {
      if (typeof key !== "string") fail("Material data must not contain symbol properties.");
      if (array && key === "length") continue;
      const descriptor = Object.getOwnPropertyDescriptor(next.value, key);
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable)
        fail("Material data requires enumerable own data properties.");
      text(key);
      pending.push({ value: descriptor.value, depth: next.depth + 1 });
    }
  }
}
function parse<T>(value: unknown, shape: z.ZodType<T>): T {
  try {
    checkBounds(value);
    const bytes = canonicalBytes(value);
    bound(bytes.byteLength <= 2 * 1024 * 1024, "material canonical bytes", 2 * 1024 * 1024);
    const snapshot = strictParse(bytes, "material data", 2 * 1024 * 1024);
    const parsed = shape.safeParse(snapshot);
    if (!parsed.success) fail("The supplied material data violates the supported contract.");
    // Zod record parsing omits __proto__. Keep the accepted strict JSON snapshot
    // so every explicitly declared installation metadata key remains digest-bound.
    return snapshot as T;
  } catch (error) {
    if (error instanceof ContractError) throw error;
    fail("The supplied material data violates the supported contract.");
  }
}
function unique(values: string[]): void {
  if (new Set(values).size !== values.length) fail("Material identities must be unique.");
}
function ordered(values: string[]): void {
  if (
    values.some((value, index) => {
      const previous = values[index - 1];
      return previous !== undefined && codeUnitCompare(previous, value) >= 0;
    })
  )
    fail("Material identities must be unique and ordered.");
}
export function parseMaterialComparison(value: unknown): CompareMaterialInventoriesInput {
  const input = parse(value, comparisonShape) as CompareMaterialInventoriesInput;
  for (const inventory of [input.before, input.after]) {
    if (!inventory) continue;
    unique(inventory.items.map((item) => item.itemId));
    unique(inventory.uncomparedItemIds ?? []);
    for (const item of inventory.items) unique(item.paths.map((entry) => entry.path));
  }
  return input;
}
const validatedSummaries = new WeakSet<object>();
export function parseMaterialChange(value: unknown): MaterialChange {
  if (value !== null && typeof value === "object" && validatedSummaries.has(value))
    return value as MaterialChange;
  const summary = parse(value, summaryShape) as MaterialChange;
  ordered(summary.inventory.uncomparedItemIds);
  ordered(summary.changes.map((entry) => entry.itemId));
  const uncompared = new Set(summary.inventory.uncomparedItemIds);
  if (summary.beforeScanId === null && summary.inventory.beforeComplete)
    fail("A null baseline cannot be complete.");
  for (const entry of summary.changes) {
    if (uncompared.has(entry.itemId)) fail("Uncompared material cannot carry a change.");
    const { beforeSha256, afterSha256, kind } = entry;
    if (kind === "added") {
      if (
        beforeSha256 !== null ||
        afterSha256 === null ||
        (summary.beforeScanId !== null && !summary.inventory.beforeComplete)
      )
        fail("An addition requires reliable absence and one present material digest.");
    } else if (kind === "removed") {
      if (
        beforeSha256 === null ||
        afterSha256 !== null ||
        summary.beforeScanId === null ||
        !summary.inventory.beforeComplete ||
        !summary.inventory.afterComplete
      )
        fail("A removal requires complete inventories and one present material digest.");
    } else if (
      beforeSha256 === null ||
      afterSha256 === null ||
      beforeSha256 === afterSha256 ||
      summary.beforeScanId === null
    )
      fail("A modification requires a baseline and unequal material digests.");
  }
  deepFreezeStrictJsonV1(summary);
  validatedSummaries.add(summary);
  return summary;
}
export function parseMaterialChangeEntry(value: unknown): MaterialChangeEntry {
  return parse(value, changeShape);
}
