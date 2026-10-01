import { describe, expect, test } from "vitest";
import { compareMaterialInventories } from "../../src/public/host.js";
import { inventory, item, scanA, scanB, sourceId } from "./fixtures.js";

async function compare(
  before: ReturnType<typeof inventory> | null,
  after: ReturnType<typeof inventory>,
) {
  const result = await compareMaterialInventories({ sourceId, before, after } as never);
  if (result.status !== "compared") throw new Error(JSON.stringify(result));
  return result.materialChange;
}

describe("material comparison", () => {
  test("matches the independently calculated canonical material digest", async () => {
    const change = await compare(
      null,
      inventory(scanB, [
        {
          itemId: "unit",
          paths: [{ path: "SKILL.md", sha256: "a".repeat(64) }],
          metadata: { executable: false, target: "tool" },
        },
      ]),
    );
    expect(change.changes).toEqual([
      {
        itemId: "unit",
        kind: "added",
        beforeSha256: null,
        afterSha256: "06b216649d5099bc197582274886f0634f5cbb025afbf38085c2352f22780ba4",
      },
    ]);
  });
  test("preserves every strict JSON metadata key in material identity", async () => {
    const metadata = JSON.parse('{"__proto__":{"installation":"copy"}}');
    const change = await compare(
      inventory(scanA, [item("unit", "1", metadata)]),
      inventory(scanB, [item("unit", "1", {})]),
    );
    expect(change.changes.map((entry) => [entry.itemId, entry.kind])).toEqual([
      ["unit", "modified"],
    ]);
  });
  test("skips declared uncompared items while reporting the limitation", async () => {
    const change = await compare(
      inventory(scanA, [item("skills/review", "1")]),
      inventory(scanB, [item("skills/review", "2")], { uncomparedItemIds: ["skills/review"] }),
    );
    expect(change.changes).toEqual([]);
    expect(change.inventory.uncomparedItemIds).toEqual(["skills/review"]);
    expect(change.diagnostics).toContainEqual({
      code: "uncompared-items",
      detail: "Some material items could not be compared reliably.",
    });
  });
  test("records incomplete missing items as uncompared rather than removals", async () => {
    const change = await compare(
      inventory(scanA, [item("skills/review", "1")]),
      inventory(scanB, [], { complete: false }),
    );
    expect(change.changes).toEqual([]);
    expect(change.inventory).toEqual({
      beforeComplete: true,
      afterComplete: false,
      uncomparedItemIds: ["skills/review"],
    });
    expect(change.diagnostics).toEqual([
      {
        code: "incomplete-inventory",
        detail: "Incomplete inventory does not establish absent material.",
      },
    ]);
  });
  test("detects modified content even when item and file counts are unchanged", async () => {
    const change = await compare(
      inventory(scanA, [item("skills/review", "1"), item("skills/deploy", "2")]),
      inventory(scanB, [item("skills/review", "1"), item("skills/deploy", "3")]),
    );
    expect(change).toEqual({
      schema: "urn:aihq:scan:material-change:1.0.0",
      sourceId,
      materialProjection: "aih-material-v1",
      beforeScanId: scanA,
      afterScanId: scanB,
      inventory: { beforeComplete: true, afterComplete: true, uncomparedItemIds: [] },
      changes: [
        {
          itemId: "skills/deploy",
          kind: "modified",
          beforeSha256: expect.stringMatching(/^[0-9a-f]{64}$/),
          afterSha256: expect.stringMatching(/^[0-9a-f]{64}$/),
        },
      ],
      diagnostics: [],
    });
    expect(change.changes[0]?.beforeSha256).not.toBe(change.changes[0]?.afterSha256);
  });
  test("initial inventory yields reliable additions in item order, including a partial selection", async () => {
    const change = await compare(
      null,
      inventory(scanB, [item("zeta", "1"), item("alpha", "2")], { complete: false }),
    );
    expect(change.beforeScanId).toBeNull();
    expect(
      change.changes.map(({ itemId, kind, beforeSha256 }) => ({ itemId, kind, beforeSha256 })),
    ).toEqual([
      { itemId: "alpha", kind: "added", beforeSha256: null },
      { itemId: "zeta", kind: "added", beforeSha256: null },
    ]);
  });
  test("complete inventories permit removals and owner metadata changes", async () => {
    const change = await compare(
      inventory(scanA, [item("alpha", "1"), item("zeta", "2")]),
      inventory(scanB, [item("alpha", "1", { install: "link" })]),
    );
    expect(
      change.changes.map(({ itemId, kind, afterSha256 }) => ({
        itemId,
        kind,
        afterSha256: kind === "removed" ? afterSha256 : "present",
      })),
    ).toEqual([
      { itemId: "alpha", kind: "modified", afterSha256: "present" },
      { itemId: "zeta", kind: "removed", afterSha256: null },
    ]);
  });
  test("an incomplete baseline cannot establish newly appearing items or removals", async () => {
    const change = await compare(
      inventory(scanA, [item("old", "1"), item("known", "1")], { complete: false }),
      inventory(scanB, [item("new", "1"), item("known", "2")]),
    );
    expect(change.changes.map((entry) => [entry.itemId, entry.kind])).toEqual([
      ["known", "modified"],
    ]);
    expect(change.inventory.uncomparedItemIds).toEqual(["new", "old"]);
  });
  test("published path order and metadata key order do not alter material identity", async () => {
    const paths = [
      { path: "z", sha256: "1".repeat(64) },
      { path: "a", sha256: "2".repeat(64) },
    ];
    const before = inventory(scanA, [{ itemId: "unit", paths, metadata: { z: 1, a: 2 } }]);
    const after = inventory(scanB, [
      { itemId: "unit", paths: [...paths].reverse(), metadata: { a: 2, z: 1 } },
    ]);
    expect((await compare(before, after)).changes).toEqual([]);
  });
  test("a changed report or findings Scan ID with identical declared material creates no change", async () => {
    const change = await compare(
      inventory(scanA, [item("skills/review", "1")]),
      inventory(scanB, [item("skills/review", "1")]),
    );
    expect(change.changes).toEqual([]);
    expect(change.beforeScanId).toBe(scanA);
    expect(change.afterScanId).toBe(scanB);
  });
  test("metadata-only material has a real identity and can change", async () => {
    const change = await compare(
      inventory(scanA, [{ itemId: "profile", paths: [], metadata: { install: "copy" } }]),
      inventory(scanB, [{ itemId: "profile", paths: [], metadata: { install: "link" } }]),
    );
    expect(change.changes).toEqual([
      {
        itemId: "profile",
        kind: "modified",
        beforeSha256: expect.stringMatching(/^[0-9a-f]{64}$/),
        afterSha256: expect.stringMatching(/^[0-9a-f]{64}$/),
      },
    ]);
  });
});
