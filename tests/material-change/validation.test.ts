import { readFileSync } from "node:fs";
import { expect, test } from "vitest";
import { contractSupport } from "../../src/public/contracts.js";
import { compareMaterialInventories, deliverMaterialChange } from "../../src/public/host.js";
import { inventory, item, scanB, sourceId } from "./fixtures.js";

test("refuses an unknown projection before declaring changes", async () => {
  const result = await compareMaterialInventories({
    sourceId,
    before: null,
    after: inventory(scanB, [item("skills/review", "1")], { projection: "unknown" }),
  } as never);
  expect(result).toEqual({
    status: "diagnostic",
    diagnostics: [{ code: "invalid-input", detail: expect.any(String) }],
  });
});

test("publishes the immutable material-change schema resource and contract support", () => {
  expect(contractSupport.contracts).toContainEqual({
    id: "urn:aihq:scan:material-change:1.0.0",
    role: "both",
    schemaExport: "@aihq/scan/schemas/material-change/1.0.0.json",
  });
  const schema = JSON.parse(
    readFileSync(new URL("../../schemas/material-change/1.0.0.json", import.meta.url), "utf8"),
  );
  expect(schema.$id).toBe("urn:aihq:scan:material-change:1.0.0");
  expect(schema.additionalProperties).toBe(false);
});

test("malformed and ambiguous inputs are refused without running getters", async () => {
  let reads = 0;
  const getterItem = Object.defineProperty(item("skills/review", "1"), "metadata", {
    enumerable: true,
    get() {
      reads++;
      return {};
    },
  });
  const hidden = Object.defineProperty(item("skills/review", "1"), "hidden", { value: true });
  const symbol = Object.assign(item("skills/review", "1"), { [Symbol("hidden")]: true });
  for (const value of [
    { sourceId: "D:/machine/source", before: null, after: inventory(scanB, []) },
    {
      sourceId: "https://user:secret@github.com/example/skills",
      before: null,
      after: inventory(scanB, []),
    },
    {
      sourceId: "https://GitHub.com/example/skills.git",
      before: null,
      after: inventory(scanB, []),
    },
    { sourceId, before: null, after: inventory(scanB, [getterItem]) },
    { sourceId, before: null, after: inventory(scanB, [hidden]) },
    { sourceId, before: null, after: inventory(scanB, [symbol]) },
    {
      sourceId,
      before: null,
      after: inventory(scanB, [{ ...item("skills/review", "1"), findings: [] } as never]),
    },
    { sourceId, before: null, after: inventory(scanB, [item("../escape", "1")]) },
    { sourceId, before: null, after: inventory(scanB, [item("e\u0301", "1")]) },
    {
      sourceId,
      before: null,
      after: inventory(scanB, [item("skills/review", "1", { negative: -1 })]),
    },
    {
      sourceId,
      before: null,
      after: inventory(scanB, [], { uncomparedItemIds: ["same", "same"] }),
    },
  ])
    expect((await compareMaterialInventories(value as never)).status).toBe("diagnostic");
  expect(reads).toBe(0);
});

test("a stable explicit local label is accepted without exposing a host path", async () => {
  expect(
    (
      await compareMaterialInventories({
        sourceId: "local:fixture-project",
        before: null,
        after: inventory(scanB, []),
      } as never)
    ).status,
  ).toBe("compared");
});

test("summary validation refuses invalid removal or ambiguous change declarations before delivery", async () => {
  const compared = await compareMaterialInventories({
    sourceId,
    before: null,
    after: inventory(scanB, [item("skills/review", "1")]),
  } as never);
  if (compared.status !== "compared") throw new Error("fixture comparison failed");
  const summary = compared.materialChange;
  const entry = summary.changes[0];
  if (!entry) throw new Error("fixture change missing");
  for (const changes of [
    [{ ...entry, kind: "removed", beforeSha256: entry.afterSha256, afterSha256: null }],
    [{ ...entry, kind: "modified", beforeSha256: entry.afterSha256 }],
    [entry, entry],
  ])
    await expect(
      deliverMaterialChange({ enabled: true, summary: { ...summary, changes } as never }),
    ).rejects.toMatchObject({ code: "invalid-input" });
});

test("refuses ambiguous inventory identities and paths", async () => {
  for (const items of [
    [item("skills/review", "1"), item("skills/review", "2")],
    [
      {
        ...item("skills/review", "1"),
        paths: [
          { path: "same", sha256: "1".repeat(64) },
          { path: "same", sha256: "2".repeat(64) },
        ],
      },
    ],
  ]) {
    expect(
      (
        await compareMaterialInventories({
          sourceId,
          before: null,
          after: inventory(scanB, items),
        } as never)
      ).status,
    ).toBe("diagnostic");
  }
});

test("bounds work before traversing oversized metadata", async () => {
  const metadata = { text: "x".repeat(2 * 1024 * 1024 + 1) };
  const result = await compareMaterialInventories({
    sourceId,
    before: null,
    after: inventory(scanB, [item("skills/review", "1", metadata)]),
  } as never);
  expect(result).toEqual({
    status: "diagnostic",
    diagnostics: [{ code: "resource-limit", detail: expect.any(String) }],
  });
});

test("bounds oversized collections and deeply nested or cyclic metadata", async () => {
  let deep: { [key: string]: unknown } = {};
  for (let at = 0; at < 33; at++) deep = { nested: deep };
  const cycle: { [key: string]: unknown } = {};
  cycle.self = cycle;
  for (const metadata of [deep, cycle, Array.from({ length: 100001 }, () => null)]) {
    expect(
      (
        await compareMaterialInventories({
          sourceId,
          before: null,
          after: inventory(scanB, [item("unit", "1", metadata as never)]),
        } as never)
      ).status,
    ).toBe("diagnostic");
  }
});
