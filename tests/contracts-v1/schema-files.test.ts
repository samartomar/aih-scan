import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { schemas } from "../../src/public/contracts.js";

/**
 * The published `schemas/*.json` files are exactly the `/contracts` schemas, one file per
 * versioned format named after its `$id`. Regenerate with
 * `AIH_SCAN_UPDATE_SCHEMAS=1 npx vitest run tests/contracts-v1/schema-files.test.ts`.
 */
const directory = join(import.meta.dirname, "..", "..", "schemas");
const expected = Object.values(schemas).map((schema) => {
  const name = schema.$id.slice(schema.$id.lastIndexOf("/") + 1);
  return { name, bytes: `${JSON.stringify(schema, null, 2)}\n` };
});

describe("published schema files", () => {
  if (process.env.AIH_SCAN_UPDATE_SCHEMAS === "1")
    for (const { name, bytes } of expected) writeFileSync(join(directory, name), bytes);

  it("are exactly the versioned /contracts schemas", () => {
    expect(readdirSync(directory).sort()).toEqual(expected.map(({ name }) => name).sort());
    for (const { name, bytes } of expected)
      expect(readFileSync(join(directory, name), "utf8"), name).toBe(bytes);
  });

  it("name each file after its format identifier", () => {
    expect(expected.map(({ name }) => name).sort()).toEqual([
      "aih-scan-request-1.json",
      "aih-scan-source-1.json",
      "aih-scan-summary-1.json",
      "aih-scan-withdrawn-1.json",
    ]);
  });
});
