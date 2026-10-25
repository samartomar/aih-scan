import { readFileSync } from "node:fs";
import { describe, expect, expectTypeOf, it } from "vitest";
import { contractSupport, entrySupport } from "../../src/public/contracts.js";

// Verbatim copy of the @aihq/core schema export schemas/package-support/1.0.0.json.
// Scan takes no runtime dependency on Core; this fixture pins the published shape.
const schema = JSON.parse(
  readFileSync(
    new URL("../fixtures/core/package-support-1.0.0.schema.json", import.meta.url),
    "utf8",
  ),
) as Schema;

type Schema = Record<string, unknown>;
const supported = new Set([
  "$schema",
  "$id",
  "title",
  "description",
  "type",
  "additionalProperties",
  "required",
  "properties",
  "items",
  "oneOf",
  "const",
  "enum",
  "minLength",
]);

// Validates the keyword subset the schema uses and fails on any other keyword, so a
// schema change cannot silently weaken this check. Returns the failing paths.
function validate(node: Schema, value: unknown, path = "$"): string[] {
  for (const keyword of Object.keys(node)) {
    if (!supported.has(keyword)) throw new Error(`unsupported keyword ${keyword} at ${path}`);
  }
  const errors: string[] = [];
  if ("const" in node && value !== node.const) errors.push(`${path}: const`);
  if (Array.isArray(node.enum) && !node.enum.includes(value)) errors.push(`${path}: enum`);
  if (
    typeof node.minLength === "number" &&
    !(typeof value === "string" && value.length >= node.minLength)
  )
    errors.push(`${path}: minLength`);
  if (node.type === "string" && typeof value !== "string") errors.push(`${path}: type`);
  if (node.type === "array") {
    if (!Array.isArray(value)) return [...errors, `${path}: type`];
    if (node.items)
      for (const [i, item] of value.entries())
        errors.push(...validate(node.items as Schema, item, `${path}[${i}]`));
  }
  if (node.type === "object") {
    if (typeof value !== "object" || value === null || Array.isArray(value))
      return [...errors, `${path}: type`];
    const properties = (node.properties ?? {}) as Record<string, Schema>;
    const record = value as Record<string, unknown>;
    for (const key of (node.required ?? []) as string[])
      if (!(key in record)) errors.push(`${path}.${key}: required`);
    for (const [key, child] of Object.entries(record)) {
      if (key in properties)
        errors.push(...validate(properties[key] as Schema, child, `${path}.${key}`));
      else if (node.additionalProperties === false)
        errors.push(`${path}.${key}: additionalProperties`);
    }
  }
  if (Array.isArray(node.oneOf)) {
    const matches = (node.oneOf as Schema[]).filter(
      (option) => validate(option, value, path).length === 0,
    );
    if (matches.length !== 1) errors.push(`${path}: oneOf matched ${matches.length}`);
  }
  return errors;
}

const plain = (value: unknown) => JSON.parse(JSON.stringify(value)) as Record<string, unknown>;

describe("contractSupport", () => {
  it("publishes schema-adjacent golden fixtures for exactly the supported contracts", () => {
    const manifest = JSON.parse(
      readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
    );
    const fixtureExports = contractSupport.contracts.map(({ schemaExport }) =>
      schemaExport.replace("@aihq/scan/", "./").replace(/\.json$/, ".fixtures.json"),
    );
    expect(
      Object.keys(manifest.exports)
        .filter((key) => key.endsWith(".fixtures.json"))
        .sort(),
    ).toEqual(fixtureExports.sort());
    for (const specifier of fixtureExports) {
      expect(manifest.exports[specifier]).toBe(specifier);
      const fixture = JSON.parse(
        readFileSync(new URL(`../../${specifier}`, import.meta.url), "utf8"),
      );
      expect(["1.0.0", "2.0.0"]).toContain(fixture.contractVersion);
      expect(contractSupport.contracts.some(({ id }) => id === fixture.contractId)).toBe(true);
      expect(
        fixture.cases.some((entry: { expectation: string }) => entry.expectation === "accept"),
      ).toBe(true);
      expect(
        fixture.cases.some((entry: { expectation: string }) => entry.expectation === "refuse"),
      ).toBe(true);
    }
  });

  it("is valid against the package-support 1.0.0 schema", () => {
    expect(schema.$id).toBe(contractSupport.schema);
    expect(validate(schema, plain(contractSupport))).toEqual([]);
  });

  it("carries no field outside the schema's closed key sets", () => {
    expect(Object.keys(contractSupport).sort()).toEqual([
      "contracts",
      "entries",
      "package",
      "schema",
    ]);
    expect(Object.keys(contractSupport.package).sort()).toEqual(["name", "version"]);
    for (const entry of contractSupport.contracts)
      expect(Object.keys(entry).sort()).toEqual(["id", "role", "schemaExport"]);
    for (const entry of contractSupport.entries)
      expect(Object.keys(entry).sort()).toEqual(
        entry.runtime === "node" ? ["export", "nodeRange", "runtime"] : ["export", "runtime"],
      );
  });

  it("rejects lifecycle fields, which belong to entrySupport", () => {
    const withStatus = plain(contractSupport);
    (withStatus.entries as Record<string, unknown>[])[0] = {
      ...(withStatus.entries as Record<string, unknown>[])[0],
      status: "current",
    };
    expect(validate(schema, withStatus)).toEqual(["$.entries[0]: oneOf matched 0"]);
  });

  it("types roles and runtimes as the schema's literals", () => {
    expectTypeOf<(typeof contractSupport.contracts)[number]["role"]>().toEqualTypeOf<
      "accepts" | "produces" | "both"
    >();
    expectTypeOf<(typeof contractSupport.entries)[number]["runtime"]>().toEqualTypeOf<
      "portable" | "node"
    >();
    expectTypeOf<
      (typeof contractSupport)["schema"]
    >().toEqualTypeOf<"urn:aihq:package-support:1.0.0">();
  });

  it("shares its package identity and entry order with entrySupport", () => {
    expect(entrySupport.package).toBe(contractSupport.package);
    expect(entrySupport.entries.map((entry) => entry.export)).toEqual(
      contractSupport.entries.map((entry) => entry.export),
    );
  });
});
