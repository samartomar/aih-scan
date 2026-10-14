import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { expect, test } from "vitest";
import {
  assemblePublicConsumerFixture,
  assertPublicFixtureExports,
  copyPackedPublicAssets,
} from "../support/public-consumer-fixture.js";

test("public fixture assets follow npm's package inventory, including new published assets", () => {
  const root = mkdtempSync(join(tmpdir(), "aih-public-fixture-assets-"));
  try {
    const source = join(root, "source"),
      destination = join(root, "consumer");
    mkdirSync(join(source, "schemas"), { recursive: true });
    writeFileSync(
      join(source, "package.json"),
      JSON.stringify({
        name: "public-fixture",
        version: "1.0.0",
        files: ["schemas"],
        exports: { "./schema.json": "./schemas/required.json" },
        bin: {},
      }),
    );
    writeFileSync(join(source, "schemas/required.json"), "{}");
    writeFileSync(join(source, "schemas/new-public-asset.json"), '{"new":true}');
    writeFileSync(join(source, "private-fixture.txt"), "not published");
    const paths = copyPackedPublicAssets(source, destination);
    expect(paths).toContain("schemas/new-public-asset.json");
    expect(paths).not.toContain("private-fixture.txt");
    expect(readFileSync(join(destination, "schemas/new-public-asset.json"), "utf8")).toBe(
      '{"new":true}',
    );
    assertPublicFixtureExports(destination);
    rmSync(join(destination, "schemas/required.json"));
    expect(() => assertPublicFixtureExports(destination)).toThrow(
      "Public fixture is missing export ./schema.json: ./schemas/required.json",
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("assembled Scan fixtures resolve every public export and load public entry modules", () => {
  const root = mkdtempSync(join(tmpdir(), "aih-public-fixture-exports-"));
  try {
    assemblePublicConsumerFixture(root);
    symlinkSync(resolve("node_modules"), join(root, "node_modules"), "junction");
    writeFileSync(
      join(root, "consumer.mjs"),
      `
import { readFileSync } from 'node:fs';
const manifest = JSON.parse(readFileSync(new URL('./package.json', import.meta.url)));
const resolved = [];
for (const entry of Object.keys(manifest.exports)) {
  const specifier = manifest.name + (entry === '.' ? '' : entry.slice(1));
  const location = import.meta.resolve(specifier);
  if (location.endsWith('.json')) JSON.parse(readFileSync(new URL(location)));
  else await import(specifier);
  resolved.push(entry);
}
process.stdout.write(JSON.stringify(resolved));
`,
    );
    const entries = JSON.parse(
      execFileSync(process.execPath, [join(root, "consumer.mjs")], {
        encoding: "utf8",
        windowsHide: true,
      }),
    );
    const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
    expect(entries).toEqual(Object.keys(manifest.exports));
    rmSync(join(root, "schemas/request/1.0.0.json"));
    expect(() => assertPublicFixtureExports(root)).toThrow(
      "Public fixture is missing export ./schemas/request/1.0.0.json",
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}, 30000);
