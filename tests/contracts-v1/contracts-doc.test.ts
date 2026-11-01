import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";
import { formats, verification } from "../../src/public/contracts.js";

const root = join(import.meta.dirname, "..", "..");
const doc = readFileSync(join(root, "CONTRACTS.md"), "utf8");

it("CONTRACTS.md names exactly the format identifiers the source exports", () => {
  for (const id of Object.values(formats)) expect(doc, id).toContain(`\`${id}\``);
  expect(doc).toContain(`\`${verification.profile}\``);
  const named = [...doc.matchAll(/`(aih-[a-z-]+\/\d+)`/g)].map((match) => match[1]);
  const known = new Set<string>([...Object.values(formats), verification.profile]);
  for (const id of named) expect(known.has(id as string), id).toBe(true);
});

it("CONTRACTS.md names only source and schema files that exist", () => {
  const paths = [...doc.matchAll(/`((?:src|schemas|trust)\/[A-Za-z0-9/._-]+)`/g)].map(
    (match) => match[1] as string,
  );
  expect(paths.length).toBeGreaterThan(10);
  for (const path of paths) expect(existsSync(join(root, path)), path).toBe(true);
});
