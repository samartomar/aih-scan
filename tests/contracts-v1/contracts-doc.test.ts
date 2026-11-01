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

/** Backticked identifiers in one column of the table under `heading` (call forms reduced to the name). */
function column(
  heading: string,
  index: number,
  rowFilter: (row: string[]) => boolean = () => true,
) {
  const start = doc.indexOf(heading);
  expect(start, heading).toBeGreaterThanOrEqual(0);
  const section = doc.slice(start + heading.length).split("\n## ")[0] as string;
  const names = new Set<string>();
  for (const line of section.split("\n")) {
    if (!line.startsWith("|") || line.startsWith("|---")) continue;
    const cells = line.split("|").slice(1, -1);
    if (!rowFilter(cells)) continue;
    for (const match of (cells[index] ?? "").matchAll(/`([A-Za-z_$][\w$]*)(?:\([^`]*\))?`/g))
      names.add(match[1] as string);
  }
  return names;
}

const sorted = (values: Iterable<string>) => [...values].sort();

it("CONTRACTS.md documents exactly the runtime exports of every entry point", async () => {
  const contracts = await import("../../src/public/contracts.js");
  const read = await import("../../src/public/read.js");
  const host = await import("../../src/public/host.js");
  expect(sorted(column("## Rules and data (`@aihq/scan/contracts`)", 1))).toEqual(
    sorted(Object.keys(contracts)),
  );
  const entry = (name: string) =>
    column("## Entry points", 1, (cells) => (cells[0] ?? "").includes(`\`${name}\``));
  expect(sorted(entry("@aihq/scan/read"))).toEqual(sorted(Object.keys(read)));
  expect(sorted(entry("@aihq/scan/host"))).toEqual(sorted(Object.keys(host)));
});
