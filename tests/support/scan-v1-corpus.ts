import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { FixtureRoot } from "./scan-v1-fixture.js";

/**
 * The single committed corpus shared by producer and reader proofs: item content as
 * path/mode/text records, plus the summary and SARIF that `scan` produced for it at
 * 2026-11-01T00:30:00Z. Producer tests rescan the content in a temporary folder and must
 * reproduce these bytes; reader tests (host and portable realm) consume them directly.
 */
export const corpusRoot = join(import.meta.dirname, "..", "fixtures", "scan-v1");
export const corpusNow = () => new Date("2026-11-01T00:30:00.000Z");

export interface CorpusCase {
  readonly name: string;
  readonly content: Readonly<Record<string, Readonly<{ mode: "100644" | "100755"; text: string }>>>;
  readonly summary: Uint8Array;
  readonly sarif: readonly Readonly<{ path: string; bytes: Uint8Array }>[];
}

export function corpusCase(name: string): CorpusCase {
  const folder = join(corpusRoot, name);
  const content = JSON.parse(readFileSync(join(folder, "content.json"), "utf8"));
  const summary = new Uint8Array(readFileSync(join(folder, "summary.json")));
  const parsed = JSON.parse(new TextDecoder().decode(summary)) as { sarif: { path: string }[] };
  return {
    name,
    content,
    summary,
    sarif: parsed.sarif.map((entry) => ({
      path: entry.path,
      bytes: new Uint8Array(readFileSync(join(folder, entry.path))),
    })),
  };
}

export function materialize(fixture: FixtureRoot, entry: CorpusCase): string {
  const files = Object.fromEntries(
    Object.entries(entry.content).map(([path, file]) => [path, file.text]),
  );
  const executable = Object.entries(entry.content)
    .filter(([, file]) => file.mode === "100755")
    .map(([path]) => path);
  return fixture.folder(`corpus-${entry.name}`, files, executable);
}

export function contentFiles(entry: CorpusCase) {
  const encoder = new TextEncoder();
  return Object.entries(entry.content).map(([path, file]) => ({
    path,
    mode: file.mode,
    bytes: encoder.encode(file.text),
  }));
}
