import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  assertBaselineAnalyzerSnapshotUnchangedV1,
  createBaselineAnalyzerSnapshotV1,
} from "../../src/baseline/batch-v1.js";
import { sealSourceObservationV1 } from "../../src/observation/source-observation-seal-v1.js";

/**
 * The runner's analyzer snapshot takes links under the observation rule, which must accept
 * exactly the trees SourceObservationSealV1 accepts and show the analyzer what the seal
 * records: a file link's target bytes at the link path, and no directory link.
 */

const temporaryDirectories: string[] = [];
afterEach(() => {
  for (const directory of temporaryDirectories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

function temporary(label: string): string {
  const root = mkdtempSync(join(tmpdir(), `aih-scan-links-${label}-`));
  temporaryDirectories.push(root);
  return root;
}

const observation = { links: "observation" } as const;

function snapshot(source: string): string {
  const root = createBaselineAnalyzerSnapshotV1(source, observation);
  temporaryDirectories.push(root);
  return root;
}

describe("analyzer snapshot under the observation link rule", () => {
  it("copies absolute and chained contained file links as bytes and leaves directory links out", () => {
    const source = temporary("accepted");
    mkdirSync(join(source, "docs", "deep"), { recursive: true });
    writeFileSync(join(source, "docs", "deep", "a.md"), "alpha\n");
    symlinkSync(join(source, "docs", "deep", "a.md"), join(source, "absolute.md"), "file");
    symlinkSync("absolute.md", join(source, "chained.md"), "file");
    symlinkSync(join(source, "docs"), join(source, "docs", "deep", "up"), "dir");
    symlinkSync(".", join(source, "self"), "dir");
    expect(() =>
      sealSourceObservationV1({ sourceRoot: source, selectedClosurePaths: [] }),
    ).not.toThrow();

    const copy = snapshot(source);
    for (const name of ["absolute.md", "chained.md"]) {
      expect(lstatSync(join(copy, name)).isFile(), name).toBe(true);
      expect(readFileSync(join(copy, name), "utf8")).toBe("alpha\n");
    }
    expect(() => lstatSync(join(copy, "self"))).toThrow();
    expect(() => lstatSync(join(copy, "docs", "deep", "up"))).toThrow();
    expect(() => assertBaselineAnalyzerSnapshotUnchangedV1(copy, observation)).not.toThrow();
  });

  it("refuses the links the seal refuses: escaping and broken", () => {
    const outside = temporary("outside");
    writeFileSync(join(outside, "secret.txt"), "secret\n");
    const escaping = temporary("escaping");
    writeFileSync(join(escaping, "a.md"), "a\n");
    symlinkSync(join(outside, "secret.txt"), join(escaping, "out.txt"), "file");
    const broken = temporary("broken");
    writeFileSync(join(broken, "a.md"), "a\n");
    symlinkSync("missing.txt", join(broken, "dangling.txt"), "file");

    for (const source of [escaping, broken]) {
      expect(() =>
        sealSourceObservationV1({ sourceRoot: source, selectedClosurePaths: [] }),
      ).toThrow();
      expect(() => createBaselineAnalyzerSnapshotV1(source, observation)).toThrow(
        /symbolic link target/,
      );
    }
  });

  it("fails the post-run check when a link appears in an observation snapshot", () => {
    const source = temporary("tamper");
    writeFileSync(join(source, "a.md"), "a\n");
    const copy = snapshot(source);
    symlinkSync("a.md", join(copy, "planted.md"), "file");
    expect(() => assertBaselineAnalyzerSnapshotUnchangedV1(copy, observation)).toThrow(
      /snapshot holds a symbolic link/,
    );
  });
});
