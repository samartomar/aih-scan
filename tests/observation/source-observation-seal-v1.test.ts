import { createHash } from "node:crypto";
import { linkSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  SOURCE_OBSERVATION_SEAL_LIMITS_V1,
  sealSourceObservationV1,
} from "../../src/observation/source-observation-seal-v1.js";

/**
 * C2a §1.3 tree acceptance: the seal a runDetectorV1 observation run takes accepts every tree
 * Core's assertTrustTreeSafe accepts (empty roots, empty selections, contained file and
 * directory links) up to declared bounds, and refuses hard links and escaping links.
 */

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});
function root(): string {
  const created = mkdtempSync(join(tmpdir(), "aih-scan-observation-seal-"));
  roots.push(created);
  return created;
}
const sha = (text: string) => createHash("sha256").update(text).digest("hex");

describe("sealSourceObservationV1", () => {
  it("declares Core-compatible bounds", () => {
    expect(SOURCE_OBSERVATION_SEAL_LIMITS_V1).toEqual({
      maxEntries: 100_000,
      maxTotalBytes: 256 * 1024 * 1024,
      maxFileBytes: 256 * 1024 * 1024,
    });
  });

  it("seals an empty root with an empty selection", () => {
    const seal = sealSourceObservationV1({ sourceRoot: root(), selectedClosurePaths: [] });
    expect(seal.protocol).toBe("SourceObservationSealV1");
    expect(seal.entries).toEqual([]);
    expect(seal.selectedClosurePaths).toEqual([]);
    expect(seal.sourceTreeSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(Object.isFrozen(seal)).toBe(true);
  });

  it("accepts an empty selection over a non-empty tree", () => {
    const source = root();
    writeFileSync(join(source, "README.md"), "hi\n");
    const seal = sealSourceObservationV1({ sourceRoot: source, selectedClosurePaths: [] });
    expect(seal.entries).toEqual([
      { kind: "file", path: "README.md", sha256: sha("hi\n"), byteLength: 3 },
    ]);
    expect(seal.selectedClosurePaths).toEqual([]);
  });

  it("records a contained file link by its link path and target bytes, and a directory link untraversed", () => {
    const source = root();
    mkdirSync(join(source, "docs", "deep"), { recursive: true });
    writeFileSync(join(source, "docs", "deep", "a.md"), "alpha\n");
    symlinkSync("docs/deep/a.md", join(source, "link.md"), "file");
    symlinkSync("docs", join(source, "docs-link"), "dir");
    const seal = sealSourceObservationV1({
      sourceRoot: source,
      selectedClosurePaths: ["link.md", "docs/deep/a.md"],
    });
    expect(seal.entries).toEqual([
      { kind: "directory", path: "docs" },
      { kind: "directory-link", path: "docs-link", target: "docs" },
      { kind: "directory", path: "docs/deep" },
      { kind: "file", path: "docs/deep/a.md", sha256: sha("alpha\n"), byteLength: 6 },
      {
        kind: "file-link",
        path: "link.md",
        target: "docs/deep/a.md",
        sha256: sha("alpha\n"),
        byteLength: 6,
      },
    ]);
    expect(seal.selectedClosurePaths).toEqual(["docs/deep/a.md", "link.md"]);
    // Nothing under the directory link is sealed twice.
    expect(seal.entries.some((entry) => entry.path.startsWith("docs-link/"))).toBe(false);
  });

  it("refuses a link that escapes the root, a broken link and a hard link", () => {
    const outside = root();
    writeFileSync(join(outside, "secret.txt"), "x");
    const escaping = root();
    symlinkSync(join(outside, "secret.txt"), join(escaping, "out.txt"), "file");
    expect(() =>
      sealSourceObservationV1({ sourceRoot: escaping, selectedClosurePaths: [] }),
    ).toThrow(/escapes the source root/);

    const broken = root();
    symlinkSync("missing.txt", join(broken, "dangling.txt"), "file");
    expect(() => sealSourceObservationV1({ sourceRoot: broken, selectedClosurePaths: [] })).toThrow(
      /link/,
    );

    const hard = root();
    writeFileSync(join(hard, "a.txt"), "a");
    linkSync(join(hard, "a.txt"), join(hard, "b.txt"));
    expect(() => sealSourceObservationV1({ sourceRoot: hard, selectedClosurePaths: [] })).toThrow(
      /hard link/,
    );
  });

  it("refuses a selection that names a directory, a directory link or nothing", () => {
    const source = root();
    mkdirSync(join(source, "docs"));
    writeFileSync(join(source, "docs", "a.md"), "a");
    symlinkSync("docs", join(source, "d"), "dir");
    for (const selected of [["docs"], ["d"], ["missing.md"], ["docs/a.md", "docs/a.md"]])
      expect(
        () => sealSourceObservationV1({ sourceRoot: source, selectedClosurePaths: selected }),
        selected.join(","),
      ).toThrow(/selected closure/);
    expect(() =>
      sealSourceObservationV1({ sourceRoot: source, selectedClosurePaths: ["../x"] }),
    ).toThrow();
  });

  it("seals more than 4,096 entries (the SourceSealV2 bound) and refuses past the declared bound", () => {
    const source = root();
    for (let index = 0; index < 5_000; index += 1)
      writeFileSync(join(source, `f${String(index).padStart(5, "0")}.txt`), "");
    const selected = ["f00000.txt", "f04999.txt"];
    const seal = sealSourceObservationV1({ sourceRoot: source, selectedClosurePaths: selected });
    expect(seal.entries).toHaveLength(5_000);
    expect(() =>
      sealSourceObservationV1({ sourceRoot: source, selectedClosurePaths: [], maxEntries: 4_999 }),
    ).toThrow(/entry bound/);
  }, 60_000);

  it("gives the same digests for the same tree and different ones when a byte changes", () => {
    const source = root();
    writeFileSync(join(source, "a.txt"), "one");
    const first = sealSourceObservationV1({ sourceRoot: source, selectedClosurePaths: ["a.txt"] });
    const again = sealSourceObservationV1({ sourceRoot: source, selectedClosurePaths: ["a.txt"] });
    expect(again.sealedSnapshotSha256).toBe(first.sealedSnapshotSha256);
    writeFileSync(join(source, "a.txt"), "two");
    const changed = sealSourceObservationV1({
      sourceRoot: source,
      selectedClosurePaths: ["a.txt"],
    });
    expect(changed.sourceTreeSha256).not.toBe(first.sourceTreeSha256);
    expect(changed.selectedClosureSha256).not.toBe(first.selectedClosureSha256);
  });
});
