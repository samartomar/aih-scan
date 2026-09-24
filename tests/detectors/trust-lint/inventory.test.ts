import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildTrustLintTreeV1 } from "../../../src/detectors/trust-lint/inventory.js";
import { coreSelectionV1 } from "./support.js";

/**
 * Parity port of Core's `tests/trust/inventory.test.ts` against
 * `buildTrustLintTreeV1`. The Core `TrustFileInventory.files` entries also
 * carry `absolutePath`; the Scan seam keeps absolute paths private, so the
 * assertions target `relativePath`/`size` — the stable metadata both share.
 * The Scan tree also lists files under Core's skip directories (§2.2(4) and
 * §2.6 cover them); Core's inventory is the selection, reproduced here by
 * `coreSelectionV1`.
 */
const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("TrustLintTreeV1 (parity: Core TrustFileInventory)", () => {
  it("stores only stable path metadata and reuses it for filtered views", () => {
    const root = mkdtempSync(join(tmpdir(), "aih-trust-inventory-"));
    roots.push(root);
    mkdirSync(join(root, "nested"), { recursive: true });
    mkdirSync(join(root, "node_modules", "ignored"), { recursive: true });
    writeFileSync(join(root, "AGENTS.md"), "# Agent\n", "utf8");
    writeFileSync(join(root, "nested", "package.json"), "{}\n", "utf8");
    writeFileSync(join(root, "node_modules", "ignored", "SKILL.md"), "ignored\n", "utf8");

    const inventory = buildTrustLintTreeV1(root);

    expect(inventory.files).toEqual([
      expect.objectContaining({ relativePath: "AGENTS.md", size: 8, symlink: false }),
      expect.objectContaining({ relativePath: "nested/package.json", size: 3 }),
      expect.objectContaining({ relativePath: "node_modules/ignored/SKILL.md", size: 8 }),
    ]);
    expect(coreSelectionV1(inventory)).toEqual(["AGENTS.md", "nested/package.json"]);
    expect([...inventory.matching((entry) => entry.relativePath.endsWith(".json"))]).toEqual([
      inventory.files[1],
    ]);
    expect(inventory.files.every((entry) => entry.realpathContained)).toBe(true);
    expect(JSON.stringify(inventory.files)).not.toContain("# Agent");
  });

  it("reports bounded inventory progress every 250 files", () => {
    const root = mkdtempSync(join(tmpdir(), "aih-trust-inventory-large-"));
    roots.push(root);
    for (let index = 0; index < 501; index++) {
      writeFileSync(join(root, `file-${String(index).padStart(3, "0")}.txt`), "x", "utf8");
    }
    const progress: number[] = [];

    const inventory = buildTrustLintTreeV1(root, {
      onProgress: (processed) => progress.push(processed),
    });

    expect(inventory.files).toHaveLength(501);
    expect(progress).toEqual([250, 500]);
  });

  it("classifies paths with lstat like Core's inspectContainedPath", () => {
    const root = mkdtempSync(join(tmpdir(), "aih-trust-inventory-kind-"));
    roots.push(root);
    mkdirSync(join(root, "dir"), { recursive: true });
    writeFileSync(join(root, "dir", "file.json"), "{}", "utf8");

    const tree = buildTrustLintTreeV1(root);

    expect(tree.pathKind("dir")).toBe("directory");
    expect(tree.pathKind("dir/file.json")).toBe("file");
    expect(tree.pathKind("missing.json")).toBe("absent");
    expect(tree.pathKind("dir/file.json/below")).toBe("absent");
    expect(tree.isDirectory("dir")).toBe(true);
    expect(tree.isDirectory("dir/file.json")).toBe(false);
    expect(tree.readText("dir/file.json")).toBe("{}");
    expect(tree.readText("missing.json")).toBeUndefined();
  });
});
