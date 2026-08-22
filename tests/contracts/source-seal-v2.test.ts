import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { canonicalStrictJsonBytesV1 } from "../../src/contract/strict-json-v1.js";
import { sealSourceV2, validateSourceSealV2 } from "../../src/observation/source-seal-v2.js";

type FileEntry = { kind: "file"; path: string; sha256: string; byteLength: number };
const sha256 = (value: Uint8Array | string) => createHash("sha256").update(value).digest("hex");
function sourceSeal(entries: readonly FileEntry[]) {
  const selectedFiles = [
    entries[0] ??
      (() => {
        throw new Error("missing source entry");
      })(),
  ];
  const sourceTreeSha256 = sha256(
    canonicalStrictJsonBytesV1({ protocol: "SourceTreeV2", entries }),
  );
  const selectedClosureSha256 = sha256(
    canonicalStrictJsonBytesV1({ protocol: "SelectedClosureV2", files: selectedFiles }),
  );
  return {
    protocol: "SourceSealV2" as const,
    algorithm: "code-unit-canonical-json-v1" as const,
    entries,
    selectedClosurePaths: selectedFiles.map((entry) => entry.path),
    selectedFiles,
    sourceTreeSha256,
    selectedClosureSha256,
    sealedSnapshotSha256: sha256(
      canonicalStrictJsonBytesV1({
        protocol: "SealedSnapshotV2",
        sourceTreeSha256,
        selectedClosureSha256,
      }),
    ),
  };
}

describe("SourceSealV2", () => {
  it("uses code-unit canonical file order and rejects a selected closure escape", () => {
    const root = mkdtempSync(join(tmpdir(), "aih-scan-source-seal-v2-"));
    try {
      writeFileSync(join(root, "z.md"), "z");
      writeFileSync(join(root, "A.md"), "A");
      mkdirSync(join(root, "empty"));
      const first = sealSourceV2({ sourceRoot: root, selectedClosurePaths: ["z.md", "A.md"] });
      const second = sealSourceV2({ sourceRoot: root, selectedClosurePaths: ["A.md", "z.md"] });
      expect(first.sourceTreeSha256).toBe(second.sourceTreeSha256);
      expect(first.selectedClosureSha256).toBe(second.selectedClosureSha256);
      expect(first.entries).toContainEqual({ kind: "directory", path: "empty" });
      expect(() =>
        validateSourceSealV2({ ...first, entries: [...first.entries].reverse() }),
      ).toThrow();
      expect(() =>
        sealSourceV2({ sourceRoot: root, selectedClosurePaths: ["../outside"] }),
      ).toThrow();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it.runIf(process.platform !== "win32")("refuses symlink source entries", () => {
    const root = mkdtempSync(join(tmpdir(), "aih-scan-source-seal-v2-link-"));
    try {
      writeFileSync(join(root, "actual.md"), "actual");
      symlinkSync(join(root, "actual.md"), join(root, "link.md"));
      expect(() =>
        sealSourceV2({ sourceRoot: root, selectedClosurePaths: ["actual.md"] }),
      ).toThrow();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("rejects a digest-valid seal whose exact canonical representation exceeds 512 KiB", () => {
    const entries = Array.from({ length: 4_096 }, (_, index) => ({
      kind: "file" as const,
      path: `file-${String(index).padStart(4, "0")}-canonical-size-bound.md`,
      sha256: "0".repeat(64),
      byteLength: 0,
    }));
    const oversized = sourceSeal(entries);

    expect(canonicalStrictJsonBytesV1(oversized).byteLength).toBeGreaterThan(512 * 1024);
    expect(() => validateSourceSealV2(oversized)).toThrow("canonical seal byte bound");
  });
});
