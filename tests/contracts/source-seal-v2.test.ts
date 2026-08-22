import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { sealSourceV2 } from "../../src/observation/source-seal-v2.js";

describe("SourceSealV2", () => {
  it("uses code-unit canonical file order and rejects a selected closure escape", () => {
    const root = mkdtempSync(join(tmpdir(), "aih-scan-source-seal-v2-"));
    try {
      writeFileSync(join(root, "z.md"), "z");
      writeFileSync(join(root, "A.md"), "A");
      const first = sealSourceV2({ sourceRoot: root, selectedClosurePaths: ["z.md", "A.md"] });
      const second = sealSourceV2({ sourceRoot: root, selectedClosurePaths: ["A.md", "z.md"] });
      expect(first.sourceTreeSha256).toBe(second.sourceTreeSha256);
      expect(first.selectedClosureSha256).toBe(second.selectedClosureSha256);
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
});
