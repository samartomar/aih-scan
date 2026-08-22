import {
  linkSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  truncateSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { sealSourceV2, validateSourceSealV2 } from "../../src/observation/source-seal-v2.js";

const roots: string[] = [];
const maxFileBytes = 16 * 1024 * 1024;

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fixtureRoot(label: string): string {
  const root = mkdtempSync(join(tmpdir(), `aih-scan-${label}-`));
  roots.push(root);
  writeFileSync(join(root, "SKILL.md"), "fixture");
  return root;
}

describe("SourceSealV2 adversarial filesystem contract", () => {
  it("refuses static selected-closure escapes before collecting source entries", () => {
    const root = fixtureRoot("source-seal-static");
    const outside = join(tmpdir(), "aih-scan-source-seal-outside.md");
    writeFileSync(outside, "outside");
    try {
      expect(() =>
        sealSourceV2({
          sourceRoot: root,
          selectedClosurePaths: ["../aih-scan-source-seal-outside.md"],
        }),
      ).toThrow();
      expect(() => sealSourceV2({ sourceRoot: root, selectedClosurePaths: [outside] })).toThrow();
    } finally {
      rmSync(outside, { force: true });
    }
  });

  it("refuses file symlinks, hardlinks, and oversize files without materializing their contents", () => {
    const root = fixtureRoot("source-seal-files");
    const regular = join(root, "regular.md");
    writeFileSync(regular, "regular");
    symlinkSync(regular, join(root, "link.md"));
    expect(() => sealSourceV2({ sourceRoot: root, selectedClosurePaths: ["SKILL.md"] })).toThrow();
    rmSync(join(root, "link.md"));
    linkSync(regular, join(root, "hardlink.md"));
    expect(() => sealSourceV2({ sourceRoot: root, selectedClosurePaths: ["SKILL.md"] })).toThrow();
    rmSync(join(root, "hardlink.md"));
    truncateSync(regular, maxFileBytes + 1);
    expect(() => sealSourceV2({ sourceRoot: root, selectedClosurePaths: ["SKILL.md"] })).toThrow();
  });

  it.runIf(process.platform === "win32")("refuses a Windows directory junction", () => {
    const root = fixtureRoot("source-seal-junction");
    const target = fixtureRoot("source-seal-junction-target");
    mkdirSync(join(target, "nested"));
    symlinkSync(target, join(root, "junction"), "junction");
    expect(() => sealSourceV2({ sourceRoot: root, selectedClosurePaths: ["SKILL.md"] })).toThrow();
  });

  it("rejects aggregate source bytes and entry-count claims without allocating large fixture files", () => {
    const root = fixtureRoot("source-seal-bounds");
    const baseline = sealSourceV2({ sourceRoot: root, selectedClosurePaths: ["SKILL.md"] });
    const oversizedAggregate = {
      ...baseline,
      entries: Array.from({ length: 17 }, (_, index) => ({
        kind: "file" as const,
        path: `entry-${String(index).padStart(2, "0")}.md`,
        sha256: "0".repeat(64),
        byteLength: maxFileBytes,
      })),
    };
    expect(() => validateSourceSealV2(oversizedAggregate)).toThrow();
    expect(() =>
      sealSourceV2({
        sourceRoot: root,
        selectedClosurePaths: Array.from({ length: 4_097 }, (_, index) => `entry-${index}.md`),
      }),
    ).toThrow();
  });

  it("rejects noncanonical, V1, and TOCTOU-substituted seal structures before they can bind a candidate", () => {
    const root = fixtureRoot("source-seal-structure");
    writeFileSync(join(root, "other.md"), "other");
    const baseline = sealSourceV2({ sourceRoot: root, selectedClosurePaths: ["SKILL.md"] });
    expect(() => validateSourceSealV2({ ...baseline, protocol: "SourceSealV1" })).toThrow();
    expect(() =>
      validateSourceSealV2({ ...baseline, entries: [...baseline.entries].reverse() }),
    ).toThrow();
    const substituted = structuredClone(baseline);
    substituted.entries[0] = {
      kind: "file",
      path: "SKILL.md",
      sha256: "f".repeat(64),
      byteLength: 7,
    };
    expect(() => validateSourceSealV2(substituted)).toThrow();
  });
});
