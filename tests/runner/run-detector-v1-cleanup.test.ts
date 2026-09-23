import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { runDetectorV1 } from "../../src/runner/run-detector-v1.js";

/**
 * The runner's private analyzer snapshot is removed after every run. When that removal
 * throws, the promise still resolves: a run that already executed reports `failed` at
 * stage `cleanup` rather than claiming success, and never a refusal, because a refusal
 * means nothing ran.
 */

const failSnapshotRemoval = vi.hoisted(() => ({ on: false }));
// The snapshot paths whose removal this test intercepted: only THOSE are cleaned up afterwards,
// never other snapshots that concurrent work may be holding in the shared temporary directory.
const interceptedSnapshots = vi.hoisted(() => [] as string[]);

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  const rmSyncMocked: typeof actual.rmSync = (path, options) => {
    if (failSnapshotRemoval.on && String(path).includes("aih-scan-baseline-source-")) {
      interceptedSnapshots.push(String(path));
      throw new Error("EBUSY: snapshot directory is held open");
    }
    actual.rmSync(path, options);
  };
  return { ...actual, rmSync: rmSyncMocked, default: { ...actual, rmSync: rmSyncMocked } };
});

const temporaryDirectories: string[] = [];

afterEach(() => {
  failSnapshotRemoval.on = false;
  for (const directory of temporaryDirectories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

function sourceFixture(): string {
  const root = mkdtempSync(join(tmpdir(), "aih-scan-run-cleanup-source-"));
  temporaryDirectories.push(root);
  mkdirSync(join(root, "rules"), { recursive: true });
  writeFileSync(join(root, "rules", "base.md"), "# Rule\n", "utf8");
  writeFileSync(join(root, "README.md"), "# Readme\n", "utf8");
  return root;
}


describe("runDetectorV1 snapshot cleanup", () => {
  it("resolves to a cleanup failure, not a rejection or a refusal, when the snapshot cannot be removed", async () => {
    failSnapshotRemoval.on = true;

    const settled = await runDetectorV1({
      detectorId: "detector.aih-native",
      subject: {
        kind: "source-tree",
        sourceRoot: sourceFixture(),
        selectedClosurePaths: ["README.md"],
      },
    }).then(
      (value) => ({ resolved: true as const, value }),
      (error: unknown) => ({ resolved: false as const, error }),
    );
    failSnapshotRemoval.on = false;
    expect(interceptedSnapshots.length).toBeGreaterThan(0);
    temporaryDirectories.push(...interceptedSnapshots.splice(0));

    expect(settled.resolved).toBe(true);
    if (!settled.resolved) return;
    expect(settled.value.outcome).toBe("failed");
    if (settled.value.outcome !== "failed") return;
    expect(settled.value.failure.stage).toBe("cleanup");
    expect(settled.value.failure.detail).toContain("EBUSY");
    expect(settled.value.producer.name).toBe("@aihq/scan");
  });

  it("still succeeds when the snapshot is removed", async () => {
    const result = await runDetectorV1({
      detectorId: "detector.aih-native",
      subject: {
        kind: "source-tree",
        sourceRoot: sourceFixture(),
        selectedClosurePaths: ["README.md"],
      },
    });

    expect(result.outcome).toBe("succeeded");
  });
});
