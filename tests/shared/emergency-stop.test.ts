import { spawn } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { spawnBoundedV1 } from "../../src/cli/process-runner.js";
import { writeSnapshot } from "../../src/host/snapshot.js";
import { createTemporaryRoot, stopNowSync } from "../../src/shared/emergency-stop.js";
import { alive } from "../support/analyzer-cli-v1.js";

/**
 * The forced stop behind a second SIGINT: whatever process trees and temporary folders are
 * still registered are ended and removed synchronously; released ones are left alone.
 */
const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) {
    chmodSync(root, 0o700);
    rmSync(root, { recursive: true, force: true });
  }
});

describe.runIf(process.platform !== "win32")("stopNowSync", () => {
  it("kills a running contained tree and removes a read-only working copy", async () => {
    const snapshot = writeSnapshot([
      { path: "a/b/file.txt", mode: "100644", bytes: new TextEncoder().encode("x"), sha256: "" },
    ]);
    const stage = join(snapshot.root, "..");
    const pidFile = join(mkdtempSync(join(tmpdir(), "aih-scan-stop-test-")), "pid");
    roots.push(join(pidFile, ".."));
    const script = `const c = require("node:child_process").spawn(process.execPath, ["-e", "process.on('SIGTERM', () => {}); setInterval(() => {}, 1000)"], { stdio: "ignore" }); require("node:fs").writeFileSync(${JSON.stringify(pidFile)}, String(c.pid)); process.on("SIGTERM", () => {}); setInterval(() => {}, 1000);`;
    const run = spawnBoundedV1([process.execPath, "-e", script], {
      env: { PATH: process.env.PATH ?? "" },
      timeoutMs: 60_000,
      maxStdoutBytes: 1024,
      maxStderrBytes: 1024,
      containProcessTree: true,
    });
    for (let tries = 0; !existsSync(pidFile) && tries < 200; tries += 1)
      await new Promise((resolve) => setTimeout(resolve, 25));
    const grandchild = Number(readFileSync(pidFile, "utf8"));
    expect(alive(grandchild)).toBe(true);

    stopNowSync();

    expect(existsSync(stage)).toBe(false);
    await run;
    for (let tries = 0; alive(grandchild) && tries < 200; tries += 1)
      await new Promise((resolve) => setTimeout(resolve, 10));
    expect(alive(grandchild)).toBe(false);
  });

  it("leaves folders and processes alone once their owner released them", () => {
    const snapshot = writeSnapshot([]);
    const stage = join(snapshot.root, "..");
    snapshot.dispose();
    const kept = mkdtempSync(join(tmpdir(), "aih-scan-stop-test-"));
    roots.push(kept);
    mkdirSync(join(kept, "inner"));
    writeFileSync(join(kept, "inner", "f"), "x");
    stopNowSync();
    expect(existsSync(stage)).toBe(false);
    expect(existsSync(join(kept, "inner", "f"))).toBe(true);
    // A detached, untracked process is not touched either.
    const untracked = spawn(process.execPath, ["-e", "setTimeout(() => {}, 5000)"], {
      stdio: "ignore",
    });
    stopNowSync();
    expect(alive(untracked.pid as number)).toBe(true);
    untracked.kill("SIGKILL");
  });

  it("creates, tracks and disposes one Scan-owned temporary root", () => {
    const parent = mkdtempSync(join(tmpdir(), "aih-scan-stop-test-"));
    roots.push(parent);
    const disposed = createTemporaryRoot("aih-scan-a-", parent);
    const tracked = createTemporaryRoot("aih-scan-b-", parent);
    expect(disposed.path.startsWith(join(parent, "aih-scan-a-"))).toBe(true);
    writeFileSync(join(disposed.path, "f"), "x");
    disposed.dispose();
    disposed.dispose();
    expect(existsSync(disposed.path)).toBe(false);
    expect(existsSync(tracked.path)).toBe(true);
    stopNowSync();
    expect(existsSync(tracked.path)).toBe(false);
  });
});
