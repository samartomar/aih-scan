import { execFileSync, spawnSync } from "node:child_process";
import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { join, resolve } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";

const { spawnMock } = vi.hoisted(() => ({ spawnMock: vi.fn() }));

vi.mock("node:child_process", async (importOriginal) => ({
  ...(await importOriginal<typeof import("node:child_process")>()),
  spawn: spawnMock,
}));

type DockerRunner = (
  argv: readonly string[],
  options: {
    readonly env: Readonly<Record<string, string>>;
    readonly timeoutMs: number;
    readonly maxStdoutBytes: number;
    readonly maxStderrBytes: number;
  },
) => Promise<unknown>;

class FakeChild extends EventEmitter {
  readonly stdout = new PassThrough();
  readonly stderr = new PassThrough();
  readonly kill = vi.fn(() => false);
}

const options = {
  env: {},
  timeoutMs: 10,
  maxStdoutBytes: 1024,
  maxStderrBytes: 1024,
};
const temporaryDirectories: string[] = [];

async function loadDockerRunner(): Promise<DockerRunner> {
  const originalArgv = process.argv;
  process.argv = [process.execPath, "aih-scan", "--help"];
  try {
    const cli = (await import("../../src/cli.js")) as { dockerRunner?: unknown };
    expect(cli.dockerRunner).toBeTypeOf("function");
    return cli.dockerRunner as DockerRunner;
  } finally {
    process.argv = originalArgv;
  }
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.resetModules();
  for (const directory of temporaryDirectories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

describe("dockerRunner", () => {
  it("rejects once and clears its timer when an error races a later close", async () => {
    vi.useFakeTimers();
    const child = new FakeChild();
    spawnMock.mockReturnValue(child);
    const dockerRunner = await loadDockerRunner();

    const completed = dockerRunner(["docker", "version"], options);
    child.emit("error", new Error("docker unavailable"));

    await expect(completed).rejects.toThrow("docker unavailable");
    await vi.advanceTimersByTimeAsync(20);
    expect(child.kill).not.toHaveBeenCalled();
    child.emit("close", 0);
  });

  it("settles with a truncated result when timeout termination cannot be requested", async () => {
    vi.useFakeTimers();
    const child = new FakeChild();
    spawnMock.mockReturnValue(child);
    const dockerRunner = await loadDockerRunner();

    const completed = dockerRunner(["docker", "version"], options);
    await vi.advanceTimersByTimeAsync(options.timeoutMs);
    const bounded = Promise.race([
      completed,
      new Promise<"not-settled">((resolve) => setTimeout(() => resolve("not-settled"), 1)),
    ]);
    await vi.advanceTimersByTimeAsync(1);

    await expect(bounded).resolves.toEqual({
      code: 1,
      stdout: "",
      stderr: "",
      truncated: true,
    });
    expect(child.kill).toHaveBeenCalledTimes(1);
  });
});

describe("aih-scan bin", () => {
  it("executes through a symlinked installed-bin path", () => {
    const directory = mkdtempSync(join(process.cwd(), ".aih-scan-bin-"));
    temporaryDirectories.push(directory);
    const outputDirectory = join(directory, "dist");
    execFileSync(
      process.execPath,
      [
        resolve("node_modules/typescript/bin/tsc"),
        "-p",
        "tsconfig.build.json",
        "--outDir",
        outputDirectory,
      ],
      { cwd: process.cwd(), stdio: "pipe" },
    );
    const binPath = join(directory, "aih-scan");
    symlinkSync(join(outputDirectory, "cli.js"), binPath, "file");

    const result = spawnSync(process.execPath, [binPath, "--help"], { encoding: "utf8" });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("Usage: aih-scan capture");
  });
});
