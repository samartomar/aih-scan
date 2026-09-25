import { execFileSync, spawnSync } from "node:child_process";
import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { join, resolve } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, describe, expect, it, vi } from "vitest";
import { dockerRunner } from "../../src/cli/docker-runner.js";
import {
  BASELINE_DOCKER_EXECUTABLE_V1,
  BASELINE_UV_EXECUTABLE_V1,
  processRunner,
} from "../../src/cli/process-runner.js";

const { spawnMock, windowsJobMock } = vi.hoisted(() => ({
  spawnMock: vi.fn(),
  windowsJobMock: vi.fn(async (_argv: readonly string[], _options: unknown) => ({
    code: 0,
    stdout: "job",
    stderr: "",
    truncated: false,
  })),
}));

vi.mock("node:child_process", async (importOriginal) => ({
  ...(await importOriginal<typeof import("node:child_process")>()),
  spawn: spawnMock,
}));

vi.mock("../../src/cli/windows-job-supervisor.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../src/cli/windows-job-supervisor.js")>()),
  runUnderWindowsJobV1: windowsJobMock,
}));

class FakeChild extends EventEmitter {
  readonly pid = 4242;
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

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.resetModules();
  for (const directory of temporaryDirectories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

describe("dockerRunner", () => {
  it("runs only the one absolute Docker executable the OCI profile gates, never a PATH lookup", () => {
    spawnMock.mockClear();
    for (const argv of [
      ["docker", "version"],
      ["/bin/docker", "version"],
      ["docker.exe", "version"],
    ])
      expect(() => dockerRunner(argv, options), argv[0]).toThrow("registered Docker argv");
    expect(() => processRunner(["docker", "version"], options)).toThrow("registered process argv");
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it("rejects once and clears its timer when an error races a later close", async () => {
    vi.useFakeTimers();
    const child = new FakeChild();
    spawnMock.mockReturnValue(child);

    const completed = dockerRunner([BASELINE_DOCKER_EXECUTABLE_V1, "version"], options);
    child.emit("error", new Error("docker unavailable"));

    await expect(completed).rejects.toThrow("docker unavailable");
    await vi.advanceTimersByTimeAsync(20);
    expect(child.kill).not.toHaveBeenCalled();
    child.emit("close", 0);
  });

  it("flags stdout that is not well-formed UTF-8 instead of handing back a silent repair (S2h)", async () => {
    for (const [bytes, flagged] of [
      [Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x7d]), true],
      [Buffer.from([0x22, 0xed, 0xa0, 0x80, 0x22]), true],
      [Buffer.from('{"é":1}', "utf8"), false],
    ] as const) {
      const child = new FakeChild();
      spawnMock.mockReturnValue(child);
      const completed = dockerRunner([BASELINE_DOCKER_EXECUTABLE_V1, "version"], {
        ...options,
        timeoutMs: 10_000,
      });
      child.stdout.write(bytes);
      await new Promise((resolve) => setImmediate(resolve));
      child.emit("close", 0);
      const result = (await completed) as { stdoutMalformedUtf8?: true };
      expect(result.stdoutMalformedUtf8 === true).toBe(flagged);
      if (!flagged) expect(result).not.toHaveProperty("stdoutMalformedUtf8");
    }
  });

  it("settles with a truncated result when timeout termination cannot be requested", async () => {
    vi.useFakeTimers();
    const child = new FakeChild();
    spawnMock.mockReturnValue(child);

    const completed = dockerRunner([BASELINE_DOCKER_EXECUTABLE_V1, "version"], options);
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
      termination: "timeout",
    });
    expect(child.kill).toHaveBeenCalledTimes(1);
  });

  it("settles with a truncated result when timeout termination throws", async () => {
    vi.useFakeTimers();
    const child = new FakeChild();
    child.kill.mockImplementation(() => {
      throw new Error("kill failed");
    });
    spawnMock.mockReturnValue(child);

    const completed = dockerRunner([BASELINE_DOCKER_EXECUTABLE_V1, "version"], options);
    await vi.advanceTimersByTimeAsync(options.timeoutMs);

    await expect(completed).resolves.toEqual({
      code: 1,
      stdout: "",
      stderr: "",
      truncated: true,
      termination: "timeout",
    });
    expect(child.kill).toHaveBeenCalledTimes(1);
  });

  it("force-settles after a successful termination request never closes", async () => {
    vi.useFakeTimers();
    const child = new FakeChild();
    child.kill.mockReturnValue(true);
    spawnMock.mockReturnValue(child);

    const completed = dockerRunner([BASELINE_DOCKER_EXECUTABLE_V1, "version"], options);
    await vi.advanceTimersByTimeAsync(options.timeoutMs);
    const bounded = Promise.race([
      completed,
      new Promise<"not-settled">((resolve) => setTimeout(() => resolve("not-settled"), 1001)),
    ]);
    await vi.advanceTimersByTimeAsync(1001);

    await expect(bounded).resolves.toEqual({
      code: 1,
      stdout: "",
      stderr: "",
      truncated: true,
      termination: "timeout",
    });
    expect(child.kill).toHaveBeenNthCalledWith(1, "SIGTERM");
    expect(child.kill).toHaveBeenNthCalledWith(2, "SIGKILL");
  });

  it.each([
    "stdout",
    "stderr",
  ] as const)("settles with a truncated result when %s exceeds its byte cap", async (stream) => {
    const child = new FakeChild();
    child.kill.mockReturnValue(true);
    spawnMock.mockReturnValue(child);

    const completed = dockerRunner([BASELINE_DOCKER_EXECUTABLE_V1, "version"], options);
    child[stream].write(Buffer.alloc(options.maxStdoutBytes + 1));

    await expect(
      Promise.race([completed.then(() => "settled"), Promise.resolve("pending")]),
    ).resolves.toBe("pending");
    child.emit("close", 0);
    await expect(completed).resolves.toEqual({
      code: 1,
      stdout: "",
      stderr: "",
      truncated: true,
      termination: "output-limit",
    });
    expect(child.kill).toHaveBeenCalledTimes(1);
  });
});

describe("processRunner process-group containment", () => {
  it("kills a residual analyzer process group before settling leader success", async () => {
    vi.spyOn(process, "platform", "get").mockReturnValue("linux");
    const child = new FakeChild();
    spawnMock.mockReturnValue(child);
    let groupAlive = true;
    const kill = vi.spyOn(process, "kill").mockImplementation((_pid, signal) => {
      if (signal === 0 && !groupAlive) {
        throw Object.assign(new Error("gone"), { code: "ESRCH" });
      }
      if (signal === "SIGKILL") groupAlive = false;
      return true;
    });

    const completed = processRunner([BASELINE_UV_EXECUTABLE_V1, "run"], {
      ...options,
      containProcessTree: true,
    });
    child.emit("close", 0);

    await expect(completed).resolves.toMatchObject({
      code: 1,
      truncated: true,
      termination: "residual-descendants",
    });
    expect(kill).toHaveBeenCalledWith(-child.pid, 0);
    expect(kill).toHaveBeenCalledWith(-child.pid, "SIGKILL");
  });

  it("retains SIGKILL escalation when the group leader closes after timeout", async () => {
    vi.useFakeTimers();
    vi.spyOn(process, "platform", "get").mockReturnValue("linux");
    const child = new FakeChild();
    spawnMock.mockReturnValue(child);
    let groupAlive = true;
    const kill = vi.spyOn(process, "kill").mockImplementation((_pid, signal) => {
      if (signal === 0 && !groupAlive) throw Object.assign(new Error("gone"), { code: "ESRCH" });
      if (signal === "SIGKILL") groupAlive = false;
      return true;
    });

    const completed = processRunner([BASELINE_UV_EXECUTABLE_V1, "run"], {
      ...options,
      containProcessTree: true,
    });
    await vi.advanceTimersByTimeAsync(options.timeoutMs);
    child.emit("close", 143);
    await expect(
      Promise.race([completed.then(() => "settled"), Promise.resolve("pending")]),
    ).resolves.toBe("pending");
    await vi.advanceTimersByTimeAsync(1_000);

    await expect(completed).resolves.toMatchObject({
      code: 1,
      truncated: true,
      termination: "timeout",
    });
    expect(kill).toHaveBeenCalledWith(-child.pid, "SIGTERM");
    expect(kill).toHaveBeenCalledWith(-child.pid, "SIGKILL");
  });

  it("contains a Windows analyzer tree in a Job Object, never a bare spawn", async () => {
    vi.spyOn(process, "platform", "get").mockReturnValue("win32");
    spawnMock.mockClear();
    windowsJobMock.mockClear();
    const controller = new AbortController();

    await expect(
      processRunner([BASELINE_UV_EXECUTABLE_V1, "run"], {
        ...options,
        containProcessTree: true,
        signal: controller.signal,
      }),
    ).resolves.toEqual({ code: 0, stdout: "job", stderr: "", truncated: false });
    expect(spawnMock).not.toHaveBeenCalled();
    expect(windowsJobMock).toHaveBeenCalledTimes(1);
    expect(windowsJobMock.mock.calls[0]?.[0]).toEqual([BASELINE_UV_EXECUTABLE_V1, "run"]);
    expect(windowsJobMock.mock.calls[0]?.[1]).toMatchObject({
      containProcessTree: true,
      signal: controller.signal,
    });
  });

  it("ends the whole group on abort exactly as on timeout", async () => {
    vi.useFakeTimers();
    vi.spyOn(process, "platform", "get").mockReturnValue("linux");
    const child = new FakeChild();
    spawnMock.mockReturnValue(child);
    let groupAlive = true;
    const kill = vi.spyOn(process, "kill").mockImplementation((_pid, signal) => {
      if (signal === 0 && !groupAlive) throw Object.assign(new Error("gone"), { code: "ESRCH" });
      if (signal === "SIGKILL") groupAlive = false;
      return true;
    });
    const controller = new AbortController();

    const completed = processRunner([BASELINE_UV_EXECUTABLE_V1, "run"], {
      ...options,
      timeoutMs: 60_000,
      containProcessTree: true,
      signal: controller.signal,
    });
    controller.abort();
    child.emit("close", null);
    await vi.advanceTimersByTimeAsync(1_000);

    await expect(completed).resolves.toMatchObject({
      code: 1,
      truncated: true,
      termination: "abort",
    });
    expect(kill).toHaveBeenCalledWith(-child.pid, "SIGTERM");
    expect(kill).toHaveBeenCalledWith(-child.pid, "SIGKILL");
  });

  it("terminates at once when the signal is already aborted", async () => {
    vi.useFakeTimers();
    vi.spyOn(process, "platform", "get").mockReturnValue("linux");
    const child = new FakeChild();
    spawnMock.mockReturnValue(child);
    const kill = vi.spyOn(process, "kill").mockImplementation((_pid, signal) => {
      if (signal === 0) throw Object.assign(new Error("gone"), { code: "ESRCH" });
      return true;
    });

    const completed = processRunner([BASELINE_UV_EXECUTABLE_V1, "run"], {
      ...options,
      timeoutMs: 60_000,
      containProcessTree: true,
      signal: AbortSignal.abort(),
    });
    expect(kill).toHaveBeenCalledWith(-child.pid, "SIGTERM");
    await vi.advanceTimersByTimeAsync(1_000);

    await expect(completed).resolves.toMatchObject({ truncated: true, termination: "abort" });
  });

  it("fails a run whose process group survives bounded polling, without claiming cleanup", async () => {
    vi.useFakeTimers();
    vi.spyOn(process, "platform", "get").mockReturnValue("linux");
    const child = new FakeChild();
    spawnMock.mockReturnValue(child);
    // The group never exits, whatever it is sent.
    const kill = vi.spyOn(process, "kill").mockImplementation(() => true);

    const completed = processRunner([BASELINE_UV_EXECUTABLE_V1, "run"], {
      ...options,
      timeoutMs: 60_000,
      containProcessTree: true,
    });
    child.emit("close", 0);
    await expect(
      Promise.race([completed.then(() => "settled"), Promise.resolve("pending")]),
    ).resolves.toBe("pending");
    await vi.advanceTimersByTimeAsync(1_000);

    await expect(completed).resolves.toMatchObject({
      code: 1,
      truncated: true,
      termination: "containment-failure",
    });
    expect(kill).toHaveBeenCalledWith(-child.pid, "SIGKILL");
    expect(kill.mock.calls.filter(([, signal]) => signal === 0).length).toBeGreaterThan(1);
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
    // The published package ships tools/baseline-analyzers next to dist (package.json
    // "files"); the CLI reads its analyzer locks when it loads (D24 completion evidence).
    symlinkSync(resolve("tools"), join(directory, "tools"), "junction");
    const binPath = join(directory, "aih-scan");
    symlinkSync(join(outputDirectory, "cli.js"), binPath, "file");

    const result = spawnSync(process.execPath, [binPath, "--help"], { encoding: "utf8" });

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("baseline-sign");
  });
});
