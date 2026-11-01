import { EventEmitter } from "node:events";
import { writeFileSync } from "node:fs";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * The Node side of the Windows Job Object supervisor, on any host: the PowerShell/C#
 * supervisor process is replaced by a fake child that writes the status record the real
 * supervisor writes, so every mapping from status to run result is exercised. The real
 * supervisor runs only on Windows (tests/cli/windows-job-supervisor.test.ts).
 */
const { spawnMock } = vi.hoisted(() => ({ spawnMock: vi.fn() }));
vi.mock("node:child_process", async (importOriginal) => ({
  ...(await importOriginal<typeof import("node:child_process")>()),
  spawn: spawnMock,
}));
const { runUnderWindowsJobV1 } = await import("../../src/cli/windows-job-supervisor.js");

class FakeSupervisor extends EventEmitter {
  readonly stdin = new PassThrough();
  readonly stdout = new PassThrough();
  readonly stderr = new PassThrough();
  readonly kill = vi.fn(() => true);
  spec: { statusPath: string; application: string; commandLine: string; environment: string[] };
  args: string[];
  constructor(command: string, args: string[], options: { env: Record<string, string> }) {
    super();
    this.args = [command, ...args];
    this.spec = JSON.parse(
      Buffer.from(options.env.AIH_SCAN_WINDOWS_JOB_SPEC as string, "base64").toString("utf8"),
    );
  }
  status(value: Record<string, unknown> | string) {
    writeFileSync(
      this.spec.statusPath,
      typeof value === "string"
        ? value
        : JSON.stringify({ protocol: "AihScanWindowsJobStatusV1", ...value }),
    );
  }
}

let supervisor: FakeSupervisor;
const options = {
  cwd: "C:\\work\\item",
  env: { PATH: "C:\\Windows\\System32", HOME: "C:\\Users\\scan" },
  timeoutMs: 60_000,
  maxStdoutBytes: 1024,
  maxStderrBytes: 1024,
  containProcessTree: true,
};
const argv = ["C:\\tools\\skillspector.exe", "scan", "C:\\work\\item dir", "--no-llm"];

beforeEach(() => {
  vi.spyOn(process, "platform", "get").mockReturnValue("win32");
  vi.stubEnv("SystemRoot", "C:\\Windows");
  spawnMock.mockImplementation((command, args, spawnOptions) => {
    supervisor = new FakeSupervisor(command, args, spawnOptions);
    return supervisor;
  });
});
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

const finished = (status: Record<string, unknown> | string | undefined, stdout = "") => {
  const run = runUnderWindowsJobV1(argv, options);
  if (stdout) supervisor.stdout.write(stdout);
  if (status !== undefined) supervisor.status(status);
  setImmediate(() => supervisor.emit("close", 0));
  return run;
};

describe("runUnderWindowsJobV1 (Node side)", () => {
  it("starts Windows PowerShell from SystemRoot with a quoted command line and the exact environment", async () => {
    const result = await finished(
      { leaderExitCode: 0, residualProcesses: 0, residualMembers: [], remainingProcesses: 0 },
      "report",
    );
    expect(result).toEqual({ code: 0, stdout: "report", stderr: "", truncated: false });
    expect(supervisor.args[0]).toBe(
      "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    );
    expect(supervisor.args).toContain("-NonInteractive");
    expect(supervisor.spec.application).toBe(argv[0]);
    expect(supervisor.spec.commandLine).toBe(
      'C:\\tools\\skillspector.exe scan "C:\\work\\item dir" --no-llm',
    );
    expect(supervisor.spec.environment).toEqual([
      "PATH=C:\\Windows\\System32",
      "HOME=C:\\Users\\scan",
    ]);
  });

  it("passes the analyzer's own exit code through", async () => {
    const result = await finished({
      leaderExitCode: 1,
      residualProcesses: 0,
      residualMembers: [],
      remainingProcesses: 0,
    });
    expect(result).toMatchObject({ code: 1, truncated: false });
  });

  it("reports descendants the job ended, and survivors as a containment failure", async () => {
    expect(
      await finished({
        leaderExitCode: 0,
        residualProcesses: 2,
        residualMembers: ["python.exe", "node.exe"],
        remainingProcesses: 0,
      }),
    ).toMatchObject({
      code: 1,
      truncated: true,
      termination: "residual-descendants",
      containmentDetail:
        "2 processes outlived the analyzer and were terminated with its job: python.exe, node.exe",
    });
    expect(
      await finished({
        leaderExitCode: 0,
        residualProcesses: 1,
        residualMembers: ["x.exe"],
        remainingProcesses: 1,
      }),
    ).toMatchObject({
      termination: "containment-failure",
      containmentDetail:
        "1 process outlived the analyzer and could not all be terminated with its job: x.exe",
    });
  });

  it("fails closed when the status is missing, malformed, cancelled or an error", async () => {
    expect(await finished(undefined)).toMatchObject({
      termination: "containment-failure",
      containmentDetail: "the Windows job supervisor exited without a status record",
    });
    expect(await finished({ cancelled: true, remainingProcesses: 0 })).toMatchObject({
      containmentDetail: "the Windows job supervisor lost its stdin and ended the job unasked",
    });
    expect(await finished({ error: "AssignProcessToJobObject failed" })).toMatchObject({
      containmentDetail:
        "the Windows job supervisor could not run the analyzer: AssignProcessToJobObject failed",
    });
    for (const bad of [
      "{}",
      JSON.stringify({ protocol: "other" }),
      JSON.stringify({ protocol: "AihScanWindowsJobStatusV1", leaderExitCode: -1 }),
      JSON.stringify({ protocol: "AihScanWindowsJobStatusV1", cancelled: true }),
      JSON.stringify({
        protocol: "AihScanWindowsJobStatusV1",
        leaderExitCode: 0,
        residualProcesses: 0,
        residualMembers: [1],
        remainingProcesses: 0,
      }),
      "",
    ])
      expect(await finished(bad), bad).toMatchObject({ termination: "containment-failure" });
  });

  it("rejects when the supervisor could not create the analyzer process", async () => {
    await expect(finished({ error: "CreateProcessW failed: 2" })).rejects.toThrow(
      "CreateProcessW failed: 2",
    );
  });

  it("ends the job cooperatively on timeout, abort and output limits", async () => {
    vi.useFakeTimers();
    const timedOut = runUnderWindowsJobV1(argv, { ...options, timeoutMs: 10 });
    await vi.advanceTimersByTimeAsync(10);
    expect(supervisor.stdin.destroyed).toBe(true);
    supervisor.status({ cancelled: true, remainingProcesses: 0 });
    supervisor.emit("close", 1);
    await expect(timedOut).resolves.toMatchObject({ truncated: true, termination: "timeout" });

    const controller = new AbortController();
    const aborted = runUnderWindowsJobV1(argv, { ...options, signal: controller.signal });
    controller.abort();
    supervisor.status({ cancelled: true, remainingProcesses: 3 });
    supervisor.emit("close", 1);
    await expect(aborted).resolves.toMatchObject({
      termination: "containment-failure",
      containmentDetail: "3 job processes survived termination",
    });

    const preAborted = runUnderWindowsJobV1(argv, { ...options, signal: AbortSignal.abort() });
    supervisor.emit("close", 1);
    await expect(preAborted).resolves.toMatchObject({ termination: "abort" });

    const noisy = runUnderWindowsJobV1(argv, options);
    supervisor.stderr.write(Buffer.alloc(1025));
    supervisor.emit("close", 1);
    await expect(noisy).resolves.toMatchObject({
      termination: "output-limit",
      outputLimit: { stream: "stderr", limit: 1024, observed: 1025 },
    });
    const chatty = runUnderWindowsJobV1(argv, options);
    supervisor.stdout.write(Buffer.alloc(1025));
    supervisor.emit("close", 1);
    await expect(chatty).resolves.toMatchObject({
      termination: "output-limit",
      outputLimit: { stream: "stdout" },
    });
  });

  it("kills a supervisor that ignores cooperative termination, then gives up as a containment failure", async () => {
    vi.useFakeTimers();
    const run = runUnderWindowsJobV1(argv, { ...options, timeoutMs: 1 });
    await vi.advanceTimersByTimeAsync(1);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(supervisor.kill).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(10_000);
    await expect(run).resolves.toMatchObject({ termination: "containment-failure" });
  });

  it("refuses unusable input before starting anything", () => {
    spawnMock.mockClear();
    expect(() => runUnderWindowsJobV1(["skillspector.exe"], options)).toThrow("absolute path");
    expect(() => runUnderWindowsJobV1(argv, { ...options, cwd: "relative" })).toThrow(
      "working directory",
    );
    expect(() => runUnderWindowsJobV1(argv, options, { pauseAfterCreateMs: -1 })).toThrow(
      "pauseAfterCreateMs",
    );
    expect(() => runUnderWindowsJobV1(argv, { ...options, env: { A: "1", a: "2" } })).toThrow(
      "declared twice",
    );
    expect(() => runUnderWindowsJobV1(argv, { ...options, env: { "A=B": "1" } })).toThrow(
      "cannot be represented",
    );
    expect(() => runUnderWindowsJobV1([...argv, "a\0b"], options)).toThrow("NUL");
    vi.stubEnv("SystemRoot", "relative");
    expect(() => runUnderWindowsJobV1(argv, options)).toThrow("SystemRoot");
    vi.spyOn(process, "platform", "get").mockReturnValue("linux");
    expect(() => runUnderWindowsJobV1(argv, options)).toThrow("requires a Windows host");
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it("rejects when the supervisor cannot be spawned or errors", async () => {
    spawnMock.mockImplementationOnce(() => {
      throw new Error("spawn EACCES");
    });
    await expect(runUnderWindowsJobV1(argv, options)).rejects.toThrow("spawn EACCES");
    const run = runUnderWindowsJobV1(argv, options);
    supervisor.emit("error", new Error("supervisor crashed"));
    await expect(run).rejects.toThrow("supervisor crashed");
  });
});
