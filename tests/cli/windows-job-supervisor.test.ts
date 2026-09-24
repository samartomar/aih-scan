import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { type ProcessRunnerOptions, spawnBoundedV1 } from "../../src/cli/process-runner.js";
import {
  findProcessesReferencingV1,
  sweepResidualProcessesV1,
} from "../../src/cli/residual-processes.js";
import {
  runUnderWindowsJobV1,
  windowsCommandLineV1,
  windowsJobSupervisorExecutableV1,
} from "../../src/cli/windows-job-supervisor.js";

/**
 * Real Windows process trees under the Job Object supervisor. The tree is node -> node ->
 * node with every child started DETACHED, so neither Node's own per-process job nor the
 * leader's exit can end it: only Scan's Job Object can. The negative control proves the
 * survivor sweep really finds such a tree when nothing contains it.
 */

const tree = resolve(import.meta.dirname, "..", "fixtures", "process-tree", "tree.mjs");
const temporaryDirectories: string[] = [];
const onWindows = process.platform === "win32";
const REAL_TIMEOUT_MS = 90_000;

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

function marker(label: string): string {
  const directory = mkdtempSync(join(tmpdir(), `aihm-${label}-`));
  temporaryDirectories.push(directory);
  return basename(directory);
}

function windowsEnvironment(): Record<string, string> {
  const systemRoot = process.env.SystemRoot ?? "C:\\Windows";
  return {
    SystemRoot: systemRoot,
    PATH: `${systemRoot}\\System32;${systemRoot}`,
    TEMP: tmpdir(),
    TMP: tmpdir(),
  };
}

function options(extra: Partial<ProcessRunnerOptions> = {}): ProcessRunnerOptions {
  return {
    cwd: resolve(import.meta.dirname, "..", "fixtures", "process-tree"),
    env: windowsEnvironment(),
    timeoutMs: 60_000,
    maxStdoutBytes: 1024 * 1024,
    maxStderrBytes: 1024 * 1024,
    containProcessTree: true,
    ...extra,
  };
}

const settle = (milliseconds: number) =>
  new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));

describe("windowsCommandLineV1", () => {
  it("quotes exactly as the Microsoft C runtime reads arguments back", () => {
    expect(windowsCommandLineV1(["C:\\uv.exe", "run", "--project", "C:\\a b\\p"])).toBe(
      'C:\\uv.exe run --project "C:\\a b\\p"',
    );
    expect(windowsCommandLineV1(["x", ""])).toBe('x ""');
    expect(windowsCommandLineV1(["x", 'say "hi"'])).toBe('x "say \\"hi\\""');
    expect(windowsCommandLineV1(["x", "C:\\dir with space\\"])).toBe('x "C:\\dir with space\\\\"');
    expect(windowsCommandLineV1(["x", 'back\\"quote'])).toBe('x "back\\\\\\"quote"');
    expect(() => windowsCommandLineV1(["x", "nul\0byte"])).toThrow(/NUL/);
    expect(() => windowsCommandLineV1([])).toThrow(/empty argv/);
  });
});

describe.runIf(onWindows)("Windows Job Object supervisor (real processes)", () => {
  it("round-trips hostile arguments and passes stdout bytes through unchanged", async () => {
    const id = marker("echo");
    const argv = [process.execPath, tree, "3", id, "echo", 'a "quoted" \\ arg\\', "", "é ✓"];
    const result = await runUnderWindowsJobV1(argv, options());

    expect(result).toMatchObject({ code: 0, truncated: false });
    expect(result.termination).toBeUndefined();
    expect(JSON.parse(result.stdout)).toEqual(argv.slice(2));
    expect(windowsJobSupervisorExecutableV1()).toMatch(
      /\\System32\\WindowsPowerShell\\v1\.0\\powershell\.exe$/i,
    );
  });

  it(
    "runs a quick three-level tree to completion with an exact stdout and no survivors",
    async () => {
      const id = marker("quick");
      const result = await spawnBoundedV1(
        [process.execPath, tree, "3", id, "quick", "detach"],
        options(),
      );

      expect(result).toMatchObject({ code: 0, truncated: false });
      expect(Buffer.from(result.stdout, "utf8").toString("utf8")).toBe(
        Buffer.from([0x70, 0x72, 0x6f, 0x62, 0x65, 0x00, 0xff, 0xe2, 0x9c, 0x93, 0x0a]).toString(
          "utf8",
        ),
      );
      expect(await findProcessesReferencingV1([id])).toEqual([]);
    },
    REAL_TIMEOUT_MS,
  );

  it(
    "gives the analyzer exactly the declared environment and none of the supervisor's",
    async () => {
      const result = await runUnderWindowsJobV1(
        [process.execPath, "-e", "process.stdout.write(JSON.stringify(process.env))"],
        options({ env: { ...windowsEnvironment(), AIH_PROBE: "declared" } }),
      );

      expect(result.code).toBe(0);
      const environment = JSON.parse(result.stdout) as Record<string, string>;
      expect(environment.AIH_PROBE).toBe("declared");
      expect(Object.keys(environment).some((key) => key.startsWith("AIH_SCAN_"))).toBe(false);
      expect(
        Object.keys(environment)
          .filter((key) => !key.startsWith("="))
          .sort(),
      ).toEqual(["AIH_PROBE", "PATH", "SystemRoot", "TEMP", "TMP"].sort());
    },
    REAL_TIMEOUT_MS,
  );

  it(
    "reports the analyzer's own exit code",
    async () => {
      const result = await runUnderWindowsJobV1(
        [process.execPath, "-e", "process.exit(7)"],
        options(),
      );
      expect(result).toMatchObject({ code: 7, truncated: false });
    },
    REAL_TIMEOUT_MS,
  );

  it(
    "leaves no survivor when nothing contains the tree, proving the sweep finds one (negative control)",
    async () => {
      const id = marker("control");
      const leader = spawn(process.execPath, [tree, "3", id, "wait", "detach"], {
        stdio: "ignore",
        windowsHide: true,
      });
      await settle(2_500);
      leader.kill();
      await settle(500);

      const survivors = await findProcessesReferencingV1([id]);
      expect(survivors.length).toBeGreaterThanOrEqual(1);
      const swept = await sweepResidualProcessesV1([id]);
      expect(swept.surviving).toEqual([]);
    },
    REAL_TIMEOUT_MS,
  );

  it(
    "kills every descendant on timeout",
    async () => {
      const id = marker("timeout");
      const result = await spawnBoundedV1(
        [process.execPath, tree, "3", id, "wait", "detach"],
        options({ timeoutMs: 3_000 }),
      );

      expect(result).toMatchObject({ code: 1, truncated: true, termination: "timeout" });
      await settle(300);
      expect(await findProcessesReferencingV1([id])).toEqual([]);
    },
    REAL_TIMEOUT_MS,
  );

  it(
    "kills every descendant on abort",
    async () => {
      const id = marker("abort");
      const controller = new AbortController();
      setTimeout(() => controller.abort(), 3_000);
      const result = await spawnBoundedV1(
        [process.execPath, tree, "3", id, "wait", "detach"],
        options({ signal: controller.signal }),
      );

      expect(result).toMatchObject({ code: 1, truncated: true, termination: "abort" });
      await settle(300);
      expect(await findProcessesReferencingV1([id])).toEqual([]);
    },
    REAL_TIMEOUT_MS,
  );

  it(
    "catches a leader that exits while its grandchild keeps running, and kills it",
    async () => {
      const id = marker("orphan");
      const result = await spawnBoundedV1(
        [process.execPath, tree, "3", id, "orphan", "detach"],
        options(),
      );

      expect(result).toMatchObject({
        code: 1,
        truncated: true,
        termination: "residual-descendants",
      });
      expect(result.containmentDetail).toMatch(/node\.exe/i);
      expect(await findProcessesReferencingV1([id])).toEqual([]);
    },
    REAL_TIMEOUT_MS,
  );

  it(
    "rejects an analyzer that cannot be created, before anything runs",
    async () => {
      await expect(
        runUnderWindowsJobV1(["C:\\no\\such\\analyzer.exe", "--version"], options()),
      ).rejects.toThrow(/CreateProcessW failed: The system cannot find the path specified \(3\)/);
    },
    REAL_TIMEOUT_MS,
  );
});
