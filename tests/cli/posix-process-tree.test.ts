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

/**
 * Real POSIX process trees (Linux and macOS) under Scan's process-group containment. The
 * tree is node -> node -> node. With "attach" every child stays in the leader's process
 * group, which is what the runner signals. With "detach" a child calls setsid() and leaves
 * the group: the runner cannot see it, and only the post-run residual sweep can, which is
 * why every host-process run ends with that sweep and fails closed on any survivor.
 */

const tree = resolve(import.meta.dirname, "..", "fixtures", "process-tree", "tree.mjs");
const temporaryDirectories: string[] = [];
const onPosix = process.platform === "linux" || process.platform === "darwin";
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

function options(extra: Partial<ProcessRunnerOptions> = {}): ProcessRunnerOptions {
  return {
    cwd: resolve(import.meta.dirname, "..", "fixtures", "process-tree"),
    env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8" },
    timeoutMs: 60_000,
    maxStdoutBytes: 1024 * 1024,
    maxStderrBytes: 1024 * 1024,
    containProcessTree: true,
    ...extra,
  };
}

const settle = (milliseconds: number) =>
  new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));

describe.runIf(onPosix)("POSIX process-group containment (real processes)", () => {
  it(
    "runs a quick three-level tree to completion with an exact stdout and no survivors",
    async () => {
      const id = marker("quick");
      const result = await spawnBoundedV1(
        [process.execPath, tree, "3", id, "quick", "attach"],
        options(),
      );

      expect(result).toMatchObject({ code: 0, truncated: false });
      expect(result.stdout).toBe(
        Buffer.from([0x70, 0x72, 0x6f, 0x62, 0x65, 0x00, 0xff, 0xe2, 0x9c, 0x93, 0x0a]).toString(
          "utf8",
        ),
      );
      expect(await findProcessesReferencingV1([id])).toEqual([]);
    },
    REAL_TIMEOUT_MS,
  );

  it(
    "leaves survivors when nothing contains the tree, proving the sweep finds them (negative control)",
    async () => {
      const id = marker("control");
      const leader = spawn(process.execPath, [tree, "3", id, "wait", "detach"], {
        stdio: "ignore",
      });
      await settle(2_000);
      leader.kill("SIGKILL");
      await settle(500);

      expect((await findProcessesReferencingV1([id])).length).toBeGreaterThanOrEqual(1);
      const swept = await sweepResidualProcessesV1([id]);
      expect(swept.surviving).toEqual([]);
    },
    REAL_TIMEOUT_MS,
  );

  it(
    "kills every descendant in the group on timeout",
    async () => {
      const id = marker("timeout");
      const result = await spawnBoundedV1(
        [process.execPath, tree, "3", id, "wait", "attach"],
        options({ timeoutMs: 3_000 }),
      );

      expect(result).toMatchObject({ code: 1, truncated: true, termination: "timeout" });
      await settle(300);
      expect(await findProcessesReferencingV1([id])).toEqual([]);
    },
    REAL_TIMEOUT_MS,
  );

  it(
    "kills every descendant in the group on abort",
    async () => {
      const id = marker("abort");
      const controller = new AbortController();
      setTimeout(() => controller.abort(), 3_000);
      const result = await spawnBoundedV1(
        [process.execPath, tree, "3", id, "wait", "attach"],
        options({ signal: controller.signal }),
      );

      expect(result).toMatchObject({ code: 1, truncated: true, termination: "abort" });
      await settle(300);
      expect(await findProcessesReferencingV1([id])).toEqual([]);
    },
    REAL_TIMEOUT_MS,
  );

  it(
    "catches a leader that exits while its grandchild keeps running in the group",
    async () => {
      const id = marker("orphan");
      const result = await spawnBoundedV1(
        [process.execPath, tree, "3", id, "orphan", "attach"],
        options(),
      );

      expect(result).toMatchObject({
        code: 1,
        truncated: true,
        termination: "residual-descendants",
      });
      await settle(300);
      expect(await findProcessesReferencingV1([id])).toEqual([]);
    },
    REAL_TIMEOUT_MS,
  );

  it(
    "does not see a descendant that left the group with setsid, which only the sweep catches",
    async () => {
      const id = marker("escape");
      const result = await spawnBoundedV1(
        [process.execPath, tree, "3", id, "orphan", "detach"],
        options(),
      );

      // The process group died with its leader, so the runner alone reports success...
      expect(result.code).toBe(0);
      // ...while the escaped grandchild is still running: the sweep must find and kill it.
      const swept = await sweepResidualProcessesV1([id]);
      expect(swept.found.length).toBeGreaterThanOrEqual(1);
      expect(swept.surviving).toEqual([]);
    },
    REAL_TIMEOUT_MS,
  );
});

/**
 * A leader that starts `/bin/sleep 600` in a new session (Node's `detached` is setsid())
 * with closed streams, prints the sleeper's pid and exits. The sleeper's command line names
 * no private directory, so only its inherited environment or its working directory can tie
 * it to the run.
 */
const DETACH_SLEEPER = [
  'import { spawn } from "node:child_process";',
  "const env = JSON.parse(process.env.AIHM_SLEEPER_ENV);",
  'const child = spawn("/bin/sleep", ["600"], { detached: true, stdio: "ignore", env, cwd: process.env.AIHM_SLEEPER_CWD });',
  "child.unref();",
  'process.stdout.write(String(child.pid) + "\\n");',
].join("\n");

async function detachSleeper(
  sleeperEnv: Record<string, string>,
  sleeperCwd: string,
): Promise<number> {
  const result = await spawnBoundedV1(
    [process.execPath, "--input-type=module", "-e", DETACH_SLEEPER],
    options({
      env: {
        PATH: "/usr/bin:/bin",
        LANG: "C.UTF-8",
        AIHM_SLEEPER_ENV: JSON.stringify(sleeperEnv),
        AIHM_SLEEPER_CWD: sleeperCwd,
      },
    }),
  );
  expect(result.code).toBe(0);
  const pid = Number(result.stdout.trim());
  expect(Number.isSafeInteger(pid) && pid > 1).toBe(true);
  await settle(300);
  return pid;
}

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

describe.runIf(onPosix)("POSIX residual sweep of detached descendants (real processes)", () => {
  it(
    "catches a setsid sleeper whose only tie to the run is an inherited private environment value",
    async () => {
      const id = marker("environ");
      const directory = join(tmpdir(), id);
      const pid = await detachSleeper(
        { PATH: "/usr/bin:/bin", HOME: join(directory, "h"), TMPDIR: join(directory, "t") },
        "/",
      );
      try {
        const swept = await sweepResidualProcessesV1([id]);
        expect(swept.found.map((entry) => entry.pid)).toContain(pid);
        expect(swept.surviving).toEqual([]);
        expect(alive(pid)).toBe(false);
      } finally {
        if (alive(pid)) process.kill(pid, "SIGKILL");
      }
    },
    REAL_TIMEOUT_MS,
  );

  it(
    "catches a setsid sleeper with a clean environment whose working directory is run-private",
    async () => {
      const id = marker("cwd");
      const pid = await detachSleeper({ PATH: "/usr/bin:/bin" }, join(tmpdir(), id));
      try {
        const swept = await sweepResidualProcessesV1([id]);
        expect(swept.found.map((entry) => entry.pid)).toContain(pid);
        expect(swept.surviving).toEqual([]);
        expect(alive(pid)).toBe(false);
      } finally {
        if (alive(pid)) process.kill(pid, "SIGKILL");
      }
    },
    REAL_TIMEOUT_MS,
  );

  it(
    "cannot see a sleeper that left the session and cleared both its environment and its cwd (documented limit)",
    async () => {
      // This is the residual limit the host-process-uv-v1 profile document states: a
      // descendant that deliberately drops every tie to the run is not detectable on POSIX.
      // The Linux namespace profile is the containment option for that threat.
      const id = marker("limit");
      const pid = await detachSleeper({ PATH: "/usr/bin:/bin" }, "/");
      try {
        expect(alive(pid)).toBe(true);
        expect((await findProcessesReferencingV1([id])).map((entry) => entry.pid)).not.toContain(
          pid,
        );
      } finally {
        if (alive(pid)) process.kill(pid, "SIGKILL");
      }
    },
    REAL_TIMEOUT_MS,
  );
});
