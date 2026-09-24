import { spawn } from "node:child_process";
import { isRegisteredHostExecutableV1 } from "./host-executable.js";
import { processOutputV1 } from "./process-output.js";
import { runUnderWindowsJobV1 } from "./windows-job-supervisor.js";

const terminationGraceMs = 1_000;
const groupExitPollMs = 10;
const groupExitPollAttempts = 100;
export const BASELINE_DOCKER_EXECUTABLE_V1 = "/usr/bin/docker";
export const BASELINE_BWRAP_EXECUTABLE_V1 = "/usr/bin/bwrap";
export const BASELINE_UV_EXECUTABLE_V1 = "/usr/local/bin/uv";
const allowedExecutables = new Set([
  BASELINE_BWRAP_EXECUTABLE_V1,
  BASELINE_DOCKER_EXECUTABLE_V1,
  BASELINE_UV_EXECUTABLE_V1,
]);

/**
 * Why the runner ended a process tree itself:
 *
 * - `timeout` and `abort`: the spawn's time budget ran out, or the caller's signal fired;
 * - `output-limit`: stdout or stderr exceeded its byte cap;
 * - `residual-descendants`: the leader exited while descendants kept running, and the runner
 *   killed them with its containment;
 * - `containment-failure`: the runner could not prove the tree was gone.
 */
export type ProcessTerminationV1 =
  | "timeout"
  | "abort"
  | "output-limit"
  | "residual-descendants"
  | "containment-failure";

export type ProcessRunnerOptions = {
  readonly cwd?: string;
  readonly env: Readonly<Record<string, string>>;
  readonly timeoutMs: number;
  readonly maxStdoutBytes: number;
  readonly maxStderrBytes: number;
  /**
   * End the whole descendant tree, not only the direct child: on POSIX the child leads its
   * own process group, which is signalled; on Windows it runs inside a Job Object with
   * KILL_ON_JOB_CLOSE and no breakaway.
   */
  readonly containProcessTree?: boolean;
  /** Aborting ends the tree exactly as a timeout does. */
  readonly signal?: AbortSignal;
};

export type ProcessRunnerResult = Readonly<{
  code: number;
  stdout: string;
  stderr: string;
  /**
   * S2h: present only when stdout was not well-formed UTF-8, so `stdout` holds a lossy
   * decode. A consumer that reads stdout as analyzer output must refuse it.
   */
  stdoutMalformedUtf8?: true;
  truncated: boolean;
  /** Present only when the runner ended the tree itself. */
  termination?: ProcessTerminationV1;
  /** What the containment observed, when it has something to say. */
  containmentDetail?: string;
}>;

function fail(message: string): never {
  throw new TypeError(`aih-scan: ${message}`);
}

/** Bounded, shell-free runner for Scanner-owned executable profiles only. */
export function processRunner(
  argv: readonly string[],
  options: ProcessRunnerOptions,
): Promise<ProcessRunnerResult> {
  const executable = argv[0];
  if (
    executable === undefined ||
    argv.length < 2 ||
    !(allowedExecutables.has(executable) || isRegisteredHostExecutableV1(executable))
  )
    fail("registered process argv");
  return spawnBoundedV1(argv, options);
}

/**
 * The spawning core behind {@link processRunner}, without its executable allow-list. Internal:
 * Scan reaches it only through `processRunner`; the real process-tree tests drive it directly.
 */
export function spawnBoundedV1(
  argv: readonly string[],
  options: ProcessRunnerOptions,
): Promise<ProcessRunnerResult> {
  const executable = argv[0];
  if (executable === undefined) fail("empty argv");
  if (options.containProcessTree === true && process.platform === "win32")
    return runUnderWindowsJobV1(argv, options);
  const group = options.containProcessTree === true;
  return new Promise((resolveResult, reject) => {
    const child = spawn(executable, argv.slice(1), {
      shell: false,
      windowsHide: true,
      cwd: options.cwd,
      env: options.env,
      stdio: ["ignore", "pipe", "pipe"],
      detached: group,
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutSize = 0;
    let stderrSize = 0;
    let termination: ProcessTerminationV1 | undefined;
    let settled = false;
    let terminationRequested = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let terminationTimer: ReturnType<typeof setTimeout> | undefined;
    let groupExitTimer: ReturnType<typeof setTimeout> | undefined;
    const onAbort = () => terminate("abort");
    const settle = (
      outcome: { readonly result: ProcessRunnerResult } | { readonly error: unknown },
    ) => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      if (terminationTimer !== undefined) clearTimeout(terminationTimer);
      if (groupExitTimer !== undefined) clearTimeout(groupExitTimer);
      options.signal?.removeEventListener("abort", onAbort);
      if ("error" in outcome) reject(outcome.error);
      else resolveResult(Object.freeze(outcome.result));
    };
    const finish = (code: number | null) => {
      const truncated = termination !== undefined;
      settle({
        result: {
          code: truncated ? 1 : (code ?? 1),
          ...processOutputV1(stdout, stderr),
          truncated,
          ...(termination === undefined ? {} : { termination }),
        },
      });
    };
    const groupExists = (): boolean => {
      if (!group || child.pid === undefined) return false;
      try {
        process.kill(-child.pid, 0);
        return true;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ESRCH") return false;
        throw error;
      }
    };
    const waitForGroupExit = (attempt = 0): void => {
      if (settled) return;
      try {
        if (!groupExists()) {
          finish(1);
          return;
        }
      } catch {
        termination = "containment-failure";
        finish(1);
        return;
      }
      if (attempt >= groupExitPollAttempts) {
        termination = "containment-failure";
        finish(1);
        return;
      }
      groupExitTimer = setTimeout(() => waitForGroupExit(attempt + 1), groupExitPollMs);
    };
    const signal = (name: NodeJS.Signals): boolean => {
      if (group && child.pid !== undefined) {
        process.kill(-child.pid, name);
        return true;
      }
      return child.kill(name);
    };
    function terminate(reason: ProcessTerminationV1): void {
      if (settled || terminationRequested) return;
      terminationRequested = true;
      termination = reason;
      try {
        if (!signal("SIGTERM")) {
          finish(1);
          return;
        }
      } catch {
        finish(1);
        return;
      }
      terminationTimer = setTimeout(() => {
        if (settled) return;
        try {
          signal("SIGKILL");
        } catch {
          // The group may already be gone; the bounded existence check decides.
        }
        waitForGroupExit();
      }, terminationGraceMs);
    }
    timer = setTimeout(() => terminate("timeout"), options.timeoutMs);
    if (options.signal?.aborted) terminate("abort");
    else options.signal?.addEventListener("abort", onAbort, { once: true });
    child.stdout.on("data", (chunk: Buffer) => {
      if (settled) return;
      stdoutSize += chunk.byteLength;
      if (stdoutSize > options.maxStdoutBytes) terminate("output-limit");
      else stdout.push(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      if (settled) return;
      stderrSize += chunk.byteLength;
      if (stderrSize > options.maxStderrBytes) terminate("output-limit");
      else stderr.push(chunk);
    });
    child.once("error", (error) => settle({ error }));
    child.once("close", (code) => {
      if (!group) {
        finish(code);
        return;
      }
      try {
        if (!groupExists()) {
          finish(code);
          return;
        }
        if (terminationRequested) return;
        terminationRequested = true;
        termination = "residual-descendants";
        signal("SIGKILL");
        waitForGroupExit();
      } catch {
        termination = "containment-failure";
        finish(1);
      }
    });
  });
}
