import { spawn } from "node:child_process";

const terminationGraceMs = 1_000;
const groupExitPollMs = 10;
const groupExitPollAttempts = 100;
export const BASELINE_DOCKER_EXECUTABLE_V1 = "/usr/bin/docker";
export const BASELINE_BWRAP_EXECUTABLE_V1 = "/usr/bin/bwrap";
export const BASELINE_UV_EXECUTABLE_V1 = "/usr/local/bin/uv";
const allowedExecutables = new Set([
  "docker",
  BASELINE_BWRAP_EXECUTABLE_V1,
  BASELINE_DOCKER_EXECUTABLE_V1,
  BASELINE_UV_EXECUTABLE_V1,
]);

export type ProcessRunnerOptions = {
  readonly cwd?: string;
  readonly env: Readonly<Record<string, string>>;
  readonly timeoutMs: number;
  readonly maxStdoutBytes: number;
  readonly maxStderrBytes: number;
  readonly killProcessGroup?: boolean;
};

export type ProcessRunnerResult = Readonly<{
  code: number;
  stdout: string;
  stderr: string;
  truncated: boolean;
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
  if (executable === undefined || !allowedExecutables.has(executable) || argv.length < 2)
    fail("registered process argv");
  if (options.killProcessGroup === true && process.platform === "win32")
    fail("process-group execution requires a Linux analyzer host");
  return new Promise((resolveResult, reject) => {
    const child = spawn(executable, argv.slice(1), {
      shell: false,
      windowsHide: true,
      cwd: options.cwd,
      env: options.env,
      stdio: "pipe",
      detached: options.killProcessGroup === true,
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutSize = 0;
    let stderrSize = 0;
    let truncated = false;
    let settled = false;
    let terminationRequested = false;
    const result = (): ProcessRunnerResult => ({
      code: 1,
      stdout: Buffer.concat(stdout).toString("utf8"),
      stderr: Buffer.concat(stderr).toString("utf8"),
      truncated,
    });
    let timer: ReturnType<typeof setTimeout> | undefined;
    let terminationTimer: ReturnType<typeof setTimeout> | undefined;
    let groupExitTimer: ReturnType<typeof setTimeout> | undefined;
    const settle = (
      outcome: { readonly result: ProcessRunnerResult } | { readonly error: unknown },
    ) => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      if (terminationTimer !== undefined) clearTimeout(terminationTimer);
      if (groupExitTimer !== undefined) clearTimeout(groupExitTimer);
      if ("error" in outcome) reject(outcome.error);
      else resolveResult(outcome.result);
    };
    const finish = (code: number | null) => {
      settle({ result: { ...result(), code: truncated ? 1 : (code ?? 1) } });
    };
    const groupExists = (): boolean => {
      if (options.killProcessGroup !== true || child.pid === undefined) return false;
      try {
        process.kill(-child.pid, 0);
        return true;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ESRCH") return false;
        throw error;
      }
    };
    const waitForGroupExit = (code: number | null, attempt = 0): void => {
      if (settled) return;
      try {
        if (!groupExists()) {
          finish(code);
          return;
        }
      } catch {
        truncated = true;
        finish(1);
        return;
      }
      if (attempt >= groupExitPollAttempts) {
        truncated = true;
        finish(1);
        return;
      }
      groupExitTimer = setTimeout(() => waitForGroupExit(code, attempt + 1), groupExitPollMs);
    };
    const signal = (name: NodeJS.Signals): boolean => {
      if (options.killProcessGroup === true && child.pid !== undefined) {
        process.kill(-child.pid, name);
        return true;
      }
      return child.kill(name);
    };
    const terminate = () => {
      if (settled || terminationRequested) return;
      terminationRequested = true;
      truncated = true;
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
        waitForGroupExit(1);
      }, terminationGraceMs);
    };
    timer = setTimeout(terminate, options.timeoutMs);
    child.stdout.on("data", (chunk: Buffer) => {
      if (settled) return;
      stdoutSize += chunk.byteLength;
      if (stdoutSize > options.maxStdoutBytes) terminate();
      else stdout.push(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      if (settled) return;
      stderrSize += chunk.byteLength;
      if (stderrSize > options.maxStderrBytes) terminate();
      else stderr.push(chunk);
    });
    child.once("error", (error) => settle({ error }));
    child.once("close", (code) => {
      if (options.killProcessGroup !== true) {
        finish(code);
        return;
      }
      try {
        if (!groupExists()) {
          finish(code);
          return;
        }
        if (terminationRequested) return;
        truncated = true;
        signal("SIGKILL");
        waitForGroupExit(1);
      } catch {
        truncated = true;
        finish(1);
      }
    });
  });
}
