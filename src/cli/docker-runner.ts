import { spawn } from "node:child_process";

type DockerRunnerOptions = {
  readonly env: Readonly<Record<string, string>>;
  readonly timeoutMs: number;
  readonly maxStdoutBytes: number;
  readonly maxStderrBytes: number;
};

function fail(message: string): never {
  throw new TypeError(`aih-scan: ${message}`);
}

export function dockerRunner(
  argv: readonly string[],
  options: DockerRunnerOptions,
): Promise<unknown> {
  if (argv[0] !== "docker" || argv.length < 2) fail("registered Docker argv");
  return new Promise((resolveResult, reject) => {
    const child = spawn("docker", argv.slice(1), {
      shell: false,
      windowsHide: true,
      env: options.env,
      stdio: "pipe",
    });
    const stdout: Buffer[] = [],
      stderr: Buffer[] = [];
    let stdoutSize = 0,
      stderrSize = 0,
      truncated = false,
      settled = false,
      terminationRequested = false;
    const result = () => ({
      code: 1,
      stdout: Buffer.concat(stdout).toString("utf8"),
      stderr: Buffer.concat(stderr).toString("utf8"),
      truncated,
    });
    let timer: ReturnType<typeof setTimeout> | undefined;
    const settle = (outcome: { readonly result: unknown } | { readonly error: unknown }) => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      if ("error" in outcome) reject(outcome.error);
      else resolveResult(outcome.result);
    };
    const finish = (code: number | null) => {
      settle({
        result: {
          ...result(),
          code: code ?? 1,
        },
      });
    };
    const terminate = () => {
      if (settled || terminationRequested) return;
      terminationRequested = true;
      truncated = true;
      try {
        if (!child.kill()) finish(1);
      } catch {
        // The bounded runner result below is still authoritative after a failed termination request.
        finish(1);
      }
    };
    timer = setTimeout(terminate, options.timeoutMs);
    child.stdout.on("data", (chunk: Buffer) => {
      if (settled) return;
      stdoutSize += chunk.byteLength;
      if (stdoutSize > options.maxStdoutBytes) {
        terminate();
      } else stdout.push(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      if (settled) return;
      stderrSize += chunk.byteLength;
      if (stderrSize > options.maxStderrBytes) {
        terminate();
      } else stderr.push(chunk);
    });
    child.once("error", (error) => settle({ error }));
    child.once("close", (code) => {
      finish(code);
    });
  });
}
