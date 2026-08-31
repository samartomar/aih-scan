import { processRunner } from "./process-runner.js";

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
  return processRunner(argv, options);
}
