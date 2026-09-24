import { BASELINE_DOCKER_EXECUTABLE_V1, processRunner } from "./process-runner.js";

type DockerRunnerOptions = {
  readonly env: Readonly<Record<string, string>>;
  readonly timeoutMs: number;
  readonly maxStdoutBytes: number;
  readonly maxStderrBytes: number;
};

function fail(message: string): never {
  throw new TypeError(`aih-scan: ${message}`);
}

/**
 * The OCI capture profile's Docker client. It runs exactly the absolute executable that
 * profile gates on and documents, never a name resolved through `PATH`, so the executable
 * probed before the run is the one that runs.
 */
export function dockerRunner(
  argv: readonly string[],
  options: DockerRunnerOptions,
): Promise<unknown> {
  if (argv[0] !== BASELINE_DOCKER_EXECUTABLE_V1 || argv.length < 2) fail("registered Docker argv");
  return processRunner(argv, options);
}
