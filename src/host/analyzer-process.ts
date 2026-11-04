import {
  type HostExecutableNameV1,
  type HostExecutableV1,
  resolveHostExecutableV1,
  selectHostExecutableV1,
} from "../cli/host-executable.js";
import { type ProcessRunnerResult, processRunner } from "../cli/process-runner.js";
import { limits } from "../contracts/limits.js";
import {
  AnalyzerOutputReadErrorV1,
  readBoundedAnalyzerOutputV1,
} from "../shared/bounded-output-read.js";
import { createTemporaryRoot } from "../shared/emergency-stop.js";

/** The process environment an analyzer adapter reads; `process.env` unless a test supplies one. */
export type HostEnv = Readonly<Record<string, string | undefined>>;

/** Largest analyzer report file Scan reads. */
export const ANALYZER_REPORT_MAX_BYTES = 64 * 1024 * 1024;
const STDOUT_MAX_BYTES = 1024 * 1024;
const STDERR_MAX_BYTES = 8 * 1024 * 1024;
const VERSION_PROBE_TIMEOUT_MS = 60_000;

export type AnalyzerSelection =
  | Readonly<{ status: "found"; executable: HostExecutableV1 }>
  | Readonly<{ status: "missing"; detail: string }>;

/**
 * Finds an installed analyzer CLI without running it. `variable` (for example
 * `AIH_SCAN_SKILLSPECTOR`) selects an exact absolute path, or `none` to disable the analyzer;
 * otherwise the caller's `PATH` and the well-known install directories are searched
 * (`~/.local/bin` is where `uv tool install` puts it). Windows accepts only `<name>.exe`.
 */
export function selectAnalyzer(
  name: HostExecutableNameV1,
  variable: string,
  env: HostEnv,
  platform: NodeJS.Platform = process.platform,
): AnalyzerSelection {
  const selected = env[variable];
  if (selected !== undefined && selected !== "") {
    if (selected === "none")
      return Object.freeze({ status: "missing" as const, detail: `disabled by ${variable}=none` });
    const executable = selectHostExecutableV1(name, selected, platform);
    return executable === undefined
      ? Object.freeze({
          status: "missing" as const,
          detail: `${variable} does not name an executable ${name}`,
        })
      : Object.freeze({ status: "found" as const, executable });
  }
  const executable = resolveHostExecutableV1(name, env as NodeJS.ProcessEnv, platform);
  return executable === undefined
    ? Object.freeze({
        status: "missing" as const,
        detail: `${name} was not found on PATH or in the usual install folders`,
      })
    : Object.freeze({ status: "found" as const, executable });
}

/** Runs an analyzer CLI shell-free under the bounded runner, its whole process tree contained. */
export function runAnalyzer(
  argv: readonly string[],
  options: Readonly<{
    cwd: string;
    env: Readonly<Record<string, string>>;
    signal: AbortSignal;
    timeoutMs?: number;
    maxStdoutBytes?: number;
  }>,
): Promise<ProcessRunnerResult> {
  return processRunner(argv, {
    cwd: options.cwd,
    env: options.env,
    timeoutMs: options.timeoutMs ?? limits.tool.timeoutMs,
    maxStdoutBytes: options.maxStdoutBytes ?? STDOUT_MAX_BYTES,
    maxStderrBytes: STDERR_MAX_BYTES,
    containProcessTree: true,
    signal: options.signal,
  });
}

const versions = new Map<string, Promise<string | undefined>>();

/**
 * The version an installed analyzer reports for `--version`, matched by `pattern` (first group).
 * Cached per executable path for the life of the process.
 */
export function probeVersion(
  executable: HostExecutableV1,
  env: Readonly<Record<string, string>>,
  cwd: string,
  pattern: RegExp,
  signal: AbortSignal,
): Promise<string | undefined> {
  const cached = versions.get(executable.path);
  if (cached !== undefined) return cached;
  const probe = runAnalyzer([executable.path, "--version"], {
    cwd,
    env,
    signal,
    timeoutMs: VERSION_PROBE_TIMEOUT_MS,
  }).then(
    (result) => {
      if (result.code !== 0 || result.termination !== undefined) return undefined;
      return pattern.exec(`${result.stdout}\n${result.stderr}`)?.[1];
    },
    () => undefined,
  );
  versions.set(executable.path, probe);
  probe.then((version) => {
    if (version === undefined) versions.delete(executable.path);
  });
  return probe;
}

/** A private scratch folder outside the item's working copy, for reports and the tool's HOME. */
export function scratchFolder(prefix: string): Readonly<{ path: string; dispose(): void }> {
  return createTemporaryRoot(prefix);
}

/** Reads and parses an analyzer's JSON report, or `undefined` when it is missing or malformed. */
export function readJsonReport(path: string, label: string): unknown {
  try {
    const bytes = readBoundedAnalyzerOutputV1(path, label, ANALYZER_REPORT_MAX_BYTES);
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch (error) {
    if (error instanceof AnalyzerOutputReadErrorV1 || error instanceof SyntaxError)
      return undefined;
    if (error instanceof TypeError) return undefined;
    throw error;
  }
}

/** A stdout report is accepted only as complete, well-formed UTF-8 JSON. */
export function readJsonStdout(
  result: Pick<ProcessRunnerResult, "stdout" | "stdoutMalformedUtf8" | "truncated">,
): unknown {
  if (result.stdoutMalformedUtf8 === true || result.truncated) return undefined;
  try {
    return JSON.parse(result.stdout);
  } catch {
    return undefined;
  }
}

const RUNTIME_POSIX = ["PATH", "LANG", "LC_ALL", "LC_CTYPE"] as const;
const RUNTIME_WINDOWS = [
  "PATH",
  "PATHEXT",
  "SYSTEMROOT",
  "SYSTEMDRIVE",
  "WINDIR",
  "COMSPEC",
  "NUMBER_OF_PROCESSORS",
  "PROCESSOR_ARCHITECTURE",
] as const;

/**
 * The static-mode environment for a Python analyzer: only what the interpreter needs to start,
 * a private HOME/TEMP in `scratch`, and no proxy, credential, provider or Python loader
 * variables from the caller. Windows variable names are matched case-insensitively.
 */
export function staticAnalyzerEnv(
  env: HostEnv,
  scratch: string,
  platform: NodeJS.Platform,
  extra: Readonly<Record<string, string>> = {},
): Record<string, string> {
  const names: readonly string[] = platform === "win32" ? RUNTIME_WINDOWS : RUNTIME_POSIX;
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) continue;
    const name = platform === "win32" ? key.toUpperCase() : key;
    if (names.includes(name)) result[platform === "win32" ? name : key] = value;
  }
  if (platform === "win32") {
    Object.assign(result, {
      USERPROFILE: scratch,
      APPDATA: scratch,
      LOCALAPPDATA: scratch,
      TEMP: scratch,
      TMP: scratch,
    });
  } else {
    Object.assign(result, { HOME: scratch, TMPDIR: scratch });
    result.LC_ALL ??= "C.UTF-8";
  }
  Object.assign(result, {
    PYTHONUTF8: "1",
    PYTHONIOENCODING: "utf-8",
    PYTHONDONTWRITEBYTECODE: "1",
    PYTHONNOUSERSITE: "1",
    NO_COLOR: "1",
    ...extra,
  });
  return result;
}

/** Python loader variables never forwarded to an analyzer, even in AI mode. */
export const PYTHON_LOADER_VARIABLES = Object.freeze([
  "PYTHONPATH",
  "PYTHONHOME",
  "PYTHONSTARTUP",
  "PYTHONINSPECT",
  "PYTHONEXECUTABLE",
  "PYTHONUSERBASE",
]);
