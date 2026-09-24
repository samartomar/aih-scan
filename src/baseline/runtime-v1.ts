import { createHash, randomUUID } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  realpathSync,
  rmSync,
  type Stats,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve, win32 } from "node:path";
import { fileURLToPath } from "node:url";
import { type HostExecutableV1, resolveHostExecutableV1 } from "../cli/host-executable.js";
import {
  BASELINE_BWRAP_EXECUTABLE_V1,
  BASELINE_DOCKER_EXECUTABLE_V1,
  BASELINE_UV_EXECUTABLE_V1,
  type ProcessRunnerResult,
  processRunner,
} from "../cli/process-runner.js";
import { type LiveProcessV1, sweepResidualProcessesV1 } from "../cli/residual-processes.js";
import { windowsSystemRootV1 } from "../cli/windows-job-supervisor.js";
import {
  canonicalStrictJsonBytesV1,
  canonicalStrictJsonSha256V1,
  parseStrictJsonObjectV1,
} from "../contract/strict-json-v1.js";
import {
  assertSarifCompletedV1,
  SarifCompletionErrorV1,
} from "../detectors/sarif-completion-v1.js";
import { hashSourceTreeV1 } from "../observation/source-hash-v1.js";
import type { BaselineAnalyzerExecutionV1, BaselineAnalyzerV1 } from "./batch-v1.js";
import { ciscoSourceRelativeSarifV1, sourceRelativeSarifV1 } from "./sarif-source-relative-v1.js";

export const SKILLSPECTOR_IMAGE_V1 =
  "ghcr.io/samartomar/skillspector@sha256:efe47bd7e073064426541381c8cb284162086950748424d1b4633788a2275bc6";
export const SKILLSPECTOR_SOURCE_REVISION_V1 = "c7958a3268d9498644b22edb75d0f051bbc8cbfc";
export const SKILLSPECTOR_IMAGE_DIGEST_V1 =
  "sha256:efe47bd7e073064426541381c8cb284162086950748424d1b4633788a2275bc6";
/**
 * The local tag Core documents for its SkillSpector image (docs/security/skillspector.md).
 * `docker-host-local-skillspector-v1` inspects only this tag and never pulls.
 */
export const SKILLSPECTOR_LOCAL_IMAGE_TAG_V1 = "skillspector:aih-c7958a3268d9";
export const CISCO_SKILL_SCANNER_VERSION_V1 = "2.1.0";
export const SEMGREP_VERSION_V1 = "1.178.0";
/** The interpreter the Linux namespace profile binds; the host profile discovers its own. */
export const BASELINE_PYTHON_EXECUTABLE_V1 = "/usr/bin/python3.13";
const baselinePythonPathV1 = "/usr/local/lib/python3.13:/usr/local/lib/python3.13/lib-dynload";
/** The Python version request `host-process-uv-v1` hands to `uv python find`. */
export const HOST_PROCESS_UV_PYTHON_REQUEST_V1 = "3.12";
/**
 * The longest private temporary directory a host run accepts. Semgrep's analyzer core fails
 * with ERROR_INSUFFICIENT_BUFFER (Windows) once its temporary directory passes 79
 * characters, an AF_UNIX socket path bound that POSIX shares; 64 leaves a margin.
 */
export const HOST_PROCESS_TEMPORARY_PATH_LIMIT_V1 = 64;

const maxOutputBytes = 16 * 1024 * 1024;
const maxStderrBytes = 64 * 1024;
const maxProjectBytes = 64 * 1024;
const maxFailureDetailCharacters = 400;
const startupTimeoutMs = 120_000;
const scanTimeoutMs = 900_000;
const containerRemovalTimeoutMs = 30_000;
const moduleDirectory = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(moduleDirectory, "..", "..");
const analyzerRoot = join(packageRoot, "tools", "baseline-analyzers");
const ciscoProject = join(analyzerRoot, "cisco-skill-scanner");
/**
 * The bundled Cisco project both uv profiles install: its 2.1.0 lock (litellm 1.102.1, no
 * win-unicode-console) has binary wheels for every host profile platform, so the host and
 * namespace profiles share one lock and one analyzerLock digest.
 */
export const CISCO_SKILL_SCANNER_PROJECT_V1 = ciscoProject;
const semgrepProject = join(analyzerRoot, "semgrep");
const semgrepRules = [
  "rules:",
  "  - id: semgrep.prompt-injection",
  "    languages: [generic]",
  "    message: prompt injection shape in trust content",
  "    severity: WARNING",
  "    pattern-regex: '(?i)(ignore|disregard)\\s+(all\\s+)?previous\\s+instructions'",
  "  - id: semgrep.malicious-code",
  "    languages: [generic]",
  "    message: download-and-execute shell shape in trust content",
  "    severity: WARNING",
  "    pattern-regex: '(?i)(curl|wget|Invoke-WebRequest|iwr).*\\b(sh|bash|iex|Invoke-Expression)\\b'",
  "",
].join("\n");

export type BaselineProcessRunnerV1 = (
  argv: readonly string[],
  options: {
    readonly cwd?: string;
    readonly env: Readonly<Record<string, string>>;
    readonly timeoutMs: number;
    readonly maxStdoutBytes: number;
    readonly maxStderrBytes: number;
    /** Every analyzer spawn contains and ends its whole process tree. */
    readonly containProcessTree: true;
    readonly signal?: AbortSignal;
  },
) => Promise<ProcessRunnerResult>;

/** The execution profiles this runtime implements, by the ID their documents publish. */
export type BaselineExecutionProfileIdV1 =
  | "in-process-native-v1"
  | "linux-namespace-uv-v1"
  | "host-process-uv-v1"
  | "docker-hardened-skillspector-v1"
  | "docker-host-local-skillspector-v1";

/**
 * Why an analyzer run failed, when the reason is not the analyzer's own error:
 *
 * - `cancelled`: the caller's signal fired; the process tree was ended;
 * - `timed-out`: a stage, or the caller's whole-run budget, ran out; the tree was ended;
 * - `residual-processes`: processes outlived the analyzer and were killed;
 * - `containment-failure`: Scan could not prove the process tree was gone.
 */
export type AnalyzerFailureCauseV1 =
  | "cancelled"
  | "timed-out"
  | "residual-processes"
  | "containment-failure";

export class AnalyzerRunFailureV1 extends TypeError {
  readonly failureCause: AnalyzerFailureCauseV1;
  constructor(failureCause: AnalyzerFailureCauseV1, message: string) {
    super(`aih-scan baseline analyzer: ${message}`);
    this.name = "AnalyzerRunFailureV1";
    this.failureCause = failureCause;
  }
}

/** What a `host-process-uv-v1` run resolved on this host, recorded with its observation. */
export type HostProcessRuntimeV1 = Readonly<{
  uv: Readonly<{ path: string; version: string; foundIn: HostExecutableV1["foundIn"] }>;
  python: Readonly<{ request: string; path: string; version: string }>;
  /** The content address of the Scan-owned uv cache the run used: its lock's digest. */
  uvCache: Readonly<{ key: string }>;
  containment: "posix-process-group" | "windows-job-object";
}>;

/** What a `docker-host-local-skillspector-v1` run resolved on this host. */
export type HostDockerRuntimeV1 = Readonly<{
  docker: Readonly<{ path: string; foundIn: HostExecutableV1["foundIn"] }>;
  context: Readonly<{ name: string; endpoint: string }>;
  containment: "posix-process-group" | "windows-job-object";
}>;

/**
 * The exact analyzer identity the in-process `aih-native` observation records.
 *
 * Declared here so a capability record can state it without recomputing it, and so a
 * test can prove the capability and the observation name the same identity.
 */
export const BASELINE_NATIVE_ANALYZER_IDENTITY_V1 = `native.${canonicalStrictJsonSha256V1({
  domain: "aih.baseline-native-observation-v1",
  algorithm: "source-hash-v1",
}).slice(0, 12)}`;

const safeEnvironmentKeys = new Set([
  "ALLUSERSPROFILE",
  "APPDATA",
  "COMSPEC",
  "DBUS_SESSION_BUS_ADDRESS",
  "LANG",
  "LOCALAPPDATA",
  "PROGRAMDATA",
  "PROGRAMFILES",
  "PROGRAMFILES(X86)",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE",
  "SYSTEMDRIVE",
  "SYSTEMROOT",
  "TEMP",
  "TMP",
  "TMPDIR",
  "WINDIR",
  "XDG_CACHE_HOME",
  "XDG_DATA_HOME",
  "XDG_RUNTIME_DIR",
]);

/** The exact environment allow-list every analyzer subprocess is scrubbed down to. */
export const BASELINE_ENVIRONMENT_ALLOW_LIST_V1: readonly string[] = Object.freeze(
  [...safeEnvironmentKeys].sort(),
);

type HostOsV1 = "linux" | "darwin" | "windows";

const HOST_COMMON_ENVIRONMENT: Readonly<Record<string, string>> = Object.freeze({
  UV_CACHE_DIR: "<Scan uv cache directory for this lock>",
  UV_PROJECT_ENVIRONMENT: "<run venv directory>",
  UV_NO_ENV_FILE: "1",
  UV_PYTHON_DOWNLOADS: "never",
  PYTHONSAFEPATH: "1",
  PYTHONUTF8: "1",
  SEMGREP_ENABLE_VERSION_CHECK: "0",
  SEMGREP_SEND_METRICS: "off",
});

/**
 * The whole environment of every `host-process-uv-v1` analyzer spawn, per OS. A `<…>` value
 * is a run-private path, or the host's own `%SystemRoot%`, substituted at run time; nothing
 * else reaches the spawn. The profile document publishes this very object.
 */
export const HOST_PROCESS_UV_ENVIRONMENT_V1: Readonly<
  Record<HostOsV1, Readonly<Record<string, string>>>
> = Object.freeze({
  linux: Object.freeze({
    PATH: "/usr/local/bin:/usr/bin:/bin",
    LANG: "C.UTF-8",
    HOME: "<run home directory>",
    TMPDIR: "<run temporary directory>",
    ...HOST_COMMON_ENVIRONMENT,
  }),
  darwin: Object.freeze({
    PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
    LANG: "en_US.UTF-8",
    HOME: "<run home directory>",
    TMPDIR: "<run temporary directory>",
    ...HOST_COMMON_ENVIRONMENT,
  }),
  windows: Object.freeze({
    SystemRoot: "<host SystemRoot>",
    windir: "<host SystemRoot>",
    PATH: "<host SystemRoot>\\System32;<host SystemRoot>",
    PATHEXT: ".COM;.EXE;.BAT;.CMD",
    TEMP: "<run temporary directory>",
    TMP: "<run temporary directory>",
    USERPROFILE: "<run home directory>",
    APPDATA: "<run roaming data directory>",
    LOCALAPPDATA: "<run local data directory>",
    ...HOST_COMMON_ENVIRONMENT,
  }),
});

/**
 * The only caller variables the Python discovery spawns (`uv python find`) receive, on top
 * of the fixed environment, so uv sees the host's own interpreters and uv-managed Pythons.
 * No analyzer spawn ever receives a caller variable.
 */
export const HOST_PROCESS_UV_DISCOVERY_VARIABLES_V1: Readonly<Record<HostOsV1, readonly string[]>> =
  Object.freeze({
    linux: Object.freeze(["PATH", "HOME", "XDG_DATA_HOME", "UV_PYTHON_INSTALL_DIR"]),
    darwin: Object.freeze(["PATH", "HOME", "XDG_DATA_HOME", "UV_PYTHON_INSTALL_DIR"]),
    windows: Object.freeze([
      "PATH",
      "USERPROFILE",
      "APPDATA",
      "LOCALAPPDATA",
      "UV_PYTHON_INSTALL_DIR",
    ]),
  });

/**
 * The whole environment of every `docker-host-local-skillspector-v1` Docker client call after the
 * current context is read, per OS. `<run Docker client directory>` is private, empty and
 * removed after the run; `<current context endpoint>` is the context's local endpoint.
 */
export const HOST_DOCKER_ENVIRONMENT_V1: Readonly<
  Record<HostOsV1, Readonly<Record<string, string>>>
> = Object.freeze({
  linux: Object.freeze({
    PATH: "/usr/bin:/bin",
    HOME: "<run Docker client directory>",
    TMPDIR: "<run Docker client directory>",
    DOCKER_CONFIG: "<run Docker client directory>",
    DOCKER_HOST: "<current context endpoint>",
  }),
  darwin: Object.freeze({
    PATH: "/usr/bin:/bin",
    HOME: "<run Docker client directory>",
    TMPDIR: "<run Docker client directory>",
    DOCKER_CONFIG: "<run Docker client directory>",
    DOCKER_HOST: "<current context endpoint>",
  }),
  windows: Object.freeze({
    SystemRoot: "<host SystemRoot>",
    windir: "<host SystemRoot>",
    PATH: "<host SystemRoot>\\System32;<host SystemRoot>",
    TEMP: "<run Docker client directory>",
    TMP: "<run Docker client directory>",
    USERPROFILE: "<run Docker client directory>",
    DOCKER_CONFIG: "<run Docker client directory>",
    DOCKER_HOST: "<current context endpoint>",
  }),
});

/** The only caller variables the context lookup (`docker context inspect`) receives. */
export const HOST_DOCKER_CONTEXT_VARIABLES_V1: Readonly<Record<HostOsV1, readonly string[]>> =
  Object.freeze({
    linux: Object.freeze(["HOME", "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_HOST"]),
    darwin: Object.freeze(["HOME", "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_HOST"]),
    windows: Object.freeze(["USERPROFILE", "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_HOST"]),
  });

function fail(reason: string): never {
  throw new TypeError(`aih-scan baseline analyzer: ${reason}`);
}

/** The hardened profiles run absolute Linux executables, so any other host is refused. */
function requireLinuxHost(profile: string): void {
  if (process.platform !== "linux")
    fail(`${profile} needs a Linux analyzer host; this host is ${process.platform}`);
}

function sameIdentity(left: Stats, right: Stats): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}

function readBoundedRegularFile(path: string, maximum: number, label: string): Buffer {
  const beforePath = lstatSync(path);
  if (
    !beforePath.isFile() ||
    beforePath.isSymbolicLink() ||
    beforePath.nlink !== 1 ||
    beforePath.size <= 0 ||
    beforePath.size > maximum
  )
    fail(`${label} file shape`);
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const before = fstatSync(descriptor);
    if (!before.isFile() || before.nlink !== 1 || !sameIdentity(beforePath, before))
      fail(`${label} file replacement`);
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    const afterPath = lstatSync(path);
    if (
      bytes.byteLength === 0 ||
      bytes.byteLength > maximum ||
      after.nlink !== 1 ||
      !sameIdentity(before, after) ||
      !sameIdentity(before, afterPath)
    )
      fail(`${label} file replacement`);
    return bytes;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function scrubEnvironment(env: Readonly<NodeJS.ProcessEnv>): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    if (value !== undefined && safeEnvironmentKeys.has(key.toUpperCase())) result[key] = value;
  }
  return result;
}

/** A caller variable by name; Windows names match case-insensitively, as Windows does. */
function callerVariable(
  env: Readonly<NodeJS.ProcessEnv>,
  name: string,
  windows: boolean,
): string | undefined {
  const direct = env[name];
  if (typeof direct === "string" && direct.length > 0) return direct;
  if (!windows) return undefined;
  const folded = name.toUpperCase();
  for (const [key, value] of Object.entries(env))
    if (key.toUpperCase() === folded && typeof value === "string" && value.length > 0) return value;
  return undefined;
}

function encodeDiagnosticLine(value: string): string {
  const jsonEscaped = JSON.stringify(value).slice(1, -1);
  return Array.from(jsonEscaped, (character) => {
    const code = character.codePointAt(0) ?? 0;
    const unsafe =
      (code >= 0x80 && code <= 0x9f) ||
      code === 0x61c ||
      code === 0x200e ||
      code === 0x200f ||
      (code >= 0x2028 && code <= 0x202e) ||
      (code >= 0x2066 && code <= 0x2069);
    return unsafe ? `\\u${code.toString(16).padStart(4, "0")}` : character;
  }).join("");
}

/** Control-character encoded, head-and-tail bounded diagnostic text for evidence and errors. */
export function boundedDiagnosticDetailV1(value: string): string {
  const encodedDetail = encodeDiagnosticLine(value.trim());
  if (encodedDetail.length <= maxFailureDetailCharacters) return encodedDetail;
  const marker = "\\n… middle omitted …\\n";
  const retained = maxFailureDetailCharacters - marker.length;
  const headLength = Math.ceil(retained / 2);
  return `${encodedDetail.slice(0, headLength)}${marker}${encodedDetail.slice(
    -(retained - headLength),
  )}`;
}

function resultFailure(result: ProcessRunnerResult, label: string): never {
  const detail = boundedDiagnosticDetailV1(result.stderr || result.stdout);
  fail(`${label} failed${detail ? `: ${detail}` : ` with exit ${result.code}`}`);
}

function requireCleanResult(
  result: ProcessRunnerResult,
  label: string,
  allowedCodes: readonly number[] = [0],
): ProcessRunnerResult {
  const containment =
    result.containmentDetail === undefined
      ? ""
      : `: ${boundedDiagnosticDetailV1(result.containmentDetail)}`;
  if (result.termination === "abort")
    throw new AnalyzerRunFailureV1(
      "cancelled",
      `${label} was cancelled; its whole process tree was ended`,
    );
  if (result.termination === "timeout")
    throw new AnalyzerRunFailureV1(
      "timed-out",
      `${label} ran out of time; its whole process tree was ended`,
    );
  if (result.termination === "residual-descendants")
    throw new AnalyzerRunFailureV1(
      "residual-processes",
      `${label} left processes running after it exited; they were killed${containment}`,
    );
  if (result.termination === "containment-failure")
    throw new AnalyzerRunFailureV1(
      "containment-failure",
      `${label} could not be proven to have ended its process tree${containment}`,
    );
  if (result.truncated || !allowedCodes.includes(result.code)) resultFailure(result, label);
  return result;
}

function lockIdentity(version: string, project: string): string {
  const path = join(project, "uv.lock");
  let bytes: Buffer;
  try {
    bytes = readBoundedRegularFile(path, maxOutputBytes, "bundled analyzer lock");
  } catch (error) {
    fail(`bundled analyzer lock unavailable: ${error instanceof Error ? error.message : path}`);
  }
  return `${version}+uvlock.${createHash("sha256").update(bytes).digest("hex").slice(0, 12)}`;
}

/** The caller's cancellation signal and whole-run deadline, applied to every spawn. */
type RunControl = Readonly<{ signal?: AbortSignal; deadline?: number }>;

function spawnTimeout(control: RunControl, stageMs: number, label: string): number {
  if (control.signal?.aborted)
    throw new AnalyzerRunFailureV1("cancelled", `${label} was not started: the run was cancelled`);
  if (control.deadline === undefined) return stageMs;
  const remaining = control.deadline - Date.now();
  if (remaining <= 0)
    throw new AnalyzerRunFailureV1(
      "timed-out",
      `${label} was not started: the run's time budget is spent`,
    );
  return Math.min(stageMs, remaining);
}

function uvSyncArgv(uv: string, project: string, python: string): string[] {
  return [
    uv,
    "sync",
    "--project",
    project,
    "--locked",
    "--no-dev",
    "--no-install-project",
    "--no-build",
    "--link-mode",
    "copy",
    "--python",
    python,
    "--default-index",
    "https://pypi.org/simple",
    "--index-strategy",
    "first-index",
    "--no-python-downloads",
    "--no-config",
    "--no-sources",
    "--keyring-provider",
    "disabled",
    "--no-progress",
    "--color",
    "never",
  ];
}

function runnerOptions(
  env: Readonly<Record<string, string>>,
  timeoutMs: number,
  control: RunControl,
  cwd?: string,
) {
  return {
    ...(cwd === undefined ? {} : { cwd }),
    env,
    timeoutMs,
    maxStdoutBytes: maxOutputBytes,
    maxStderrBytes,
    containProcessTree: true as const,
    ...(control.signal === undefined ? {} : { signal: control.signal }),
  };
}

type AnalyzerOutput = {
  readonly mediaType: "application/sarif+json" | "application/vnd.aih.baseline-native+json";
  readonly bytes: Uint8Array;
  readonly analyzerVersion: string;
  readonly image?: SkillspectorImageMatchV1;
  readonly hostRuntime?: HostProcessRuntimeV1;
  readonly hostDocker?: HostDockerRuntimeV1;
};

/**
 * The analyzer's SARIF, strict JSON that proves a completed analysis (S2e,
 * {@link assertSarifCompletedV1}): a shortfall in the document is an `output` failure (the
 * message names the observation); an invocation that reports its own failure, or an
 * error-level notification, is an `execution` failure.
 */
function parsedSarif(text: string, analyzer: string): Record<string, unknown> {
  let document: Record<string, unknown>;
  try {
    document = parseStrictJsonObjectV1(text, `${analyzer} observation`);
  } catch (error) {
    fail(
      `baseline ${analyzer} observation is invalid: ${error instanceof Error ? error.message : "JSON"}`,
    );
  }
  try {
    assertSarifCompletedV1(document);
  } catch (error) {
    if (!(error instanceof SarifCompletionErrorV1)) throw error;
    fail(
      error.stage === "output"
        ? `baseline ${analyzer} observation SARIF ${error.message}`
        : `${analyzer} analysis SARIF ${error.message}`,
    );
  }
  return document;
}

function sarifOutput(
  document: Record<string, unknown>,
  analyzerVersion: string,
): Pick<AnalyzerOutput, "mediaType" | "bytes" | "analyzerVersion"> {
  return {
    mediaType: "application/sarif+json" as const,
    bytes: canonicalStrictJsonBytesV1(document),
    analyzerVersion,
  };
}

/** The spellings of a host snapshot root an analyzer may print: as given, and resolved. */
function hostRoots(sourceRoot: string): string[] {
  const roots = new Set([resolve(sourceRoot)]);
  try {
    roots.add(realpathSync.native(sourceRoot));
  } catch {
    // The snapshot exists for the whole run; a failed resolution only drops one spelling.
  }
  return [...roots];
}

function bubblewrapContainedRunner(
  runner: BaselineProcessRunnerV1,
  input: {
    readonly project: string;
    readonly sourceRoot?: string;
    readonly workDirectory: string;
    readonly cacheDirectory: string;
    readonly venvDirectory: string;
    readonly network: boolean;
    readonly workingDirectory: "/aih/project" | "/aih/source";
  },
): BaselineProcessRunnerV1 {
  return (argv, options) => {
    const namespace = [
      BASELINE_BWRAP_EXECUTABLE_V1,
      "--unshare-all",
      "--unshare-user",
      ...(input.network ? ["--share-net"] : []),
      "--die-with-parent",
      "--as-pid-1",
      "--disable-userns",
      "--assert-userns-disabled",
      "--clearenv",
      "--ro-bind",
      "/usr",
      "/usr",
      "--ro-bind",
      "/etc",
      "/etc",
      "--ro-bind-try",
      "/bin",
      "/bin",
      "--ro-bind-try",
      "/sbin",
      "/sbin",
      "--ro-bind-try",
      "/lib",
      "/lib",
      "--ro-bind-try",
      "/lib64",
      "/lib64",
      "--proc",
      "/proc",
      "--dev",
      "/dev",
      "--tmpfs",
      "/tmp",
      "--dir",
      "/run",
      "--dir",
      "/run/systemd",
      "--dir",
      "/run/systemd/resolve",
      "--ro-bind-try",
      "/run/systemd/resolve/stub-resolv.conf",
      "/run/systemd/resolve/stub-resolv.conf",
      "--ro-bind-try",
      "/run/systemd/resolve/resolv.conf",
      "/run/systemd/resolve/resolv.conf",
      "--dir",
      "/aih",
      "--ro-bind",
      input.project,
      "/aih/project",
      ...(input.sourceRoot === undefined ? [] : ["--ro-bind", input.sourceRoot, "/aih/source"]),
      "--bind",
      input.workDirectory,
      "/aih/work",
      "--bind",
      input.cacheDirectory,
      "/aih/cache",
      "--bind",
      input.venvDirectory,
      "/aih/venv",
      "--dir",
      "/nonexistent",
      "--setenv",
      "HOME",
      "/nonexistent",
      "--setenv",
      "PATH",
      "/usr/local/bin:/usr/bin:/bin",
      "--setenv",
      "LANG",
      "C.UTF-8",
      "--setenv",
      "TMPDIR",
      "/tmp",
      "--setenv",
      "UV_CACHE_DIR",
      "/aih/cache",
      "--setenv",
      "UV_PROJECT_ENVIRONMENT",
      "/aih/venv",
      "--setenv",
      "UV_NO_ENV_FILE",
      "1",
      "--setenv",
      "PYTHONSAFEPATH",
      "1",
      "--setenv",
      "PYTHONPATH",
      baselinePythonPathV1,
      "--chdir",
      input.workingDirectory,
      "--",
      ...argv,
    ];
    return runner(namespace, options);
  };
}

async function syncUvEnvironment(
  runner: BaselineProcessRunnerV1,
  input: {
    readonly project: string;
    readonly workDirectory: string;
    readonly cacheDirectory: string;
    readonly venvDirectory: string;
  },
  env: Readonly<Record<string, string>>,
  control: RunControl,
): Promise<void> {
  const label = "analyzer environment acquisition";
  requireCleanResult(
    await bubblewrapContainedRunner(runner, {
      ...input,
      network: true,
      workingDirectory: "/aih/project",
    })(
      uvSyncArgv(BASELINE_UV_EXECUTABLE_V1, "/aih/project", BASELINE_PYTHON_EXECUTABLE_V1),
      runnerOptions(env, spawnTimeout(control, scanTimeoutMs, label), control),
    ),
    label,
  );
}

/** The most caller-accepted SkillSpector image digests one run will consult. */
export const SKILLSPECTOR_ACCEPTED_IMAGE_DIGESTS_MAX_V1 = 32;
const imageDigestPattern = /^sha256:[0-9a-f]{64}$/u;

/**
 * Why a caller-supplied accepted-digest list cannot be used, or `undefined` when it can.
 *
 * The list only adds images a caller vouches for; it never replaces or relaxes Scan's
 * own pinned digest, so a malformed list is refused rather than partly honoured.
 */
export function skillspectorAcceptedImageDigestsRefusalV1(value: unknown): string | undefined {
  if (!Array.isArray(value))
    return "acceptedImageDigests must be an array of sha256:<64 lowercase hex> image digests.";
  if (value.length === 0)
    return "acceptedImageDigests is empty, so it accepts nothing; omit it to use only Scan's pinned image.";
  if (value.length > SKILLSPECTOR_ACCEPTED_IMAGE_DIGESTS_MAX_V1)
    return `acceptedImageDigests names ${value.length} digests; at most ${SKILLSPECTOR_ACCEPTED_IMAGE_DIGESTS_MAX_V1} are consulted.`;
  const seen = new Set<string>();
  for (const [index, digest] of value.entries()) {
    if (typeof digest !== "string" || !imageDigestPattern.test(digest))
      return `acceptedImageDigests[${index}] is not a sha256:<64 lowercase hex> image digest.`;
    if (seen.has(digest)) return `acceptedImageDigests[${index}] repeats ${digest}.`;
    seen.add(digest);
  }
  return undefined;
}

/** Which image a SkillSpector run executed, and whose digest admitted it. */
export type SkillspectorImageMatchV1 = Readonly<{
  /** The digest the executed image matched: Scan's pinned digest or one the caller accepted. */
  digest: string;
  /** The exact image reference passed to `docker run`. */
  reference: string;
  /**
   * `scan-pinned`: Scan's pinned image, present or acquired by Scan's own pull, or (local
   * profile) the local tag's image carrying the pinned digest.
   * `caller-accepted`: an image carrying one of the caller's accepted digests ran instead,
   * because Scan's own pinned pull failed or (local profile) because the local tag's image
   * carries that digest rather than the pinned one.
   */
  acceptance: "scan-pinned" | "caller-accepted";
  /** Only with `caller-accepted`: why Scan's own pinned pull did not yield its image. */
  pinnedPullFailure?: string;
}>;

function parseVerifiedSkillspectorImage(stdout: string): string {
  let parsed: Record<string, unknown>;
  try {
    parsed = parseStrictJsonObjectV1(stdout, "SkillSpector image inspection");
  } catch {
    fail("SkillSpector image inspection JSON");
  }
  const image = parsed;
  if (image.Id === SKILLSPECTOR_IMAGE_DIGEST_V1) return SKILLSPECTOR_IMAGE_DIGEST_V1;
  if (Array.isArray(image.RepoDigests)) {
    const match = image.RepoDigests.find(
      (value): value is string =>
        typeof value === "string" && value.endsWith(`@${SKILLSPECTOR_IMAGE_DIGEST_V1}`),
    );
    if (match !== undefined) return match;
  }
  fail(`SkillSpector image digest does not match ${SKILLSPECTOR_IMAGE_DIGEST_V1}`);
}

/**
 * The local image ID to run for one caller-accepted digest. The inspected image must
 * carry that exact digest as its ID or as a repository digest; it is then run by its
 * local image ID, which Docker can resolve only from the local store and never pulls.
 */
function verifiedAcceptedSkillspectorImage(stdout: string, digest: string): string {
  let image: Record<string, unknown>;
  try {
    image = parseStrictJsonObjectV1(stdout, "SkillSpector image inspection");
  } catch {
    fail("SkillSpector image inspection JSON");
  }
  const id = image.Id;
  const carries =
    id === digest ||
    (Array.isArray(image.RepoDigests) &&
      image.RepoDigests.some((value) => typeof value === "string" && value.endsWith(`@${digest}`)));
  if (!carries || typeof id !== "string" || !imageDigestPattern.test(id))
    fail(
      `SkillSpector image availability: the image found for ${digest} does not carry accepted digest ${digest}`,
    );
  return id;
}

/**
 * `docker-host-local-skillspector-v1` (Core's legacy rule): the image behind the local tag
 * is admitted when its `Id` is the pinned digest or a caller-accepted one, and then runs by
 * that bare digest; otherwise when a `RepoDigests` entry is, as a whole value or by its `@`
 * suffix, and then runs by that full entry. Anything else fails; nothing is pulled.
 */
function verifiedLocalSkillspectorImage(
  stdout: string,
  acceptedImageDigests: readonly string[] | undefined,
): SkillspectorImageMatchV1 {
  const allowed = [SKILLSPECTOR_IMAGE_DIGEST_V1, ...(acceptedImageDigests ?? [])];
  const admitted = (digest: string, reference: string): SkillspectorImageMatchV1 =>
    Object.freeze({
      digest,
      reference,
      acceptance:
        digest === SKILLSPECTOR_IMAGE_DIGEST_V1
          ? ("scan-pinned" as const)
          : ("caller-accepted" as const),
    });
  let image: Record<string, unknown>;
  try {
    image = parseStrictJsonObjectV1(stdout, "SkillSpector image inspection");
  } catch {
    fail("SkillSpector image availability: the local image inspection JSON could not be read");
  }
  const id = image.Id;
  if (typeof id === "string" && allowed.includes(id)) return admitted(id, id);
  if (Array.isArray(image.RepoDigests)) {
    for (const entry of image.RepoDigests) {
      if (typeof entry !== "string") continue;
      if (allowed.includes(entry)) return admitted(entry, entry);
      const at = entry.lastIndexOf("@");
      if (at > 0 && allowed.includes(entry.slice(at + 1)))
        return admitted(entry.slice(at + 1), entry);
    }
  }
  fail(
    `SkillSpector image availability: the local image ${SKILLSPECTOR_LOCAL_IMAGE_TAG_V1} carries neither the pinned digest ${SKILLSPECTOR_IMAGE_DIGEST_V1} nor a caller-accepted digest; docker-host-local-skillspector-v1 never pulls, so build or load the approved image under that tag`,
  );
}

/** How one SkillSpector profile reaches Docker. */
type DockerClient = Readonly<{
  /** The argv prefix: the Docker executable and any global flags. */
  prefix: readonly string[];
  env: Readonly<Record<string, string>>;
  hostDocker?: HostDockerRuntimeV1;
}>;

/**
 * `docker-host-local-skillspector-v1`: Docker from the declared PATH (or a well-known Docker
 * Desktop directory), talking to the endpoint of the host's current Docker context. The
 * context is read once with the caller's own Docker client configuration; every later call
 * runs with a private, empty DOCKER_CONFIG and that endpoint as DOCKER_HOST, so no caller
 * credential helper or plugin reaches the run.
 */
async function hostDockerClient(
  runner: BaselineProcessRunnerV1,
  callerEnv: Readonly<NodeJS.ProcessEnv>,
  dockerConfig: string,
  control: RunControl,
): Promise<DockerClient> {
  const os = hostOs();
  const windows = os === "windows";
  const docker =
    resolveHostExecutableV1("docker", callerEnv) ??
    fail("Docker availability: docker is on neither the declared PATH nor a well-known directory");
  const fixed = (endpoint: string) =>
    substitute(HOST_DOCKER_ENVIRONMENT_V1[os], {
      "<host SystemRoot>": windows ? windowsSystemRootV1() : "",
      "<run Docker client directory>": dockerConfig,
      "<current context endpoint>": endpoint,
    });
  // The lookup sees the caller's own client variables, and no private DOCKER_CONFIG/HOST.
  const { DOCKER_CONFIG: _config, DOCKER_HOST: _host, ...lookupBase } = fixed("unused");
  const contextEnvironment: Record<string, string> = { ...lookupBase };
  for (const name of HOST_DOCKER_CONTEXT_VARIABLES_V1[os]) {
    const value = callerVariable(callerEnv, name, windows);
    if (value !== undefined) contextEnvironment[name] = value;
  }
  const label = "Docker availability: current context";
  const inspected = requireCleanResult(
    await runner(
      [docker.path, "context", "inspect", "--format", "{{json .}}"],
      runnerOptions(
        contextEnvironment,
        spawnTimeout(control, startupTimeoutMs, label),
        control,
        dockerConfig,
      ),
    ),
    label,
  );
  let context: Record<string, unknown>;
  try {
    context = parseStrictJsonObjectV1(inspected.stdout.trim(), "Docker context");
  } catch {
    fail("Docker availability: the current context could not be read");
  }
  const endpoints = context.Endpoints as Record<string, unknown> | undefined;
  const endpoint = (endpoints?.docker as Record<string, unknown> | undefined)?.Host;
  const name = context.Name;
  const tls = context.TLSMaterial as Record<string, unknown> | undefined;
  if (
    typeof name !== "string" ||
    typeof endpoint !== "string" ||
    !/^(npipe|unix):\/\//u.test(endpoint)
  )
    fail("Docker availability: the current context names no local npipe:// or unix:// endpoint");
  if (tls !== undefined && tls !== null && Object.keys(tls).length > 0)
    fail(
      `Docker availability: context ${name} uses TLS material, which docker-host-local-skillspector-v1 does not carry into its private client configuration`,
    );
  return Object.freeze({
    prefix: Object.freeze([docker.path]),
    env: Object.freeze(fixed(endpoint)),
    hostDocker: Object.freeze({
      docker: Object.freeze({ path: docker.path, foundIn: docker.foundIn }),
      context: Object.freeze({ name, endpoint }),
      containment: windows ? ("windows-job-object" as const) : ("posix-process-group" as const),
    }),
  });
}

async function skillspector(
  sourceRoot: string,
  runner: BaselineProcessRunnerV1,
  env: Readonly<Record<string, string>>,
  callerEnv: Readonly<NodeJS.ProcessEnv>,
  acceptedImageDigests: readonly string[] | undefined,
  control: RunControl,
  host: boolean,
): Promise<AnalyzerOutput> {
  if (!host) requireLinuxHost("docker-hardened-skillspector-v1");
  const dockerConfig = mkdtempSync(join(tmpdir(), "aih-scan-docker-config-"));
  try {
    const client: DockerClient = host
      ? await hostDockerClient(runner, callerEnv, dockerConfig, control)
      : Object.freeze({
          prefix: Object.freeze([BASELINE_DOCKER_EXECUTABLE_V1, "--context", "default"]),
          env: Object.freeze({ ...env, DOCKER_CONFIG: dockerConfig }),
        });
    // The private client directory is every Docker call's working directory.
    const docker = (argv: readonly string[], stageMs: number, label: string) =>
      runner(
        [...client.prefix, ...argv],
        runnerOptions(client.env, spawnTimeout(control, stageMs, label), control, dockerConfig),
      );
    const inspect = (reference: string) =>
      docker(
        ["image", "inspect", reference, "--format", "{{json .}}"],
        startupTimeoutMs,
        "SkillSpector image inspection",
      );
    requireCleanResult(
      await docker(["version"], startupTimeoutMs, "Docker availability"),
      "Docker availability",
    );
    // Local profile: inspect only the documented local tag and admit it by digest; the
    // image is never pulled.
    const localImage = async (): Promise<SkillspectorImageMatchV1> => {
      const local = await inspect(SKILLSPECTOR_LOCAL_IMAGE_TAG_V1);
      if (local.termination !== undefined)
        requireCleanResult(local, "SkillSpector image inspection");
      if (local.truncated || local.code !== 0)
        fail(
          `SkillSpector image availability: the local image ${SKILLSPECTOR_LOCAL_IMAGE_TAG_V1} is absent or cannot be inspected (${
            boundedDiagnosticDetailV1(local.stderr || local.stdout) || `exit ${local.code}`
          }); docker-host-local-skillspector-v1 never pulls, so build or load the image carrying ${SKILLSPECTOR_IMAGE_DIGEST_V1} under that tag`,
        );
      return verifiedLocalSkillspectorImage(local.stdout, acceptedImageDigests);
    };
    const pinnedImage = async (): Promise<SkillspectorImageMatchV1> => {
      // (a) Scan's pinned image present: run it. (b) Absent: attempt Scan's own pinned pull,
      // exactly as when no list is supplied. (c) Only if the pinned image is still absent
      // after that attempt are the caller's accepted digests consulted, in order, against
      // local images alone; the first present runs by image ID and nothing more is pulled.
      // (d) None present: the run fails at availability.
      let inspected = await inspect(SKILLSPECTOR_IMAGE_V1);
      if (inspected.termination !== undefined)
        requireCleanResult(inspected, "SkillSpector image inspection");
      let accepted: SkillspectorImageMatchV1 | undefined;
      if (inspected.truncated || inspected.code !== 0) {
        const pull = () =>
          docker(["pull", SKILLSPECTOR_IMAGE_V1], scanTimeoutMs, "SkillSpector image acquisition");
        if (acceptedImageDigests === undefined) {
          requireCleanResult(await pull(), "SkillSpector image acquisition");
          inspected = requireCleanResult(
            await inspect(SKILLSPECTOR_IMAGE_V1),
            "SkillSpector image inspection",
          );
        } else {
          let pinnedPullFailure: string | undefined;
          try {
            const pulled = await pull();
            if (pulled.termination === "abort" || pulled.termination === "timeout")
              requireCleanResult(pulled, "SkillSpector image acquisition");
            if (pulled.truncated || pulled.code !== 0)
              pinnedPullFailure =
                boundedDiagnosticDetailV1(pulled.stderr || pulled.stdout) ||
                `exit ${pulled.code}${pulled.truncated ? " with truncated output" : ""}`;
          } catch (error) {
            if (error instanceof AnalyzerRunFailureV1) throw error;
            pinnedPullFailure =
              boundedDiagnosticDetailV1(error instanceof Error ? error.message : "") ||
              "the pull could not be run";
          }
          if (pinnedPullFailure === undefined) {
            inspected = await inspect(SKILLSPECTOR_IMAGE_V1);
            if (inspected.truncated || inspected.code !== 0)
              pinnedPullFailure = `the pull succeeded but the pinned image is still absent: ${
                boundedDiagnosticDetailV1(inspected.stderr || inspected.stdout) ||
                `exit ${inspected.code}`
              }`;
          }
          if (pinnedPullFailure !== undefined) {
            for (const digest of acceptedImageDigests) {
              const candidate = await inspect(digest);
              if (candidate.truncated || candidate.code !== 0) continue;
              accepted = Object.freeze({
                digest,
                reference: verifiedAcceptedSkillspectorImage(candidate.stdout, digest),
                acceptance: "caller-accepted" as const,
                pinnedPullFailure,
              });
              break;
            }
            if (accepted === undefined)
              fail(
                `SkillSpector image availability: Scan's pinned image ${SKILLSPECTOR_IMAGE_DIGEST_V1} could not be acquired and no local image matches any of the ${acceptedImageDigests.length} caller-accepted digests; pinned pull failed: ${pinnedPullFailure}`,
              );
          }
        }
      }
      return (
        accepted ??
        Object.freeze({
          digest: SKILLSPECTOR_IMAGE_DIGEST_V1,
          reference: parseVerifiedSkillspectorImage(inspected.stdout),
          acceptance: "scan-pinned" as const,
        })
      );
    };
    const match = host ? await localImage() : await pinnedImage();
    const image = match.reference;
    if (
      sourceRoot.includes(",") ||
      [...sourceRoot].some((character) => {
        const code = character.charCodeAt(0);
        return code <= 31 || code === 127;
      })
    )
      fail("SkillSpector source path cannot be represented as a Docker bind mount");
    const containerName = `aih-scan-baseline-${randomUUID()}`;
    const argv = [
      "run",
      ...(host ? ["--pull", "never"] : []),
      "--rm",
      "--name",
      containerName,
      "--network",
      "none",
      "--cpus",
      "2",
      "--memory",
      "4g",
      "--memory-swap",
      "4g",
      "--pids-limit",
      "256",
      "--cap-drop",
      "ALL",
      "--cap-add",
      "DAC_OVERRIDE",
      "--security-opt",
      "no-new-privileges",
      "--read-only",
      "--tmpfs",
      "/tmp:rw,noexec,nosuid,size=64m",
      "--mount",
      `type=bind,src=${sourceRoot},dst=/scan,readonly`,
      image,
      "scan",
      "/scan",
      "--no-llm",
      "--format",
      "sarif",
    ];
    const result = await docker(argv, scanTimeoutMs, "SkillSpector scan");
    if (result.truncated || (result.code !== 0 && result.code !== 1)) {
      // Ending the docker client does not stop the container, so it is removed by name,
      // without the caller's signal, even when the run was cancelled or timed out.
      await runner(
        [...client.prefix, "rm", "--force", "--volumes", containerName],
        runnerOptions(client.env, containerRemovalTimeoutMs, {}, dockerConfig),
      ).catch(() => undefined);
      requireCleanResult(result, "SkillSpector scan", [0, 1]);
    }
    if (!result.stdout.trim()) fail("SkillSpector scan emitted no SARIF");
    const normalized = sourceRelativeSarifV1(parsedSarif(result.stdout, "skillspector"), ["/scan"]);
    return {
      ...sarifOutput(normalized.document, `${SKILLSPECTOR_SOURCE_REVISION_V1}@${match.digest}`),
      image: match,
      ...(client.hostDocker === undefined ? {} : { hostDocker: client.hostDocker }),
    };
  } finally {
    rmSync(dockerConfig, { recursive: true, force: true });
  }
}

type HostDirectories = Readonly<{
  root: string;
  temporary: string;
  home: string;
  roamingData: string;
  localData: string;
  work: string;
  venv: string;
  project: string;
}>;

/**
 * The persistent, Scan-owned uv cache for one analyzer lock, addressed by that lock's
 * digest, under the declared user's cache directory. Acquisition may fill it from the
 * network; a warm cache lets the offline scan stage run without downloading again.
 */
function scanUvCacheDirectory(
  callerEnv: Readonly<NodeJS.ProcessEnv>,
  lockSha256: string,
): { readonly directory: string; readonly key: string } {
  const windows = process.platform === "win32";
  const absolute = (value: string | undefined) =>
    value !== undefined && (windows ? win32.isAbsolute(value) : value.startsWith("/"))
      ? value
      : undefined;
  const base = windows
    ? (absolute(callerVariable(callerEnv, "LOCALAPPDATA", true)) ??
      (() => {
        const profile = absolute(callerVariable(callerEnv, "USERPROFILE", true));
        return profile === undefined ? undefined : win32.join(profile, "AppData", "Local");
      })())
    : process.platform === "darwin"
      ? (() => {
          const home = absolute(callerVariable(callerEnv, "HOME", false));
          return home === undefined ? undefined : join(home, "Library", "Caches");
        })()
      : (absolute(callerVariable(callerEnv, "XDG_CACHE_HOME", false)) ??
        (() => {
          const home = absolute(callerVariable(callerEnv, "HOME", false));
          return home === undefined ? undefined : join(home, ".cache");
        })());
  if (base === undefined)
    fail(
      `host runtime availability: no per-user cache directory can be derived from the declared environment (${
        windows ? "LOCALAPPDATA or USERPROFILE" : "XDG_CACHE_HOME or HOME"
      })`,
    );
  const key = `uv-cache-v1/${lockSha256.slice(0, 32)}`;
  const directory = join(base, "aih-scan", ...key.split("/"));
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const stat = lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink())
    fail(`host runtime availability: the Scan uv cache ${directory} is not a plain directory`);
  if (!windows && typeof process.getuid === "function" && stat.uid !== process.getuid())
    fail(`host runtime availability: the Scan uv cache ${directory} belongs to another user`);
  return { directory, key };
}

function substitute(
  template: Readonly<Record<string, string>>,
  values: Readonly<Record<string, string>>,
): Record<string, string> {
  const environment: Record<string, string> = {};
  for (const [name, value] of Object.entries(template)) {
    let resolved = value;
    for (const [placeholder, replacement] of Object.entries(values))
      resolved = resolved.replaceAll(placeholder, replacement);
    if (/<[^>]+>/u.test(resolved)) fail(`host environment ${name} has an unresolved placeholder`);
    environment[name] = resolved;
  }
  return environment;
}

function hostOs(): HostOsV1 {
  if (process.platform === "linux") return "linux";
  if (process.platform === "darwin") return "darwin";
  if (process.platform === "win32") return "windows";
  return fail(`host runtime availability: ${process.platform} has no host-process containment`);
}

/** Marker-safe names of the run's private directories, for the residual process sweep. */
function sweepMarkers(runRoot: string, sourceRoot: string): string[] {
  const markers = [basename(runRoot)];
  const snapshot = basename(sourceRoot);
  if (/^aih-scan-baseline-source-[A-Za-z0-9]{6}$/u.test(snapshot)) markers.push(snapshot);
  return markers;
}

type ResidualSweep = (markers: readonly string[]) => Promise<
  Readonly<{
    found: readonly LiveProcessV1[];
    surviving: readonly LiveProcessV1[];
  }>
>;

/**
 * `host-process-uv-v1`: uv and the analyzer run as ordinary host processes. uv is resolved
 * from the declared PATH (then well-known directories) and discovers a Python 3.12 without
 * downloading one; every analyzer spawn gets only the fixed per-OS environment and leads a
 * contained process tree (a POSIX process group, a Windows Job Object). Acquisition fills
 * a persistent, lock-addressed uv cache and may use the network; the scan stage runs
 * `--offline`. Nothing is isolated and the network is not enforced.
 */
type HostUvSessionInput = {
  readonly sourceRoot: string;
  readonly runner: BaselineProcessRunnerV1;
  readonly callerEnv: Readonly<NodeJS.ProcessEnv>;
  readonly control: RunControl;
  readonly sweep?: ResidualSweep;
};

/** One prepared host-process-uv-v1 environment: uv resolved, Python found, lock synced. */
type HostUvSession = Readonly<{
  /** Runs a contained spawn and requires a clean exit among `allowedCodes`. */
  run: (
    argv: readonly string[],
    label: string,
    stageMs: number,
    env?: Readonly<Record<string, string>>,
    allowedCodes?: readonly number[],
  ) => Promise<ProcessRunnerResult>;
  /** Runs a contained spawn and returns its raw result, exit code and termination included. */
  spawn: (
    argv: readonly string[],
    label: string,
    stageMs: number,
    env: Readonly<Record<string, string>>,
    cwd?: string,
  ) => Promise<ProcessRunnerResult>;
  tool: (name: string) => string;
  uvRun: (argv: readonly string[]) => string[];
  /** The fixed per-OS spawn environment for this run. */
  fixed: Readonly<Record<string, string>>;
  work: string;
  hostRuntime: HostProcessRuntimeV1;
}>;

async function hostProcessUv(
  analyzer: "semgrep" | "cisco",
  input: HostUvSessionInput,
): Promise<AnalyzerOutput> {
  const project = analyzer === "semgrep" ? semgrepProject : ciscoProject;
  const version = analyzer === "semgrep" ? SEMGREP_VERSION_V1 : CISCO_SKILL_SCANNER_VERSION_V1;
  return withHostUvSession(project, input, async (session) => {
    const { run, tool, uvRun, hostRuntime } = session;
    const roots = hostRoots(input.sourceRoot);
    if (analyzer === "semgrep") {
      writeFileSync(join(session.work, "rules.yml"), semgrepRules, {
        encoding: "utf8",
        mode: 0o600,
        flag: "wx",
      });
      const reported = (
        await run(uvRun([tool("semgrep"), "--version"]), "Semgrep version", startupTimeoutMs)
      ).stdout.trim();
      if (reported !== version) fail(`Semgrep version ${reported} is not ${version}`);
      const result = await run(
        uvRun([
          tool("semgrep"),
          "scan",
          "--config",
          "rules.yml",
          "--sarif",
          "--metrics=off",
          "--disable-version-check",
          "--x-ignore-semgrepignore-files",
          "--no-git-ignore",
          "--scan-unknown-extensions",
          "--",
          input.sourceRoot,
        ]),
        "Semgrep scan",
        scanTimeoutMs,
      );
      if (!result.stdout.trim()) fail("Semgrep scan emitted no SARIF");
      const normalized = sourceRelativeSarifV1(parsedSarif(result.stdout, "semgrep"), roots);
      return {
        ...sarifOutput(normalized.document, lockIdentity(version, project)),
        hostRuntime,
      };
    }
    const expectedSkills = hashSourceTreeV1(input.sourceRoot).files.filter(
      ({ path }) => path === "SKILL.md" || path.endsWith("/SKILL.md"),
    ).length;
    if (expectedSkills === 0) fail("Cisco skill discovery found no SKILL.md files");
    const reported = (
      await run(
        uvRun([tool("skill-scanner"), "--version"]),
        "Cisco skill-scanner version",
        startupTimeoutMs,
      )
    ).stdout.trim();
    if (reported !== `skill-scanner ${version}`)
      fail(`Cisco skill-scanner version ${reported} is not ${version}`);
    const jsonPath = join(session.work, "results.json");
    const sarifPath = join(session.work, "results.sarif");
    await run(
      uvRun([
        tool("skill-scanner"),
        "scan-all",
        input.sourceRoot,
        "--recursive",
        "--format",
        "json",
        "--format",
        "sarif",
        "--output-json",
        jsonPath,
        "--output-sarif",
        sarifPath,
      ]),
      "Cisco skill-scanner scan",
      scanTimeoutMs,
    );
    const report = verifyCiscoCoverage(
      readBoundedAnalyzerOutput(jsonPath, "Cisco JSON output"),
      expectedSkills,
    );
    const sarif = parsedSarif(
      readBoundedAnalyzerOutput(sarifPath, "Cisco SARIF output").toString("utf8"),
      "cisco",
    );
    return {
      ...sarifOutput(
        ciscoSourceRelativeSarifV1(sarif, report, roots).document,
        lockIdentity(version, project),
      ),
      hostRuntime,
    };
  });
}

/**
 * Prepares a host-process-uv-v1 run for one bundled uv project, gives it to `body`, and
 * then always sweeps residual processes and removes the run's private directories. A
 * residual or containment failure outranks the body's own failure; a cleanup failure is
 * reported only when nothing else failed.
 */
async function withHostUvSession<T>(
  project: string,
  input: HostUvSessionInput,
  body: (session: HostUvSession) => Promise<T>,
): Promise<T> {
  const os = hostOs();
  const windows = os === "windows";
  let lockBytes: Buffer;
  let projectBytes: Buffer;
  try {
    lockBytes = readBoundedRegularFile(join(project, "uv.lock"), maxOutputBytes, "analyzer lock");
    projectBytes = readBoundedRegularFile(
      join(project, "pyproject.toml"),
      maxProjectBytes,
      "analyzer project",
    );
  } catch (error) {
    fail(`bundled analyzer lock unavailable: ${error instanceof Error ? error.message : project}`);
  }
  const lockSha256 = createHash("sha256").update(lockBytes).digest("hex");
  const uv =
    resolveHostExecutableV1("uv", input.callerEnv) ??
    fail(
      "host runtime availability: uv is on neither the declared PATH nor a well-known directory",
    );
  const cache = scanUvCacheDirectory(input.callerEnv, lockSha256);
  const runRoot = mkdtempSync(join(tmpdir(), "aihs-"));
  let output: { readonly value: T } | undefined;
  let primary: unknown;
  try {
    const directories: HostDirectories = {
      root: runRoot,
      temporary: join(runRoot, "t"),
      home: join(runRoot, "h"),
      roamingData: join(runRoot, "a"),
      localData: join(runRoot, "l"),
      work: join(runRoot, "w"),
      venv: join(runRoot, "v"),
      project: join(runRoot, "p"),
    };
    if (directories.temporary.length > HOST_PROCESS_TEMPORARY_PATH_LIMIT_V1)
      fail(
        `host runtime availability: the private temporary directory ${directories.temporary} is ${directories.temporary.length} characters; the analyzer needs at most ${HOST_PROCESS_TEMPORARY_PATH_LIMIT_V1}. Point ${windows ? "TEMP and TMP" : "TMPDIR"} at a shorter directory.`,
      );
    for (const directory of [
      directories.temporary,
      directories.home,
      directories.work,
      directories.venv,
      directories.project,
      ...(windows ? [directories.roamingData, directories.localData] : []),
    ])
      mkdirSync(directory, { mode: 0o700 });
    writeFileSync(join(directories.project, "uv.lock"), lockBytes, { flag: "wx", mode: 0o600 });
    writeFileSync(join(directories.project, "pyproject.toml"), projectBytes, {
      flag: "wx",
      mode: 0o600,
    });
    const systemRoot = windows ? windowsSystemRootV1() : "";
    const fixed = substitute(HOST_PROCESS_UV_ENVIRONMENT_V1[os], {
      "<host SystemRoot>": systemRoot,
      "<run temporary directory>": directories.temporary,
      "<run home directory>": directories.home,
      "<run roaming data directory>": directories.roamingData,
      "<run local data directory>": directories.localData,
      "<run venv directory>": directories.venv,
      "<Scan uv cache directory for this lock>": cache.directory,
    });
    const discovery: Record<string, string> = { ...fixed };
    for (const name of HOST_PROCESS_UV_DISCOVERY_VARIABLES_V1[os]) {
      const value = callerVariable(input.callerEnv, name, windows);
      if (value !== undefined) discovery[name] = value;
    }
    const run = async (
      argv: readonly string[],
      label: string,
      stageMs: number,
      env: Readonly<Record<string, string>> = fixed,
      allowedCodes: readonly number[] = [0],
    ) =>
      requireCleanResult(
        await input.runner(
          argv,
          runnerOptions(
            env,
            spawnTimeout(input.control, stageMs, label),
            input.control,
            directories.work,
          ),
        ),
        label,
        allowedCodes,
      );
    const uvVersionLine = (
      await run([uv.path, "--version"], "host runtime availability: uv version", startupTimeoutMs)
    ).stdout.trim();
    const uvVersion = /^uv (\d+\.\d+\.\d+\S*)/u.exec(uvVersionLine)?.[1];
    if (uvVersion === undefined)
      fail(
        `host runtime availability: uv version output is not recognised: ${boundedDiagnosticDetailV1(uvVersionLine)}`,
      );
    const find = [
      uv.path,
      "python",
      "find",
      HOST_PROCESS_UV_PYTHON_REQUEST_V1,
      "--no-python-downloads",
      "--no-project",
      "--no-config",
      "--resolve-links",
      "--no-progress",
      "--color",
      "never",
    ];
    const pythonPath = (
      await run(find, "host runtime availability: Python discovery", startupTimeoutMs, discovery)
    ).stdout.trim();
    const pythonVersion = (
      await run(
        [...find, "--show-version"],
        "host runtime availability: Python discovery",
        startupTimeoutMs,
        discovery,
      )
    ).stdout.trim();
    const absolutePython = windows ? win32.isAbsolute(pythonPath) : pythonPath.startsWith("/");
    if (!absolutePython || pythonPath.includes("\n") || !statSync(pythonPath).isFile())
      fail(
        `host runtime availability: Python discovery returned no interpreter path: ${boundedDiagnosticDetailV1(pythonPath)}`,
      );
    if (
      !new RegExp(`^${HOST_PROCESS_UV_PYTHON_REQUEST_V1.replace(".", "\\.")}\\.\\d+$`, "u").test(
        pythonVersion,
      )
    )
      fail(
        `host runtime availability: the discovered Python reports ${boundedDiagnosticDetailV1(pythonVersion)}, not ${HOST_PROCESS_UV_PYTHON_REQUEST_V1}`,
      );
    await run(
      uvSyncArgv(uv.path, directories.project, pythonPath),
      "analyzer environment acquisition",
      scanTimeoutMs,
    );
    const tool = (name: string) =>
      windows
        ? join(directories.venv, "Scripts", `${name}.exe`)
        : join(directories.venv, "bin", name);
    const uvRun = (argv: readonly string[]) => [
      uv.path,
      "run",
      "--project",
      directories.project,
      "--no-sync",
      "--offline",
      "--no-config",
      "--no-python-downloads",
      "--no-progress",
      "--color",
      "never",
      "--",
      ...argv,
    ];
    const hostRuntime: HostProcessRuntimeV1 = Object.freeze({
      uv: Object.freeze({ path: uv.path, version: uvVersion, foundIn: uv.foundIn }),
      python: Object.freeze({
        request: HOST_PROCESS_UV_PYTHON_REQUEST_V1,
        path: pythonPath,
        version: pythonVersion,
      }),
      uvCache: Object.freeze({ key: cache.key }),
      containment: windows ? "windows-job-object" : "posix-process-group",
    });
    output = {
      value: await body(
        Object.freeze({
          run,
          spawn: async (
            argv: readonly string[],
            label: string,
            stageMs: number,
            env: Readonly<Record<string, string>>,
            cwd?: string,
          ) =>
            input.runner(
              argv,
              runnerOptions(
                env,
                spawnTimeout(input.control, stageMs, label),
                input.control,
                cwd ?? directories.work,
              ),
            ),
          tool,
          uvRun,
          fixed,
          work: directories.work,
          hostRuntime,
        }),
      ),
    };
  } catch (error) {
    primary = error;
  }
  let residual: AnalyzerRunFailureV1 | undefined;
  if (input.sweep !== undefined) {
    try {
      const swept = await input.sweep(sweepMarkers(runRoot, input.sourceRoot));
      if (swept.found.length > 0)
        residual = new AnalyzerRunFailureV1(
          swept.surviving.length > 0 ? "containment-failure" : "residual-processes",
          `${swept.found.length} process${swept.found.length === 1 ? "" : "es"} still referenced the run's private directories after it ended${
            swept.surviving.length > 0
              ? ` and ${swept.surviving.length} survived being killed`
              : "; they were killed"
          }: ${boundedDiagnosticDetailV1(
            swept.found.map((entry) => `${entry.pid} ${entry.command}`).join("; "),
          )}`,
        );
    } catch (error) {
      residual = new AnalyzerRunFailureV1(
        "containment-failure",
        `the residual process sweep could not run: ${error instanceof Error ? error.message : "unknown failure"}`,
      );
    }
  }
  try {
    rmSync(runRoot, { recursive: true, force: true });
  } catch (error) {
    if (primary === undefined && residual === undefined)
      primary = new TypeError(
        `aih-scan baseline analyzer: run directory cleanup failed: ${error instanceof Error ? error.message : runRoot}`,
      );
  }
  if (residual !== undefined) throw residual;
  if (primary !== undefined) throw primary;
  return (output as { readonly value: T }).value;
}

/** The uv argv an engine builds (Core's shape), and the only one the adapter accepts. */
const ENGINE_UV_PREFIX = [
  "--locked",
  "--isolated",
  "--python",
  HOST_PROCESS_UV_PYTHON_REQUEST_V1,
  "--offline",
  "--no-python-downloads",
  "--no-env-file",
] as const;

/** What an engine's process seam sees: Core's `RunResult` shape. */
export type HostUvEngineProcessResultV1 = Readonly<{
  code: number | null;
  stdout: string;
  stderr: string;
  /** Set when Scan ended the spawn or refused it; the run then fails with the recorded cause. */
  spawnError?: boolean;
}>;

/** The process seam handed to an engine: it runs only the engine's locked uv argv. */
export type HostUvEngineRunnerV1 = (
  argv: readonly string[],
  options: Readonly<{
    env?: Readonly<Record<string, string | undefined>>;
    timeoutMs?: number;
    cwd?: string;
  }>,
) => Promise<HostUvEngineProcessResultV1>;

export interface HostUvEngineRequestV1<T> {
  /** Absolute bundled uv project directory (pyproject.toml + uv.lock) the engine names. */
  readonly project: string;
  /** The analyzer version the lock pins, recorded as `<version>+uvlock.<digest>`. */
  readonly version: string;
  /** Console scripts the engine may run from the synced environment. */
  readonly tools: readonly string[];
  /**
   * Variables the engine may hand one spawn through its own `env`, by name; every other
   * variable an engine passes is dropped for the fixed per-OS environment.
   */
  readonly passEnv?: readonly string[];
  /** The private snapshot the engine scans; named in the residual sweep. */
  readonly sourceRoot: string;
  readonly runner?: BaselineProcessRunnerV1;
  /** The host environment uv and Python are resolved from. */
  readonly callerEnv: Readonly<NodeJS.ProcessEnv>;
  readonly signal?: AbortSignal;
  readonly deadline?: number;
  /** Drives the engine; `work` is a private directory the run removes. */
  readonly body: (session: Readonly<{ run: HostUvEngineRunnerV1; work: string }>) => Promise<T>;
}

/**
 * Runs an engine-driven detector under host-process-uv-v1: the same uv resolution, Python
 * discovery, locked acquisition, process-tree containment, residual sweep and private
 * directory removal as Semgrep and Cisco. The engine keeps Core's argv; the adapter accepts
 * only its exact locked offline uv prefix and runs the named console script from the synced
 * environment with `uv run --no-sync --offline`. A spawn Scan ends (timeout, abort, output
 * bound, residual descendants) is shown to the engine as a failed spawn, and the recorded
 * cause is thrown once the engine returns, so the engine's own classification never hides it.
 */
export async function runHostUvEngineV1<T>(
  request: HostUvEngineRequestV1<T>,
): Promise<Readonly<{ value: T; analyzerVersion: string; hostRuntime: HostProcessRuntimeV1 }>> {
  if (process.platform === "linux" && process.getuid?.() === 0)
    fail("analyzer execution refuses root identity");
  const control: RunControl = Object.freeze({
    ...(request.signal === undefined ? {} : { signal: request.signal }),
    ...(request.deadline === undefined ? {} : { deadline: request.deadline }),
  });
  if (control.signal?.aborted)
    throw new AnalyzerRunFailureV1(
      "cancelled",
      "the analyzer was not started: the run was cancelled",
    );
  const analyzerVersion = lockIdentity(request.version, request.project);
  const passEnv = new Set(request.passEnv ?? []);
  let hostRuntime: HostProcessRuntimeV1 | undefined;
  const value = await withHostUvSession(
    request.project,
    {
      sourceRoot: request.sourceRoot,
      runner: request.runner ?? processRunner,
      callerEnv: request.callerEnv,
      control,
      ...(request.runner === undefined ? { sweep: sweepResidualProcessesV1 } : {}),
    },
    async (session) => {
      hostRuntime = session.hostRuntime;
      let recorded: unknown;
      const run: HostUvEngineRunnerV1 = async (argv, options) => {
        const tool = argv[11];
        const shaped =
          argv[0] === "uv" &&
          argv[1] === "run" &&
          argv[2] === "--project" &&
          argv[3] === request.project &&
          ENGINE_UV_PREFIX.every((value, index) => argv[4 + index] === value) &&
          typeof tool === "string" &&
          request.tools.includes(tool);
        if (!shaped) {
          recorded ??= new TypeError(
            "aih-scan baseline analyzer: the engine asked for a spawn outside its locked offline uv argv",
          );
          return Object.freeze({ code: null, stdout: "", stderr: "", spawnError: true });
        }
        const env: Record<string, string> = { ...session.fixed };
        for (const name of passEnv) {
          const passed = options.env?.[name];
          if (typeof passed === "string") env[name] = passed;
        }
        const label = `the ${tool} analyzer`;
        let result: ProcessRunnerResult;
        try {
          result = await session.spawn(
            session.uvRun([session.tool(tool), ...argv.slice(12)]),
            label,
            options.timeoutMs ?? scanTimeoutMs,
            env,
            options.cwd,
          );
          if (result.termination !== undefined || result.truncated) {
            // Only the termination is classified here: the analyzer's own output never
            // reaches a diagnostic from this seam.
            try {
              requireCleanResult({ ...result, code: 0, truncated: false }, label);
            } catch (error) {
              recorded ??= error;
            }
            recorded ??= new TypeError(
              `aih-scan baseline analyzer: ${label} output exceeded its bound`,
            );
            return Object.freeze({ code: null, stdout: "", stderr: "", spawnError: true });
          }
        } catch (error) {
          recorded ??= error;
          return Object.freeze({ code: null, stdout: "", stderr: "", spawnError: true });
        }
        return Object.freeze({ code: result.code, stdout: result.stdout, stderr: result.stderr });
      };
      let produced: T;
      try {
        produced = await request.body(Object.freeze({ run, work: session.work }));
      } catch (error) {
        throw recorded ?? error;
      }
      if (recorded !== undefined) throw recorded;
      return produced;
    },
  );
  return Object.freeze({
    value,
    analyzerVersion,
    hostRuntime: hostRuntime as HostProcessRuntimeV1,
  });
}

async function semgrep(
  sourceRoot: string,
  runner: BaselineProcessRunnerV1,
  env: Readonly<Record<string, string>>,
  control: RunControl,
): Promise<AnalyzerOutput> {
  requireLinuxHost("linux-namespace-uv-v1");
  const temporary = mkdtempSync(join(tmpdir(), "aih-scan-semgrep-"));
  try {
    const workDirectory = join(temporary, "work");
    const cacheDirectory = join(temporary, "cache");
    const venvDirectory = join(temporary, "venv");
    mkdirSync(workDirectory, { mode: 0o700 });
    mkdirSync(cacheDirectory, { mode: 0o700 });
    mkdirSync(venvDirectory, { mode: 0o700 });
    const config = join(workDirectory, "rules.yml");
    writeFileSync(config, semgrepRules, { encoding: "utf8", mode: 0o600, flag: "wx" });
    const sandboxState = {
      project: semgrepProject,
      workDirectory,
      cacheDirectory,
      venvDirectory,
    };
    await syncUvEnvironment(runner, sandboxState, env, control);
    const sandbox = bubblewrapContainedRunner(runner, {
      ...sandboxState,
      sourceRoot,
      network: false,
      workingDirectory: "/aih/source",
    });
    const executable = "/aih/venv/bin/semgrep";
    const version = requireCleanResult(
      await sandbox(
        [executable, "--version"],
        runnerOptions(env, spawnTimeout(control, startupTimeoutMs, "Semgrep version"), control),
      ),
      "Semgrep version",
    ).stdout.trim();
    if (version !== SEMGREP_VERSION_V1)
      fail(`Semgrep version ${version} is not ${SEMGREP_VERSION_V1}`);
    const result = requireCleanResult(
      await sandbox(
        [
          executable,
          "scan",
          "--config",
          "/aih/work/rules.yml",
          "--sarif",
          "--metrics=off",
          "--disable-version-check",
          "--x-ignore-semgrepignore-files",
          "--no-git-ignore",
          "--scan-unknown-extensions",
          "--",
          "/aih/source",
        ],
        runnerOptions(env, spawnTimeout(control, scanTimeoutMs, "Semgrep scan"), control),
      ),
      "Semgrep scan",
    );
    if (!result.stdout.trim()) fail("Semgrep scan emitted no SARIF");
    const normalized = sourceRelativeSarifV1(parsedSarif(result.stdout, "semgrep"), [
      "/aih/source",
    ]);
    return sarifOutput(normalized.document, lockIdentity(SEMGREP_VERSION_V1, semgrepProject));
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

function readBoundedAnalyzerOutput(path: string, label: string): Buffer {
  return readBoundedRegularFile(path, maxOutputBytes, label);
}

/** Checks the Cisco JSON report's coverage and returns the parsed report. */
function verifyCiscoCoverage(output: Buffer, expectedSkills: number): Record<string, unknown> {
  let report: Record<string, unknown>;
  try {
    report = parseStrictJsonObjectV1(output.toString("utf8"), "Cisco JSON report");
  } catch {
    fail("Cisco JSON report is invalid");
  }
  const summary = report.summary;
  if (typeof summary !== "object" || summary === null || Array.isArray(summary))
    fail("Cisco JSON report summary is invalid");
  const values = summary as Record<string, unknown>;
  const skipped = values.skills_skipped;
  if (skipped !== undefined && !Array.isArray(skipped))
    fail("Cisco JSON report skipped-skill state is invalid");
  if (Array.isArray(skipped) && skipped.length > 0)
    fail(
      `Cisco skill-scanner skipped ${skipped.length} skill${skipped.length === 1 ? "" : "s"}, so its coverage is incomplete`,
    );
  const scanned = values.total_skills_scanned;
  if (!Number.isSafeInteger(scanned) || (scanned as number) < 1)
    fail("Cisco JSON report scanned-skill count is invalid");
  if (scanned !== expectedSkills)
    fail(`Cisco skill coverage mismatch: expected ${expectedSkills}, scanned ${String(scanned)}`);
  return report;
}

async function cisco(
  sourceRoot: string,
  runner: BaselineProcessRunnerV1,
  env: Readonly<Record<string, string>>,
  control: RunControl,
): Promise<AnalyzerOutput> {
  requireLinuxHost("linux-namespace-uv-v1");
  const temporary = mkdtempSync(join(tmpdir(), "aih-scan-cisco-"));
  try {
    const workDirectory = join(temporary, "work");
    const cacheDirectory = join(temporary, "cache");
    const venvDirectory = join(temporary, "venv");
    mkdirSync(workDirectory, { mode: 0o700 });
    mkdirSync(cacheDirectory, { mode: 0o700 });
    mkdirSync(venvDirectory, { mode: 0o700 });
    const sarifOutputPath = join(workDirectory, "results.sarif");
    const jsonOutput = join(workDirectory, "results.json");
    const expectedSkills = hashSourceTreeV1(sourceRoot).files.filter(
      ({ path }) => path === "SKILL.md" || path.endsWith("/SKILL.md"),
    ).length;
    if (expectedSkills === 0) fail("Cisco skill discovery found no SKILL.md files");
    const sandboxState = {
      project: ciscoProject,
      workDirectory,
      cacheDirectory,
      venvDirectory,
    };
    await syncUvEnvironment(runner, sandboxState, env, control);
    const sandbox = bubblewrapContainedRunner(runner, {
      ...sandboxState,
      sourceRoot,
      network: false,
      workingDirectory: "/aih/source",
    });
    const executable = "/aih/venv/bin/skill-scanner";
    const version = requireCleanResult(
      await sandbox(
        [executable, "--version"],
        runnerOptions(
          env,
          spawnTimeout(control, startupTimeoutMs, "Cisco skill-scanner version"),
          control,
        ),
      ),
      "Cisco skill-scanner version",
    ).stdout.trim();
    if (version !== `skill-scanner ${CISCO_SKILL_SCANNER_VERSION_V1}`)
      fail(`Cisco skill-scanner version ${version} is not ${CISCO_SKILL_SCANNER_VERSION_V1}`);
    requireCleanResult(
      await sandbox(
        [
          executable,
          "scan-all",
          "/aih/source",
          "--recursive",
          "--format",
          "json",
          "--format",
          "sarif",
          "--output-json",
          "/aih/work/results.json",
          "--output-sarif",
          "/aih/work/results.sarif",
        ],
        runnerOptions(
          env,
          spawnTimeout(control, scanTimeoutMs, "Cisco skill-scanner scan"),
          control,
        ),
      ),
      "Cisco skill-scanner scan",
    );
    const report = verifyCiscoCoverage(
      readBoundedAnalyzerOutput(jsonOutput, "Cisco JSON output"),
      expectedSkills,
    );
    const sarif = parsedSarif(
      readBoundedAnalyzerOutput(sarifOutputPath, "Cisco SARIF output").toString("utf8"),
      "cisco",
    );
    return sarifOutput(
      ciscoSourceRelativeSarifV1(sarif, report, ["/aih/source"]).document,
      lockIdentity(CISCO_SKILL_SCANNER_VERSION_V1, ciscoProject),
    );
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

function native(sourceRoot: string): AnalyzerOutput {
  const source = hashSourceTreeV1(sourceRoot);
  const bytes = canonicalStrictJsonBytesV1({
    protocol: "BaselineNativeObservationV1",
    sourceTreeSha256: source.treeSha256,
    files: source.files,
  });
  return {
    mediaType: "application/vnd.aih.baseline-native+json" as const,
    bytes,
    analyzerVersion: BASELINE_NATIVE_ANALYZER_IDENTITY_V1,
  };
}

export type BaselineAnalyzerRunV1 = (input: {
  readonly analyzer: BaselineAnalyzerV1;
  readonly sourceRoot: string;
}) => Promise<{
  readonly mediaType: "application/sarif+json" | "application/vnd.aih.baseline-native+json";
  readonly bytes: Uint8Array;
  readonly analyzerVersion: string;
  /** Present only for SkillSpector: the image that ran and whose digest admitted it. */
  readonly image?: SkillspectorImageMatchV1;
  /** Present only for `host-process-uv-v1`: the uv, Python and cache the run resolved. */
  readonly hostRuntime?: HostProcessRuntimeV1;
  /** Present only for `docker-host-local-skillspector-v1`: the Docker client and context used. */
  readonly hostDocker?: HostDockerRuntimeV1;
}>;

const PROFILE_ANALYZERS: Readonly<
  Record<BaselineExecutionProfileIdV1, readonly BaselineAnalyzerV1[]>
> = Object.freeze({
  "in-process-native-v1": ["aih-native"],
  "linux-namespace-uv-v1": ["semgrep", "cisco"],
  "host-process-uv-v1": ["semgrep", "cisco"],
  "docker-hardened-skillspector-v1": ["skillspector"],
  "docker-host-local-skillspector-v1": ["skillspector"],
});

/**
 * Runs exactly one analyzer over one already-sealed snapshot.
 *
 * This is the single-detector entry point; `createBaselineAnalyzerExecutionV1` is the
 * batch-shaped adapter over it. Neither invents subject metadata it was not given.
 */
export function createBaselineAnalyzerRunV1(
  options: {
    readonly runner?: BaselineProcessRunnerV1;
    readonly env?: Readonly<NodeJS.ProcessEnv>;
    /**
     * Image digests the caller also accepts for SkillSpector, consulted in order against
     * local images only when Scan's own pinned pull has failed. They are never pulled.
     */
    readonly skillspectorAcceptedImageDigests?: readonly string[];
    /**
     * The profile to run under. Absent, each analyzer uses its hardened default. A named
     * profile runs only the analyzers it declares, and nothing falls back to another.
     */
    readonly executionProfileId?: BaselineExecutionProfileIdV1;
    /** Aborting ends the running process tree and fails the run as cancelled. */
    readonly signal?: AbortSignal;
    /** Epoch milliseconds after which no stage starts and a running one is ended. */
    readonly deadline?: number;
  } = {},
): BaselineAnalyzerRunV1 {
  if (process.platform === "linux" && process.getuid?.() === 0)
    fail("analyzer execution refuses root identity");
  const runner = options.runner ?? processRunner;
  const callerEnv = options.env ?? process.env;
  const env = scrubEnvironment(callerEnv);
  let acceptedImageDigests: readonly string[] | undefined;
  if (options.skillspectorAcceptedImageDigests !== undefined) {
    const refusal = skillspectorAcceptedImageDigestsRefusalV1(
      options.skillspectorAcceptedImageDigests,
    );
    if (refusal !== undefined) fail(refusal);
    acceptedImageDigests = Object.freeze([...options.skillspectorAcceptedImageDigests]);
  }
  const profile = options.executionProfileId;
  if (profile !== undefined && !Object.hasOwn(PROFILE_ANALYZERS, profile))
    fail("unknown execution profile");
  const control: RunControl = Object.freeze({
    ...(options.signal === undefined ? {} : { signal: options.signal }),
    ...(options.deadline === undefined ? {} : { deadline: options.deadline }),
  });
  // The residual sweep inspects real processes, so it runs only with Scan's own runner.
  const sweep: ResidualSweep | undefined =
    options.runner === undefined ? sweepResidualProcessesV1 : undefined;
  return async ({ analyzer, sourceRoot }) => {
    if (profile !== undefined && !PROFILE_ANALYZERS[profile].includes(analyzer))
      fail(`${profile} does not run ${analyzer}`);
    if (control.signal?.aborted)
      throw new AnalyzerRunFailureV1(
        "cancelled",
        `${analyzer} was not started: the run was cancelled`,
      );
    const host = profile === "host-process-uv-v1";
    const implementations: Record<BaselineAnalyzerV1, () => Promise<AnalyzerOutput>> = {
      "aih-native": async () => native(sourceRoot),
      skillspector: () =>
        skillspector(
          sourceRoot,
          runner,
          env,
          callerEnv,
          acceptedImageDigests,
          control,
          profile === "docker-host-local-skillspector-v1",
        ),
      semgrep: () =>
        host
          ? hostProcessUv("semgrep", {
              sourceRoot,
              runner,
              callerEnv,
              control,
              ...(sweep === undefined ? {} : { sweep }),
            })
          : semgrep(sourceRoot, runner, env, control),
      cisco: () =>
        host
          ? hostProcessUv("cisco", {
              sourceRoot,
              runner,
              callerEnv,
              control,
              ...(sweep === undefined ? {} : { sweep }),
            })
          : cisco(sourceRoot, runner, env, control),
    };
    return implementations[analyzer]();
  };
}

export function createBaselineAnalyzerExecutionV1(
  options: {
    readonly runner?: BaselineProcessRunnerV1;
    readonly env?: Readonly<NodeJS.ProcessEnv>;
  } = {},
): BaselineAnalyzerExecutionV1 {
  const run = createBaselineAnalyzerRunV1(options);
  return ({ analyzer, sourceRoot }) => run({ analyzer, sourceRoot });
}
