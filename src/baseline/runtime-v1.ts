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
  rmSync,
  type Stats,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  BASELINE_BWRAP_EXECUTABLE_V1,
  BASELINE_DOCKER_EXECUTABLE_V1,
  BASELINE_UV_EXECUTABLE_V1,
  type ProcessRunnerResult,
  processRunner,
} from "../cli/process-runner.js";
import {
  canonicalStrictJsonBytesV1,
  canonicalStrictJsonSha256V1,
  parseStrictJsonObjectV1,
} from "../contract/strict-json-v1.js";
import { hashSourceTreeV1 } from "../observation/source-hash-v1.js";
import type { BaselineAnalyzerExecutionV1, BaselineAnalyzerV1 } from "./batch-v1.js";

export const SKILLSPECTOR_IMAGE_V1 =
  "ghcr.io/samartomar/skillspector@sha256:c5d4a1816419f129ae85ff96b3e366d4a062c1859997e26b7ab87341a43d4800";
export const SKILLSPECTOR_SOURCE_REVISION_V1 = "2d198ab910add401cad658d1087e7c7ba24fd640";
export const SKILLSPECTOR_IMAGE_DIGEST_V1 =
  "sha256:c5d4a1816419f129ae85ff96b3e366d4a062c1859997e26b7ab87341a43d4800";
export const CISCO_SKILL_SCANNER_VERSION_V1 = "2.0.14";
export const SEMGREP_VERSION_V1 = "1.173.0";
export const BASELINE_PYTHON_EXECUTABLE_V1 = "/usr/bin/python3.13";
const baselinePythonPathV1 = "/usr/local/lib/python3.13:/usr/local/lib/python3.13/lib-dynload";

const maxOutputBytes = 16 * 1024 * 1024;
const maxStderrBytes = 64 * 1024;
const maxFailureDetailCharacters = 400;
const startupTimeoutMs = 120_000;
const scanTimeoutMs = 900_000;
const moduleDirectory = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(moduleDirectory, "..", "..");
const analyzerRoot = join(packageRoot, "tools", "baseline-analyzers");
const ciscoProject = join(analyzerRoot, "cisco-skill-scanner");
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
    readonly killProcessGroup: true;
  },
) => Promise<ProcessRunnerResult>;

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

function fail(reason: string): never {
  throw new TypeError(`aih-scan baseline analyzer: ${reason}`);
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

function resultFailure(result: ProcessRunnerResult, label: string): never {
  const rawDetail = (result.stderr || result.stdout).trim();
  const encodedDetail = encodeDiagnosticLine(rawDetail);
  let detail = encodedDetail;
  if (encodedDetail.length > maxFailureDetailCharacters) {
    const marker = "\\n… middle omitted …\\n";
    const retained = maxFailureDetailCharacters - marker.length;
    const headLength = Math.ceil(retained / 2);
    detail = `${encodedDetail.slice(0, headLength)}${marker}${encodedDetail.slice(
      -(retained - headLength),
    )}`;
  }
  fail(`${label} failed${detail ? `: ${detail}` : ` with exit ${result.code}`}`);
}

function requireCleanResult(
  result: ProcessRunnerResult,
  label: string,
  allowedCodes: readonly number[] = [0],
): ProcessRunnerResult {
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

function uvSyncArgv(): string[] {
  return [
    BASELINE_UV_EXECUTABLE_V1,
    "sync",
    "--project",
    "/aih/project",
    "--locked",
    "--no-dev",
    "--no-install-project",
    "--no-build",
    "--link-mode",
    "copy",
    "--python",
    BASELINE_PYTHON_EXECUTABLE_V1,
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

function runnerOptions(env: Readonly<Record<string, string>>, timeoutMs: number, cwd?: string) {
  return {
    ...(cwd === undefined ? {} : { cwd }),
    env,
    timeoutMs,
    maxStdoutBytes: maxOutputBytes,
    maxStderrBytes,
    killProcessGroup: true as const,
  };
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

function analyzerSandbox(
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
  return bubblewrapContainedRunner(runner, input);
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
): Promise<void> {
  requireCleanResult(
    await analyzerSandbox(runner, {
      ...input,
      network: true,
      workingDirectory: "/aih/project",
    })(uvSyncArgv(), runnerOptions(env, scanTimeoutMs)),
    "analyzer environment acquisition",
  );
}

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

async function skillspector(
  sourceRoot: string,
  runner: BaselineProcessRunnerV1,
  env: Readonly<Record<string, string>>,
) {
  const dockerConfig = mkdtempSync(join(tmpdir(), "aih-scan-docker-config-"));
  const dockerEnvironment = { ...env, DOCKER_CONFIG: dockerConfig };
  try {
    requireCleanResult(
      await runner(
        [BASELINE_DOCKER_EXECUTABLE_V1, "--context", "default", "version"],
        runnerOptions(dockerEnvironment, startupTimeoutMs),
      ),
      "Docker availability",
    );
    let inspected = await runner(
      [
        BASELINE_DOCKER_EXECUTABLE_V1,
        "--context",
        "default",
        "image",
        "inspect",
        SKILLSPECTOR_IMAGE_V1,
        "--format",
        "{{json .}}",
      ],
      runnerOptions(dockerEnvironment, startupTimeoutMs),
    );
    if (inspected.truncated || inspected.code !== 0) {
      requireCleanResult(
        await runner(
          [BASELINE_DOCKER_EXECUTABLE_V1, "--context", "default", "pull", SKILLSPECTOR_IMAGE_V1],
          runnerOptions(dockerEnvironment, scanTimeoutMs),
        ),
        "SkillSpector image acquisition",
      );
      inspected = requireCleanResult(
        await runner(
          [
            BASELINE_DOCKER_EXECUTABLE_V1,
            "--context",
            "default",
            "image",
            "inspect",
            SKILLSPECTOR_IMAGE_V1,
            "--format",
            "{{json .}}",
          ],
          runnerOptions(dockerEnvironment, startupTimeoutMs),
        ),
        "SkillSpector image inspection",
      );
    }
    const image = parseVerifiedSkillspectorImage(inspected.stdout);
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
      BASELINE_DOCKER_EXECUTABLE_V1,
      "--context",
      "default",
      "run",
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
    const result = await runner(argv, runnerOptions(dockerEnvironment, scanTimeoutMs));
    if (result.truncated || (result.code !== 0 && result.code !== 1)) {
      await runner(
        [
          BASELINE_DOCKER_EXECUTABLE_V1,
          "--context",
          "default",
          "rm",
          "--force",
          "--volumes",
          containerName,
        ],
        runnerOptions(dockerEnvironment, 30_000),
      ).catch(() => undefined);
      resultFailure(result, "SkillSpector scan");
    }
    if (!result.stdout.trim()) fail("SkillSpector scan emitted no SARIF");
    return {
      mediaType: "application/sarif+json" as const,
      bytes: Buffer.from(result.stdout, "utf8"),
      analyzerVersion: `${SKILLSPECTOR_SOURCE_REVISION_V1}@${SKILLSPECTOR_IMAGE_DIGEST_V1}`,
    };
  } finally {
    rmSync(dockerConfig, { recursive: true, force: true });
  }
}

async function semgrep(
  sourceRoot: string,
  runner: BaselineProcessRunnerV1,
  env: Readonly<Record<string, string>>,
) {
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
    await syncUvEnvironment(runner, sandboxState, env);
    const sandbox = analyzerSandbox(runner, {
      ...sandboxState,
      sourceRoot,
      network: false,
      workingDirectory: "/aih/source",
    });
    const executable = "/aih/venv/bin/semgrep";
    const version = requireCleanResult(
      await sandbox([executable, "--version"], runnerOptions(env, startupTimeoutMs)),
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
        runnerOptions(env, scanTimeoutMs),
      ),
      "Semgrep scan",
    );
    if (!result.stdout.trim()) fail("Semgrep scan emitted no SARIF");
    return {
      mediaType: "application/sarif+json" as const,
      bytes: Buffer.from(result.stdout, "utf8"),
      analyzerVersion: lockIdentity(SEMGREP_VERSION_V1, semgrepProject),
    };
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

function readBoundedAnalyzerOutput(path: string, label: string): Buffer {
  return readBoundedRegularFile(path, maxOutputBytes, label);
}

function verifyCiscoCoverage(output: Buffer, expectedSkills: number): void {
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
    fail(`Cisco skill-scanner skipped ${skipped.length} skill${skipped.length === 1 ? "" : "s"}`);
  const scanned = values.total_skills_scanned;
  if (!Number.isSafeInteger(scanned) || (scanned as number) < 1)
    fail("Cisco JSON report scanned-skill count is invalid");
  if (scanned !== expectedSkills)
    fail(`Cisco skill coverage mismatch: expected ${expectedSkills}, scanned ${String(scanned)}`);
}

async function cisco(
  sourceRoot: string,
  runner: BaselineProcessRunnerV1,
  env: Readonly<Record<string, string>>,
) {
  const temporary = mkdtempSync(join(tmpdir(), "aih-scan-cisco-"));
  try {
    const workDirectory = join(temporary, "work");
    const cacheDirectory = join(temporary, "cache");
    const venvDirectory = join(temporary, "venv");
    mkdirSync(workDirectory, { mode: 0o700 });
    mkdirSync(cacheDirectory, { mode: 0o700 });
    mkdirSync(venvDirectory, { mode: 0o700 });
    const sarifOutput = join(workDirectory, "results.sarif");
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
    await syncUvEnvironment(runner, sandboxState, env);
    const sandbox = analyzerSandbox(runner, {
      ...sandboxState,
      sourceRoot,
      network: false,
      workingDirectory: "/aih/source",
    });
    const executable = "/aih/venv/bin/skill-scanner";
    const version = requireCleanResult(
      await sandbox([executable, "--version"], runnerOptions(env, startupTimeoutMs)),
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
        runnerOptions(env, scanTimeoutMs),
      ),
      "Cisco skill-scanner scan",
    );
    verifyCiscoCoverage(readBoundedAnalyzerOutput(jsonOutput, "Cisco JSON output"), expectedSkills);
    return {
      mediaType: "application/sarif+json" as const,
      bytes: readBoundedAnalyzerOutput(sarifOutput, "Cisco SARIF output"),
      analyzerVersion: lockIdentity(CISCO_SKILL_SCANNER_VERSION_V1, ciscoProject),
    };
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

function native(sourceRoot: string) {
  const source = hashSourceTreeV1(sourceRoot);
  const bytes = canonicalStrictJsonBytesV1({
    protocol: "BaselineNativeObservationV1",
    sourceTreeSha256: source.treeSha256,
    files: source.files,
  });
  return {
    mediaType: "application/vnd.aih.baseline-native+json" as const,
    bytes,
    analyzerVersion: `native.${canonicalStrictJsonSha256V1({
      domain: "aih.baseline-native-observation-v1",
      algorithm: "source-hash-v1",
    }).slice(0, 12)}`,
  };
}

export function createBaselineAnalyzerExecutionV1(
  options: {
    readonly runner?: BaselineProcessRunnerV1;
    readonly env?: Readonly<NodeJS.ProcessEnv>;
  } = {},
): BaselineAnalyzerExecutionV1 {
  if (process.platform === "linux" && process.getuid?.() === 0)
    fail("analyzer execution refuses root identity");
  const runner = options.runner ?? processRunner;
  const env = scrubEnvironment(options.env ?? process.env);
  return async ({ analyzer, sourceRoot }) => {
    const implementations: Record<
      BaselineAnalyzerV1,
      () => ReturnType<BaselineAnalyzerExecutionV1>
    > = {
      "aih-native": async () => native(sourceRoot),
      skillspector: () => skillspector(sourceRoot, runner, env),
      semgrep: () => semgrep(sourceRoot, runner, env),
      cisco: () => cisco(sourceRoot, runner, env),
    };
    return implementations[analyzer]();
  };
}
