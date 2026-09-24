import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Planning for the `detector.cisco` multi-skill scan, ported behaviour-for-
 * behaviour from Core's `src/trust/detectors.ts` (`ciscoSkillScannerRunArgv`, `ciscoSkillScannerVersionArgv`,
 * `resolveCiscoScanConcurrency`) and `src/trust/fetch.ts` (`scrubFetchEnv`).
 *
 * This module only plans: argv, environment and concurrency. For the C2a
 * `source-tree` subject it plans jobs from Core's `selectedClosurePaths` ({@link planCiscoSourceTreeJobsV1}) and
 * validates `detectorOptions` ({@link validateCiscoDetectorOptionsV1}). It
 * never spawns a process and never reads detector output; the runtime drives
 * execution through the injected {@link CiscoMultiSkillRunnerV1} seam.
 */

export type CiscoMultiSkillPlatformV1 = "windows" | "darwin" | "linux";

/** Process result shape the runtime's runner must report (Core's `RunResult`). */
export interface CiscoMultiSkillRunResultV1 {
  /** Process exit code; null when terminated by signal. */
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
  /** True when the executable could not be found / spawned (ENOENT, timeout). */
  readonly spawnError?: boolean;
  /** True when captured output exceeded the configured bound and is incomplete. */
  readonly truncated?: boolean;
}

export interface CiscoMultiSkillRunOptionsV1 {
  readonly cwd?: string;
  readonly env?: NodeJS.ProcessEnv;
  readonly timeoutMs?: number;
}

/** Injected process seam; the runtime supplies it, tests fake it. */
export type CiscoMultiSkillRunnerV1 = (
  argv: readonly string[],
  options?: CiscoMultiSkillRunOptionsV1,
) => Promise<CiscoMultiSkillRunResultV1>;

/** The pinned analyzer version the locked uv project provides. */
export const CISCO_MULTI_SKILL_SCANNER_VERSION_V1 = "2.1.0";
const UV_SCANNER_PYTHON_V1 = "3.12";
/** Core runs both the version probe and each per-skill scan under one bound. */
export const CISCO_MULTI_SKILL_SCAN_TIMEOUT_MS_V1 = 120_000;

const moduleDirectory = dirname(fileURLToPath(import.meta.url));
/** The bundled, locked analyzer project whose `uv.lock` pins the scanner. */
export const CISCO_MULTI_SKILL_SCANNER_PROJECT_V1 = resolve(
  moduleDirectory,
  "..",
  "..",
  "..",
  "tools",
  "baseline-analyzers",
  "cisco-skill-scanner",
);

export const DEFAULT_CISCO_SCAN_CONCURRENCY_V1 = 4;
export const MAX_CISCO_SCAN_CONCURRENCY_V1 = 64;

/** Typed result of validating `detectorOptions` for `detector.cisco` (C2a §3.3). */
export type CiscoDetectorOptionsValidationV1 = Readonly<
  | { ok: true; concurrency: number }
  | { ok: false; reason: "detector-options-invalid"; detail: string }
>;

function invalidCiscoDetectorOptionsV1(detail: string): CiscoDetectorOptionsValidationV1 {
  return Object.freeze({ ok: false as const, reason: "detector-options-invalid" as const, detail });
}

/**
 * Boundary validation for the `detector.cisco` `detectorOptions` (C2a §3.3):
 * an absent option selects the default; a present option must be a plain
 * object holding only `concurrency`, a safe integer from 1 through 64. Core
 * clamps `AIH_CISCO_SCAN_CONCURRENCY` before sending; Scan validates the
 * received integer and never coerces. Bad input is a typed refusal, never a
 * thrown error.
 */
export function validateCiscoDetectorOptionsV1(value: unknown): CiscoDetectorOptionsValidationV1 {
  if (value === undefined) {
    return Object.freeze({ ok: true as const, concurrency: DEFAULT_CISCO_SCAN_CONCURRENCY_V1 });
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return invalidCiscoDetectorOptionsV1("detectorOptions must be a plain object");
  }
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    return invalidCiscoDetectorOptionsV1("detectorOptions must be a plain object");
  }
  for (const key of Object.keys(value)) {
    if (key !== "concurrency") {
      return invalidCiscoDetectorOptionsV1(
        `detectorOptions holds unknown key: ${JSON.stringify(key)}`,
      );
    }
  }
  const concurrency = (value as { readonly concurrency?: unknown }).concurrency;
  if (concurrency === undefined) {
    return Object.freeze({ ok: true as const, concurrency: DEFAULT_CISCO_SCAN_CONCURRENCY_V1 });
  }
  if (
    typeof concurrency !== "number" ||
    !Number.isSafeInteger(concurrency) ||
    concurrency < 1 ||
    concurrency > MAX_CISCO_SCAN_CONCURRENCY_V1
  ) {
    return invalidCiscoDetectorOptionsV1(
      `concurrency must be an integer from 1 through ${MAX_CISCO_SCAN_CONCURRENCY_V1}`,
    );
  }
  return Object.freeze({ ok: true as const, concurrency });
}

/**
 * Mirrors Core's `resolveCiscoScanConcurrency`: unset, empty, malformed or
 * out-of-range values all fall back to the default; a value above the maximum
 * is not clamped down to the maximum but rejected to the default.
 */
export function resolveCiscoScanConcurrencyV1(env: NodeJS.ProcessEnv): number {
  const raw = env.AIH_CISCO_SCAN_CONCURRENCY?.trim();
  if (raw === undefined || raw.length === 0) return DEFAULT_CISCO_SCAN_CONCURRENCY_V1;
  if (!/^[1-9][0-9]*$/.test(raw)) return DEFAULT_CISCO_SCAN_CONCURRENCY_V1;
  const parsed = Number(raw);
  return Number.isSafeInteger(parsed) && parsed <= MAX_CISCO_SCAN_CONCURRENCY_V1
    ? parsed
    : DEFAULT_CISCO_SCAN_CONCURRENCY_V1;
}

// Core's `WIN_CMD_SHIMS` (`src/tools/install.ts`): Windows cannot execFile a
// `.cmd` shim directly, so those executables route through `cmd /c`. `uv` is
// not a shim, so every argv this engine builds passes through unchanged on
// every platform; the branch is retained so that parity holds if the shim set
// ever grows.
const WIN_CMD_SHIMS_V1 = new Set(["claude", "npm", "npx", "pnpm", "scoop", "yarn"]);

function execArgvV1(platform: CiscoMultiSkillPlatformV1, argv: string[]): string[] {
  if (platform !== "windows" || argv[0] === undefined || !WIN_CMD_SHIMS_V1.has(argv[0]))
    return argv;
  return ["cmd", "/c", ...argv];
}

function ciscoSkillScannerBaseArgvV1(project: string): string[] {
  return [
    "uv",
    "run",
    "--project",
    project,
    "--locked",
    "--isolated",
    "--python",
    UV_SCANNER_PYTHON_V1,
    "--offline",
    "--no-python-downloads",
    "--no-env-file",
    "skill-scanner",
  ];
}

/** `skill-scanner --version` under the locked, offline uv project. */
export function ciscoSkillScannerVersionArgvV1(
  platform: CiscoMultiSkillPlatformV1,
  project: string = CISCO_MULTI_SKILL_SCANNER_PROJECT_V1,
): string[] {
  return execArgvV1(platform, [...ciscoSkillScannerBaseArgvV1(project), "--version"]);
}

/**
 * One `skill-scanner scan <skillDir> --format sarif --format json --output-sarif <out>
 * --output-json <json>` invocation, run with `<skillDir>` as the working directory. SARIF
 * stays the primary format. U1i, coordinator decision D30 (revised 20:58Z): the job also asks
 * for Cisco's single-skill JSON report, since only its `analyzers_failed` says whether an
 * analyzer failed; Core's argv asked for SARIF alone.
 */
export function ciscoSkillScannerRunArgvV1(
  platform: CiscoMultiSkillPlatformV1,
  skillDir: string,
  outputSarif: string,
  outputJson: string,
  project: string = CISCO_MULTI_SKILL_SCANNER_PROJECT_V1,
): string[] {
  return execArgvV1(platform, [
    ...ciscoSkillScannerBaseArgvV1(project),
    "scan",
    skillDir,
    "--format",
    "sarif",
    "--format",
    "json",
    "--output-sarif",
    outputSarif,
    "--output-json",
    outputJson,
  ]);
}

const SAFE_ENV_KEYS_V1 = new Set([
  "ALLUSERSPROFILE",
  "APPDATA",
  "COMSPEC",
  "HOME",
  "HOMEDRIVE",
  "HOMEPATH",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "LANG",
  "LOCALAPPDATA",
  "NO_PROXY",
  "NODE_EXTRA_CA_CERTS",
  "PATH",
  "PATHEXT",
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
  "USERPROFILE",
  "UV_CACHE_DIR",
  "WINDIR",
  "XDG_DATA_HOME",
  "XDG_CACHE_HOME",
]);

function isSecretEnvKeyV1(key: string): boolean {
  const upper = key.toUpperCase();
  return (
    upper.includes("TOKEN") ||
    upper.includes("SECRET") ||
    upper.includes("PASSWORD") ||
    upper.endsWith("_KEY") ||
    upper.endsWith("_CREDENTIALS") ||
    upper.startsWith("AWS_") ||
    upper.startsWith("GITHUB_") ||
    upper.startsWith("ANTHROPIC_") ||
    upper.startsWith("OPENAI_")
  );
}

/**
 * The environment a scanner subprocess may see: Core's `scrubFetchEnv`
 * allow-list, with anything secret-shaped removed first, then only the
 * allow-listed keys kept.
 */
export function scrubCiscoScanEnvV1(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined || isSecretEnvKeyV1(key)) continue;
    if (SAFE_ENV_KEYS_V1.has(key.toUpperCase())) out[key] = value;
  }
  return out;
}

/** One Cisco job planned from a source-tree subject's selection (C2a §3.1). */
export interface CiscoSourceTreeJobV1 {
  /** Source-relative POSIX skill directory; `""` for a root-level `SKILL.md`. */
  readonly path: string;
  /** Absolute skill directory the job scans; also its working directory. */
  readonly skillDir: string;
}

/**
 * Job planning for a `source-tree` subject (C2a §3.1): the skill directories
 * are the `dirname` of every SELECTED path whose basename is `SKILL.md`,
 * deduplicated and sorted by relative path with Core's `localeCompare`
 * collation (coordinator decision 7). Jobs come from the selection alone —
 * the tree is never walked and skip directories are never consulted here.
 * Nested skill directories are separate jobs; a root-level `SKILL.md` plans
 * the root job with the empty prefix. `sourceRoot` is Core's absolute
 * realpath of the scanned root.
 */
export function planCiscoSourceTreeJobsV1(
  sourceRoot: string,
  selectedClosurePaths: readonly string[],
): CiscoSourceTreeJobV1[] {
  const dirs = new Set<string>();
  for (const entry of selectedClosurePaths) {
    if (entry === "SKILL.md") {
      dirs.add("");
    } else if (entry.endsWith("/SKILL.md")) {
      dirs.add(entry.slice(0, entry.length - "/SKILL.md".length));
    }
  }
  return [...dirs]
    .sort((left, right) => left.localeCompare(right))
    .map((path) =>
      Object.freeze({
        path,
        skillDir: path.length === 0 ? sourceRoot : join(sourceRoot, ...path.split("/")),
      }),
    );
}
