import { lstatSync, readdirSync, statSync } from "node:fs";
import { basename, dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Planning for the `detector.cisco` multi-skill scan, ported behaviour-for-
 * behaviour from Core's `src/trust/detectors.ts` (`collectCiscoSkillDirs`,
 * `ciscoSkillScannerRunArgv`, `ciscoSkillScannerVersionArgv`,
 * `resolveCiscoScanConcurrency`) and `src/trust/fetch.ts` (`scrubFetchEnv`).
 *
 * This module only plans: it computes skill directories, argv, environment and
 * concurrency for a subject. It never spawns a process and never reads
 * detector output; the runtime drives execution through the injected
 * {@link CiscoMultiSkillRunnerV1} seam.
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
export const CISCO_MULTI_SKILL_SCANNER_VERSION_V1 = "2.0.14";
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
 * One `skill-scanner scan <skillDir> --format sarif --output-sarif <out>`
 * invocation; Core runs it with `<skillDir>` as the working directory.
 */
export function ciscoSkillScannerRunArgvV1(
  platform: CiscoMultiSkillPlatformV1,
  skillDir: string,
  outputSarif: string,
  project: string = CISCO_MULTI_SKILL_SCANNER_PROJECT_V1,
): string[] {
  return execArgvV1(platform, [
    ...ciscoSkillScannerBaseArgvV1(project),
    "scan",
    skillDir,
    "--format",
    "sarif",
    "--output-sarif",
    outputSarif,
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

/** Directories Core's trust walk never descends into. */
export const CISCO_SKILL_SKIP_DIRS_V1: ReadonlySet<string> = new Set([
  ".git",
  ".hg",
  ".svn",
  ".aih",
  "coverage",
  "dist",
  "node_modules",
  "vendor",
]);

/** Minimal inventory seam: Core's `TrustFileInventory` as this engine reads it. */
export interface CiscoSkillInventoryEntryV1 {
  readonly absolutePath: string;
  readonly relativePath: string;
  readonly size: number;
}

export interface CiscoSkillInventoryV1 {
  matching(
    predicate: (entry: CiscoSkillInventoryEntryV1) => boolean,
  ): Iterable<CiscoSkillInventoryEntryV1>;
}

function toPosixV1(path: string): string {
  return path.replace(/\\/g, "/");
}

/**
 * Filesystem fallback for {@link collectCiscoSkillDirsV1}, mirroring Core's
 * `collectFilesUnder` over `buildTrustFileInventory`: skip directories are not
 * descended (except the root itself), a symlink is followed only when its
 * target is a file, and a symlinked directory is never traversed.
 */
function walkSkillFilesV1(root: string): string[] {
  const absoluteRoot = resolve(root);
  const files: string[] = [];
  const visit = (absolutePath: string): void => {
    const stats = lstatSync(absolutePath);
    if (stats.isSymbolicLink()) {
      const target = statSync(absolutePath);
      if (target.isFile() && basename(absolutePath) === "SKILL.md") files.push(absolutePath);
      return;
    }
    if (stats.isDirectory()) {
      if (absolutePath !== absoluteRoot && CISCO_SKILL_SKIP_DIRS_V1.has(basename(absolutePath)))
        return;
      for (const entry of readdirSync(absolutePath).sort()) visit(join(absolutePath, entry));
      return;
    }
    if (!stats.isFile()) return;
    if (basename(absolutePath) === "SKILL.md") files.push(absolutePath);
  };
  visit(absoluteRoot);
  return files;
}

/**
 * Every directory holding a `SKILL.md`, sorted by its source-relative POSIX
 * path with Core's `localeCompare` ordering. Nested skills are each listed;
 * when an inventory is supplied it is the only source of candidates.
 */
export function collectCiscoSkillDirsV1(root: string, inventory?: CiscoSkillInventoryV1): string[] {
  const dirs = new Set<string>();
  const skillFiles: Iterable<string> = inventory
    ? {
        *[Symbol.iterator]() {
          for (const entry of inventory.matching(
            (candidate) => basename(candidate.absolutePath) === "SKILL.md",
          )) {
            yield entry.absolutePath;
          }
        },
      }
    : walkSkillFilesV1(root);
  for (const file of skillFiles) dirs.add(dirname(file));
  return [...dirs].sort((left, right) =>
    toPosixV1(relative(root, left)).localeCompare(toPosixV1(relative(root, right))),
  );
}
