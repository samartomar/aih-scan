import { realpathSync, statSync } from "node:fs";
import { posix, win32 } from "node:path";

/**
 * Resolves a host executable for the host profiles without running anything.
 *
 * The caller-declared `PATH` is searched first, in order, then a fixed list of well-known
 * install directories for that OS (Homebrew, `~/.local/bin`, `/usr/local/bin`, ...). Only
 * absolute directories are consulted, and on Windows only `<name>.exe` is accepted, never a
 * `.cmd`, `.bat` or `.ps1` shim that would need a shell. The resolved file's real path is what
 * Scan records and spawns, and only a path resolved here may be spawned by Scan's runner.
 */

export type HostExecutableNameV1 = "uv" | "docker";

export type HostExecutableV1 = Readonly<{
  name: HostExecutableNameV1;
  /** The real (symlink-resolved) absolute path that is spawned and recorded. */
  path: string;
  /** Where the search found it. */
  foundIn: "PATH" | "well-known-directory";
}>;

const registered = new Set<string>();

function home(env: Readonly<NodeJS.ProcessEnv>, platform: NodeJS.Platform): string | undefined {
  const value = platform === "win32" ? env.USERPROFILE : env.HOME;
  if (typeof value !== "string" || value.length === 0) return undefined;
  return platform === "win32"
    ? win32.isAbsolute(value)
      ? value
      : undefined
    : value.startsWith("/")
      ? value
      : undefined;
}

/** The fixed, OS-specific directories searched after `PATH`, in order. */
export function wellKnownExecutableDirectoriesV1(
  name: HostExecutableNameV1,
  env: Readonly<NodeJS.ProcessEnv>,
  platform: NodeJS.Platform = process.platform,
): readonly string[] {
  const user = home(env, platform);
  if (platform === "win32") {
    const programFiles = env.ProgramFiles ?? env.PROGRAMFILES;
    const localAppData = env.LOCALAPPDATA;
    const directories = [
      ...(user === undefined
        ? []
        : [win32.join(user, ".local", "bin"), win32.join(user, ".cargo", "bin")]),
      ...(name === "docker"
        ? [
            ...(typeof programFiles === "string" && win32.isAbsolute(programFiles)
              ? [win32.join(programFiles, "Docker", "Docker", "resources", "bin")]
              : []),
            ...(typeof localAppData === "string" && win32.isAbsolute(localAppData)
              ? [win32.join(localAppData, "Programs", "DockerDesktop", "resources", "bin")]
              : []),
          ]
        : []),
    ];
    return Object.freeze(directories);
  }
  const shared =
    platform === "darwin"
      ? ["/opt/homebrew/bin", "/usr/local/bin"]
      : ["/usr/local/bin", "/usr/bin", "/home/linuxbrew/.linuxbrew/bin"];
  const userDirectories =
    user === undefined
      ? []
      : [posix.join(user, ".local", "bin"), posix.join(user, ".cargo", "bin")];
  const docker =
    name === "docker" && platform === "darwin"
      ? ["/Applications/Docker.app/Contents/Resources/bin"]
      : name === "docker"
        ? ["/snap/bin"]
        : [];
  return Object.freeze([...userDirectories, ...shared, ...docker]);
}

/** The absolute directories of a declared `PATH`, in order; relative entries are skipped. */
export function pathDirectoriesV1(
  env: Readonly<NodeJS.ProcessEnv>,
  platform: NodeJS.Platform = process.platform,
): readonly string[] {
  const value = platform === "win32" ? (env.Path ?? env.PATH ?? env.path) : env.PATH;
  if (typeof value !== "string") return Object.freeze([]);
  const separator = platform === "win32" ? ";" : ":";
  const directories: string[] = [];
  for (const raw of value.split(separator)) {
    const entry = platform === "win32" ? raw.trim().replace(/^"(.*)"$/u, "$1") : raw;
    if (!entry || entry.includes("\0")) continue;
    if (platform === "win32" ? !/^[A-Za-z]:[\\/]/u.test(entry) : !entry.startsWith("/")) continue;
    directories.push(entry);
  }
  return Object.freeze(directories);
}

function candidate(
  directory: string,
  name: HostExecutableNameV1,
  platform: NodeJS.Platform,
): string | undefined {
  const file =
    platform === "win32" ? win32.join(directory, `${name}.exe`) : posix.join(directory, name);
  try {
    const stat = statSync(file);
    if (!stat.isFile()) return undefined;
    if (platform !== "win32" && (stat.mode & 0o111) === 0) return undefined;
    return realpathSync.native(file);
  } catch {
    return undefined;
  }
}

/**
 * Finds `name` on the declared `PATH`, then in the well-known directories. Returns
 * `undefined` when it is nowhere, so the caller can refuse before spawning anything.
 */
export function resolveHostExecutableV1(
  name: HostExecutableNameV1,
  env: Readonly<NodeJS.ProcessEnv>,
  platform: NodeJS.Platform = process.platform,
): HostExecutableV1 | undefined {
  for (const [directories, foundIn] of [
    [pathDirectoriesV1(env, platform), "PATH"],
    [wellKnownExecutableDirectoriesV1(name, env, platform), "well-known-directory"],
  ] as const) {
    for (const directory of directories) {
      const path = candidate(directory, name, platform);
      if (path === undefined) continue;
      if (platform === process.platform) registered.add(path);
      return Object.freeze({ name, path, foundIn });
    }
  }
  return undefined;
}

/** `true` only for a path this module resolved; Scan's runner spawns nothing else by path. */
export function isRegisteredHostExecutableV1(path: string): boolean {
  return registered.has(path);
}
