import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { readPackedPackage } from "./npm-pack-output.js";

const sourceRoot = resolve(import.meta.dirname, "../..");

export function npmCliPath(): string {
  const configured = process.env.npm_execpath;
  if (
    configured &&
    isAbsolute(configured) &&
    basename(configured) === "npm-cli.js" &&
    existsSync(configured)
  )
    return configured;
  const nodeDirectory = dirname(process.execPath);
  for (const candidate of [
    join(nodeDirectory, "node_modules/npm/bin/npm-cli.js"),
    resolve(nodeDirectory, "../lib/node_modules/npm/bin/npm-cli.js"),
  ])
    if (existsSync(candidate)) return candidate;
  throw new Error("npm CLI entrypoint unavailable");
}

// npm owns the public asset selection, including implicit package files and
// future additions to published directories. Never import npm's private internals.
export function copyPackedPublicAssets(source: string, destination: string): string[] {
  const packed = readPackedPackage(
    execFileSync(
      process.execPath,
      [npmCliPath(), "pack", "--ignore-scripts", "--dry-run", "--json"],
      { cwd: source, encoding: "utf8", windowsHide: true },
    ),
  );
  if (!packed) throw new Error("Public fixture package inventory unavailable");
  const paths = packed.files.map(({ path }) => path);
  for (const path of paths) {
    // Each fixture compiles its own dist instead of using mutable checkout output.
    if (path.startsWith("dist/")) continue;
    const target = resolve(destination, path);
    const local = relative(resolve(destination), target);
    if (
      isAbsolute(local) ||
      local === ".." ||
      local.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`)
    )
      throw new Error(`Public fixture asset escapes its destination: ${path}`);
    mkdirSync(dirname(target), { recursive: true });
    cpSync(join(source, path), target);
  }
  return paths;
}

export function assertPublicFixtureExports(destination: string): void {
  const manifest = JSON.parse(readFileSync(join(destination, "package.json"), "utf8")) as {
    exports: Record<string, unknown>;
    bin: Record<string, string>;
  };
  function check(value: unknown, label: string): void {
    if (typeof value === "string") {
      if (!existsSync(resolve(destination, value)))
        throw new Error(`Public fixture is missing ${label}: ${value}`);
    } else if (value !== null && typeof value === "object") {
      for (const [condition, target] of Object.entries(value))
        check(target, `${label}/${condition}`);
    }
  }
  for (const [entry, target] of Object.entries(manifest.exports)) check(target, `export ${entry}`);
  for (const [entry, target] of Object.entries(manifest.bin)) check(target, `bin ${entry}`);
}

export function assemblePublicConsumerFixture(destination: string): void {
  mkdirSync(destination, { recursive: true });
  execFileSync(
    process.execPath,
    [
      join(sourceRoot, "node_modules/typescript/bin/tsc"),
      "-p",
      "tsconfig.build.json",
      "--outDir",
      join(destination, "dist"),
    ],
    { cwd: sourceRoot, stdio: "pipe", windowsHide: true },
  );
  copyPackedPublicAssets(sourceRoot, destination);
  assertPublicFixtureExports(destination);
}
