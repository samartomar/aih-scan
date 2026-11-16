import { existsSync } from "node:fs";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";

/** Invoke this JavaScript entrypoint with process.execPath; .cmd files are shell scripts. */
export function npmCli() {
  const configured = process.env.npm_execpath;
  if (typeof configured === "string" && isAbsolute(configured) &&
      basename(configured) === "npm-cli.js" && existsSync(configured)) return configured;
  const directory = dirname(process.execPath);
  for (const candidate of [
    join(directory, "node_modules/npm/bin/npm-cli.js"),
    resolve(directory, "../lib/node_modules/npm/bin/npm-cli.js"),
    resolve(directory, "../share/nodejs/npm/bin/npm-cli.js"),
  ]) if (existsSync(candidate)) return candidate;
  throw new Error("npm CLI entrypoint unavailable");
}
