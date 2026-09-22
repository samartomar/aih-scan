/**
 * Loads the public `@aihq/scan` entry point.
 *
 * An installed consumer resolves the package by name. Run from a clone of this
 * repository there is no installed copy, so the local build is used instead and the
 * example says which one it loaded. Nothing below reaches past the published entry
 * point: no `dist/` subpath and no source file is imported.
 */
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const localBuild = resolve(here, "..", "dist", "index.js");

export async function loadScan() {
  try {
    return { scan: await import("@aihq/scan"), from: "@aihq/scan" };
  } catch (error) {
    // Only a package that is not there at all falls back. An installed package that
    // fails while loading reports its own error rather than being masked by the build.
    if (error?.code !== "ERR_MODULE_NOT_FOUND") throw error;
    if (!existsSync(localBuild)) {
      process.stderr.write(
        `Cannot load @aihq/scan: it is not installed, and ${localBuild} does not exist.\n` +
          "Install the package, or run `npm run build` in a clone of this repository first.\n",
      );
      throw error;
    }
    return { scan: await import(pathToFileURL(localBuild).href), from: localBuild };
  }
}
