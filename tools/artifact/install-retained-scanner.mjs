// Restore only independently selected retained package/lock bytes. npm executes
// no lifecycle scripts. loadScanner subsequently checks every installed byte.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import {
  canonicalBytes,
  parseJson,
  readRegular,
  sha256,
  validateManifest,
} from "../refresh/contracts.mjs";
import { loadScanner } from "../refresh/scanner.mjs";

try {
  const independentReader = process.argv[5] === "independent-reader";
  if (!(process.argv.length === 5 || (process.argv.length === 6 && independentReader)))
    throw new Error("Expected retained directory, manifest SHA and exclusive consumer path");
  const [, , retained, expectedSha, output] = process.argv;
  const manifestBytes = readRegular(join(retained, "manifest.json"), 2097152);
  if (sha256(manifestBytes) !== expectedSha) throw new Error("Frozen input substitution");
  const manifest = validateManifest(parseJson(manifestBytes, 2097152, true));
  if (
    !independentReader &&
    !canonicalBytes(manifest.runtime).equals(
      canonicalBytes({
        node: process.version,
        platform: process.platform,
        architecture: process.arch,
      }),
    )
  )
    throw new Error("Actual runtime differs from frozen execution runtime");
  const custody = parseJson(readRegular(join(retained, "custody.json"), 2097152), 2097152, true);
  const lockBytes = readRegular(join(retained, "consumer-package-lock.json"), 8 * 1024 * 1024);
  const lock = parseJson(lockBytes, 8 * 1024 * 1024);
  if (
    sha256(lockBytes) !== custody.consumerLockSha256 ||
    lock.lockfileVersion !== 3 ||
    !lock.packages?.[""]?.dependencies ||
    sha256(readRegular(join(retained, "scanner.tgz"), 64 * 1024 * 1024)) !==
      manifest.scanner.tarballSha256
  )
    throw new Error("Retained package or lock substitution");
  // A fixed sibling filename makes file:../scanner.tgz lock attribution portable
  // across job workspace paths, while the installation digest remains exact.
  if (
    lock.packages["node_modules/@aihq/scan"]?.resolved !== "file:../scanner.tgz" ||
    lock.packages[""].dependencies["@aihq/scan"] !== "file:../scanner.tgz"
  )
    throw new Error("Consumer lock must retain fixed sibling tarball attribution");
  mkdirSync(dirname(output), { recursive: true, mode: 0o700 });
  const siblingTarball = join(dirname(output), "scanner.tgz");
  const tarballBytes = readRegular(join(retained, "scanner.tgz"), 64 * 1024 * 1024);
  if (existsSync(siblingTarball)) {
    if (!readRegular(siblingTarball, 64 * 1024 * 1024).equals(tarballBytes))
      throw new Error("Existing sibling tarball collision");
  } else writeFileSync(siblingTarball, tarballBytes, { flag: "wx", mode: 0o600 });
  mkdirSync(output, { mode: 0o700 });
  writeFileSync(join(output, "package-lock.json"), lockBytes, { flag: "wx" });
  writeFileSync(
    join(output, "package.json"),
    canonicalBytes({
      name: lock.name,
      version: lock.version,
      private: true,
      type: "module",
      dependencies: lock.packages[""].dependencies,
    }),
    { flag: "wx" },
  );
  const npm = [
    process.env.npm_execpath,
    join(dirname(process.execPath), "node_modules/npm/bin/npm-cli.js"),
    resolve(dirname(process.execPath), "../lib/node_modules/npm/bin/npm-cli.js"),
  ].find((path) => typeof path === "string" && existsSync(path));
  if (!npm) throw new Error("npm entrypoint unavailable");
  const env = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => !/^npm_config_allow_scripts$/i.test(key)),
  );
  const result = spawnSync(
    process.execPath,
    [npm, "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
    { cwd: output, env, stdio: "inherit", windowsHide: true },
  );
  if (result.status !== 0) throw new Error("Frozen install refused");
  const scanner = await loadScanner(
    join(retained, "scanner.tgz"),
    output,
    manifest.scanner.sourceCommit,
  );
  if (
    !canonicalBytes({
      ...scanner.identity,
      installationSha256: independentReader
        ? manifest.scanner.installationSha256
        : scanner.identity.installationSha256,
    }).equals(canonicalBytes(manifest.scanner))
  )
    throw new Error("Actual installation differs from frozen identity");
  if (independentReader)
    writeFileSync(
      join(output, "reader-custody.json"),
      canonicalBytes({
        schema: "urn:aihq:scan:independent-reader-custody:1.0.0",
        scanner: scanner.identity,
        runtime: { node: process.version, platform: process.platform, architecture: process.arch },
        producerScanner: manifest.scanner,
        producerRuntime: manifest.runtime,
        consumerLockSha256: sha256(lockBytes),
      }),
      { flag: "wx", mode: 0o600 },
    );
  process.stdout.write(
    `${JSON.stringify({ event: "scan-refresh-install.completed", phase: "retained-installation", batchId: manifest.batchId, inputSha256: expectedSha, installationSha256: scanner.identity.installationSha256 })}\n`,
  );
} catch {
  process.stderr.write(
    `${JSON.stringify({ event: "scan-refresh-install.refused", phase: "retained-installation", reason: "frozen-package-or-lock-or-installation-refused" })}\n`,
  );
  process.exitCode = 2;
}
