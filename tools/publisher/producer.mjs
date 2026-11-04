// Independently reviewed producer code is prepared before any candidate is downloaded.
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { gunzipSync } from "node:zlib";
import { digest, extractArchive, MAX_ARCHIVE_BYTES, need } from "./prepared-archive.mjs";
import { regularFiles } from "./prepared.mjs";

export function validateProducerContext(bytes, expectedSha256) {
  need(/^[0-9a-f]{64}$/.test(expectedSha256 ?? "") && digest(bytes) === expectedSha256, "Reviewed producer context digest mismatch");
  const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  const hashes = ["packageSha256", "lockSha256", "archiveSha256", "manifestSha256", "receiptSha256", "selectionSha256"];
  need(value && Object.keys(value).sort().join(",") === ["format", "sourceCommit", ...hashes].sort().join(",") && value.format === "aih-scan-producer-context/1" && /^[0-9a-f]{40}$/.test(value.sourceCommit) && hashes.every((key) => /^[0-9a-f]{64}$/.test(value[key] ?? "")), "Invalid reviewed producer context");
  return value;
}
export function checkProducerSource(context, source) {
  const git = (args) => execFileSync("git", ["-C", source, ...args], { encoding: "utf8", windowsHide: true }).trim();
  need(git(["remote", "get-url", "origin"]).replace(/\.git$/, "") === "https://github.com/samartomar/aih-scan", "Producer source repository mismatch");
  need(git(["rev-parse", "HEAD"]) === context.sourceCommit, "Producer source commit mismatch");
  need(git(["status", "--porcelain", "--untracked-files=all"]) === "", "Producer source is modified");
  need(digest(readFileSync(join(source, "package-lock.json"))) === context.lockSha256, "Producer dependency lock mismatch");
}
const runtimeDigest = (consumer) => digest(JSON.stringify(regularFiles(consumer, new Set(["node_modules/.bin", "producer-context.json"])).map(({ path, file, stat }) => [path, stat.mode & 0o111 ? "100755" : "100644", digest(readFileSync(file))])));
export function sealProducerContext(bytes, expectedSha256, source, consumer, tarball) {
  const context = validateProducerContext(bytes, expectedSha256);
  checkProducerSource(context, source);
  need(digest(readFileSync(tarball)) === context.packageSha256, "Reviewed producer package mismatch");
  writeFileSync(join(consumer, "producer-context.json"), JSON.stringify({ contextSha256: expectedSha256, runtimeSha256: runtimeDigest(consumer) }), { flag: "wx" });
  return context;
}
export function checkProducerContext(bytes, expectedSha256, consumer) {
  const context = validateProducerContext(bytes, expectedSha256);
  const sealed = JSON.parse(readFileSync(join(consumer, "producer-context.json"), "utf8"));
  need(sealed.contextSha256 === expectedSha256 && sealed.runtimeSha256 === runtimeDigest(consumer), "Prepared producer runtime/context mismatch");
  return context;
}
export function buildProducerContext(bytes, expectedSha256, source, consumer) {
  const context = validateProducerContext(bytes, expectedSha256);
  checkProducerSource(context, source); // Refuse before executing any producer code.
  const home = `${resolve(consumer)}.home`;
  mkdirSync(home);
  const env = { PATH: `${dirname(process.execPath)}${process.platform === "win32" ? ";" : ":"}${process.env.PATH ?? ""}`, HOME: home, USERPROFILE: home, TMPDIR: home, TEMP: home, TMP: home, npm_config_cache: join(home, "cache"), npm_config_userconfig: join(home, "npmrc"), npm_config_globalconfig: join(home, "global-npmrc"), GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: join(home, "gitconfig"), ...(process.platform === "win32" ? { SystemRoot: process.env.SystemRoot } : {}) };
  for (const file of ["npmrc", "global-npmrc", "gitconfig"]) writeFileSync(join(home, file), "");
  const npm = (args, cwd) => execFileSync(process.platform === "win32" ? "npm.cmd" : "npm", args, { cwd, env, stdio: "pipe", windowsHide: true });
  npm(["ci", "--ignore-scripts", "--no-audit", "--no-fund"], source);
  npm(["--ignore-scripts", "run", "build"], source);
  const packed = JSON.parse(npm(["pack", "--ignore-scripts", "--json"], source).toString());
  const tarball = join(source, packed[0].filename);
  need(digest(readFileSync(tarball)) === context.packageSha256, "Reviewed producer package mismatch");
  // npm ci uses the independently reviewed committed dependency lock, never archive metadata.
  mkdirSync(consumer);
  for (const file of ["package.json", "package-lock.json"]) cpSync(join(source, file), join(consumer, file));
  npm(["ci", "--omit=dev", "--ignore-scripts", "--no-audit", "--no-fund"], consumer);
  const unpack = `${resolve(consumer)}.package`;
  extractArchive(gunzipSync(readFileSync(tarball), { maxOutputLength: MAX_ARCHIVE_BYTES }), unpack);
  mkdirSync(join(consumer, "node_modules/@aihq"), { recursive: true });
  need(!existsSync(join(consumer, "node_modules/@aihq/scan")), "Producer package destination already exists");
  cpSync(join(unpack, "package"), join(consumer, "node_modules/@aihq/scan"), { recursive: true });
  // Build outputs are expected after source verification; seal against the reviewed input bytes.
  writeFileSync(join(consumer, "producer-context.json"), JSON.stringify({ contextSha256: expectedSha256, runtimeSha256: runtimeDigest(consumer) }), { flag: "wx" });
  return context;
}
