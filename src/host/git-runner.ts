import { dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnBoundedV1 } from "../cli/process-runner.js";
import { base64Decode, bound, ContractError, fail, strictParse } from "../shared/json.js";

/**
 * The hardened Git runner shared by pinned acquisition and remote ref resolution.
 * Git always runs through `git-command` under Scan's bounded process-tree runner, with
 * argument arrays only (never a shell), an allowlisted environment (no inherited GIT_*,
 * proxy or credential variables, a private empty HOME so no ~/.netrc or user configuration is
 * read, no askpass program, no system or global configuration, no terminal prompt), HTTPS as the only transport, no redirects, verified TLS and an empty hooks
 * directory.
 */
export interface PinnedGitOptions {
  signal?: AbortSignal;
}
export class GitContainmentError extends ContractError {
  constructor() {
    super(
      "git-containment-failed",
      "Pinned Git acquisition could not confirm process-tree cleanup",
    );
  }
}
/** Variables (compared in upper case) that locate executables, temporary space and the OS. */
const INHERITED = new Set([
  "PATH",
  "PATHEXT",
  "SYSTEMROOT",
  "WINDIR",
  "COMSPEC",
  "TMPDIR",
  "TMP",
  "TEMP",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
]);
export async function runPinnedGit(
  argv: string[],
  cwd: string,
  options: PinnedGitOptions,
  hooks: string,
  maxBytes = 16 * 1024 * 1024,
): Promise<Uint8Array> {
  // Only what Git needs to start is inherited; everything else (credentials, GIT_*, proxies,
  // NODE_OPTIONS, curl and netrc settings) is left behind. HOME and its platform equivalents
  // point at the empty, Scan-owned hooks folder, so libcurl finds no ~/.netrc to answer a 401
  // with and Git finds no user configuration.
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env))
    if (value !== undefined && INHERITED.has(key.toUpperCase())) env[key] = value;
  Object.assign(env, {
    HOME: hooks,
    USERPROFILE: hooks,
    XDG_CONFIG_HOME: hooks,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
    GIT_TERMINAL_PROMPT: "0",
    // Git asks GIT_ASKPASS, core.askPass, then SSH_ASKPASS before the terminal prompt; an
    // empty GIT_ASKPASS ends that chain, so no credential dialog can appear.
    GIT_ASKPASS: "",
    GIT_NO_REPLACE_OBJECTS: "1",
  });
  const moduleFile = fileURLToPath(import.meta.url),
    helper = join(dirname(moduleFile), `git-command${extname(moduleFile)}`);
  const gitArgs = [
    "-c",
    "protocol.allow=never",
    "-c",
    "protocol.https.allow=always",
    "-c",
    "http.followRedirects=false",
    "-c",
    "http.sslVerify=true",
    "-c",
    `core.hooksPath=${hooks}`,
    "-c",
    "core.autocrlf=false",
    ...argv,
  ];
  const output = await spawnBoundedV1(
    [process.execPath, helper, JSON.stringify(gitArgs), String(maxBytes)],
    {
      cwd,
      env,
      signal: options.signal,
      timeoutMs: 600000,
      maxStdoutBytes: Math.ceil(maxBytes / 3) * 4 + 64,
      maxStderrBytes: 65536,
      containProcessTree: true,
    },
  );
  if (output.termination === "containment-failure") throw new GitContainmentError();
  if (output.termination === "timeout")
    throw new ContractError(
      "resource-limit",
      "gitCommandTimeoutMs limit 600000; observed elapsed time at least 600000 ms",
    );
  if (output.termination === "output-limit") {
    const crossed = output.outputLimit;
    if (crossed)
      throw new ContractError(
        "resource-limit",
        `Git wrapper ${crossed.stream === "stdout" ? "maxStdoutBytes" : "maxStderrBytes"} limit ${crossed.limit}; observed ${crossed.observed} bytes`,
      );
    throw new ContractError(
      "git-acquisition-failed",
      "Git wrapper stopped for output overflow without byte-count evidence",
    );
  }
  if (output.termination === "abort")
    throw new ContractError("git-acquisition-failed", "Pinned Git acquisition was cancelled");
  const value =
    output.stdout && !output.stdoutMalformedUtf8
      ? strictParse(
          new TextEncoder().encode(output.stdout),
          "Git transport",
          Math.ceil(maxBytes / 3) * 4 + 64,
        )
      : null;
  if (
    typeof value === "object" &&
    value !== null &&
    "failure" in value &&
    "observed" in value &&
    (value.failure === "stdout-limit" || value.failure === "stderr-limit") &&
    typeof value.observed === "number" &&
    Number.isSafeInteger(value.observed)
  ) {
    const limit = value.failure === "stdout-limit" ? maxBytes : 65536;
    bound(
      false,
      value.failure === "stdout-limit" ? "gitStdoutBytes" : "gitStderrBytes",
      limit,
      value.observed,
    );
  }
  if (output.code !== 0 || output.truncated || output.termination || output.stdoutMalformedUtf8)
    throw new ContractError(
      "git-acquisition-failed",
      `Pinned Git acquisition failed (exit code ${output.code}${output.termination === "residual-descendants" ? "; residual descendants were terminated" : ""}); check Git availability and repository/commit access`,
    );
  if (
    typeof value !== "object" ||
    value === null ||
    !("bytesBase64" in value) ||
    typeof value.bytesBase64 !== "string" ||
    Object.keys(value).length !== 1
  )
    fail("Git transport returned malformed bytes");
  return base64Decode(value.bytesBase64, maxBytes);
}
