import { execFileSync } from "node:child_process";
import * as fsBoundary from "node:fs";
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { readArtifact } from "../../src/artifact/read.js";
import { runScan, runScanPrepared } from "../../src/assessment/run.js";
import type { ScanRunResult } from "../../src/assessment/types.js";
import type { ProcessRunnerResult } from "../../src/cli/process-runner.js";
import * as processBoundary from "../../src/cli/process-runner.js";
import { runScanCommand, type ScanCommandIo, scanUsage } from "../../src/cli/scan-command.js";

// Each case runs a real Git fixture and a complete assessment.
vi.setConfig({ testTimeout: 30_000 });

vi.mock("node:fs", async (importOriginal) => ({
  ...(await importOriginal<typeof import("node:fs")>()),
}));

/**
 * Git sources are exercised against a disposable real repository: the bounded process
 * boundary is replaced and each Git subcommand is answered from the fixture, with the
 * remote URL substituted by the fixture path. No network is used.
 */

const remote = "https://example.invalid/owner/fixture.git";
const roots: string[] = [];
/** Fixtures live under the real temporary directory; the command's own temporaries do not. */
const fixtureParent = tmpdir();
let temporary: string;

function directory(prefix: string): string {
  const root = realpathSync.native(mkdtempSync(join(fixtureParent, prefix)));
  roots.push(root);
  return root;
}

beforeEach(() => {
  // Every temporary directory the command and the assessment own lands here.
  temporary = directory("aih-scan-git-temp-");
  vi.stubEnv("TMPDIR", temporary);
  vi.stubEnv("TEMP", temporary);
  vi.stubEnv("TMP", temporary);
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

const gitEnv = {
  ...process.env,
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
};

interface Fixture {
  root: string;
  git: (args: string[]) => string;
  commits: { first: string; second: string; feature: string };
}

/** trunk (default HEAD) has two commits; feature branches from the first. */
function repository(): Fixture {
  const root = directory("aih-scan-git-fixture-");
  const git = (args: string[]) =>
    execFileSync("git", args, { cwd: root, env: gitEnv, windowsHide: true }).toString("utf8");
  const commit = (message: string) => {
    git(["add", "."]);
    git([
      "-c",
      "user.name=Scan fixture",
      "-c",
      "user.email=scan-fixture@example.invalid",
      "commit",
      "--quiet",
      "-m",
      message,
    ]);
    return git(["rev-parse", "HEAD"]).trim();
  };
  git(["init", "--quiet", "--initial-branch=trunk"]);
  git(["config", "core.autocrlf", "false"]);
  writeFileSync(join(root, "SKILL.md"), "# Fixture\n");
  const first = commit("First");
  writeFileSync(join(root, "notes.md"), "second\n");
  const second = commit("Second");
  git(["checkout", "--quiet", "-b", "feature", first]);
  writeFileSync(join(root, "feature.md"), "feature\n");
  const feature = commit("Feature");
  git(["checkout", "--quiet", "trunk"]);
  return { root, git, commits: { first, second, feature } };
}

interface Served {
  /** The Git arguments of every runner call, in order. */
  calls: string[][];
  /** The complete process argv of every runner call. */
  argv: string[][];
  /** The environment of every runner call. */
  envs: Readonly<Record<string, string>>[];
}
type Answer = (tail: string[], args: string[]) => ProcessRunnerResult | undefined;

function ok(bytes: Buffer | string): ProcessRunnerResult {
  return {
    code: 0,
    stdout: JSON.stringify({ bytesBase64: Buffer.from(bytes).toString("base64") }),
    stderr: "",
    truncated: false,
  };
}

/** Answers the hardened runner's Git subcommands from the fixture repository. */
function serve(fixture: Fixture, answer: Answer = () => undefined): Served {
  const served: Served = { calls: [], argv: [], envs: [] };
  vi.spyOn(processBoundary, "spawnBoundedV1").mockImplementation(async (argv, options) => {
    expect(options.containProcessTree).toBe(true);
    const args = JSON.parse(argv[2] as string) as string[];
    served.calls.push(args);
    served.argv.push([...argv]);
    served.envs.push(options.env);
    const operation = args.findIndex((arg) =>
      ["init", "fetch", "ls-remote", "rev-parse", "ls-tree", "cat-file"].includes(arg),
    );
    const tail = args.slice(operation);
    const answered = answer(tail, args);
    if (answered !== undefined) return answered;
    if (tail[0] === "init" || tail[0] === "fetch") return ok(Buffer.alloc(0));
    // Any repository URL is answered by the fixture; Git never sees the URL.
    const local = tail.map((arg) => (arg.startsWith("https://") ? fixture.root : arg));
    return ok(execFileSync("git", local, { cwd: fixture.root, env: gitEnv, windowsHide: true }));
  });
  return served;
}

function harness(extra: Partial<ScanCommandIo> = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const io: ScanCommandIo = {
    stdout: (text) => out.push(text),
    stderr: (text) => err.push(text),
    ...extra,
  };
  return { io, stdout: () => out.join(""), stderr: () => err.join("") };
}

function expectOwnedTemporaryRemoved(): void {
  expect(readdirSync(temporary)).toEqual([]);
}

test("resolves the default HEAD of a non-main default branch and assesses that commit", async () => {
  const fixture = repository();
  serve(fixture);
  const requests: unknown[] = [];
  const run = harness({
    runScan: (request, options) => {
      requests.push(request);
      return runScan(request, options);
    },
  });
  expect(await runScanCommand([remote], run.io)).toBe(0);
  expect(requests).toMatchObject([
    { source: { kind: "git", repository: remote, commit: fixture.commits.second } },
  ]);
  const lines = run.stdout().split("\n");
  expect(lines).toContain(`Target: ${remote} (2 files, 2 entries)`);
  expect(lines).toContain(`Commit: ${fixture.commits.second} (refs/heads/trunk)`);
  expect(run.stderr()).toContain(`aih-scan: assessing ${remote} at ${fixture.commits.second}\n`);
  expectOwnedTemporaryRemoved();
});

function lsRemoteCalls(served: Served): string[][] {
  return served.calls.filter((args) => args.includes("ls-remote"));
}

/** Runs the command with a recording runScan; returns its exit, output and requests. */
async function command(args: string[], extra: Partial<ScanCommandIo> = {}) {
  const requests: { source: unknown }[] = [];
  const seen: { result?: ScanRunResult } = {};
  const run = harness({
    runScan: async (request, options, prepare) => {
      requests.push(request as { source: unknown });
      seen.result = await runScanPrepared(request, options, prepare);
      return seen.result;
    },
    ...extra,
  });
  const exit = await runScanCommand(args, run.io);
  return { exit, stdout: run.stdout(), stderr: run.stderr(), requests, seen };
}

function tagged(fixture: Fixture): Fixture {
  fixture.git(["tag", "light", fixture.commits.first]);
  fixture.git([
    "-c",
    "user.name=Scan fixture",
    "-c",
    "user.email=scan-fixture@example.invalid",
    "tag",
    "-a",
    "-m",
    "Annotated",
    "v1",
    fixture.commits.first,
  ]);
  fixture.git(["branch", "both", fixture.commits.feature]);
  fixture.git(["tag", "both", fixture.commits.first]);
  return fixture;
}

test.each([
  ["a branch", "feature", "feature", "refs/heads/feature"],
  ["a lightweight tag", "light", "first", "refs/tags/light"],
  ["an annotated tag, peeled to its commit", "v1", "first", "refs/tags/v1"],
  ["a qualified branch", "refs/heads/both", "feature", "refs/heads/both"],
  ["a qualified tag", "refs/tags/both", "first", "refs/tags/both"],
] as const)("--ref resolves %s to its full commit", async (_name, ref, expected, resolved) => {
  const fixture = tagged(repository());
  serve(fixture);
  const commit = fixture.commits[expected];
  const result = await command([remote, "--ref", ref]);
  expect(result.exit).toBe(0);
  expect(result.requests).toMatchObject([{ source: { kind: "git", repository: remote, commit } }]);
  expect(result.stdout.split("\n")).toContain(`Commit: ${commit} (${resolved})`);
  expect(result.stderr).toContain(`aih-scan: resolved ${ref} to ${commit} (${resolved})\n`);
  expectOwnedTemporaryRemoved();
});

test("--ref refuses a name that is both a branch and a tag and names the qualified forms", async () => {
  const fixture = tagged(repository());
  serve(fixture);
  const result = await command([remote, "--ref", "both"]);
  expect(result.exit).toBe(2);
  expect(result.stderr).toContain(
    "aih-scan: --ref both names both a branch and a tag; use refs/heads/both or refs/tags/both\n",
  );
  expect(result.requests).toEqual([]);
  expect(result.stdout).toBe("");
  expectOwnedTemporaryRemoved();
});

test("--ref with a full commit uses it as given without listing refs", async () => {
  const fixture = repository();
  const served = serve(fixture);
  const result = await command([remote, "--ref", fixture.commits.first]);
  expect(result.exit).toBe(0);
  expect(lsRemoteCalls(served)).toEqual([]);
  expect(result.requests).toMatchObject([
    { source: { kind: "git", repository: remote, commit: fixture.commits.first } },
  ]);
  expect(result.stdout.split("\n")).toContain(`Commit: ${fixture.commits.first}`);
  expectOwnedTemporaryRemoved();
});

test("--ref that names no branch or tag is refused with exit 2", async () => {
  const fixture = repository();
  serve(fixture);
  const result = await command([remote, "--ref", "absent"]);
  expect(result.exit).toBe(2);
  expect(result.stderr).toContain(
    "aih-scan: --ref absent was not found as a branch or tag; a commit must be the full 40-character hash\n",
  );
  expect(result.requests).toEqual([]);
  expectOwnedTemporaryRemoved();
});

test("an unavailable repository exits 2 with a fixed message and never prints Git's output", async () => {
  const fixture = repository();
  serve(fixture, (tail) =>
    tail[0] === "ls-remote"
      ? {
          code: 1,
          stdout: "",
          stderr: "fatal: could not read Username: secret-diagnostic",
          truncated: false,
        }
      : undefined,
  );
  const result = await command([remote]);
  expect(result.exit).toBe(2);
  expect(result.stderr).toContain(
    "aih-scan: the Git repository is unavailable, requires credentials, or could not be resolved\n",
  );
  expect(result.stderr + result.stdout).not.toContain("secret-diagnostic");
  expect(result.requests).toEqual([]);
  expectOwnedTemporaryRemoved();
});

test.each([
  ["a SHA-256 object name", `${"a".repeat(64)}\tHEAD\n`],
  ["a short object name", `${"a".repeat(39)}\tHEAD\n`],
  ["an unterminated line", `${"a".repeat(40)}\tHEAD`],
  ["a space separator", `${"a".repeat(40)} HEAD\n`],
  ["a repeated ref", `${"a".repeat(40)}\tHEAD\n${"b".repeat(40)}\tHEAD\n`],
  ["an unexpected line", "warning: something\n"],
])("a ref listing with %s is refused", async (_name, listing) => {
  const fixture = repository();
  serve(fixture, (tail) => (tail[0] === "ls-remote" ? ok(listing) : undefined));
  const result = await command([remote]);
  expect(result.exit).toBe(2);
  expect(result.stderr).toContain(
    "aih-scan: the Git repository returned an unsupported ref listing (only SHA-1 repositories are supported)\n",
  );
  expect(result.requests).toEqual([]);
  expectOwnedTemporaryRemoved();
});

test("a repository without a default HEAD is refused and asks for --ref", async () => {
  const fixture = repository();
  serve(fixture, (tail) => (tail[0] === "ls-remote" ? ok("") : undefined));
  const result = await command([remote]);
  expect(result.exit).toBe(2);
  expect(result.stderr).toContain(
    "aih-scan: the Git repository has no default branch (HEAD); name one with --ref\n",
  );
  expectOwnedTemporaryRemoved();
});

test.each([
  ["a user and password", "https://user:tok3n-value@example.invalid/owner/repo.git"],
  ["a token as the user", "https://tok3n-value@example.invalid/owner/repo.git"],
  ["an empty user and a password", "https://:tok3n-value@example.invalid/owner/repo.git"],
])("a Git URL with %s is refused without printing it", async (_name, url) => {
  const served = serve(repository());
  const result = await command([url]);
  expect(result.exit).toBe(2);
  expect(result.stderr).toBe(
    "aih-scan: the Git URL contains credentials; credentials are never accepted in a Git URL\n",
  );
  expect(result.stdout + result.stderr).not.toContain("tok3n");
  expect(served.calls).toEqual([]);
});

test.each([
  ["a query", "https://example.invalid/owner/repo.git?token=tok3n-value"],
  ["a fragment", "https://example.invalid/owner/repo.git#tok3n-value"],
])("a Git URL with %s is refused without printing it", async (_name, url) => {
  const served = serve(repository());
  const result = await command([url]);
  expect(result.exit).toBe(2);
  expect(result.stderr).toBe(
    "aih-scan: the Git URL has a query or fragment; name the repository URL only\n",
  );
  expect(result.stdout + result.stderr).not.toContain("tok3n");
  expect(served.calls).toEqual([]);
});

test.each([
  "http://example.invalid/owner/tok3n.git",
  "ssh://git@example.invalid/owner/tok3n.git",
  "git://example.invalid/owner/tok3n.git",
  "file:///srv/owner/tok3n.git",
  "git@example.invalid:owner/tok3n.git",
])("an unsupported Git source %s is refused without printing it", async (spelling) => {
  const served = serve(repository());
  const result = await command([spelling], { cwd: directory("aih-scan-git-cwd-") });
  expect(result.exit).toBe(2);
  expect(result.stderr).toBe(
    "aih-scan: unsupported Git source; use an https:// URL or a GitHub owner/repo\n",
  );
  expect(result.stdout + result.stderr).not.toContain("tok3n");
  expect(served.calls).toEqual([]);
});

test.each([
  ["owner/fixture", "https://github.com/owner/fixture.git"],
  ["owner/fixture.git", "https://github.com/owner/fixture.git"],
  ["Some-Owner/re.po_x", "https://github.com/Some-Owner/re.po_x.git"],
])("the GitHub shorthand %s names %s when no such local path exists", async (spelling, url) => {
  const fixture = repository();
  const served = serve(fixture);
  const result = await command([spelling], { cwd: directory("aih-scan-git-cwd-") });
  expect(result.exit).toBe(0);
  expect(lsRemoteCalls(served)).toHaveLength(1);
  expect(lsRemoteCalls(served)[0]).toContain(url);
  expect(result.requests).toMatchObject([
    { source: { kind: "git", repository: url, commit: fixture.commits.second } },
  ]);
  expect(result.stdout.split("\n")).toContain(`Target: ${url} (2 files, 2 entries)`);
});

test("an existing local directory spelled like owner/repo is assessed locally, as before", async () => {
  const cwd = directory("aih-scan-git-cwd-");
  mkdirSync(join(cwd, "owner", "repo"), { recursive: true });
  writeFileSync(join(cwd, "owner", "repo", "SKILL.md"), "# Local\n");
  const served = serve(repository());
  const relative = await command(["owner/repo"], { cwd });
  const absolute = await command([join(cwd, "owner", "repo")], { cwd });
  expect(relative.exit).toBe(0);
  expect(relative.requests).toEqual([
    expect.objectContaining({ source: { kind: "local", path: join(cwd, "owner", "repo") } }),
  ]);
  // The Scan ID binds the observation time; every other line is the same.
  const withoutScanId = (text: string) => text.replace(/^Scan ID: .*$/m, "");
  expect(withoutScanId(relative.stdout)).toBe(withoutScanId(absolute.stdout));
  expect(relative.stderr).toBe(absolute.stderr);
  expect(relative.stdout).not.toContain("Commit:");
  expect(lsRemoteCalls(served)).toEqual([]);
});

test("--ref with a local directory is refused", async () => {
  const cwd = directory("aih-scan-git-cwd-");
  writeFileSync(join(cwd, "SKILL.md"), "# Local\n");
  const result = await command([cwd, "--ref", "main"]);
  expect(result.exit).toBe(2);
  expect(result.stderr).toBe("aih-scan: --ref applies only to Git sources\n");
  expect(result.requests).toEqual([]);
});

/** Commits the files to the fixture's checked-out branch; returns the new commit. */
function commitFiles(fixture: Fixture, files: Record<string, string>): string {
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(fixture.root, path)), { recursive: true });
    writeFileSync(join(fixture.root, path), text);
  }
  fixture.git(["add", "."]);
  fixture.git([
    "-c",
    "user.name=Scan fixture",
    "-c",
    "user.email=scan-fixture@example.invalid",
    "commit",
    "--quiet",
    "-m",
    "Add files",
  ]);
  return fixture.git(["rev-parse", "HEAD"]).trim();
}

const secret = `ghp_${"a1".repeat(18)}`;
const secretConfig = `${JSON.stringify({ mcpServers: { demo: { env: { GITHUB_TOKEN: secret } } } })}\n`;

/** The trust-lint configuration a completed assessment recorded in its report. */
function trustLintConfiguration(result: { seen: { result?: ScanRunResult } }): unknown {
  const run = result.seen.result;
  if (run?.status !== "assessment") throw new Error("expected an assessment");
  return run.report.requestedDetectors.find((d) => d.detectorId === "detector.aih-trust-lint")
    ?.configuration;
}

test("a .mcp.json inside the Git target is discovered and linted like a local one", async () => {
  const fixture = repository();
  const commit = commitFiles(fixture, { ".mcp.json": secretConfig });
  serve(fixture);
  const result = await command([remote]);
  expect(result.exit).toBe(0);
  expect(result.stdout).toContain("mcp.hardcoded-secret");
  expect(result.stdout).not.toContain(secret);
  expect(result.stderr).not.toContain(secret);
  const run = result.seen.result;
  if (run?.status !== "assessment") throw new Error("expected an assessment");
  expect(run.report.source).toMatchObject({ kind: "git", repository: remote, commit });
  expect(run.report.completion).toBe("complete");
  expect(trustLintConfiguration(result)).toEqual({
    internalScopes: [],
    mcpConfigPaths: [".mcp.json"],
  });
  expectOwnedTemporaryRemoved();
});

test.each([
  ["a POSIX path", "/etc/mcp.json"],
  ["a Windows drive path", "C:Userssomeonemcp.json"],
  ["a UNC path", "\\hostsharemcp.json"],
])("--mcp-config with %s is refused for a Git source before any Git process", async (_name, path) => {
  const served = serve(repository());
  const result = await command([remote, "--mcp-config", path]);
  expect(result.exit).toBe(2);
  expect(result.stderr).toBe(
    `aih-scan: --mcp-config ${path} must be relative to the Git target, not a host path\n`,
  );
  expect(served.calls).toEqual([]);
  expect(result.requests).toEqual([]);
});

test("--mcp-config names a file of the Git target and replaces discovery", async () => {
  const fixture = repository();
  commitFiles(fixture, {
    ".mcp.json": "{}\n",
    "skills/alpha/SKILL.md": "# Alpha\n",
    "skills/alpha/mcp.json": secretConfig,
  });
  serve(fixture);
  const result = await command([remote, "--mcp-config", "skills/alpha/mcp.json"]);
  expect(result.exit).toBe(0);
  expect(result.stdout).toContain("mcp.hardcoded-secret");
  expect(result.stdout).not.toContain(secret);
  expect(trustLintConfiguration(result)).toEqual({
    internalScopes: [],
    mcpConfigPaths: ["skills/alpha/mcp.json"],
  });
  expectOwnedTemporaryRemoved();
});

test.each([
  ["missing from the target", "absent/mcp.json", "does not exist inside the target"],
  ["outside the target", "../mcp.json", "outside the target directory"],
])("--mcp-config %s is refused for a Git source with no assessment", async (_name, path, why) => {
  const fixture = repository();
  serve(fixture);
  const result = await command([remote, "--mcp-config", path, "--json"]);
  expect(result.exit).toBe(2);
  expect(result.seen.result).toMatchObject({
    status: "diagnostic",
    phase: "request",
    diagnostics: [{ code: "invalid-input", detail: expect.stringContaining(why) }],
  });
  expectOwnedTemporaryRemoved();
});

test("a Git target without MCP configuration is complete and says none was found", async () => {
  const fixture = repository();
  serve(fixture);
  const result = await command([remote]);
  expect(result.exit).toBe(0);
  expect(result.stdout).toContain(
    "detector.aih-trust-lint: no MCP configuration found inside the target",
  );
  expect(trustLintConfiguration(result)).toEqual({ internalScopes: [], mcpConfigPaths: [] });
});

test("--mcp-config with a Git source still needs a detector that reads MCP configuration", async () => {
  const served = serve(repository());
  const result = await command([
    remote,
    "--detector",
    "detector.aih-native",
    "--mcp-config",
    "m.json",
  ]);
  expect(result.exit).toBe(2);
  expect(result.stderr).toContain("--mcp-config requires a selected detector");
  expect(served.calls).toEqual([]);
});

test.each([
  ["a range", "a..b"],
  ["a space", "a b"],
  ["a control character", "a\u0007b"],
  ["a reflog selector", "main@{1}"],
  ["a revision suffix", "main~1"],
  ["a peel suffix", "v1^{}"],
  ["a colon", "a:b"],
  ["a glob", "feat*"],
  ["a backslash", "a\\b"],
  ["a lock suffix", "topic.lock"],
  ["a hidden component", "a/.hidden"],
  ["a trailing slash", "topic/"],
  ["a trailing dot", "topic."],
  ["a double slash", "a//b"],
  ["a leading slash", "/topic"],
  ["a non-ASCII name", "café"],
  ["an over-long name", "a".repeat(256)],
  ["a ref outside heads and tags", "refs/pull/1/head"],
  ["an empty qualified branch", "refs/heads/"],
  ["HEAD", "HEAD"],
  ["a lone @", "@"],
])("--ref with %s is refused before any Git process", async (_name, ref) => {
  const served = serve(repository());
  const result = await command([remote, "--ref", ref]);
  expect(result.exit).toBe(2);
  expect(result.stderr).toMatch(/^aih-scan: --ref [^\n]*\n$/);
  expect(served.calls).toEqual([]);
  expect(result.requests).toEqual([]);
});

test.each([
  ["no value", [remote, "--ref"]],
  ["an option-like value", [remote, "--ref", "-x"]],
  ["a repeated --ref", [remote, "--ref", "a", "--ref", "b"]],
])("--ref with %s is refused", async (_name, args) => {
  const served = serve(repository());
  const result = await command(args);
  expect(result.exit).toBe(2);
  expect(served.calls).toEqual([]);
});

test("Git runs as an argument array behind the hardening options, never through a shell", async () => {
  const fixture = repository();
  const served = serve(fixture);
  // Shell metacharacters that the repository shape admits reach Git as plain data.
  const tricky = "https://example.invalid/owner/a;b&c|d$(id)'q\"r>s.git";
  const result = await command([tricky, "--ref", "feature"]);
  expect(result.exit).toBe(0);
  const listing = lsRemoteCalls(served);
  expect(listing).toHaveLength(1);
  const args = listing[0] as string[];
  const call = served.argv[served.calls.indexOf(args)] as string[];
  expect(call[0]).toBe(process.execPath);
  expect(call[1]).toMatch(/git-command\.(ts|js)$/);
  expect(args.slice(0, 8)).toEqual([
    "-c",
    "protocol.allow=never",
    "-c",
    "protocol.https.allow=always",
    "-c",
    "http.followRedirects=false",
    "-c",
    "http.sslVerify=true",
  ]);
  expect(args).toContain("credential.helper=");
  expect(args.some((arg) => arg.startsWith("http.proxy=http://127.0.0.1:"))).toBe(true);
  expect(args.slice(args.indexOf("ls-remote"))).toEqual([
    "ls-remote",
    tricky,
    "refs/heads/feature",
    "refs/tags/feature",
    "refs/tags/feature^{}",
  ]);
});

test("a cancellation while resolving exits 130 before any assessment and removes its temporaries", async () => {
  const fixture = repository();
  const cancellation = new AbortController();
  serve(fixture, (tail) => {
    if (tail[0] !== "ls-remote") return undefined;
    cancellation.abort();
    return { code: 1, stdout: "", stderr: "", truncated: true, termination: "abort" };
  });
  const result = await command(["--json", remote], { cancellation: cancellation.signal });
  expect(result.exit).toBe(130);
  expect(result.stderr).toContain("aih-scan: cancelled; no assessment was produced\n");
  expect(result.stdout).toBe("");
  expect(result.requests).toEqual([]);
  expectOwnedTemporaryRemoved();
});

test("a cancellation requested before resolving runs no Git process", async () => {
  const served = serve(repository());
  const cancellation = new AbortController();
  cancellation.abort();
  const result = await command([remote], { cancellation: cancellation.signal });
  expect(result.exit).toBe(130);
  expect(result.stderr).toBe("aih-scan: cancelled; no assessment was produced\n");
  expect(served.calls).toEqual([]);
  expectOwnedTemporaryRemoved();
});

test("--json writes the canonical run result with the commit and reports the resolution on stderr", async () => {
  const fixture = repository();
  serve(fixture);
  const result = await command(["--json", remote]);
  expect(result.exit).toBe(0);
  expect(JSON.parse(result.stdout)).toMatchObject({
    status: "assessment",
    report: { source: { kind: "git", repository: remote, commit: fixture.commits.second } },
  });
  expect(result.stderr).toContain(
    `aih-scan: resolved HEAD to ${fixture.commits.second} (refs/heads/trunk)\n`,
  );
  expectOwnedTemporaryRemoved();
});

test("--json reports the resolved commit on stderr even when the assessment is a diagnostic", async () => {
  const fixture = repository();
  serve(fixture, (tail) =>
    tail[0] === "rev-parse" ? { code: 1, stdout: "", stderr: "", truncated: false } : undefined,
  );
  const result = await command(["--json", remote]);
  expect(result.exit).toBe(2);
  expect(JSON.parse(result.stdout)).toMatchObject({ status: "diagnostic", phase: "capture" });
  expect(result.stderr).toContain(
    `aih-scan: resolved HEAD to ${fixture.commits.second} (refs/heads/trunk)\n`,
  );
  expectOwnedTemporaryRemoved();
});

test("--artifact for a Git source reads back with the assessed commit", async () => {
  const fixture = repository();
  serve(fixture);
  const path = join(directory("aih-scan-git-artifact-"), "git.artifact.json");
  const result = await command(["--artifact", path, remote, "--ref", "feature"]);
  expect(result.exit).toBe(0);
  const read = await readArtifact(new Uint8Array(readFileSync(path)));
  expect(read).toMatchObject({
    status: "read",
    report: { source: { kind: "git", repository: remote, commit: fixture.commits.feature } },
  });
  expectOwnedTemporaryRemoved();
});

test("a cancellation during detection of a Git source keeps finished results and exits 130", async () => {
  const fixture = repository();
  serve(fixture);
  const path = join(directory("aih-scan-git-artifact-"), "cancelled.artifact.json");
  const cancellation = new AbortController();
  // The external detector's process boundary is simulated, as in the local command tests.
  const nativeStat = fsBoundary.statSync(process.execPath);
  const actualStat = fsBoundary.statSync;
  vi.spyOn(process, "platform", "get").mockReturnValue("linux");
  vi.spyOn(process, "arch", "get").mockReturnValue("x64");
  vi.spyOn(fsBoundary, "statSync").mockImplementation(((
    target: Parameters<typeof fsBoundary.statSync>[0],
    ...args: unknown[]
  ) =>
    String(target) === "/usr/bin/bwrap" || String(target) === "/usr/local/bin/uv"
      ? nativeStat
      : Reflect.apply(actualStat, fsBoundary, [target, ...args])) as typeof fsBoundary.statSync);
  vi.spyOn(processBoundary, "processRunner").mockImplementation(async () => {
    cancellation.abort();
    return {
      code: 1,
      stdout: "",
      stderr: "external detector unavailable",
      truncated: true,
      termination: "abort" as const,
    };
  });
  const result = await command(
    [
      "--artifact",
      path,
      "--detector",
      "detector.aih-native",
      "--detector",
      "detector.semgrep",
      remote,
    ],
    { cancellation: cancellation.signal },
  );
  expect(result.exit).toBe(130);
  const assessment = result.seen.result;
  if (assessment?.status !== "assessment") throw new Error("expected an assessment");
  expect(assessment.report.results.map((entry) => [entry.detectorId, entry.outcome])).toEqual([
    ["detector.aih-native", "succeeded"],
    ["detector.semgrep", "cancelled"],
  ]);
  expect(result.stdout.split("\n")).toContain(
    `Commit: ${fixture.commits.second} (refs/heads/trunk)`,
  );
  expect(result.stderr).toContain("aih-scan: cancelled; finished results are preserved\n");
  const read = await readArtifact(new Uint8Array(readFileSync(path)));
  expect(read).toMatchObject({
    status: "read",
    scanId: assessment.scanId,
    report: { source: { kind: "git", commit: fixture.commits.second } },
  });
  expectOwnedTemporaryRemoved();
});

test("the scan usage documents Git sources and --ref", async () => {
  const run = harness();
  expect(await runScanCommand(["--help"], run.io)).toBe(0);
  expect(run.stdout()).toBe(scanUsage);
  for (const documented of [
    "aih-scan scan <https-url | owner/repo> [--ref <name>] [options]",
    "--ref <name>",
    "https://github.com/owner/repo to force Git",
  ])
    expect(scanUsage).toContain(documented);
});

test("Git never inherits an askpass program, so no credential dialog can appear", async () => {
  vi.stubEnv("SSH_ASKPASS", "/inherited/ssh-askpass");
  vi.stubEnv("GIT_ASKPASS", "/inherited/git-askpass");
  const fixture = repository();
  const served = serve(fixture);
  const result = await command([remote]);
  expect(result.exit).toBe(0);
  // Resolution and pinned acquisition both run through the hardened runner.
  expect(lsRemoteCalls(served)).toHaveLength(1);
  expect(served.calls.some((args) => args.includes("cat-file"))).toBe(true);
  for (const env of served.envs) {
    expect(Object.keys(env).filter((key) => key.toUpperCase() === "SSH_ASKPASS")).toEqual([]);
    expect(env.GIT_ASKPASS).toBe("");
    expect(env.GIT_TERMINAL_PROMPT).toBe("0");
  }
});

test("a Git process whose cleanup cannot be confirmed is refused with its own message", async () => {
  const fixture = repository();
  serve(fixture, (tail) =>
    tail[0] === "ls-remote"
      ? {
          code: 1,
          stdout: "",
          stderr: "",
          truncated: true,
          termination: "containment-failure",
        }
      : undefined,
  );
  const result = await command([remote]);
  expect(result.exit).toBe(2);
  expect(result.stderr).toContain("aih-scan: Git process cleanup could not be confirmed\n");
  expect(result.stderr).not.toContain("unavailable");
  expect(result.requests).toEqual([]);
  expectOwnedTemporaryRemoved();
});

/** Makes removal of the resolver's own temporary directory fail. */
function failResolverCleanup(): void {
  const actual = fsBoundary.rmSync;
  vi.spyOn(fsBoundary, "rmSync").mockImplementation(((
    path: Parameters<typeof fsBoundary.rmSync>[0],
    ...args: unknown[]
  ) => {
    if (String(path).includes("aih-scan-git-source-"))
      throw Object.assign(new Error("busy"), { code: "EBUSY" });
    return Reflect.apply(actual, fsBoundary, [path, ...args]);
  }) as typeof fsBoundary.rmSync);
}

test("a resolved source whose temporary directory cannot be removed is refused, not assessed", async () => {
  const fixture = repository();
  serve(fixture);
  failResolverCleanup();
  const result = await command([remote]);
  expect(result.exit).toBe(2);
  expect(result.stderr).toContain(
    "aih-scan: a temporary Git directory could not be removed; no assessment was produced\n",
  );
  expect(result.requests).toEqual([]);
});

test("a cleanup failure never replaces the refusal already being reported", async () => {
  const fixture = repository();
  serve(fixture, (tail) =>
    tail[0] === "ls-remote" ? { code: 1, stdout: "", stderr: "", truncated: false } : undefined,
  );
  failResolverCleanup();
  const result = await command([remote]);
  expect(result.exit).toBe(2);
  expect(result.stderr).toContain(
    "aih-scan: the Git repository is unavailable, requires credentials, or could not be resolved\n",
  );
  expect(result.stderr).not.toContain("could not be removed");
});
