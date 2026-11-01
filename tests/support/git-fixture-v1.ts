import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { expect, vi } from "vitest";
import * as processBoundary from "../../src/cli/process-runner.js";

/**
 * Git sources against a disposable local repository: Scan's hardened runner is intercepted at
 * the process boundary and each Git subcommand is answered by real Git in the fixture, with the
 * remote URL replaced by the fixture path. Transport (init/fetch) is answered as empty because
 * the fixture already holds the objects. No network is used.
 */
export const remoteUrl = "https://example.invalid/owner/fixture.git";

const gitEnv = {
  ...process.env,
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
};

export interface GitFixture {
  readonly root: string;
  git(args: string[], input?: string): string;
  write(files: Readonly<Record<string, string>>, executable?: readonly string[]): void;
  commit(message: string): string;
}

export function gitRepository(root: string): GitFixture {
  mkdirSync(root, { recursive: true });
  const git = (args: string[], input?: string) =>
    execFileSync("git", args, { cwd: root, env: gitEnv, input, windowsHide: true }).toString(
      "utf8",
    );
  git(["init", "--quiet", "--initial-branch=trunk"]);
  git(["config", "core.autocrlf", "false"]);
  return {
    root,
    git,
    write(files, executable = []) {
      for (const [path, text] of Object.entries(files)) {
        const target = join(root, ...path.split("/"));
        mkdirSync(dirname(target), { recursive: true });
        writeFileSync(target, text);
        chmodSync(target, executable.includes(path) ? 0o755 : 0o644);
      }
    },
    commit(message) {
      git(["add", "--all"]);
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
    },
  };
}

export interface Served {
  /** Git arguments of every runner call, in order. */
  readonly calls: string[][];
  readonly envs: Readonly<Record<string, string>>[];
}

const operations = ["init", "fetch", "ls-remote", "rev-parse", "rev-list", "ls-tree", "cat-file"];

/** Answers the hardened runner from the fixture; `fail` makes chosen subcommands fail. */
export function serveGit(
  fixture: GitFixture,
  fail: (tail: string[]) => boolean = () => false,
): Served {
  const served: Served = { calls: [], envs: [] };
  vi.spyOn(processBoundary, "spawnBoundedV1").mockImplementation(async (argv, options) => {
    expect(options.containProcessTree).toBe(true);
    const args = JSON.parse(argv[2] as string) as string[];
    served.calls.push(args);
    served.envs.push(options.env);
    const tail = args.slice(args.findIndex((arg) => operations.includes(arg)));
    if (fail(tail)) return { code: 1, stdout: "", stderr: "", truncated: false };
    const bytes =
      tail[0] === "init" || tail[0] === "fetch"
        ? Buffer.alloc(0)
        : execFileSync(
            "git",
            tail.map((arg) => (arg.startsWith("https://") ? fixture.root : arg)),
            { cwd: fixture.root, env: gitEnv, windowsHide: true, maxBuffer: 256 * 1024 * 1024 },
          );
    return {
      code: 0,
      stdout: JSON.stringify({ bytesBase64: bytes.toString("base64") }),
      stderr: "",
      truncated: false,
    };
  });
  return served;
}
