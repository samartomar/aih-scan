import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, expect, test } from "vitest";

const checker = resolve(import.meta.dirname, "../../tools/verify-signoffs.mjs");
const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function history() {
  const root = mkdtempSync(join(tmpdir(), "scan-signoffs-"));
  roots.push(root);
  const env = {
    ...process.env,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
  };
  const git = (...args: string[]) =>
    execFileSync("git", args, { cwd: root, env, encoding: "utf8", windowsHide: true }).trim();
  git("init", "--quiet", "--initial-branch=main");
  git("config", "user.name", "Scan fixture");
  git("config", "user.email", "fixture@example.invalid");
  const commit = (message: string) => {
    git("-c", "core.hooksPath=", "commit", "--quiet", "--allow-empty", "-m", message);
    return git("rev-parse", "HEAD");
  };
  const base = commit("Baseline");
  return {
    git,
    commit,
    check: (head = git("rev-parse", "HEAD"), selectedBase = base) =>
      spawnSync(process.execPath, [checker, "--base", selectedBase, "--head", head], {
        cwd: root,
        env,
        encoding: "utf8",
        windowsHide: true,
      }),
  };
}

test("accepts real signoff trailers on every branch commit, including a merge", () => {
  const repo = history();
  const signed = "\n\nSigned-off-by: Scan fixture <fixture@example.invalid>";
  repo.git("checkout", "--quiet", "-b", "topic");
  repo.commit(`Topic${signed}`);
  repo.git("checkout", "--quiet", "main");
  repo.commit(`Main${signed}`);
  repo.git("merge", "--quiet", "--no-ff", "topic", "-m", `Merge${signed}`);
  const result = repo.check();
  expect(result.status, result.stderr).toBe(0);
  expect(result.stdout).toContain("3 commits");
});

test("rejects an unsigned merge even when both parents are signed", () => {
  const repo = history();
  const signed = "\n\nSigned-off-by: Scan fixture <fixture@example.invalid>";
  repo.git("checkout", "--quiet", "-b", "topic");
  repo.commit(`Topic${signed}`);
  repo.git("checkout", "--quiet", "main");
  repo.commit(`Main${signed}`);
  repo.git("merge", "--quiet", "--no-ff", "topic", "-m", "Unsigned merge");
  const head = repo.git("rev-parse", "HEAD");
  const result = repo.check();
  expect(result.status).toBe(1);
  expect(result.stderr).toContain(head);
});

test.each([
  "Unsigned",
  "Subject\n\nSigned-off-by: Scan fixture <fixture@example.invalid>\n\nThis is message text, not a trailer.",
  "Subject\n\nSigned-off-by: missing email",
  "Subject\n\nSigned-off-by:  <fixture@example.invalid>",
])("rejects missing, body-only or malformed signoffs: %s", (message) => {
  const repo = history();
  const unsigned = repo.commit(message);
  repo.commit("Later\n\nSigned-off-by: Scan fixture <fixture@example.invalid>");
  const result = repo.check();
  expect(result.status).toBe(1);
  expect(result.stderr).toContain(unsigned);
});

test("fails closed on invalid or missing commit history", () => {
  const repo = history();
  repo.commit("Signed\n\nSigned-off-by: Scan fixture <fixture@example.invalid>");
  expect(repo.check("a".repeat(40)).status).toBe(1);
  expect(repo.check("--all").status).toBe(1);
});
