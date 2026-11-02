import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { classifyScanTarget, parseGitRef } from "../../src/cli/git-source.js";
import { acquireGit } from "../../src/host/acquire-git.js";
import { type GitFixture, gitRepository, remoteUrl, serveGit } from "../support/git-fixture-v1.js";

/**
 * How a Git source's ref resolves, against a local fixture repository answered at the process
 * boundary (no network): the default HEAD, short names that are a branch or a tag, qualified
 * refs, full commits, and the refusals for ambiguous, unknown and malformed refs.
 */
let root: string;
let repo: GitFixture;
const commits: Record<string, string> = {};
beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "aih-scan-git-refs-"));
  repo = gitRepository(join(root, "repo"));
  repo.write({ "skills/a/SKILL.md": "# A\n" });
  commits.first = repo.commit("first");
  repo.git(["tag", "v1", commits.first]);
  repo.write({ "skills/a/notes.md": "two\n" });
  commits.second = repo.commit("second");
  repo.git(["branch", "both", commits.first]);
  repo.git(["tag", "both", commits.second]);
  return () => rmSync(root, { recursive: true, force: true });
});
afterEach(() => vi.restoreAllMocks());

const acquire = (ref?: string) =>
  acquireGit(
    { repo: remoteUrl, ...(ref === undefined ? {} : { ref }) },
    new AbortController().signal,
  );
const commitOf = (result: Awaited<ReturnType<typeof acquire>>) =>
  result.status === "ok" ? result.commit : result;

describe("Git ref resolution", () => {
  it("uses the default HEAD, short and qualified branch and tag names and full commits", async () => {
    serveGit(repo);
    expect(commitOf(await acquire())).toBe(commits.second);
    expect(commitOf(await acquire("trunk"))).toBe(commits.second);
    expect(commitOf(await acquire("refs/heads/trunk"))).toBe(commits.second);
    expect(commitOf(await acquire("v1"))).toBe(commits.first);
    expect(commitOf(await acquire("refs/tags/v1"))).toBe(commits.first);
    expect(commitOf(await acquire("refs/heads/both"))).toBe(commits.first);
    expect(commitOf(await acquire("refs/tags/both"))).toBe(commits.second);
    expect(commitOf(await acquire(commits.first))).toBe(commits.first);
  });

  it("refuses a name that is both a branch and a tag, an unknown name and malformed refs", async () => {
    serveGit(repo);
    expect(await acquire("both")).toMatchObject({
      status: "refused",
      reason: "source-unavailable",
    });
    expect(await acquire("missing")).toMatchObject({ status: "refused" });
    for (const ref of ["HEAD", "-x", "a..b", "refs/notes/x", "a b", "x.lock"])
      expect(await acquire(ref), ref).toMatchObject({ status: "invalid", reason: "ref" });
  });

  it("parses refs before any Git process and classifies targets", () => {
    expect(parseGitRef(undefined)).toEqual({ ok: true, request: { kind: "head" } });
    expect(parseGitRef("HEAD")).toMatchObject({ ok: false });
    expect(parseGitRef("refs/tags/v1")).toEqual({
      ok: true,
      request: { kind: "tag", name: "refs/tags/v1" },
    });
    expect(classifyScanTarget("owner/repo", root)).toEqual({
      kind: "git",
      repository: "https://github.com/owner/repo.git",
    });
    expect(classifyScanTarget("https://github.com/owner/repo", root)).toMatchObject({
      kind: "git",
    });
    for (const target of [
      "git@github.com:owner/repo.git",
      "ssh://github.com/owner/repo",
      "http://github.com/owner/repo",
      "https://user:pass@github.com/owner/repo",
      "https://github.com/owner/repo?x=1",
    ])
      expect(() => classifyScanTarget(target, root), target).toThrow();
  });
});
