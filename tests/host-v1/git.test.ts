import { mkdirSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { scan } from "../../src/public/host.js";
import { readSummary } from "../../src/public/read.js";
import { type GitFixture, gitRepository, remoteUrl, serveGit } from "../support/git-fixture-v1.js";
import { type FixtureRoot, fixtureRoot } from "../support/scan-v1-fixture.js";

vi.setConfig({ testTimeout: 30_000 });

let fixture: FixtureRoot;
let repo: GitFixture;
let sentinels: string;
let commits: { first: string; second: string; dangling: string };

const skillMd = "---\nname: alpha\ndescription: fixture\n---\n# Alpha\n\nSummarise text.\n";

beforeEach(() => {
  fixture = fixtureRoot("aih-scan-v1-git-");
  sentinels = fixture.path("sentinels");
  mkdirSync(sentinels);
  repo = gitRepository(fixture.path("repo"));
  repo.write(
    {
      "skills/alpha/SKILL.md": skillMd,
      "skills/alpha/scripts/run.sh": `#!/bin/sh\ntouch ${join(sentinels, "script")}\n`,
      "agents/reviewer.md": "# Reviewer\n\nReview the diff.\n",
      "hooks/hooks.json": JSON.stringify({
        hooks: {
          Stop: [{ hooks: [{ type: "command", command: `touch ${join(sentinels, "hook")}` }] }],
        },
      }),
      "README.md": "# Fixture\n",
    },
    ["skills/alpha/scripts/run.sh"],
  );
  const first = repo.commit("first");
  repo.write({ "agents/reviewer.md": "# Reviewer\n\nReview carefully.\n" });
  const second = repo.commit("second");
  // A commit object that exists but no branch or tag reaches.
  repo.git(["checkout", "--quiet", "-b", "scratch"]);
  repo.write({ "README.md": "# Unreachable\n" });
  const dangling = repo.commit("dangling");
  repo.git(["checkout", "--quiet", "trunk"]);
  repo.git(["branch", "--quiet", "-D", "scratch"]);
  commits = { first, second, dangling };
});
afterEach(() => {
  vi.restoreAllMocks();
  fixture.dispose();
});

const request = (source: Record<string, unknown>, extra: Record<string, unknown> = {}) => ({
  format: "aih-scan-request/1",
  origin: "published",
  source: { type: "git", repo: remoteUrl, ...source },
  ...extra,
});
const summaryOf = (path: string) => {
  const read = readSummary(new Uint8Array(readFileSync(path)));
  if (read.status !== "ok") throw new Error(JSON.stringify(read));
  return read.summary;
};

describe("public Git repositories", () => {
  it("resolves a ref, discovers items with Git modes and pins commit and path outside the summary", async () => {
    const served = serveGit(repo);
    const result = await scan(request({ ref: "trunk" }), { outDir: fixture.path("out") });
    expect(result.status).toBe("ok");
    expect(result.acquisition).toEqual({ type: "git", fetched: true });
    const found = Object.fromEntries(
      result.results.map((entry) => [`${entry.kind}:${entry.path}`, entry]),
    );
    expect(Object.keys(found).sort()).toEqual([
      "agent:agents/reviewer.md",
      "hook:hooks",
      "remaining-files:.",
      "skill:skills/alpha",
    ]);
    const alpha = found["skill:skills/alpha"];
    if (alpha?.status !== "ok") throw new Error("expected a scan");
    expect(alpha.source).toEqual({
      type: "git",
      repo: remoteUrl,
      ref: "refs/heads/trunk",
      commit: commits.second,
      item: "skills/alpha",
    });
    expect(summaryOf(alpha.summaryPath).files.map((file) => [file.path, file.mode])).toEqual([
      ["SKILL.md", "100644"],
      ["scripts/run.sh", "100755"],
    ]);
    for (const entry of result.results)
      if (entry.status === "ok") {
        const text = readFileSync(entry.summaryPath, "utf8");
        expect(text).not.toContain("example.invalid");
        expect(text).not.toContain(commits.second);
      }
    // Locked-down Git: HTTPS only, no redirects, no hooks, no credential helper, no prompts.
    for (const args of served.calls) {
      expect(args).toEqual(
        expect.arrayContaining([
          "protocol.allow=never",
          "protocol.https.allow=always",
          "http.followRedirects=false",
          "http.sslVerify=true",
        ]),
      );
      expect(args.some((arg) => arg.startsWith("core.hooksPath="))).toBe(true);
    }
    for (const args of served.calls.filter((call) => call.includes("fetch")))
      expect(args).toContain("credential.helper=");
    for (const env of served.envs) {
      expect(env).toMatchObject({
        GIT_ASKPASS: "",
        GIT_TERMINAL_PROMPT: "0",
        GIT_CONFIG_NOSYSTEM: "1",
      });
      expect(Object.keys(env).filter((key) => key.startsWith("GIT_CONFIG_KEY"))).toEqual([]);
    }
    expect(readdirSync(sentinels)).toEqual([]);
  });

  it("scans one item named by path and kind with the key it has as a folder, and keeps unchanged keys across commits", async () => {
    serveGit(repo);
    const item = await scan(request({ ref: commits.first, path: "skills/alpha", kind: "skill" }), {
      outDir: fixture.path("out1"),
    });
    expect(item.status).toBe("ok");
    expect(item.results).toHaveLength(1);
    const entry = item.results[0];
    if (entry?.status !== "ok") throw new Error(JSON.stringify(item));
    expect(entry).toMatchObject({
      kind: "skill",
      path: "skills/alpha",
      source: { commit: commits.first, item: "skills/alpha" },
    });
    const folder = fixture.folder(
      "copy",
      {
        "SKILL.md": skillMd,
        "scripts/run.sh": `#!/bin/sh\ntouch ${join(sentinels, "script")}\n`,
      },
      ["scripts/run.sh"],
    );
    const handed = await scan(
      { format: "aih-scan-request/1", origin: "local", items: [{ path: folder }] },
      { outDir: fixture.path("out2") },
    );
    expect(handed.results[0]).toMatchObject({ scanKey: entry.scanKey });
    // The same skill at a later commit keeps its key; the changed agent does not.
    const later = await scan(request({ ref: "trunk" }), { outDir: fixture.path("out3") });
    const earlier = await scan(request({ ref: commits.first }), { outDir: fixture.path("out4") });
    const key = (result: typeof later, path: string) =>
      result.results.find((candidate) => candidate.path === path && candidate.status === "ok");
    expect(key(later, "skills/alpha")).toMatchObject({ scanKey: entry.scanKey });
    expect((key(later, "agents/reviewer.md") as { scanKey: string }).scanKey).not.toBe(
      (key(earlier, "agents/reviewer.md") as { scanKey: string }).scanKey,
    );
    // A link to one file discovers that file's layout.
    const file = await scan(request({ ref: "trunk", path: "agents/reviewer.md" }), {
      outDir: fixture.path("out5"),
    });
    expect(file.results.map((result) => `${result.kind}:${result.path}`)).toEqual([
      "agent:agents/reviewer.md",
    ]);
  });

  it("agrees with the folder route for the same checkout and records a local clone's commit, never its remote", async () => {
    serveGit(repo);
    repo.git(["remote", "add", "origin", "https://token@example.invalid/private.git"]);
    const fetched = await scan(request({ ref: "trunk" }), { outDir: fixture.path("g") });
    const local = await scan(
      {
        format: "aih-scan-request/1",
        origin: "local",
        source: { type: "folder", path: repo.root },
      },
      { outDir: fixture.path("f") },
    );
    const keys = (result: typeof local) =>
      Object.fromEntries(
        result.results.map((entry) => [entry.path, entry.status === "ok" ? entry.scanKey : null]),
      );
    expect(keys(local)).toEqual(keys(fetched));
    expect(local.results[0]?.source).toEqual({
      type: "folder",
      path: repo.root,
      item: local.results[0]?.path,
      commit: commits.second,
    });
    expect(JSON.stringify(local)).not.toContain("private.git");
    // A Git source naming a kind must name the item's path.
    const kindOnly = await scan(request({ ref: "trunk", kind: "skill" }), {
      outDir: fixture.path("k"),
    });
    expect(kindOnly.status).toBe("invalid");
  });

  it("refuses unreachable commits, links, submodules, missing paths and unavailable repositories without echoing the URL", async () => {
    serveGit(repo);
    const unreachable = await scan(request({ ref: commits.dangling }), {
      outDir: fixture.path("o1"),
    });
    expect(unreachable).toMatchObject({ status: "refused", reason: "commit-unreachable" });

    const missing = await scan(request({ ref: "trunk", path: "nope" }), {
      outDir: fixture.path("o2"),
    });
    expect(missing).toMatchObject({ status: "refused", reason: "path-not-found" });

    const invalidRef = await scan(request({ ref: "bad..ref" }), { outDir: fixture.path("o3") });
    expect(invalidRef.status).toBe("invalid");

    const oid = repo.git(["hash-object", "-w", "--stdin"], "../../etc/passwd").trim();
    repo.git(["update-index", "--add", "--cacheinfo", `120000,${oid},skills/alpha/link`]);
    repo.git(["update-index", "--add", "--cacheinfo", `160000,${commits.first},vendor/sub`]);
    repo.git([
      "-c",
      "user.name=Scan fixture",
      "-c",
      "user.email=scan-fixture@example.invalid",
      "commit",
      "--quiet",
      "-m",
      "links",
    ]);
    const link = await scan(request({ ref: "trunk", path: "skills" }), {
      outDir: fixture.path("o4"),
    });
    expect(link).toMatchObject({ status: "refused", reason: "link" });
    const submodule = await scan(request({ ref: "trunk", path: "vendor" }), {
      outDir: fixture.path("o5"),
    });
    expect(submodule).toMatchObject({ status: "refused", reason: "special-file" });
    // Nothing is written when acquisition is refused.
    expect(readdirSync(fixture.root).filter((name) => name.startsWith("o"))).toEqual([]);

    vi.restoreAllMocks();
    serveGit(repo, (tail) => tail[0] === "ls-remote");
    const down = await scan(request({ ref: "trunk" }), { outDir: fixture.path("o6") });
    expect(down).toMatchObject({ status: "refused", reason: "source-unavailable" });
    expect(JSON.stringify(down)).not.toContain("example.invalid");
  });
});
