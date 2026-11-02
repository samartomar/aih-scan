import { mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { Socket } from "node:net";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { exitCodes, runScanCommandV1 } from "../../src/cli/commands-v1.js";
import { scan } from "../../src/public/host.js";
import { gitRepository, serveGit } from "../support/git-fixture-v1.js";
import { npmTarball, registryStub, sha256Of } from "../support/npm-tarball-v1.js";
import { remoteMcpGolden } from "../support/scan-v1-corpus.js";
import { type FixtureRoot, fixtureRoot } from "../support/scan-v1-fixture.js";

vi.setConfig({ testTimeout: 30_000 });

let fixture: FixtureRoot;
beforeEach(() => {
  fixture = fixtureRoot("aih-scan-v1-cli-sources-");
});
afterEach(() => {
  vi.restoreAllMocks();
  fixture.dispose();
});

function capture(internals?: Parameters<typeof runScanCommandV1>[1]["internals"]) {
  const out: string[] = [];
  const err: string[] = [];
  return {
    io: {
      stdout: (t: string) => void out.push(t),
      stderr: (t: string) => void err.push(t),
      cwd: fixture.root,
      ...(internals === undefined ? {} : { internals }),
    },
    out: () => out.join(""),
    err: () => err.join(""),
    json: () => JSON.parse(out.join("")),
  };
}

const layout = {
  "skills/a/SKILL.md": "---\nname: a\ndescription: x\n---\n# A\n\nSummarise.\n",
  ".kiro/skills/a/SKILL.md": "---\nname: a\ndescription: x\n---\n# A\n\nSummarise.\n",
  "agents/r.md": "# R\n\nReview.\n",
  ".kiro/steering/p.md": "# P\n",
  "hooks/hooks.json": '{ "hooks": { "Stop": [ { "command": "echo stop" } ] } }\n',
  "plugin.json": '{ "name": "x" }\n',
};

describe("aih-scan scan <target> forms", () => {
  it("scans a folder by discovery and prints per-item results and the roll-up", async () => {
    const root = fixture.folder("repo", layout);
    const run = capture();
    expect(await runScanCommandV1(["repo", "--out", "out"], run.io)).toBe(exitCodes.ok);
    for (const line of [
      "skill skills/a\n",
      "skill .kiro/skills/a\n",
      "agent agents/r.md\n",
      "rule .kiro/steering/p.md\n",
      "hook hooks\n",
      "remaining-files .\n",
    ])
      expect(run.out()).toContain(line);
    expect(run.out()).toMatch(/^Roll-up: CAUTION \(partial\) \(unavailable\); 6 scanned/m);
    expect(run.out()).not.toContain("Fetched");

    const filtered = capture();
    expect(
      await runScanCommandV1([root, "--out", "out2", "--kinds", "skill", "--json"], filtered.io),
    ).toBe(exitCodes.ok);
    const [target] = filtered.json().targets;
    expect(target.results.map((entry: { kind: string }) => entry.kind)).toEqual(["skill", "skill"]);
    expect(target.results[0].scanKey).toBe(target.results[1].scanKey);
    expect(target.rollup).toMatchObject({
      coverage: "partial",
      notSelected: { agent: 1, rule: 1, hook: 1, "remaining-files": 1 },
    });
    // --ref belongs to Git targets only.
    expect(await runScanCommandV1([root, "--out", "out3", "--ref", "main"], capture().io)).toBe(
      exitCodes.input,
    );
  });

  it("gives mcp-url: the same inventory and key as the structured descriptor, without contact", async () => {
    const connect = vi.spyOn(Socket.prototype, "connect");
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const run = capture();
    expect(await runScanCommandV1([remoteMcpGolden.cli, "--out", "out", "--json"], run.io)).toBe(
      exitCodes.ok,
    );
    const [target] = run.json().targets;
    expect(target.results).toMatchObject([
      {
        kind: "mcp",
        scanKey: remoteMcpGolden.scanKey,
        source: { type: "remote", url: remoteMcpGolden.input.url },
      },
    ]);
    const structured = await scan(
      { format: "aih-scan-request/1", origin: "local", source: remoteMcpGolden.input },
      { outDir: fixture.path("out2") },
    );
    expect(structured.results[0]).toMatchObject({ scanKey: remoteMcpGolden.scanKey });
    expect(connect).not.toHaveBeenCalled();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("acquires npm: through the registry and reads npm-file: offline, pinning each", async () => {
    const sentinels = fixture.path("sentinels");
    mkdirSync(sentinels);
    const tarball = npmTarball([
      {
        path: "package/package.json",
        text: JSON.stringify({
          name: "@fixture/mcp",
          version: "2.0.0",
          scripts: { postinstall: `touch ${join(sentinels, "postinstall")}` },
        }),
      },
      { path: "package/index.js", text: "module.exports = {};\n" },
    ]);
    const registry = registryStub({ "@fixture/mcp@2.0.0": { tarball } });
    const run = capture({ fetch: registry.fetch });
    expect(await runScanCommandV1(["npm:@fixture/mcp@2.0.0", "--out", "out"], run.io)).toBe(
      exitCodes.ok,
    );
    expect(run.out()).toContain("Fetched the npm source before scanning");
    expect(run.out()).toContain("mcp .\n");
    writeFileSync(fixture.path("pkg.tgz"), tarball);
    const local = capture();
    expect(await runScanCommandV1(["npm-file:pkg.tgz", "--out", "out2", "--json"], local.io)).toBe(
      exitCodes.ok,
    );
    expect(local.json().targets[0].results[0].source).toEqual({
      type: "npm-file",
      path: fixture.path("pkg.tgz"),
      package: "@fixture/mcp",
      version: "2.0.0",
      tarballSha256: sha256Of(tarball),
    });
    expect(readdirSync(sentinels)).toEqual([]);
    // A range is not an exact version.
    expect(
      await runScanCommandV1(
        ["npm:@fixture/mcp@^2", "--out", "out3"],
        capture({ fetch: registry.fetch }).io,
      ),
    ).toBe(exitCodes.input);
  });

  it("reads owner/repo, https URLs and GitHub item links as Git descriptors", async () => {
    const repo = gitRepository(fixture.path("git"));
    repo.write(layout);
    const commit = repo.commit("first");
    serveGit(repo);
    const whole = capture();
    expect(
      await runScanCommandV1(
        ["owner/fixture", "--ref", "trunk", "--out", "o1", "--json"],
        whole.io,
      ),
    ).toBe(exitCodes.ok);
    const [target] = whole.json().targets;
    expect(target.acquisition).toEqual({ type: "git", fetched: true });
    expect(target.results[0].source).toMatchObject({
      type: "git",
      repo: "https://github.com/owner/fixture.git",
      ref: "refs/heads/trunk",
      commit,
    });
    const link = capture();
    expect(
      await runScanCommandV1(
        ["https://github.com/owner/fixture/tree/trunk/skills/a", "--out", "o2", "--json"],
        link.io,
      ),
    ).toBe(exitCodes.ok);
    expect(link.json().targets[0].results).toMatchObject([
      {
        kind: "skill",
        path: "skills/a",
        scanKey: target.results.find((e: { path: string }) => e.path === "skills/a").scanKey,
      },
    ]);
    const blob = capture();
    expect(
      await runScanCommandV1(
        ["https://github.com/owner/fixture/blob/trunk/agents/r.md", "--out", "o3", "--json"],
        blob.io,
      ),
    ).toBe(exitCodes.ok);
    expect(blob.json().targets[0].results).toMatchObject([{ kind: "agent", path: "agents/r.md" }]);
    // A private clone stays on the folder path: an existing local spelling is never fetched.
    mkdirSync(fixture.path("owner", "fixture"), { recursive: true });
    const local = capture();
    expect(await runScanCommandV1(["owner/fixture", "--out", "o4", "--json"], local.io)).toBe(
      exitCodes.ok,
    );
    expect(local.json().targets[0].acquisition).toEqual({ type: "folder", fetched: false });
  });
});
