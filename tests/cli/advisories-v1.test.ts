import { readFileSync, writeFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { type AdvisoriesIo, runAdvisoriesCommand } from "../../src/cli/advisories-v1.js";
import { exitCodes } from "../../src/cli/commands-v1.js";
import { checkAdvisories } from "../../src/public/read.js";
import { gitRepository, serveGit } from "../support/git-fixture-v1.js";
import { npmTarball, registryStub } from "../support/npm-tarball-v1.js";
import { ghsa, type OsvService, osvService } from "../support/osv-service-v1.js";
import { corpusCase } from "../support/scan-v1-corpus.js";
import { type FixtureRoot, fixtureRoot } from "../support/scan-v1-fixture.js";

vi.setConfig({ testTimeout: 30_000 });

const now = () => new Date("2026-11-01T09:00:00Z");
const realFetch = globalThis.fetch.bind(globalThis);
let fixture: FixtureRoot;
let service: OsvService;
beforeEach(async () => {
  fixture = fixtureRoot("aih-scan-v1-advisories-");
  service = await osvService({
    affected: { "npm/x@1.0.0": ["GHSA-aaaa-bbbb-cccc"] },
    records: [ghsa("GHSA-aaaa-bbbb-cccc", "x", "1.0.1")],
  });
  // No live service: only the controlled advisory service (and fixture stubs) answer.
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    throw new Error(`unexpected global fetch ${String(input)}`);
  });
});
afterEach(async () => {
  vi.restoreAllMocks();
  await service.close();
  fixture.dispose();
});

const advisoryFetch = (url: string, init: RequestInit) => {
  if (!url.startsWith(service.endpoint)) throw new Error(`unexpected advisory URL ${url}`);
  return realFetch(url, init);
};

function capture(extra: Partial<AdvisoriesIo> = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const io: AdvisoriesIo = {
    stdout: (t) => void out.push(t),
    stderr: (t) => void err.push(t),
    cwd: fixture.root,
    advisories: { endpoint: service.endpoint, fetch: advisoryFetch, now },
    ...extra,
  };
  return {
    io,
    out: () => out.join(""),
    err: () => err.join(""),
    json: () => JSON.parse(out.join("")),
  };
}

const manifest = JSON.stringify({
  name: "fixture",
  dependencies: { ws: "8.18.0", x: "1.0.0", "@acme/internal-tool": "1.0.0", ranged: "^2.0.0" },
});
const content = {
  "skills/a/SKILL.md": "---\nname: a\ndescription: x\n---\n# A\n",
  "skills/a/scripts/package.json": manifest,
  ".mcp.json": JSON.stringify({
    mcpServers: { s: { command: "npx", args: ["-y", "mcp-thing@0.3.1"] } },
  }),
};
const bodies = () =>
  service.requests.filter((r) => r.path === "/v1/querybatch").map((r) => JSON.parse(r.body));

describe("aih-scan advisories", () => {
  it("sends nothing for a folder unless --include-private, then only exact public versions", async () => {
    fixture.folder("repo", content);
    const quiet = capture();
    expect(await runAdvisoriesCommand(["repo"], quiet.io)).toBe(exitCodes.ok);
    expect(quiet.out()).toContain("treated as private: nothing was sent. 5 dependencies found");
    expect(service.requests).toEqual([]);
    const listed = capture();
    expect(await runAdvisoriesCommand(["repo", "--json"], listed.io)).toBe(exitCodes.ok);
    expect(listed.json()).toMatchObject({
      status: "ok",
      source: "folder",
      private: true,
      checked: false,
    });
    expect(listed.json().dependencies).toHaveLength(5);
    expect(service.requests).toEqual([]);

    const run = capture();
    expect(
      await runAdvisoriesCommand(
        ["repo", "--include-private", "--internal-scope", "@acme", "--json"],
        run.io,
      ),
    ).toBe(exitCodes.ok);
    const result = run.json();
    expect(result).toMatchObject({
      status: "ok",
      private: true,
      checked: true,
      checkedAt: "2026-11-01T09:00:00Z",
    });
    expect(
      result.results.map((r: { name: string; state: string; file: string }) => [
        r.name,
        r.state,
        r.file,
      ]),
    ).toEqual([
      ["mcp-thing", "none-known", ".mcp.json"],
      ["ws", "none-known", "skills/a/scripts/package.json"],
      ["x", "vulnerable", "skills/a/scripts/package.json"],
      ["@acme/internal-tool", "not-checked", "skills/a/scripts/package.json"],
      ["ranged", "not-checked", "skills/a/scripts/package.json"],
    ]);
    expect(bodies()).toEqual([
      {
        queries: [
          { package: { name: "mcp-thing", ecosystem: "npm" }, version: "0.3.1" },
          { package: { name: "ws", ecosystem: "npm" }, version: "8.18.0" },
          { package: { name: "x", ecosystem: "npm" }, version: "1.0.0" },
        ],
      },
    ]);
    expect(service.received()).not.toMatch(/acme|internal-tool|ranged|\^2/);

    // CLI/library parity over the same dependencies, service and clock.
    const library = await checkAdvisories(
      result.results.map(({ ecosystem, name, version, file }: Record<string, string>) => ({
        ecosystem,
        name,
        version,
        file,
      })),
      { internalScopes: ["@acme"], endpoint: service.endpoint, fetch: advisoryFetch, now },
    );
    expect({ status: result.status, checkedAt: result.checkedAt, results: result.results }).toEqual(
      library,
    );
  });

  it("prints advisories as text with their identity, severity, fix and summary", async () => {
    fixture.folder("repo", content);
    const run = capture();
    expect(await runAdvisoriesCommand(["repo", "--include-private"], run.io)).toBe(exitCodes.ok);
    expect(run.out()).toContain("live, unsigned, separate from scan scores");
    expect(run.out()).toContain("VULNERABLE   npm x@1.0.0 (skills/a/scripts/package.json)\n");
    expect(run.out()).toContain(
      "  GHSA-aaaa-bbbb-cccc HIGH fixed in 1.0.1: Advisory GHSA-aaaa-bbbb-cccc for x\n",
    );
    expect(run.out()).toContain("none known   npm ws@8.18.0");
    expect(run.out()).toContain(
      "not checked  npm ranged@^2.0.0 (skills/a/scripts/package.json): no exact version\n",
    );
  });

  it("checks a public npm package by default and honours --private", async () => {
    const tarball = npmTarball([
      {
        path: "package/package.json",
        text: JSON.stringify({
          name: "@fixture/mcp",
          version: "2.0.0",
          dependencies: { x: "1.0.0" },
        }),
      },
    ]);
    const registry = registryStub({ "@fixture/mcp@2.0.0": { tarball } });
    const forced = capture({ internals: { fetch: registry.fetch } });
    expect(
      await runAdvisoriesCommand(["npm:@fixture/mcp@2.0.0", "--private", "--json"], forced.io),
    ).toBe(exitCodes.ok);
    expect(forced.json()).toMatchObject({ private: true, checked: false });
    expect(service.requests).toEqual([]);
    const run = capture({ internals: { fetch: registry.fetch } });
    expect(await runAdvisoriesCommand(["npm:@fixture/mcp@2.0.0", "--json"], run.io)).toBe(
      exitCodes.ok,
    );
    expect(run.json()).toMatchObject({ source: "npm", private: false, checked: true });
    expect(run.json().results).toEqual([
      expect.objectContaining({ name: "x", state: "vulnerable", file: "package.json" }),
    ]);
    // A downloaded tarball is private by default.
    writeFileSync(fixture.path("pkg.tgz"), tarball);
    const file = capture();
    expect(await runAdvisoriesCommand(["npm-file:pkg.tgz", "--json"], file.io)).toBe(exitCodes.ok);
    expect(file.json()).toMatchObject({ source: "npm-file", private: true, checked: false });
    expect(bodies()).toHaveLength(1);
  });

  it("checks a public repository by default", async () => {
    const repo = gitRepository(fixture.path("git"));
    repo.write(content);
    repo.commit("first");
    serveGit(repo);
    const run = capture();
    expect(await runAdvisoriesCommand(["owner/fixture", "--ref", "trunk", "--json"], run.io)).toBe(
      exitCodes.ok,
    );
    expect(run.json()).toMatchObject({ source: "git", private: false, checked: true });
    expect(run.json().results).toHaveLength(5);
    const forced = capture();
    expect(
      await runAdvisoriesCommand(["owner/fixture", "--ref", "trunk", "--private"], forced.io),
    ).toBe(exitCodes.ok);
    expect(bodies()).toHaveLength(1);
  });

  it("treats a summary as private and checks its listed dependencies with --include-private", async () => {
    const corpus = corpusCase("clean");
    const summary = JSON.parse(new TextDecoder().decode(corpus.summary));
    const file = summary.files[0].path;
    summary.dependencies = [
      { ecosystem: "npm", name: "x", version: "1.0.0", file },
      { ecosystem: "npm", name: "@acme/secret", version: "1.0.0", file },
    ];
    const bytes = `${JSON.stringify(summary, null, 2)}\n`;
    const summaryPath = fixture.path("summary.json");
    writeFileSync(summaryPath, bytes);
    const quiet = capture();
    expect(await runAdvisoriesCommand(["summary.json", "--json"], quiet.io)).toBe(exitCodes.ok);
    expect(quiet.json()).toMatchObject({ source: "summary", private: true, checked: false });
    expect(quiet.json().dependencies).toEqual(summary.dependencies);
    expect(service.requests).toEqual([]);
    const run = capture();
    expect(
      await runAdvisoriesCommand(
        ["summary.json", "--include-private", "--internal-scope", "@acme", "--json"],
        run.io,
      ),
    ).toBe(exitCodes.ok);
    expect(run.json().results.map((r: { state: string }) => r.state)).toEqual([
      "vulnerable",
      "not-checked",
    ]);
    expect(service.received()).not.toContain("acme");
    // The summary bytes are untouched: advisory output never changes a scan.
    expect(readFileSync(summaryPath, "utf8")).toBe(bytes);
  });

  it("reports every entry not checked when the service is unreachable", async () => {
    fixture.folder("repo", content);
    await service.close();
    const run = capture();
    expect(await runAdvisoriesCommand(["repo", "--include-private", "--json"], run.io)).toBe(
      exitCodes.ok,
    );
    expect(run.json().status).toBe("ok");
    expect(run.json().results.map((r: { state: string }) => r.state)).toEqual(
      Array(5).fill("not-checked"),
    );
    expect(run.err()).toContain("could not be reached");
    service = await osvService();
  });

  it.each([
    [["repo", "--private", "--include-private"]],
    [["mcp-url:https://mcp.example.com/sse", "--include-private"]],
    [["repo", "--internal-scope", "acme"]],
    [[]],
    [["a", "b"]],
    [["missing-folder", "--include-private"]],
  ])("is invalid for %j (exit 2) and sends nothing", async (args) => {
    fixture.folder("repo", content);
    const run = capture();
    expect(await runAdvisoriesCommand(args, run.io)).toBe(exitCodes.input);
    expect(service.requests).toEqual([]);
  });
});
