import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { Socket } from "node:net";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { scanWith } from "../../src/host/scan.js";
import { scan } from "../../src/public/host.js";
import { readSummary } from "../../src/public/read.js";
import { npmTarball, registryStub, sha256Of, type TarEntry } from "../support/npm-tarball-v1.js";
import { type FixtureRoot, fixtureRoot } from "../support/scan-v1-fixture.js";

let fixture: FixtureRoot;
let sentinels: string;
beforeEach(() => {
  fixture = fixtureRoot("aih-scan-v1-npm-");
  sentinels = fixture.path("sentinels");
  mkdirSync(sentinels);
});
afterEach(() => {
  vi.restoreAllMocks();
  fixture.dispose();
});

const touch = (name: string) => `touch ${join(sentinels, name)}`;
const packageEntries = (name = "@fixture/mcp", version = "1.2.3"): TarEntry[] => [
  { path: "package", type: "5", mode: 0o755 },
  {
    path: "package/package.json",
    text: JSON.stringify({
      name,
      version,
      bin: { server: "server.js" },
      scripts: {
        preinstall: touch("preinstall"),
        install: touch("install"),
        postinstall: touch("postinstall"),
        prepare: touch("prepare"),
      },
      dependencies: { ws: "8.18.0" },
    }),
  },
  {
    path: "package/server.js",
    text: `#!/usr/bin/env node\nrequire("node:fs").writeFileSync(${JSON.stringify(join(sentinels, "server"))}, "");\n`,
    mode: 0o755,
  },
  { path: "package/README.md", text: "# MCP fixture\n" },
];
const request = (source: unknown, extra: Record<string, unknown> = {}) => ({
  format: "aih-scan-request/1",
  origin: "local",
  source,
  ...extra,
});

describe("npm MCP packages", () => {
  it("acquires one exact public version through the registry, pins it and never runs it", async () => {
    const tarball = npmTarball(packageEntries());
    const registry = registryStub({ "@fixture/mcp@1.2.3": { tarball } });
    const connect = vi.spyOn(Socket.prototype, "connect");
    const result = await scanWith(
      request({ type: "npm", package: "@fixture/mcp", version: "1.2.3", kind: "mcp" }),
      { outDir: fixture.path("out") },
      { fetch: registry.fetch },
    );
    expect(result.status).toBe("ok");
    expect(result.acquisition).toEqual({ type: "npm", fetched: true });
    const entry = result.results[0];
    if (entry?.status !== "ok") throw new Error(JSON.stringify(result));
    expect(result.results).toHaveLength(1);
    expect(entry).toMatchObject({
      kind: "mcp",
      path: ".",
      source: {
        type: "npm",
        package: "@fixture/mcp",
        version: "1.2.3",
        tarballSha256: sha256Of(tarball),
      },
    });
    const read = readSummary(new Uint8Array(readFileSync(entry.summaryPath)));
    if (read.status !== "ok") throw new Error(JSON.stringify(read));
    expect(read.summary.files.map((file) => [file.path, file.mode])).toEqual([
      ["README.md", "100644"],
      ["package.json", "100644"],
      ["server.js", "100755"],
    ]);
    expect(read.summary.dependencies).toEqual([
      { ecosystem: "npm", name: "ws", version: "8.18.0", file: "package.json" },
    ]);
    // Only the registry metadata and its tarball were requested, without credentials or redirects.
    expect(registry.calls.map((call) => call.url)).toEqual([
      "https://registry.npmjs.org/@fixture%2fmcp/1.2.3",
      "https://registry.example.invalid/%40fixture%2Fmcp-1.2.3.tgz",
    ]);
    for (const call of registry.calls)
      expect(call.init).toMatchObject({ redirect: "error", credentials: "omit" });
    expect(connect).not.toHaveBeenCalled();
    expect(readdirSync(sentinels)).toEqual([]);
    // The pin is outside the summary.
    expect(readFileSync(entry.summaryPath, "utf8")).not.toContain("@fixture/mcp");
  });

  it("reads a downloaded npm-file tarball offline into the same key and records its own pin", async () => {
    const tarball = npmTarball(packageEntries("@acme/internal", "1.4.0"));
    const path = fixture.path("server-internal-1.4.0.tgz");
    writeFileSync(path, tarball);
    const registry = registryStub({ "@acme/internal@1.4.0": { tarball } });
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const local = await scan(request({ type: "npm-file", path, kind: "mcp" }), {
      outDir: fixture.path("out1"),
    });
    expect(local.acquisition).toEqual({ type: "npm-file", fetched: false });
    expect(fetchSpy).not.toHaveBeenCalled();
    const fetched = await scanWith(
      request({ type: "npm", package: "@acme/internal", version: "1.4.0" }),
      { outDir: fixture.path("out2") },
      { fetch: registry.fetch },
    );
    const [a, b] = [local.results[0], fetched.results[0]];
    if (a?.status !== "ok" || b?.status !== "ok") throw new Error("expected scans");
    expect(a.scanKey).toBe(b.scanKey);
    expect(a.source).toEqual({
      type: "npm-file",
      path,
      package: "@acme/internal",
      version: "1.4.0",
      tarballSha256: sha256Of(tarball),
    });
    expect(readdirSync(sentinels)).toEqual([]);
  });

  it("leaves .git metadata out of an archive, as a folder source does", async () => {
    const plain = fixture.path("plain.tgz");
    writeFileSync(plain, npmTarball(packageEntries()));
    const withGit = fixture.path("with-git.tgz");
    writeFileSync(
      withGit,
      npmTarball([
        ...packageEntries(),
        { path: "package/.git/config", text: "[core]\n" },
        { path: "package/lib/.git/HEAD", text: "ref: refs/heads/main\n" },
      ]),
    );
    const a = await scan(request({ type: "npm-file", path: plain }), {
      outDir: fixture.path("out-plain"),
    });
    const b = await scan(request({ type: "npm-file", path: withGit }), {
      outDir: fixture.path("out-with-git"),
    });
    const [first, second] = [a.results[0], b.results[0]];
    if (first?.status !== "ok" || second?.status !== "ok") throw new Error("expected scans");
    expect(second.scanKey).toBe(first.scanKey);
    expect(readFileSync(second.summaryPath, "utf8")).not.toContain(".git/");
  });

  it("refuses hostile archives and failed acquisition before anything is scanned", async () => {
    const base = packageEntries();
    const cases: [string, TarEntry[], string][] = [
      ["symlink", [...base, { path: "package/link", type: "2", link: "../../etc/passwd" }], "link"],
      [
        "hard link",
        [...base, { path: "package/hard", type: "1", link: "package/README.md" }],
        "hard-link",
      ],
      ["device", [...base, { path: "package/dev", type: "3" }], "special-file"],
      ["traversal", [...base, { path: "package/../escape.txt", text: "x" }], "invalid-name"],
      ["absolute", [...base, { path: "/etc/escape.txt", text: "x" }], "escaping-path"],
      ["second root", [...base, { path: "other/file.txt", text: "x" }], "escaping-path"],
      ["depth", [...base, { path: `package/${"d/".repeat(65)}f.txt`, text: "x" }], "depth"],
      ["no package.json", [{ path: "package/README.md", text: "x" }], "not-a-package"],
    ];
    for (const [name, entries, reason] of cases) {
      const path = fixture.path(`${name.replace(" ", "-")}.tgz`);
      writeFileSync(path, npmTarball(entries));
      const result = await scan(request({ type: "npm-file", path }), {
        outDir: fixture.path(`out-${name.replace(" ", "-")}`),
      });
      expect([name, result.status, "reason" in result ? result.reason : undefined]).toEqual([
        name,
        "refused",
        reason,
      ]);
      expect(result.results).toEqual([]);
    }
    // Over the one-file limit (50 MB): refused with the limit's name.
    const big = fixture.path("big.tgz");
    writeFileSync(
      big,
      npmTarball([
        ...base,
        { path: "package/blob.bin", text: new Uint8Array(50 * 1024 * 1024 + 1) },
      ]),
    );
    const oversize = await scan(request({ type: "npm-file", path: big }), {
      outDir: fixture.path("out-big"),
    });
    expect(oversize).toMatchObject({ status: "refused", reason: "file-size" });

    const tarball = npmTarball(base);
    const fetchCases: [string, Parameters<typeof registryStub>[0], string][] = [
      ["unknown package", {}, "source-unavailable"],
      [
        "integrity",
        { "@fixture/mcp@1.2.3": { tarball, integrity: `sha512-${"A".repeat(86)}==` } },
        "source-integrity",
      ],
      [
        "renamed",
        { "@fixture/mcp@1.2.3": { tarball: npmTarball(packageEntries("@evil/mcp")) } },
        "source-integrity",
      ],
    ];
    for (const [name, packages, reason] of fetchCases) {
      const registry = registryStub(packages);
      const result = await scanWith(
        request({ type: "npm", package: "@fixture/mcp", version: "1.2.3" }),
        { outDir: fixture.path(`out-${name.replace(" ", "-")}`) },
        { fetch: registry.fetch },
      );
      expect([name, result.status, "reason" in result ? result.reason : undefined]).toEqual([
        name,
        "refused",
        reason,
      ]);
    }
    // A version range is invalid and fetches nothing.
    const registry = registryStub({});
    const range = await scanWith(
      request({ type: "npm", package: "@fixture/mcp", version: "^1.2.3" }),
      { outDir: fixture.path("out-range") },
      { fetch: registry.fetch },
    );
    expect(range.status).toBe("invalid");
    expect(registry.calls).toEqual([]);
    expect(readdirSync(sentinels)).toEqual([]);
  });
});
