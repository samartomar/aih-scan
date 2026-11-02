import { existsSync, mkdirSync, readdirSync, readFileSync } from "node:fs";
import net from "node:net";
import { join } from "node:path";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { matchScan, scan } from "../../src/public/host.js";
import { fixtureRoot } from "../support/scan-v1-fixture.js";

const fixture = fixtureRoot("aih-scan-v1-sentinel-");
afterEach(() => vi.restoreAllMocks());
afterAll(() => fixture.dispose());

describe("supplied content never runs and static scans stay offline", () => {
  it("does not execute hooks, package scripts, MCP commands or executable files, and opens no connection", async () => {
    const sentinels = fixture.path("sentinels");
    mkdirSync(sentinels);
    const touch = (name: string) => `touch ${join(sentinels, name)}`;
    const item = fixture.folder(
      "item",
      {
        "SKILL.md": "# Sentinel\n\nRun `scripts/run.sh` first.\n",
        "hooks/hooks.json": JSON.stringify({
          hooks: { SessionStart: [{ hooks: [{ type: "command", command: touch("hook") }] }] },
        }),
        "package.json": JSON.stringify({
          name: "x",
          scripts: { preinstall: touch("preinstall"), postinstall: touch("postinstall") },
        }),
        ".mcp.json": JSON.stringify({
          mcpServers: {
            local: { command: "sh", args: ["-c", touch("mcp")] },
            remote: { url: "http://127.0.0.1:9/sse" },
          },
        }),
        "scripts/run.sh": `#!/bin/sh\n${touch("script")}\n`,
        "run.py": `import os\nos.system(${JSON.stringify(touch("python"))})\n`,
        ".git/hooks/post-checkout": `#!/bin/sh\n${touch("git-hook")}\n`,
      },
      ["scripts/run.sh", "run.py", ".git/hooks/post-checkout"],
    );
    const connect = vi.spyOn(net.Socket.prototype, "connect");
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    // The source route discovers the same folder's items (skill, hooks, MCP) without running them.
    const discovered = await scan(
      { format: "aih-scan-request/1", origin: "local", source: { type: "folder", path: item } },
      { outDir: fixture.path("out-source") },
    );
    expect(discovered.status).toBe("ok");
    const result = await scan(
      { format: "aih-scan-request/1", origin: "local", items: [{ path: item }] },
      { outDir: fixture.path("out") },
    );
    expect(result.status).toBe("ok");
    const entry = result.results[0];
    if (entry?.status !== "ok") throw new Error("expected a scan");
    expect(
      (await matchScan(JSON.parse(readFileSync(entry.summaryPath, "utf8")), item)).status,
    ).toBe("ok");
    expect(readdirSync(sentinels)).toEqual([]);
    expect(connect).not.toHaveBeenCalled();
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(existsSync(join(sentinels, "hook"))).toBe(false);
  });
});
