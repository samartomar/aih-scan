import { readFileSync } from "node:fs";
import { createServer, Socket } from "node:net";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { gitBlobHex, sha256Hex, treeKeyOf } from "../../src/contracts/git-tree.js";
import { remoteMcpFile } from "../../src/contracts/remote-mcp.js";
import { matchScan as hostMatchScan, scan } from "../../src/public/host.js";
import { matchScan, readSummary } from "../../src/public/read.js";
import { remoteMcpGolden } from "../support/scan-v1-corpus.js";
import { type FixtureRoot, fixtureRoot } from "../support/scan-v1-fixture.js";

const golden = remoteMcpGolden;

let fixture: FixtureRoot;
beforeEach(() => {
  fixture = fixtureRoot("aih-scan-v1-remote-");
});
afterEach(() => {
  vi.restoreAllMocks();
  fixture.dispose();
});

const remoteRequest = (source: unknown) => ({
  format: "aih-scan-request/1",
  origin: "local",
  source,
});

describe("remote MCP configuration", () => {
  it("materializes the exact published bytes, digests and key", async () => {
    const file = remoteMcpFile(golden.input.url);
    expect(file.path).toBe(golden.file.path);
    expect(file.mode).toBe(golden.file.mode);
    expect(new TextDecoder().decode(file.bytes)).toBe(golden.file.text);
    expect(file.bytes.length).toBe(golden.file.length);
    expect(file.bytes[0]).toBe(0x7b); // no BOM
    expect(file.bytes.at(-1)).toBe(0x0a);
    expect(file.bytes.at(-2)).not.toBe(0x0a);
    expect(await sha256Hex(file.bytes)).toBe(golden.file.sha256);
    expect(await gitBlobHex("sha1", file.bytes)).toBe(golden.file.gitBlobSha1);
    expect(await treeKeyOf([file])).toBe(golden.scanKey);
  });

  it("scans the descriptor as configuration only, and host and portable matching agree on the golden file", async () => {
    const connect = vi.spyOn(Socket.prototype, "connect");
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const result = await scan(remoteRequest(golden.input), { outDir: fixture.path("out") });
    expect(result.status).toBe("ok");
    expect(result.acquisition).toEqual({ type: "remote", fetched: false });
    expect(result.results).toHaveLength(1);
    const entry = result.results[0];
    if (entry?.status !== "ok") throw new Error(JSON.stringify(result));
    expect(entry).toMatchObject({
      kind: "mcp",
      path: ".",
      scanKey: golden.scanKey,
      source: { type: "remote", url: golden.input.url },
    });
    const summaryBytes = new Uint8Array(readFileSync(entry.summaryPath));
    const read = readSummary(summaryBytes);
    if (read.status !== "ok") throw new Error(JSON.stringify(read));
    expect(read.summary.files).toEqual([
      { path: ".mcp.json", mode: "100644", part: "config", sha256: golden.file.sha256 },
    ]);
    expect(connect).not.toHaveBeenCalled();
    expect(fetchSpy).not.toHaveBeenCalled();

    // A consumer supplying the golden file gets the same answer from both matching overloads.
    const folder = fixture.folder("consumer", { ".mcp.json": golden.file.text });
    const host = await hostMatchScan(read.summary, folder);
    const portable = await matchScan(read.summary, [
      {
        path: golden.file.path,
        mode: golden.file.mode,
        bytes: new TextEncoder().encode(golden.file.text),
      },
    ]);
    expect(host).toMatchObject({ status: "ok", matches: true });
    expect(portable).toEqual(host);
  });

  it("never contacts the endpoint and preserves the URL spelling exactly", async () => {
    let contacted = 0;
    const server = createServer((socket) => {
      contacted += 1;
      socket.destroy();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("no address");
    try {
      const url = `http://127.0.0.1:${address.port}/A/./b%2F/../sse?Token=X#Frag`;
      const result = await scan(remoteRequest({ type: "remote", url }), {
        outDir: fixture.path("out"),
      });
      const entry = result.results[0];
      if (entry?.status !== "ok") throw new Error(JSON.stringify(result));
      expect(entry.scanKey).toBe(await treeKeyOf([remoteMcpFile(url)]));
      expect(new TextDecoder().decode(remoteMcpFile(url).bytes)).toBe(
        `{"mcpServers":{"remote":{"url":"${url}"}}}\n`,
      );
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(contacted).toBe(0);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("refuses invalid Unicode, credentials and non-web schemes as invalid", async () => {
    for (const url of [
      "https://mcp.example.com/\uD800",
      "https://user:secret@mcp.example.com/sse",
      "file:///etc/passwd",
    ]) {
      const result = await scan(remoteRequest({ type: "remote", url }), {
        outDir: fixture.path(`out-${url.length}`),
      });
      expect(result.status).toBe("invalid");
      expect(result.results).toEqual([]);
    }
  });
});
