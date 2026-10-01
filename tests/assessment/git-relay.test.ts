import { once } from "node:events";
import { connect, createServer, type Socket } from "node:net";
import { afterEach, expect, test, vi } from "vitest";
import { startGitFetchRelay } from "../../src/assessment/git-fetch-relay.js";
import * as processBoundary from "../../src/cli/process-runner.js";
import { runScan } from "../../src/public/host.js";

const cleanups: (() => Promise<void>)[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});
async function upstream(handler: (socket: Socket) => void) {
  const sockets = new Set<Socket>();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on("error", () => socket.destroy());
    socket.once("close", () => sockets.delete(socket));
    handler(socket);
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("fixture address unavailable");
  cleanups.push(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
  return `127.0.0.1:${address.port}`;
}
function tunnel(proxy: string, authority: string, suffix = "") {
  const port = Number(new URL(proxy).port);
  const client = connect({ host: "127.0.0.1", port });
  client.on("error", () => client.destroy());
  client.once("connect", () =>
    client.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n${suffix}\r\n`),
  );
  const chunks: Buffer[] = [];
  client.on("data", (chunk: Buffer) => chunks.push(chunk));
  const complete = new Promise<Buffer>((resolve) =>
    client.once("close", () => resolve(Buffer.concat(chunks))),
  );
  cleanups.push(async () => {
    client.destroy();
  });
  return { client, complete };
}
test("normal upstream EOF flushes a large response through a paused downstream reader", async () => {
  const bytes = Buffer.alloc(2 * 1024 * 1024, 0x61);
  const authority = await upstream((socket) => socket.end(bytes));
  const relay = await startGitFetchRelay(`https://${authority}/fixture.git`, bytes.length);
  cleanups.push(relay.close);
  const { client, complete } = tunnel(relay.proxy, authority);
  client.pause();
  // Resume from a real asynchronous boundary, allowing upstream EOF and write backpressure first.
  await new Promise<void>((resolve) => setTimeout(resolve, 40));
  client.resume();
  const received = await complete;
  const end = received.indexOf("\r\n\r\n");
  const body = received.subarray(end + 4);
  expect(body.length).toBe(bytes.length);
  expect(body.equals(bytes)).toBe(true);
  relay.assertWithinBounds();
});
test("aggregate cutoff occurs before forwarding excess bytes across retries", async () => {
  const authority = await upstream((socket) => socket.end("123456"));
  const relay = await startGitFetchRelay(`https://${authority}/fixture.git`, 10);
  cleanups.push(relay.close);
  expect((await tunnel(relay.proxy, authority).complete).toString()).toContain("123456");
  const retry = (await tunnel(relay.proxy, authority).complete).toString();
  expect(retry).not.toContain("123456");
  expect(() => relay.assertWithinBounds()).toThrow(/Git acquisition transport/);
});
test.each([
  "different-authority",
  "oversized-header",
])("%s cannot contact the upstream", async (kind) => {
  let calls = 0;
  const authority = await upstream((socket) => {
    calls++;
    socket.end();
  });
  const relay = await startGitFetchRelay(`https://${authority}/fixture.git`, 1024);
  cleanups.push(relay.close);
  await tunnel(
    relay.proxy,
    kind === "different-authority" ? "example.invalid:443" : authority,
    kind === "oversized-header" ? `X-Large: ${"x".repeat(9000)}\r\n` : "",
  ).complete;
  expect(calls).toBe(0);
});
test("connection admission remains finite even when clients send no tunnel payload", async () => {
  const authority = await upstream((socket) => socket.end());
  const relay = await startGitFetchRelay(`https://${authority}/fixture.git`, 1024);
  cleanups.push(relay.close);
  for (let count = 0; count < 8; count++) await tunnel(relay.proxy, "other.invalid:443").complete;
  relay.assertWithinBounds();
  await tunnel(relay.proxy, "other.invalid:443").complete;
  expect(relay.limitSignal.aborted).toBe(true);
  expect(() => relay.assertWithinBounds()).toThrow(/Git acquisition transport/);
});
test.each([
  false,
  true,
])("public pinned acquisition bounds transport with inherited proxy bypass; containment failure %s", async (containmentFailure) => {
  const authority = await upstream((socket) => socket.end(Buffer.alloc(2 * 1024 * 1024)));
  vi.stubEnv("NO_PROXY", "*");
  vi.stubEnv("no_proxy", "*");
  vi.stubEnv("HTTPS_PROXY", "http://attacker.invalid:9000");
  let received = 0;
  vi.spyOn(processBoundary, "spawnBoundedV1").mockImplementation(async (argv, options) => {
    const args = JSON.parse(argv[2]!) as string[];
    if (!args.includes("fetch"))
      return { code: 0, stdout: '{"bytesBase64":""}', stderr: "", truncated: false };
    expect(options.containProcessTree).toBe(true);
    expect(
      Object.keys(options.env!).some((key) =>
        ["NO_PROXY", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"].includes(key.toUpperCase()),
      ),
    ).toBe(false);
    expect(args).toContain("fetch.unpackLimit=1");
    expect(args).toContain("transfer.unpackLimit=1");
    expect(args).toContain("http.sslVerify=true");
    expect(args).toContain("http.followRedirects=false");
    const proxy = args.find((arg) => arg.startsWith("http.proxy="))?.slice("http.proxy=".length);
    expect(proxy).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
    if (proxy) received = (await tunnel(proxy, authority).complete).length;
    expect(options.signal?.aborted).toBe(true);
    return {
      code: 1,
      stdout: "",
      stderr: "",
      truncated: false,
      ...(containmentFailure ? { termination: "containment-failure" as const } : {}),
    };
  });
  const result = await runScan({
    schema: "urn:aihq:scan:request:1.0.0",
    source: { kind: "git", repository: `https://${authority}/fixture.git`, commit: "0".repeat(40) },
    selection: { paths: "all", excludedPaths: [] },
    detectors: [{ detectorId: "detector.unavailable", configuration: {} }],
    limits: { maxSourceBytes: 1, maxSourceEntries: 1 },
  });
  expect(result).toMatchObject({
    status: "diagnostic",
    phase: "capture",
    diagnostics: [{ code: containmentFailure ? "invalid-input" : "resource-limit" }],
  });
  expect(result).not.toHaveProperty("scanId");
  if (containmentFailure) expect(result.diagnostics[0]?.detail).toContain("process-tree cleanup");
  expect(received).toBeLessThanOrEqual(1024 * 1024 + 1024 + 1 + 39);
});
