import { execFile } from "node:child_process";
import { createServer, type IncomingHttpHeaders } from "node:http";
import { join, resolve } from "node:path";
import { promisify } from "node:util";

export async function publisherTransport(bytes: Uint8Array) {
  const state = {
    metadata: {} as Record<string, unknown>,
    redirect:
      "https://release-assets.githubusercontent.com/github-production-release-asset/1336836161/fixture?signature=fixture-query-secret",
    terminalStatus: 200,
    bytes,
    headers: [] as IncomingHttpHeaders[],
  };
  const server = createServer((request, response) => {
    state.headers.push(request.headers);
    const host = request.headers["x-fixture-host"];
    if (host === "api.github.com") {
      response.setHeader("content-type", "application/json");
      response.end(
        JSON.stringify({
          id: 123,
          name: "reviewed.tar",
          state: "uploaded",
          size: bytes.length,
          url: "https://api.github.com/repos/samartomar/aih-scan/releases/assets/123",
          browser_download_url:
            "https://github.com/samartomar/aih-scan/releases/download/fixture/reviewed.tar",
          ...state.metadata,
        }),
      );
    } else if (host === "github.com") {
      response.writeHead(302, { location: state.redirect });
      response.end();
    } else if (host === "release-assets.githubusercontent.com") {
      response.writeHead(
        state.terminalStatus,
        state.terminalStatus === 302 ? { location: state.redirect } : {},
      );
      response.end(state.bytes);
    } else {
      response.writeHead(302, { location: "https://example.com/refused.tar" });
      response.end();
    }
  });
  await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Fixture address");
  return {
    state,
    async run(args: string[], env: NodeJS.ProcessEnv = {}) {
      return promisify(execFile)(
        process.execPath,
        [
          "--import",
          resolve(import.meta.dirname, "publisher-transport-preload.mjs"),
          join(resolve(import.meta.dirname, "../.."), "tools/publisher/candidate.mjs"),
          ...args,
        ],
        {
          env: {
            ...process.env,
            AIH_SCAN_TEST_PUBLISHER_SERVICE: `http://127.0.0.1:${address.port}`,
            ...env,
          },
          timeout: 30000,
        },
      );
    },
    async close() {
      server.closeAllConnections();
      await new Promise<void>((done, reject) =>
        server.close((error) => (error ? reject(error) : done())),
      );
    },
  };
}
