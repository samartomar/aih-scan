import { connect, createServer, type Socket } from "node:net";
import { bound, fail } from "./json.js";

/** Transport ciphertext has its own finite budget; source material is bounded separately. */
export function gitTransportLimit(sourceBytes: number, sourceEntries: number): number {
  return sourceBytes + sourceEntries * 1024 + 1024 * 1024;
}

/** Transparent CONNECT only: Git retains end-to-end TLS certificate verification.
 * Git's http.proxy override is documented at https://git-scm.com/docs/git-config#Documentation/git-config.txt-httpproxy.
 * Admission occurs before forwarding a chunk, cumulatively across all connections/retries.
 */
interface GitFetchRelay {
  proxy: string;
  limitSignal: AbortSignal;
  assertWithinBounds(): void;
  close(): Promise<void>;
}
export async function startGitFetchRelay(
  repository: string,
  maximum: number,
  signal?: AbortSignal,
): Promise<GitFetchRelay> {
  bound(Number.isSafeInteger(maximum) && maximum >= 0, "Git transport budget", maximum);
  const url = new URL(repository),
    authority = `${url.hostname}:${url.port || "443"}`,
    sockets = new Set<Socket>(),
    limitController = new AbortController();
  let transferred = 0,
    connections = 0,
    exceeded = false,
    closed = false;
  const destroySockets = () => {
    for (const socket of sockets) socket.destroy();
  };
  const exceed = () => {
    exceeded = true;
    destroySockets();
    limitController.abort();
  };
  const server = createServer((client) => {
    sockets.add(client);
    client.on("error", () => client.destroy());
    client.once("close", () => sockets.delete(client));
    if (closed || exceeded || ++connections > 8) {
      exceed();
      return;
    }
    client.setTimeout(30000, () => client.destroy());
    let header = Buffer.alloc(0);
    const readHeader = (chunk: Buffer) => {
      if (header.length + chunk.length > 8192) {
        client.destroy();
        return;
      }
      header = Buffer.concat([header, chunk]);
      const end = header.indexOf("\r\n\r\n");
      if (end < 0) return;
      client.removeListener("data", readHeader);
      const firstLine = header.subarray(0, header.indexOf("\r\n")).toString("ascii");
      if (
        firstLine !== `CONNECT ${authority} HTTP/1.1` &&
        firstLine !== `CONNECT ${authority} HTTP/1.0`
      ) {
        client.destroy();
        return;
      }
      // URL IPv6 brackets belong to HTTP authority, not the net.connect hostname.
      const remote = connect({
        host: url.hostname.replace(/^\[|\]$/g, ""),
        port: Number(url.port || 443),
      });
      sockets.add(remote);
      remote.on("error", () => {
        remote.destroy();
        client.destroy();
      });
      remote.once("close", (hadError) => {
        sockets.delete(remote);
        // Normal EOF must let client.end() flush queued bytes, including a paused reader.
        if (hadError || !remote.readableEnded) client.destroy();
      });
      client.once("close", () => remote.destroy());
      remote.setTimeout(60000, () => {
        remote.destroy();
        client.destroy();
      });
      const forward = (source: Socket, destination: Socket, bytes: Buffer) => {
        if (exceeded || closed) return;
        if (bytes.length > maximum - transferred) {
          exceed();
          return;
        }
        transferred += bytes.length;
        if (!destination.write(bytes)) {
          source.pause();
          destination.once("drain", () => {
            if (!source.destroyed) source.resume();
          });
        }
      };
      client.pause();
      remote.once("connect", () => {
        if (closed || exceeded) {
          remote.destroy();
          return;
        }
        client.setTimeout(600000);
        client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        client.on("data", (bytes: Buffer) => forward(client, remote, bytes));
        remote.on("data", (bytes: Buffer) => forward(remote, client, bytes));
        client.on("end", () => remote.end());
        remote.on("end", () => client.end());
        const remainder = header.subarray(end + 4);
        if (remainder.length) forward(client, remote, remainder);
        client.resume();
      });
    };
    client.on("data", readHeader);
  });
  const abort = () => {
    closed = true;
    destroySockets();
  };
  signal?.addEventListener("abort", abort, { once: true });
  try {
    if (signal?.aborted) fail("Pinned Git acquisition was cancelled");
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        server.removeListener("error", reject);
        resolve();
      });
    });
    server.on("error", abort);
    const address = server.address();
    if (address === null || typeof address === "string") fail("Git transport relay is unavailable");
    return {
      proxy: `http://127.0.0.1:${address.port}`,
      limitSignal: limitController.signal,
      assertWithinBounds: () =>
        bound(!exceeded, "Git acquisition transport bytes or connections", maximum),
      close: async () => {
        closed = true;
        signal?.removeEventListener("abort", abort);
        destroySockets();
        await new Promise<void>((resolve) => server.close(() => resolve()));
      },
    };
  } catch (error) {
    signal?.removeEventListener("abort", abort);
    destroySockets();
    server.close();
    throw error;
  }
}
