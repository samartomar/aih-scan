import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

/** One advisory record as the controlled service serves it from `/v1/vulns/<id>`. */
export type OsvRecord = Readonly<Record<string, unknown>> & { readonly id: string };

export interface CapturedRequest {
  readonly method: string;
  readonly path: string;
  readonly body: string;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
}

export interface OsvService {
  /** `http://127.0.0.1:<port>`: pass as the advisory endpoint. */
  readonly endpoint: string;
  /** Every request received, in order, with its exact body. */
  readonly requests: CapturedRequest[];
  /** Every byte the service received (request lines, headers and bodies). */
  received(): string;
  close(): Promise<void>;
}

export interface OsvServiceOptions {
  /** `<ecosystem>/<name>@<version>` → advisory ids returned by querybatch. */
  readonly affected?: Readonly<Record<string, readonly string[]>>;
  readonly records?: readonly OsvRecord[];
  /** Answer every request with this status (a failing service). */
  readonly failWith?: number;
  /** Answer `/v1/vulns/*` with this status (the batch succeeds, the details fail). */
  readonly failDetailsWith?: number;
  /** Answer querybatch with this raw body. */
  readonly batchBody?: string;
}

/**
 * A controlled OSV-compatible advisory service on the loopback interface (TEST-ONLY). It
 * answers `POST /v1/querybatch` and `GET /v1/vulns/<id>` from fixed data and records every
 * request byte, so tests can prove exactly what an advisory check discloses.
 */
export async function osvService(options: OsvServiceOptions = {}): Promise<OsvService> {
  const requests: CapturedRequest[] = [];
  const raw: string[] = [];
  const records = new Map((options.records ?? []).map((record) => [record.id, record]));
  const server: Server = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      const path = request.url ?? "";
      requests.push({ method: request.method ?? "", path, body, headers: request.headers });
      raw.push(`${request.method} ${path}\n${JSON.stringify(request.rawHeaders)}\n${body}\n`);
      const send = (status: number, value: unknown) => {
        response.writeHead(status, { "content-type": "application/json" });
        response.end(typeof value === "string" ? value : JSON.stringify(value));
      };
      if (options.failWith !== undefined) return send(options.failWith, { message: "down" });
      if (request.method === "POST" && path === "/v1/querybatch") {
        if (options.batchBody !== undefined) return send(200, options.batchBody);
        const parsed = JSON.parse(body) as {
          queries: { package: { name: string; ecosystem: string }; version: string }[];
        };
        return send(200, {
          results: parsed.queries.map((query) => {
            const ids =
              options.affected?.[
                `${query.package.ecosystem}/${query.package.name}@${query.version}`
              ] ?? [];
            return ids.length === 0
              ? {}
              : { vulns: ids.map((id) => ({ id, modified: "2026-10-01T00:00:00Z" })) };
          }),
        });
      }
      if (request.method === "GET" && path.startsWith("/v1/vulns/")) {
        if (options.failDetailsWith !== undefined)
          return send(options.failDetailsWith, { message: "down" });
        const record = records.get(decodeURIComponent(path.slice("/v1/vulns/".length)));
        return record === undefined ? send(404, { message: "not found" }) : send(200, record);
      }
      send(404, { message: "unknown" });
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    endpoint: `http://127.0.0.1:${port}`,
    requests,
    received: () => raw.join(""),
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

/** A GHSA-style record: severity in database_specific, one fixed event for the package. */
export function ghsa(
  id: string,
  name: string,
  fixed: string | undefined,
  extra: Record<string, unknown> = {},
): OsvRecord {
  return {
    id,
    summary: `Advisory ${id} for ${name}`,
    details: "Long details.",
    modified: "2026-10-01T00:00:00Z",
    database_specific: { severity: "HIGH" },
    affected: [
      {
        package: { ecosystem: "npm", name },
        ranges: [
          {
            type: "SEMVER",
            events: [{ introduced: "0" }, ...(fixed === undefined ? [] : [{ fixed }])],
          },
        ],
      },
    ],
    ...extra,
  };
}
