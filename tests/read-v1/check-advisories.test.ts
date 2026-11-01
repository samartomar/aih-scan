import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { checkAdvisories } from "../../src/public/read.js";
import { ghsa, type OsvService, osvService } from "../support/osv-service-v1.js";

const now = () => new Date("2026-11-01T09:00:00.123Z");
const npm = (name: string, version: string | null, file = "package.json") => ({
  ecosystem: "npm" as const,
  name,
  version,
  file,
});

const realFetch = globalThis.fetch.bind(globalThis);
let service: OsvService | undefined;
beforeEach(() => {
  // Nothing may reach a live service: only the injected fetch to the local service is used.
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    throw new Error(`unexpected global fetch ${String(input)}`);
  });
});
afterEach(async () => {
  vi.restoreAllMocks();
  await service?.close();
  service = undefined;
});
const local = (endpoint: string) => ({
  endpoint,
  now,
  fetch: (url: string, init: RequestInit) => {
    expect(url.startsWith(endpoint)).toBe(true);
    return realFetch(url, init);
  },
});
const batchBodies = (s: OsvService) =>
  s.requests.filter((r) => r.path === "/v1/querybatch").map((r) => JSON.parse(r.body));

describe("checkAdvisories", () => {
  it("reports none-known and vulnerable per dependency with checkedAt", async () => {
    service = await osvService({
      affected: { "npm/x@1.0.0": ["GHSA-aaaa-bbbb-cccc"] },
      records: [ghsa("GHSA-aaaa-bbbb-cccc", "x", "1.0.1")],
    });
    const result = await checkAdvisories(
      [npm("ws", "8.18.0"), npm("x", "1.0.0")],
      local(service.endpoint),
    );
    expect(result).toEqual({
      status: "ok",
      checkedAt: "2026-11-01T09:00:00Z",
      results: [
        {
          ecosystem: "npm",
          name: "ws",
          version: "8.18.0",
          file: "package.json",
          state: "none-known",
        },
        {
          ecosystem: "npm",
          name: "x",
          version: "1.0.0",
          file: "package.json",
          state: "vulnerable",
          code: "trust.known-vulnerability",
          advisories: [
            {
              id: "GHSA-aaaa-bbbb-cccc",
              severity: "HIGH",
              summary: "Advisory GHSA-aaaa-bbbb-cccc for x",
              fixedIn: "1.0.1",
            },
          ],
        },
      ],
    });
    expect(batchBodies(service)).toEqual([
      {
        queries: [
          { package: { name: "ws", ecosystem: "npm" }, version: "8.18.0" },
          { package: { name: "x", ecosystem: "npm" }, version: "1.0.0" },
        ],
      },
    ]);
  });

  it("never sends internal scopes or nonexact versions", async () => {
    service = await osvService();
    const result = await checkAdvisories(
      [
        npm("@acme/tools", "1.0.0"),
        npm("@ACME/other", "2.0.0"),
        npm("caret-secret-name", "^1.2.0"),
        npm("tilde-name", "~1.2.0"),
        npm("star-name", "*"),
        npm("tag-name", "latest"),
        npm("git-name", "github:acme/private-repo"),
        npm("file-name", "file:../private"),
        npm("alias-name", "npm:other@1.0.0"),
        npm("v-name", "v1.0.0"),
        npm("unversioned", null),
        { ecosystem: "pypi", name: "pyrange", version: ">=2.0", file: "requirements.txt" },
        { ecosystem: "pypi", name: "pywild", version: "==1.0.*", file: "requirements.txt" },
        { ecosystem: "pypi", name: "requests", version: "==2.31.0", file: "requirements.txt" },
        npm("@public/pkg", "3.1.4"),
      ],
      { ...local(service.endpoint), internalScopes: ["@acme"] },
    );
    expect(result.status).toBe("ok");
    if (result.status !== "ok") return;
    expect(
      result.results.map((r) => [r.name, r.state, "reason" in r ? r.reason : undefined]),
    ).toEqual([
      ["@acme/tools", "not-checked", "internal scope"],
      ["@ACME/other", "not-checked", "internal scope"],
      ["caret-secret-name", "not-checked", "no exact version"],
      ["tilde-name", "not-checked", "no exact version"],
      ["star-name", "not-checked", "no exact version"],
      ["tag-name", "not-checked", "no exact version"],
      ["git-name", "not-checked", "no exact version"],
      ["file-name", "not-checked", "no exact version"],
      ["alias-name", "not-checked", "no exact version"],
      ["v-name", "not-checked", "no exact version"],
      ["unversioned", "not-checked", "no exact version"],
      ["pyrange", "not-checked", "no exact version"],
      ["pywild", "not-checked", "no exact version"],
      ["requests", "none-known", undefined],
      ["@public/pkg", "none-known", undefined],
    ]);
    expect(batchBodies(service)).toEqual([
      {
        queries: [
          { package: { name: "requests", ecosystem: "PyPI" }, version: "2.31.0" },
          { package: { name: "@public/pkg", ecosystem: "npm" }, version: "3.1.4" },
        ],
      },
    ]);
    const received = service.received().toLowerCase();
    for (const secret of [
      "acme",
      "caret",
      "tilde",
      "star-name",
      "tag-name",
      "git-name",
      "private",
      "alias",
      "v-name",
      "unversioned",
      "pyrange",
      "pywild",
      "^",
      "~",
    ])
      expect(received).not.toContain(secret);
    expect(
      service.requests.every(
        (r) => r.headers.cookie === undefined && r.headers.authorization === undefined,
      ),
    ).toBe(true);
  });

  it("sends nothing at all when no dependency may be sent", async () => {
    service = await osvService();
    const result = await checkAdvisories([npm("@acme/a", "1.0.0"), npm("b", "^1")], {
      ...local(service.endpoint),
      internalScopes: ["@acme"],
    });
    expect(result.status).toBe("ok");
    expect(service.requests).toEqual([]);
    expect(await checkAdvisories([], local(service.endpoint))).toEqual({
      status: "ok",
      checkedAt: "2026-11-01T09:00:00Z",
      results: [],
    });
    expect(service.requests).toEqual([]);
  });

  it("queries each exact package version once and keeps one result per dependency", async () => {
    service = await osvService({
      affected: { "npm/x@1.0.0": ["GHSA-1111-2222-3333"] },
      records: [ghsa("GHSA-1111-2222-3333", "x", "1.0.1")],
    });
    const result = await checkAdvisories(
      [npm("x", "1.0.0", "a/package.json"), npm("x", "1.0.0", "b/package.json")],
      local(service.endpoint),
    );
    expect(result.status === "ok" && result.results.map((r) => [r.file, r.state])).toEqual([
      ["a/package.json", "vulnerable"],
      ["b/package.json", "vulnerable"],
    ]);
    expect(batchBodies(service)[0].queries).toHaveLength(1);
    expect(service.requests.filter((r) => r.path.startsWith("/v1/vulns/"))).toHaveLength(1);
  });

  it.each([
    ["the service fails", { failWith: 503 }],
    [
      "advisory details fail",
      { failDetailsWith: 500, affected: { "npm/x@1.0.0": ["GHSA-1111-2222-3333"] } },
    ],
    ["the batch answer is malformed", { batchBody: '{"results": 5}' }],
    ["the batch answer has the wrong length", { batchBody: '{"results": []}' }],
    ["the batch answer is not JSON", { batchBody: "<html>" }],
    ["an advisory id is unsafe", { batchBody: '{"results":[{"vulns":[{"id":"../x"}]},{}]}' }],
  ])("returns every entry not-checked when %s", async (_name, options) => {
    service = await osvService(options);
    const result = await checkAdvisories(
      [npm("x", "1.0.0"), npm("ws", "8.18.0"), npm("y", "^1")],
      local(service.endpoint),
    );
    expect(result).toEqual({
      status: "ok",
      checkedAt: "2026-11-01T09:00:00Z",
      results: [
        { ...npm("x", "1.0.0"), state: "not-checked", reason: "advisory service unreachable" },
        { ...npm("ws", "8.18.0"), state: "not-checked", reason: "advisory service unreachable" },
        { ...npm("y", "^1"), state: "not-checked", reason: "no exact version" },
      ],
    });
  });

  it("returns every entry not-checked when nothing answers", async () => {
    service = await osvService();
    const endpoint = service.endpoint;
    await service.close();
    service = undefined;
    const result = await checkAdvisories([npm("ws", "8.18.0")], local(endpoint));
    expect(result.status === "ok" && result.results).toEqual([
      { ...npm("ws", "8.18.0"), state: "not-checked", reason: "advisory service unreachable" },
    ]);
  });

  it("reports only what the advisory supplies and skips withdrawn advisories", async () => {
    service = await osvService({
      affected: {
        "npm/x@1.5.0": [
          "GHSA-aaaa-0000-0001",
          "GHSA-aaaa-0000-0002",
          "GHSA-aaaa-0000-0003",
          "GHSA-aaaa-0000-0004",
        ],
        "PyPI/Django@4.2.0": ["PYSEC-2024-1"],
      },
      records: [
        { id: "GHSA-aaaa-0000-0001", modified: "2026-01-01T00:00:00Z", affected: [] },
        {
          ...ghsa("GHSA-aaaa-0000-0002", "x", undefined),
          affected: [
            {
              package: { ecosystem: "npm", name: "x" },
              ranges: [
                {
                  type: "SEMVER",
                  events: [
                    { introduced: "0" },
                    { fixed: "1.2.0" },
                    { introduced: "1.4.0" },
                    { fixed: "1.6.0" },
                    { introduced: "2.0.0" },
                    { fixed: "2.0.1" },
                  ],
                },
              ],
            },
            {
              package: { ecosystem: "npm", name: "other" },
              ranges: [{ type: "SEMVER", events: [{ fixed: "1.5.1" }] }],
            },
          ],
        },
        ghsa("GHSA-aaaa-0000-0003", "x", "9.9.9", { withdrawn: "2026-05-01T00:00:00Z" }),
        {
          ...ghsa("GHSA-aaaa-0000-0004", "x", undefined),
          summary: "Bad\u202e text\u200b",
          database_specific: {},
        },
        {
          id: "PYSEC-2024-1",
          details: "Details only.",
          affected: [
            {
              package: { ecosystem: "PyPI", name: "django" },
              ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "4.2.1rc1" }] }],
            },
          ],
        },
      ],
    });
    const result = await checkAdvisories(
      [npm("x", "1.5.0"), { ecosystem: "pypi", name: "Django", version: "4.2.0" }],
      local(service.endpoint),
    );
    expect(result.status === "ok" && result.results).toEqual([
      {
        ...npm("x", "1.5.0"),
        state: "vulnerable",
        code: "trust.known-vulnerability",
        advisories: [
          { id: "GHSA-aaaa-0000-0001" },
          {
            id: "GHSA-aaaa-0000-0002",
            severity: "HIGH",
            summary: "Advisory GHSA-aaaa-0000-0002 for x",
            fixedIn: "1.6.0",
          },
          { id: "GHSA-aaaa-0000-0004", summary: "Bad text" },
        ],
      },
      {
        ecosystem: "pypi",
        name: "Django",
        version: "4.2.0",
        state: "vulnerable",
        code: "trust.known-vulnerability",
        advisories: [{ id: "PYSEC-2024-1", summary: "Details only.", fixedIn: "4.2.1rc1" }],
      },
    ]);
  });

  it("reports none-known when every advisory was withdrawn", async () => {
    service = await osvService({
      affected: { "npm/x@1.0.0": ["GHSA-aaaa-0000-0003"] },
      records: [ghsa("GHSA-aaaa-0000-0003", "x", "1.0.1", { withdrawn: "2026-05-01T00:00:00Z" })],
    });
    const result = await checkAdvisories([npm("x", "1.0.0")], local(service.endpoint));
    expect(result.status === "ok" && result.results[0]?.state).toBe("none-known");
  });

  it("asks the public OSV service by default without credentials or redirects", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const result = await checkAdvisories([npm("ws", "8.18.0")], {
      now,
      fetch: async (url, init) => {
        calls.push({ url, init });
        return new Response(JSON.stringify({ results: [{}] }), { status: 200 });
      },
    });
    expect(result.status === "ok" && result.results[0]?.state).toBe("none-known");
    expect(calls.map((c) => [c.url, c.init.method, c.init.credentials, c.init.redirect])).toEqual([
      ["https://api.osv.dev/v1/querybatch", "POST", "omit", "error"],
    ]);
  });

  it("follows page tokens for the queries that have more advisories", async () => {
    const bodies: unknown[] = [];
    const result = await checkAdvisories([npm("a", "1.0.0"), npm("b", "1.0.0")], {
      now,
      fetch: async (url, init) => {
        if (url.endsWith("/v1/querybatch")) {
          const body = JSON.parse(String(init.body));
          bodies.push(body);
          return Response.json(
            bodies.length === 1
              ? { results: [{ vulns: [{ id: "OSV-1" }], next_page_token: "t1" }, {}] }
              : { results: [{ vulns: [{ id: "OSV-2" }] }] },
          );
        }
        const id = decodeURIComponent(url.slice(url.lastIndexOf("/") + 1));
        return Response.json({ id });
      },
    });
    expect(bodies[1]).toEqual({
      queries: [{ package: { name: "a", ecosystem: "npm" }, version: "1.0.0", page_token: "t1" }],
    });
    expect(result.status === "ok" && result.results.map((r) => r.state)).toEqual([
      "vulnerable",
      "none-known",
    ]);
  });

  it("is invalid for malformed input and refuses when cancelled", async () => {
    const fetcher = vi.fn();
    for (const input of [
      null,
      [{ ecosystem: "cargo", name: "x", version: "1.0.0" }],
      [{ ecosystem: "npm", name: "", version: "1" }],
      [{ ecosystem: "npm", name: "x", version: 1 }],
    ])
      expect((await checkAdvisories(input as never, { fetch: fetcher })).status).toBe("invalid");
    expect((await checkAdvisories([], { internalScopes: ["acme"] })).status).toBe("invalid");
    expect((await checkAdvisories([], { endpoint: "ftp://x" })).status).toBe("invalid");
    expect((await checkAdvisories([], { endpoint: "https://u:p@x.test" })).status).toBe("invalid");
    expect(fetcher).not.toHaveBeenCalled();
    const controller = new AbortController();
    controller.abort();
    expect(
      await checkAdvisories([npm("ws", "8.18.0")], { fetch: fetcher, signal: controller.signal }),
    ).toEqual({
      status: "refused",
      reason: "cancelled",
      detail: "the advisory check was cancelled",
    });
  });
});
