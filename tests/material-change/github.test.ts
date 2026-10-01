import { afterEach, expect, test, vi } from "vitest";
import { deliverMaterialChange, type MaterialChange } from "../../src/public/host.js";

afterEach(() => vi.unstubAllGlobals());
const summary: MaterialChange = {
  schema: "urn:aihq:scan:material-change:1.0.0",
  sourceId: "https://github.com/example/materials",
  materialProjection: "aih-material-v1",
  beforeScanId: `scan:sha256:${"a".repeat(64)}`,
  afterScanId: `scan:sha256:${"b".repeat(64)}`,
  inventory: { beforeComplete: true, afterComplete: true, uncomparedItemIds: [] },
  changes: [
    {
      itemId: "skill.alpha",
      kind: "modified",
      beforeSha256: "a".repeat(64),
      afterSha256: "b".repeat(64),
    },
  ],
  diagnostics: [],
};
const input = {
  summary,
  enabled: true,
  target: { owner: "example", repository: "tracker" },
  credential: "fake-secret-only",
};
test("default GitHub delivery uses fixed API target, explicit bearer and safe redirect handling", async () => {
  const requests: { url: string; init: RequestInit }[] = [];
  vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
    requests.push({ url, init });
    if (init.method === "GET")
      return new Response("[]", { status: 200, headers: { "content-type": "application/json" } });
    const payload = JSON.parse(init.body as string);
    return Response.json(
      {
        number: 1,
        state: "open",
        body: payload.body,
        html_url: "https://github.com/example/tracker/issues/1",
      },
      { status: 201 },
    );
  });
  const result = await deliverMaterialChange(input);
  expect(result.results).toMatchObject([{ status: "created" }]);
  expect(requests.map((request) => request.url)).toEqual([
    "https://api.github.com/repos/example/tracker/issues?state=all&sort=created&direction=asc&per_page=100&page=1",
    "https://api.github.com/repos/example/tracker/issues",
  ]);
  for (const request of requests) {
    expect(request.init).toMatchObject({
      redirect: "error",
      credentials: "omit",
      headers: { Authorization: "Bearer fake-secret-only" },
    });
    expect(request.init.signal).toBeInstanceOf(AbortSignal);
  }
});

test("pagination uses fixed numbered requests even when GitHub links a numeric repository route", async () => {
  const urls: string[] = [];
  vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
    urls.push(url);
    if (init.method === "POST") {
      const { body } = JSON.parse(init.body as string);
      return Response.json({
        number: 1,
        state: "open",
        body,
        html_url: "https://github.com/example/tracker/issues/1",
      });
    }
    return new Response("[]", {
      headers:
        urls.length === 1
          ? {
              link: '<https://api.github.com/repositories/123/issues?state=all&per_page=100&page=2>; rel="next"',
            }
          : {},
    });
  });
  expect((await deliverMaterialChange(input)).results[0]?.status).toBe("created");
  expect(urls[1]).toBe(
    "https://api.github.com/repos/example/tracker/issues?state=all&sort=created&direction=asc&per_page=100&page=2",
  );
});

const created = (init: RequestInit) =>
  Response.json(
    {
      number: 9,
      state: "open",
      body: JSON.parse(init.body as string).body,
      html_url: "https://github.com/example/tracker/issues/9",
    },
    { status: 201 },
  );

test("unrelated third-party issue data may be non-NFC and use ordinary finite numbers", async () => {
  let mutations = 0;
  vi.stubGlobal("fetch", async (_url: string, init: RequestInit) => {
    if (init.method !== "GET") {
      mutations++;
      return created(init);
    }
    // Human text is not AIHQ control data: decomposed accents and negative or
    // fractional numbers in unrelated issue and pull-request objects are ordinary.
    return new Response(
      JSON.stringify([
        { number: 3, state: "open", title: "Café", pull_request: {}, score: -1.5 },
        {
          number: 2,
          state: "closed",
          body: "Résumé notes",
          html_url: "https://github.com/example/tracker/issues/2",
          reactions: { total_count: 0 },
          offset: -2,
          ratio: 0.1,
        },
      ]),
    );
  });
  const result = await deliverMaterialChange(input);
  expect(result.results).toMatchObject([
    { status: "created", issueUrl: "https://github.com/example/tracker/issues/9" },
  ]);
  expect(mutations).toBe(1);
});

test("duplicate JSON keys in an otherwise admissible page still refuse before mutation", async () => {
  let mutations = 0;
  vi.stubGlobal("fetch", async (_url: string, init: RequestInit) => {
    if (init.method !== "GET") {
      mutations++;
      return created(init);
    }
    return new Response('[{"number":3,"pull_request":{},"pull_request":{}}]');
  });
  const result = await deliverMaterialChange(input);
  expect(result.results).toMatchObject([
    { status: "failed", diagnostics: [{ code: "invalid-response" }] },
  ]);
  expect(mutations).toBe(0);
});

test.each([
  [401, {}, "unauthorized"],
  [403, {}, "forbidden"],
  [403, { "x-ratelimit-remaining": "0" }, "rate-limited"],
  [429, { "retry-after": "60" }, "rate-limited"],
  [404, {}, "not-found"],
  [500, {}, "invalid-response"],
] as const)("HTTP %i lookup refusal reports a safe status class only", async (status, headers, code) => {
  vi.stubGlobal(
    "fetch",
    async () => new Response("server detail fake-secret-only", { status, headers }),
  );
  const result = await deliverMaterialChange(input);
  expect(result.results).toMatchObject([{ status: "failed", diagnostics: [{ code }] }]);
  expect(JSON.stringify(result)).not.toContain("server detail");
  expect(JSON.stringify(result)).not.toContain("fake-secret-only");
});

test.each([
  () =>
    new Response("redirect", { status: 302, headers: { location: "https://elsewhere.example/" } }),
  () => new Response("secret server error fake-secret-only", { status: 403 }),
  () => new Response("[]", { headers: { "content-length": "2097153" } }),
  () => new Response(`"${"x".repeat(2097153)}"`),
  () => new Response("[]", { headers: { link: "not a pagination link" } }),
  () => new Response('{"duplicate":1,"duplicate":2}'),
  () => new Response("[]", { headers: { "content-length": "invalid" } }),
])("HTTP redirects, malformed and oversized responses fail without mutation or unsafe details", async (response) => {
  let mutations = 0;
  vi.stubGlobal("fetch", async (_url: string, init: RequestInit) => {
    if (init.method !== "GET") mutations++;
    return response();
  });
  const result = await deliverMaterialChange(input);
  expect(result.results[0]?.status).toBe("failed");
  expect(result.retryableSummary).toEqual(summary);
  expect(JSON.stringify(result)).not.toContain("fake-secret-only");
  expect(mutations).toBe(0);
});
