import { createHash } from "node:crypto";
import { expect, test, vi } from "vitest";
import type { GitHubTransport, MaterialChange } from "../../src/public/host.js";
import * as host from "../../src/public/host.js";

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
const changeId = "change:sha256:0390a0d3fb086c4ff186b2c35b46fc2c81760d2c529e58f0f7f18f2184d00fe2";
const itemKey = "f0ae0bb1900ea286fd07d655431501bbf168c4378ca8f0c790110e870682af0c";
const start = "<!-- aihq-scan-managed:v1 -->";
const end = "<!-- /aihq-scan-managed:v1 -->";
const managed = (change = changeId) =>
  `${start}\n<!-- aihq-scan-change:v1 ${change} -->\n<!-- aihq-scan-item:v1 ${itemKey} -->\nOld description\n${end}`;
const issue = (number: number, body: string, state = "open") => ({
  number,
  body,
  state,
  html_url: `https://github.com/example/tracker/issues/${number}`,
});
const configured = (transport: GitHubTransport) => ({
  summary,
  enabled: true,
  target: { owner: "example", repository: "tracker" },
  credential: "test-only",
  transport,
});

test("ordinary marker prose does not claim a managed section or block creation", async () => {
  const prose = "Store exact `aihq-scan-change:v1` and `aihq-scan-item:v1` HTML comment markers.";
  let creations = 0;
  const result = await host.deliverMaterialChange(
    configured({
      listIssues: async () => ({ issues: [issue(5, prose)], hasNextPage: false }),
      createIssue: async ({ body }) => {
        creations++;
        return issue(6, body);
      },
      updateIssue: async () => {
        throw new Error("Prose must not match a change");
      },
    }),
  );
  expect(result.results).toMatchObject([{ status: "created" }]);
  expect(creations).toBe(1);
});

test("ordinary marker prose around a valid section is preserved during update", async () => {
  const prose =
    "These aihq-scan-managed:v1, aihq-scan-change:v1 and aihq-scan-item:v1 names explain the format.\n";
  let updated = "";
  const result = await host.deliverMaterialChange(
    configured({
      listIssues: async () => ({
        issues: [issue(7, prose + managed() + prose)],
        hasNextPage: false,
      }),
      createIssue: async () => {
        throw new Error("An exact managed section must update");
      },
      updateIssue: async ({ body }) => {
        updated = body;
        return issue(7, body);
      },
    }),
  );
  expect(result.results).toMatchObject([{ status: "updated" }]);
  expect(updated.startsWith(prose)).toBe(true);
  expect(updated.endsWith(prose)).toBe(true);
});

test("a new change searches all pages, excludes PRs and links the highest prior item issue", async () => {
  let createdBody = "";
  const transport: GitHubTransport = {
    listIssues: async ({ page }) =>
      page === 1
        ? {
            issues: [
              { ...issue(90, managed()), pull_request: {} },
              issue(8, managed(`change:sha256:${"c".repeat(64)}`), "closed"),
            ],
            hasNextPage: true,
          }
        : { issues: [issue(12, managed(`change:sha256:${"d".repeat(64)}`))], hasNextPage: false },
    createIssue: async ({ body }) => {
      createdBody = body;
      return issue(13, body);
    },
    updateIssue: async () => {
      throw new Error("Must create rather than update prior change");
    },
  };
  const result = await host.deliverMaterialChange(configured(transport));
  expect(result.results).toMatchObject([
    {
      changeId,
      status: "created",
      issueUrl: "https://github.com/example/tracker/issues/13",
      diagnostics: [],
    },
  ]);
  expect(createdBody).toContain(`<!-- aihq-scan-change:v1 ${changeId} -->`);
  expect(createdBody).toContain(`<!-- aihq-scan-item:v1 ${itemKey} -->`);
  expect(createdBody).toContain("https://github.com/example/tracker/issues/12");
  expect(createdBody).not.toContain("issues/8");
  expect(result.retryableSummary).toBeUndefined();
});

test("an exact open change updates only its managed section and retains human text", async () => {
  const prefix = "Human plan @maintainer\r\n\r\n";
  const suffix = "\r\n\r\nHuman follow-up stays exactly here.";
  let updatedBody = "";
  const transport: GitHubTransport = {
    listIssues: async () => ({
      issues: [issue(7, prefix + managed() + suffix)],
      hasNextPage: false,
    }),
    createIssue: async () => {
      throw new Error("Existing open change must update");
    },
    updateIssue: async ({ issueNumber, body }) => {
      expect(issueNumber).toBe(7);
      updatedBody = body;
      return issue(7, body);
    },
  };
  const result = await host.deliverMaterialChange(configured(transport));
  expect(result.results).toMatchObject([{ changeId, status: "updated" }]);
  expect(updatedBody.startsWith(prefix)).toBe(true);
  expect(updatedBody.endsWith(suffix)).toBe(true);
  expect(updatedBody).not.toContain("Old description");
});

test("an exact closed disposition stays closed without any mutation", async () => {
  let mutations = 0;
  const mutate = async () => {
    mutations++;
    throw new Error("Must remain closed");
  };
  const result = await host.deliverMaterialChange(
    configured({
      listIssues: async () => ({ issues: [issue(7, managed(), "closed")], hasNextPage: false }),
      createIssue: mutate,
      updateIssue: mutate,
    }),
  );
  expect(result.results).toMatchObject([
    {
      changeId,
      status: "closed-disposition",
      issueUrl: "https://github.com/example/tracker/issues/7",
    },
  ]);
  expect(mutations).toBe(0);
});

test("multiple exact changes across open and closed pages fail ambiguous-match before mutation", async () => {
  let mutations = 0;
  const mutate = async () => {
    mutations++;
    return issue(20, "");
  };
  const result = await host.deliverMaterialChange(
    configured({
      listIssues: async ({ page }) => ({
        issues: [issue(page, managed(), page === 1 ? "open" : "closed")],
        hasNextPage: page === 1,
      }),
      createIssue: mutate,
      updateIssue: mutate,
    }),
  );
  expect(result.results).toMatchObject([
    { status: "failed", diagnostics: [{ code: "ambiguous-match" }] },
  ]);
  expect(mutations).toBe(0);
  expect(result.retryableSummary).toEqual(summary);
});

test.each([
  managed() + managed(),
  managed().replace(end, ""),
  managed().replace(itemKey, "0".repeat(64)),
  managed().replace(`<!-- aihq-scan-item:v1 ${itemKey} -->`, ""),
  managed().replace("<!-- aihq-scan-change:v1", "<!-- aihq-scan-change:v2"),
  `Outside <!-- aihq-scan-change:v1 ${changeId} -->\n${managed()}`,
  managed().replace("Old description", `<!-- aihq-scan-item:v1 ${itemKey} -->`),
])("malformed or contradictory managed sections refuse safely", async (body) => {
  let mutations = 0;
  const mutate = async () => {
    mutations++;
    return issue(1, "");
  };
  const result = await host.deliverMaterialChange(
    configured({
      listIssues: async () => ({ issues: [issue(1, body)], hasNextPage: false }),
      createIssue: mutate,
      updateIssue: mutate,
    }),
  );
  expect(result.results).toMatchObject([
    { status: "failed", diagnostics: [{ code: "invalid-managed-section" }] },
  ]);
  expect(mutations).toBe(0);
});

test("long non-ASCII human issue text within the UTF-8 body bound does not block lookup", async () => {
  let posted = 0;
  const result = await host.deliverMaterialChange(
    configured({
      // 30,000 three-byte characters: 90,000 UTF-8 bytes of ordinary human text.
      listIssues: async () => ({
        issues: [issue(1, "漢".repeat(30000))],
        hasNextPage: false,
      }),
      createIssue: async ({ body }) => {
        posted++;
        return issue(2, body);
      },
      updateIssue: async () => {
        throw new Error("Must create");
      },
    }),
  );
  expect(result.results).toMatchObject([{ status: "created" }]);
  expect(posted).toBe(1);
});

test("oversized issue bodies and repeated pagination refuse incomplete lookup before mutation", async () => {
  for (const listed of [
    [issue(1, "x".repeat(256 * 1024 + 1))],
    [issue(1, "human"), issue(1, "human")],
  ]) {
    let mutations = 0;
    const mutate = async () => {
      mutations++;
      return issue(3, "");
    };
    const result = await host.deliverMaterialChange(
      configured({
        listIssues: async () => ({ issues: listed, hasNextPage: false }),
        createIssue: mutate,
        updateIssue: mutate,
      }),
    );
    expect(result.results).toMatchObject([
      { status: "failed", diagnostics: [{ code: "incomplete-lookup" }] },
    ]);
    expect(mutations).toBe(0);
  }
});

test("disabled material delivery returns a retryable summary without external requests", async () => {
  const deliver = (
    host as unknown as { deliverMaterialChange: (input: unknown) => Promise<unknown> }
  ).deliverMaterialChange;
  expect(typeof deliver).toBe("function");
  const result = await deliver({ summary, enabled: false });
  expect(result).toMatchObject({
    results: [
      {
        changeId: "change:sha256:0390a0d3fb086c4ff186b2c35b46fc2c81760d2c529e58f0f7f18f2184d00fe2",
        status: "failed",
        diagnostics: [{ code: "delivery-disabled" }],
      },
    ],
    retryableSummary: summary,
  });
});

test("missing explicit target or credential refuses without requests, including an empty summary", async () => {
  const unavailable = async () => {
    throw new Error("External request must not occur");
  };
  const transport = { listIssues: unavailable, createIssue: unavailable, updateIssue: unavailable };
  const empty = { ...summary, changes: [] };
  for (const [input, code] of [
    [{ summary, enabled: true, credential: "test-only", transport }, "missing-target"],
    [
      {
        summary: empty,
        enabled: true,
        target: { owner: "example", repository: "tracker" },
        transport,
      },
      "missing-credential",
    ],
  ] as const) {
    const result = await host.deliverMaterialChange(input);
    expect(result.diagnostics).toMatchObject([{ code }]);
    expect(result.retryableSummary).toEqual(input.summary);
  }
});

test("malformed targets and bearer credentials refuse before contacting a transport", async () => {
  for (const overrides of [
    { target: { owner: "../other", repository: "tracker" } },
    { target: { owner: "example", repository: ".." } },
    { target: { owner: "example", repository: "tracker?redirect=elsewhere" } },
    { credential: "secret\r\nInjected: header" },
    { credential: "x".repeat(4097) },
  ]) {
    let requests = 0;
    const request = async () => {
      requests++;
      throw new Error("No request permitted");
    };
    const result = await host.deliverMaterialChange({
      ...configured({ listIssues: request, createIssue: request, updateIssue: request }),
      ...overrides,
    });
    expect(result.diagnostics).toMatchObject([{ code: "invalid-configuration" }]);
    expect(requests).toBe(0);
  }
});

test("an unresponsive injected transport fails within the request timeout without mutation", async () => {
  vi.useFakeTimers();
  try {
    let mutations = 0;
    const mutate = async () => {
      mutations++;
      return issue(1, "");
    };
    const pending = host.deliverMaterialChange(
      configured({
        listIssues: () => new Promise(() => {}),
        createIssue: mutate,
        updateIssue: mutate,
      }),
    );
    await vi.waitFor(() => expect(vi.getTimerCount()).toBeGreaterThan(0));
    await vi.advanceTimersByTimeAsync(10001);
    const result = await pending;
    expect(result.results).toMatchObject([
      { status: "failed", diagnostics: [{ code: "delivery-timeout" }] },
    ]);
    expect(mutations).toBe(0);
  } finally {
    vi.useRealTimers();
  }
});

test("long item display text cannot forge markers or mentions and keeps the issue title bounded", async () => {
  const malicious = `@team-<!--aihq-scan-change-v1${"x".repeat(1000)}`;
  const data = { ...summary, changes: [{ ...summary.changes[0]!, itemId: malicious }] };
  let postedBody = "",
    postedTitle = "";
  const transport: GitHubTransport = {
    listIssues: async () => ({ issues: [], hasNextPage: false }),
    createIssue: async ({ body, title }) => {
      postedBody = body;
      postedTitle = title;
      return issue(1, body);
    },
    updateIssue: async () => {
      throw new Error("No existing issue");
    },
  };
  expect(
    (await host.deliverMaterialChange({ ...configured(transport), summary: data })).results[0]
      ?.status,
  ).toBe("created");
  expect(postedTitle.length).toBeLessThanOrEqual(256);
  expect(postedTitle).not.toContain("@team");
  expect(postedBody).not.toContain("@team");
  expect(postedBody.match(/<!-- aihq-scan-change:v1 /g)).toHaveLength(1);
  expect(postedBody).toContain("&#64;team");
});

test("uncertain create retains safe retry data and retry reuses the issue marker", async () => {
  let stored: ReturnType<typeof issue> | undefined;
  let creations = 0;
  const transport: GitHubTransport = {
    listIssues: async () => ({ issues: stored ? [stored] : [], hasNextPage: false }),
    createIssue: async ({ body }) => {
      creations++;
      stored = issue(4, body);
      throw new Error("fake credential must never appear in diagnostics");
    },
    updateIssue: async ({ body }) => {
      stored = issue(4, body);
      return stored;
    },
  };
  const failed = await host.deliverMaterialChange(configured(transport));
  expect(failed.results[0]?.status).toBe("failed");
  expect(failed.retryableSummary).toEqual(summary);
  expect(JSON.stringify(failed)).not.toContain("fake credential");
  const retry = await host.deliverMaterialChange({
    ...configured(transport),
    summary: failed.retryableSummary!,
  });
  expect(retry.results).toMatchObject([
    { changeId, status: "updated", issueUrl: "https://github.com/example/tracker/issues/4" },
  ]);
  expect(creations).toBe(1);
});

test("malformed success cannot report delivery and caller summary/config are snapshotted before awaits", async () => {
  const original = structuredClone(summary);
  const target = { owner: "example", repository: "tracker" };
  let observedSource = "";
  const transport: GitHubTransport = {
    listIssues: async ({ target: requestTarget }) => {
      expect(requestTarget).toEqual({ owner: "example", repository: "tracker" });
      return { issues: [], hasNextPage: false };
    },
    createIssue: async ({ body }) => {
      observedSource = body;
      return { html_url: "https://github.com/example/tracker/issues/1" };
    },
    updateIssue: async () => {
      throw new Error("No matching issue");
    },
  };
  const pending = host.deliverMaterialChange({
    ...configured(transport),
    summary: original,
    target,
  });
  original.sourceId = "local:changed";
  original.changes[0]!.afterSha256 = "e".repeat(64);
  target.owner = "changed";
  const result = await pending;
  expect(result.results).toMatchObject([
    { changeId, status: "failed", diagnostics: [{ code: "invalid-response" }] },
  ]);
  expect(result.retryableSummary).toEqual(summary);
  expect(observedSource).toContain("https&#58;//github.com/example/materials");
  expect(observedSource).not.toContain("local:changed");
});

test("reaching the page bound never turns an incomplete search into an issue mutation", async () => {
  let mutations = 0;
  const mutate = async () => {
    mutations++;
    return issue(1, "");
  };
  const result = await host.deliverMaterialChange(
    configured({
      listIssues: async () => ({ issues: [], hasNextPage: true }),
      createIssue: mutate,
      updateIssue: mutate,
    }),
  );
  expect(result.results).toMatchObject([
    { status: "failed", diagnostics: [{ code: "incomplete-lookup" }] },
  ]);
  expect(mutations).toBe(0);
});

test("refreshing a managed section retains its safe prior-item link", async () => {
  const priorUrl = "https://github.com/example/tracker/issues/2";
  let updated = "";
  const result = await host.deliverMaterialChange(
    configured({
      listIssues: async () => ({
        issues: [issue(5, managed().replace("Old description", `Prior item change: ${priorUrl}`))],
        hasNextPage: false,
      }),
      createIssue: async () => {
        throw new Error("Must update");
      },
      updateIssue: async ({ body }) => {
        updated = body;
        return issue(5, body);
      },
    }),
  );
  expect(result.results[0]?.status).toBe("updated");
  expect(updated).toContain(`Prior item change: ${priorUrl}`);
});

test("GitHub's canonical owner and repository case matches the configured target case-insensitively", async () => {
  let stored: ReturnType<typeof issue> | undefined;
  const transport: GitHubTransport = {
    listIssues: async () => ({ issues: stored ? [stored] : [], hasNextPage: false }),
    createIssue: async ({ body }) => {
      stored = issue(6, body);
      return stored;
    },
    updateIssue: async ({ body }) => {
      stored = issue(6, body);
      return stored;
    },
  };
  const mixedCase = {
    ...configured(transport),
    target: { owner: "Example", repository: "TRACKER" },
  };
  const first = await host.deliverMaterialChange(mixedCase);
  expect(first.results).toMatchObject([
    { status: "created", issueUrl: "https://github.com/example/tracker/issues/6" },
  ]);
  const repeated = await host.deliverMaterialChange(mixedCase);
  expect(repeated.results).toMatchObject([
    { status: "updated", issueUrl: "https://github.com/example/tracker/issues/6" },
  ]);
});

test.each([
  "https://github.com/other/tracker/issues/6",
  "https://github.com/example/tracker/issues/7",
  "https://github.com:443/example/tracker/issues/6",
  "https://user@github.com/example/tracker/issues/6",
  "https://github.com/example/tracker/issues/6?x=1",
  "https://github.com/example/tracker/issues/6#top",
  "http://github.com/example/tracker/issues/6",
  "https://github.com/example/tracker/pull/6",
])("a created issue URL outside the target route is not delivery: %s", async (url) => {
  const result = await host.deliverMaterialChange(
    configured({
      listIssues: async () => ({ issues: [], hasNextPage: false }),
      createIssue: async ({ body }) => ({ ...issue(6, body), html_url: url }),
      updateIssue: async () => {
        throw new Error("Must create");
      },
    }),
  );
  expect(result.results).toMatchObject([
    { status: "failed", diagnostics: [{ code: "invalid-response" }] },
  ]);
  expect(result.results[0]?.issueUrl).toBeUndefined();
});

test("a failed later lookup page never becomes permission to create", async () => {
  let mutations = 0;
  const mutate = async () => {
    mutations++;
    return issue(1, "");
  };
  const result = await host.deliverMaterialChange(
    configured({
      listIssues: async ({ page }) => {
        if (page === 2) throw new Error("page two unavailable");
        return { issues: [issue(1, "human")], hasNextPage: true };
      },
      createIssue: mutate,
      updateIssue: mutate,
    }),
  );
  expect(result.results).toMatchObject([
    { status: "failed", diagnostics: [{ code: "delivery-failed" }] },
  ]);
  expect(result.retryableSummary).toEqual(summary);
  expect(mutations).toBe(0);
});

test("the first failed mutation stops later mutations while logical dispositions still report", async () => {
  const entry = (itemId: string) => ({ ...summary.changes[0]!, itemId });
  const several: MaterialChange = {
    ...summary,
    changes: [entry("skill.alpha"), entry("skill.beta"), entry("skill.gamma")],
  };
  const disabled = await host.deliverMaterialChange({ summary: several, enabled: false });
  const ids = disabled.results.map((result) => result.changeId);
  // Independent item-key oracle: ASCII canonical JSON equals sorted-key JSON text.
  const betaKey = createHash("sha256")
    .update(
      JSON.stringify({
        domain: "aih.scan.material-item.v1",
        itemId: "skill.beta",
        sourceId: summary.sourceId,
      }),
    )
    .digest("hex");
  const markers = `<!-- aihq-scan-change:v1 ${ids[1]} -->\n<!-- aihq-scan-item:v1 ${betaKey} -->`;
  const closed = issue(3, `${start}\n${markers}\n${end}`, "closed");
  let creations = 0;
  const result = await host.deliverMaterialChange({
    ...configured({
      listIssues: async () => ({ issues: [closed], hasNextPage: false }),
      createIssue: async () => {
        creations++;
        throw new Error("connection reset after the request was sent");
      },
      updateIssue: async () => {
        throw new Error("No update expected");
      },
    }),
    summary: several,
  });
  expect(creations).toBe(1);
  expect(result.results.map((entry) => [entry.status, entry.diagnostics[0]?.code])).toEqual([
    ["failed", "delivery-failed"],
    ["closed-disposition", undefined],
    ["failed", "not-attempted"],
  ]);
  expect(result.retryableSummary).toEqual(several);
});
