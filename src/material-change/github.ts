import {
  decodeStrictUtf8V1,
  parseStrictJsonV1,
  StrictJsonBoundErrorV1,
} from "../assessment/strict-json.js";
import type { GitHubRequestContext, GitHubTransport } from "./delivery-types.js";

export class GitHubResponseError extends Error {
  constructor(
    readonly code:
      | "invalid-response"
      | "response-limit"
      | "unauthorized"
      | "forbidden"
      | "rate-limited"
      | "not-found",
  ) {
    super("GitHub delivery response could not be validated safely.");
  }
}
const maxResponseBytes = 2 * 1024 * 1024;

/** Classifies a refused status from the status line and headers only, never the body. */
function refusal(response: Response): GitHubResponseError {
  const { status, headers } = response;
  if (status === 401) return new GitHubResponseError("unauthorized");
  if (
    status === 429 ||
    (status === 403 && (headers.get("x-ratelimit-remaining") === "0" || headers.has("retry-after")))
  )
    return new GitHubResponseError("rate-limited");
  if (status === 403) return new GitHubResponseError("forbidden");
  if (status === 404) return new GitHubResponseError("not-found");
  return new GitHubResponseError("invalid-response");
}
/**
 * GitHub data is third-party human content, not AIHQ control JSON: it may hold non-NFC text
 * and ordinary finite numbers. Well-formed UTF-8/Unicode, duplicate-key refusal, nesting and
 * the strict parser's number-loss policy still apply.
 */
function parseResponse(bytes: Uint8Array): unknown {
  try {
    return parseStrictJsonV1(decodeStrictUtf8V1(bytes, "GitHub response"), "GitHub response", {
      requireNfc: false,
    });
  } catch (error) {
    throw new GitHubResponseError(
      error instanceof StrictJsonBoundErrorV1 ? "response-limit" : "invalid-response",
    );
  }
}

async function request(
  context: GitHubRequestContext,
  method: "GET" | "POST" | "PATCH",
  suffix: string,
  payload?: { title?: string; body: string },
): Promise<{ value: unknown; link: string | null }> {
  const target = context.target;
  const response = await fetch(
    `https://api.github.com/repos/${target.owner}/${target.repository}/issues${suffix}`,
    {
      method,
      signal: context.signal,
      redirect: "error",
      credentials: "omit",
      headers: {
        Authorization: `Bearer ${context.credential}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        ...(payload ? { "Content-Type": "application/json" } : {}),
      },
      ...(payload ? { body: JSON.stringify(payload) } : {}),
    },
  );
  const reader = response.body?.getReader();
  if (!reader) throw new GitHubResponseError("invalid-response");
  try {
    if (
      response.redirected ||
      (response.url && !response.url.startsWith("https://api.github.com/"))
    )
      throw new GitHubResponseError("invalid-response");
    if (!response.ok) throw refusal(response);
    const length = response.headers.get("content-length");
    if (length !== null && (!/^[0-9]+$/.test(length) || BigInt(length) > BigInt(maxResponseBytes)))
      throw new GitHubResponseError("response-limit");
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      context.signal.throwIfAborted();
      const { done, value } = await reader.read();
      context.signal.throwIfAborted();
      if (done) break;
      total += value.byteLength;
      if (total > maxResponseBytes) throw new GitHubResponseError("response-limit");
      chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return { value: parseResponse(bytes), link: response.headers.get("link") };
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}
function hasNextPage(link: string | null): boolean {
  if (link === null) return false;
  if (link.length > 8192) throw new GitHubResponseError("response-limit");
  const relations = new Set<string>();
  for (const entry of link.split(",")) {
    const match = /^\s*<https:\/\/[^<>]+>;\s*rel="(next|prev|first|last)"\s*$/.exec(entry);
    if (!match || relations.has(match[1]!)) throw new GitHubResponseError("invalid-response");
    relations.add(match[1]!);
  }
  // Never follow link URLs: GitHub may use its numeric repository route.
  // The next request is reconstructed at the fixed caller-selected target.
  return relations.has("next");
}
export const githubTransport: GitHubTransport = {
  async listIssues(input) {
    // Oldest first: issues created during the lookup append instead of shifting earlier pages.
    const response = await request(
      input,
      "GET",
      `?state=all&sort=created&direction=asc&per_page=${input.perPage}&page=${input.page}`,
    );
    if (!Array.isArray(response.value)) throw new GitHubResponseError("invalid-response");
    return { issues: response.value, hasNextPage: hasNextPage(response.link) };
  },
  async createIssue(input) {
    return (await request(input, "POST", "", { title: input.title, body: input.body })).value;
  },
  async updateIssue(input) {
    return (await request(input, "PATCH", `/${input.issueNumber}`, { body: input.body })).value;
  },
};
