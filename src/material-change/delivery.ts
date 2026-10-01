import type { Diagnostic } from "../assessment/types.js";
import type {
  DeliverMaterialChangeInput,
  GitHubTarget,
  GitHubTransport,
  MaterialChangeDeliveryEntry,
  MaterialChangeDeliveryResult,
} from "./delivery-types.js";
import { GitHubResponseError, githubTransport } from "./github.js";
import { identityForChange } from "./identity.js";
import type { MaterialChange, MaterialChangeEntry } from "./types.js";
import { parseMaterialChange } from "./validation.js";

const start = "<!-- aihq-scan-managed:v1 -->";
const end = "<!-- /aihq-scan-managed:v1 -->";
/** Adapter bound on one listed issue body: long human text fits; the lookup budget still applies. */
const maxIssueBodyBytes = 256 * 1024;
const issueUrlPattern =
  /^https:\/\/github\.com\/([A-Za-z0-9-]+)\/([A-Za-z0-9._-]+)\/issues\/([1-9][0-9]*)$/;
interface Issue {
  number: number;
  body: string;
  state: "open" | "closed";
  url: string;
  managed?: { changeId: string; itemKey: string; begin: number; finish: number };
}
class DeliveryError extends Error {
  constructor(readonly code: string) {
    super("Material delivery could not be confirmed safely.");
  }
}
function diagnostic(error: unknown): Diagnostic {
  return {
    code:
      error instanceof DeliveryError || error instanceof GitHubResponseError
        ? error.code
        : "delivery-failed",
    detail:
      "Material delivery could not be confirmed safely; retry the retained summary after resolving the cause.",
  };
}
async function boundedCall<T>(
  deadline: number,
  invoke: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  const milliseconds = Math.min(10000, deadline - Date.now());
  if (milliseconds <= 0) throw new DeliveryError("delivery-timeout");
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new DeliveryError("delivery-timeout"));
    }, milliseconds);
  });
  try {
    return await Promise.race([Promise.resolve().then(() => invoke(controller.signal)), timeout]);
  } finally {
    clearTimeout(timer);
  }
}
function parseIssue(value: unknown, target: GitHubTarget): Issue {
  const entry = value as Record<string, unknown>;
  if (
    !entry ||
    typeof entry !== "object" ||
    !Number.isSafeInteger(entry.number) ||
    (entry.number as number) < 1 ||
    (entry.state !== "open" && entry.state !== "closed") ||
    (entry.body !== null && typeof entry.body !== "string")
  )
    throw new DeliveryError("invalid-response");
  if (issueNumberOf(entry.html_url, target) !== entry.number)
    throw new DeliveryError("invalid-response");
  const url = entry.html_url as string;
  const body = (entry.body as string | null) ?? "";
  if (Buffer.byteLength(body, "utf8") > maxIssueBodyBytes)
    throw new DeliveryError("incomplete-lookup");
  const managed = parseSection(body);
  return { number: entry.number as number, body, state: entry.state, url, managed };
}
/**
 * The issue number of an exact `https://github.com/<owner>/<repository>/issues/<n>` URL for
 * the configured target. GitHub owner and repository names are not case sensitive, and its
 * responses use the canonical case, so they compare ASCII-case-insensitively. No port,
 * userinfo, query, fragment or other route is admitted.
 */
function issueNumberOf(value: unknown, target: GitHubTarget): number | undefined {
  if (typeof value !== "string" || value.length > 2048) return undefined;
  const match = issueUrlPattern.exec(value);
  if (
    !match ||
    match[1]!.toLowerCase() !== target.owner.toLowerCase() ||
    match[2]!.toLowerCase() !== target.repository.toLowerCase()
  )
    return undefined;
  const number = Number(match[3]);
  return Number.isSafeInteger(number) ? number : undefined;
}
function parseSection(body: string): Issue["managed"] {
  if (!body.includes("aihq-scan-")) return undefined;
  const markerHints = ["aihq-scan-managed:", "aihq-scan-change:", "aihq-scan-item:"];
  if (!markerHints.some((hint) => body.includes(hint))) return undefined;
  const changes = [...body.matchAll(/<!-- aihq-scan-change:v1 (change:sha256:[a-f0-9]{64}) -->/g)];
  const items = [...body.matchAll(/<!-- aihq-scan-item:v1 ([a-f0-9]{64}) -->/g)];
  const begin = body.indexOf(start),
    finish = body.indexOf(end) + end.length;
  if (
    body.split(start).length !== 2 ||
    body.split(end).length !== 2 ||
    changes.length !== 1 ||
    items.length !== 1 ||
    body.split(markerHints[0]!).length !== 3 ||
    body.split(markerHints[1]!).length !== 2 ||
    body.split(markerHints[2]!).length !== 2 ||
    finish <= begin + start.length ||
    changes[0]!.index! < begin + start.length ||
    items[0]!.index! < begin + start.length ||
    changes[0]!.index! + changes[0]![0].length > finish - end.length ||
    items[0]!.index! + items[0]![0].length > finish - end.length
  )
    throw new DeliveryError("invalid-managed-section");
  return { changeId: changes[0]![1]!, itemKey: items[0]![1]!, begin, finish };
}
function display(value: string): string {
  return Array.from(value, (character) =>
    /^[A-Za-z0-9 ./]$/.test(character) ? character : `&#${character.codePointAt(0)};`,
  ).join("");
}
function retainedPrior(match: Issue, target: GitHubTarget): string | undefined {
  const region = match.body.slice(match.managed?.begin, match.managed?.finish);
  const links = [...region.matchAll(/^Prior item change: (\S+)\r?$/gm)];
  if (links.length !== 1) return undefined;
  const link = links[0]?.[1],
    number = issueNumberOf(link, target);
  return number !== undefined && number < match.number ? link : undefined;
}
function section(
  summary: MaterialChange,
  entry: MaterialChangeEntry,
  changeId: string,
  itemKey: string,
  prior?: string,
): string {
  return `${start}\n<!-- aihq-scan-change:v1 ${changeId} -->\n<!-- aihq-scan-item:v1 ${itemKey} -->\nMaterial ${entry.kind}: ${display(entry.itemId)}\nSource: ${display(summary.sourceId)}\nProjection: ${summary.materialProjection}\nBefore: ${entry.beforeSha256 ?? "absent"}\nAfter: ${entry.afterSha256 ?? "absent"}\nCompared assessments: ${summary.beforeScanId ?? "initial"} → ${summary.afterScanId}\n${prior ? `Prior item change: ${prior}\n` : ""}${end}`;
}
async function listIssues(
  transport: GitHubTransport,
  target: GitHubTarget,
  credential: string,
  deadline: number,
): Promise<Issue[]> {
  const issues: Issue[] = [];
  const seen = new Set<number>();
  let totalBytes = 0;
  for (let page = 1; page <= 20; page++) {
    const response = await boundedCall(deadline, (signal) =>
      transport.listIssues({ target: { ...target }, credential, page, perPage: 100, signal }),
    );
    if (
      !response ||
      !Array.isArray(response.issues) ||
      response.issues.length > 100 ||
      typeof response.hasNextPage !== "boolean"
    )
      throw new DeliveryError("incomplete-lookup");
    for (const value of response.issues) {
      if (value && typeof value === "object" && "pull_request" in value) continue;
      const parsed = parseIssue(value, target);
      totalBytes += Buffer.byteLength(parsed.body, "utf8");
      if (seen.has(parsed.number) || totalBytes > 8 * 1024 * 1024)
        throw new DeliveryError("incomplete-lookup");
      seen.add(parsed.number);
      issues.push(parsed);
    }
    if (!response.hasNextPage) return issues;
  }
  throw new DeliveryError("incomplete-lookup");
}
export async function deliverMaterialChange(
  input: DeliverMaterialChangeInput,
): Promise<MaterialChangeDeliveryResult> {
  const deadline = Date.now() + 60000;
  const summary = parseMaterialChange(input.summary);
  const enabled = input.enabled,
    target = input.target
      ? { owner: input.target.owner, repository: input.target.repository }
      : undefined,
    credential = input.credential,
    transport = input.transport ?? githubTransport;
  const validTarget =
    target &&
    typeof target.owner === "string" &&
    /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(target.owner) &&
    typeof target.repository === "string" &&
    /^[A-Za-z0-9._-]{1,100}$/.test(target.repository) &&
    target.repository !== "." &&
    target.repository !== "..";
  const validCredential =
    typeof credential === "string" &&
    credential.length <= 4096 &&
    /^[\x21-\x7e]+$/.test(credential);
  const code =
    enabled !== true
      ? "delivery-disabled"
      : !target
        ? "missing-target"
        : !credential
          ? "missing-credential"
          : !validTarget || !validCredential
            ? "invalid-configuration"
            : undefined;
  const identities = await Promise.all(
    summary.changes.map((entry) => identityForChange(summary, entry)),
  );
  const refuse = (diagnostics: Diagnostic[]): MaterialChangeDeliveryResult => ({
    results: identities.map(({ changeId }) => ({ changeId, status: "failed", diagnostics })),
    diagnostics,
    retryableSummary: summary,
  });
  if (code)
    return refuse([
      { code, detail: "Material delivery requires explicit enablement, target and credential." },
    ]);
  if (!summary.changes.length) return { results: [], diagnostics: [] };
  let issues: Issue[];
  try {
    issues = await listIssues(transport, target!, credential!, deadline);
  } catch (error) {
    return refuse([diagnostic(error)]);
  }
  const results: MaterialChangeDeliveryEntry[] = [];
  // A failed or uncertain mutation (which may still have committed) says the tracker or its
  // transport is unhealthy: later changes needing a mutation are not attempted, while logical
  // dispositions from the completed lookup still report. Retry is caller-driven.
  let halted = false;
  const mutate = async (work: () => Promise<Issue>): Promise<Issue> => {
    if (halted) throw new DeliveryError("not-attempted");
    try {
      return await work();
    } catch (error) {
      halted = true;
      throw error;
    }
  };
  for (const [index, entry] of summary.changes.entries()) {
    const { changeId, itemKey } = identities[index]!;
    try {
      const matches = issues.filter((issue) => issue.managed?.changeId === changeId);
      if (matches.length > 1) throw new DeliveryError("ambiguous-match");
      const match = matches[0];
      if (match) {
        if (match.managed!.itemKey !== itemKey) throw new DeliveryError("invalid-managed-section");
        if (match.state === "closed") {
          results.push({
            changeId,
            status: "closed-disposition",
            issueUrl: match.url,
            diagnostics: [],
          });
          continue;
        }
        const replacement = section(
          summary,
          entry,
          changeId,
          itemKey,
          retainedPrior(match, target!),
        );
        const body =
          match.body.slice(0, match.managed!.begin) +
          replacement +
          match.body.slice(match.managed!.finish);
        const updated = await mutate(async () => {
          const value = parseIssue(
            await boundedCall(deadline, (signal) =>
              transport.updateIssue({
                target: { ...target! },
                credential: credential!,
                issueNumber: match.number,
                body,
                signal,
              }),
            ),
            target!,
          );
          if (value.number !== match.number || value.state !== "open" || value.body !== body)
            throw new DeliveryError("invalid-response");
          return value;
        });
        results.push({ changeId, status: "updated", issueUrl: updated.url, diagnostics: [] });
        continue;
      }
      const prior = issues
        .filter((issue) => issue.managed?.itemKey === itemKey)
        .sort((a, b) => b.number - a.number)[0];
      const body = section(summary, entry, changeId, itemKey, prior?.url);
      const created = await mutate(async () => {
        const value = parseIssue(
          await boundedCall(deadline, (signal) =>
            transport.createIssue({
              target: { ...target! },
              credential: credential!,
              title: `Material ${entry.kind}: ${changeId}`,
              body,
              signal,
            }),
          ),
          target!,
        );
        if (value.state !== "open" || value.body !== body)
          throw new DeliveryError("invalid-response");
        return value;
      });
      results.push({ changeId, status: "created", issueUrl: created.url, diagnostics: [] });
    } catch (error) {
      results.push({ changeId, status: "failed", diagnostics: [diagnostic(error)] });
    }
  }
  return {
    results,
    diagnostics: [],
    ...(results.some((entry) => entry.status === "failed") ? { retryableSummary: summary } : {}),
  };
}
