import { advisoryCodes } from "../contracts/codes.js";
import type { Problem } from "../contracts/formats.js";
import { limits } from "../contracts/limits.js";
import { NPM_SCOPE_PATTERN } from "../contracts/npm.js";
import { sanitizeText } from "../contracts/text.js";
import { readBoundedText } from "../shared/bounded-response.js";
import { isRecord, type Json } from "../shared/values.js";

/** One dependency to check, as listed in a summary's `dependencies` (`file` is optional). */
export interface AdvisoryDependency {
  readonly ecosystem: "npm" | "pypi";
  readonly name: string;
  /** The version exactly as written; only an exact version is ever sent. */
  readonly version: string | null;
  readonly file?: string;
}

/** One advisory as the service supplied it; `severity` and `fixedIn` only when supplied. */
export interface Advisory {
  readonly id: string;
  readonly severity?: string;
  readonly summary?: string;
  readonly fixedIn?: string;
}

export type NotCheckedReason =
  | "internal scope"
  | "no exact version"
  | "advisory service unreachable";

type Echo = Readonly<{
  ecosystem: AdvisoryDependency["ecosystem"];
  name: string;
  version: string | null;
  file?: string;
}>;

export type AdvisoryResult =
  | (Echo & Readonly<{ state: "none-known" }>)
  | (Echo &
      Readonly<{
        state: "vulnerable";
        /** `trust.known-vulnerability`: only ever used here, never in a scan or score. */
        code: (typeof advisoryCodes)[number];
        advisories: readonly Advisory[];
      }>)
  | (Echo & Readonly<{ state: "not-checked"; reason: NotCheckedReason }>);

export type CheckAdvisoriesResult =
  | Readonly<{ status: "ok"; checkedAt: string; results: readonly AdvisoryResult[] }>
  | Problem;

export type AdvisoryFetch = (url: string, init: RequestInit) => Promise<Response>;

export interface CheckAdvisoriesOptions {
  /** npm scopes (`@acme`) whose packages are never sent. */
  readonly internalScopes?: readonly string[];
  /** Cancels the check (`refused`, reason `cancelled`). */
  readonly signal?: AbortSignal;
  /** The advisory service base URL; default {@link osvEndpoint}. */
  readonly endpoint?: string;
  /** The HTTP client; default the global `fetch`. */
  readonly fetch?: AdvisoryFetch;
  /** The clock for `checkedAt`. */
  readonly now?: () => Date;
}

/** The public OSV service that `checkAdvisories` asks by default. */
export const osvEndpoint = "https://api.osv.dev";

const ECOSYSTEMS = Object.freeze({ npm: "npm", pypi: "PyPI" } as const);
/** OSV accepts at most 1000 queries per batch. */
const BATCH = 1000;
const MAX_PAGES = 16;
const REQUEST_TIMEOUT_MS = 60_000;
/** Bytes read from one advisory-service response (streamed; the read stops past it). */
const MAX_RESPONSE_BYTES = 32 * 1024 * 1024;
const ADVISORY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const NPM_EXACT =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const PEP440_EXACT =
  /^(?:\d+!)?\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?(?:\+[a-z0-9]+(?:\.[a-z0-9]+)*)?$/i;

const invalid = (detail: string): Problem =>
  Object.freeze({ status: "invalid" as const, reason: "schema", detail });

/** The exact version to send, or undefined for ranges, tags, URLs and anything else. */
export function exactVersion(
  ecosystem: AdvisoryDependency["ecosystem"],
  version: string | null,
): string | undefined {
  if (version === null) return undefined;
  if (ecosystem === "npm") return NPM_EXACT.test(version) ? version : undefined;
  const pinned = /^===?\s*(\S+)$/.exec(version.trim());
  const candidate = pinned === null ? version.trim() : (pinned[1] as string);
  return PEP440_EXACT.test(candidate) ? candidate : undefined;
}

function isInternal(dependency: AdvisoryDependency, scopes: readonly string[]): boolean {
  if (dependency.ecosystem !== "npm") return false;
  const name = dependency.name.toLowerCase();
  return scopes.some((scope) => name.startsWith(`${scope}/`));
}

function validDependencies(value: unknown): readonly AdvisoryDependency[] | Problem {
  if (!Array.isArray(value)) return invalid("dependencies must be an array");
  for (const [index, entry] of value.entries()) {
    const at = `dependencies[${index}]`;
    if (typeof entry !== "object" || entry === null) return invalid(`${at} must be an object`);
    const { ecosystem, name, version, file } = entry as Record<string, unknown>;
    if (ecosystem !== "npm" && ecosystem !== "pypi")
      return invalid(`${at}.ecosystem must be npm or pypi`);
    if (typeof name !== "string" || name.length === 0 || name.length > 214)
      return invalid(`${at}.name must be a package name`);
    if (version !== null && typeof version !== "string")
      return invalid(`${at}.version must be a string or null`);
    if (file !== undefined && typeof file !== "string")
      return invalid(`${at}.file must be a string`);
  }
  return value as readonly AdvisoryDependency[];
}

class Unreachable extends Error {}
class Cancelled extends Error {}

const isObject = isRecord<Json>;

async function request(
  fetcher: AdvisoryFetch,
  url: string,
  init: RequestInit,
  signal: AbortSignal | undefined,
): Promise<unknown> {
  if (signal?.aborted) throw new Cancelled();
  // Browser-like realms may lack timers or AbortController; the caller's signal still applies.
  const controller = typeof AbortController === "function" ? new AbortController() : undefined;
  const abort = () => controller?.abort();
  signal?.addEventListener("abort", abort, { once: true });
  const timer =
    controller !== undefined && typeof setTimeout === "function"
      ? setTimeout(abort, REQUEST_TIMEOUT_MS)
      : undefined;
  try {
    const response = await fetcher(url, {
      ...init,
      credentials: "omit",
      redirect: "error",
      cache: "no-store",
      referrerPolicy: "no-referrer",
      ...(controller !== undefined
        ? { signal: controller.signal }
        : signal !== undefined
          ? { signal }
          : {}),
    });
    if (!response.ok) {
      await response.body?.cancel().catch(() => {});
      throw new Unreachable();
    }
    const text = await readBoundedText(response, MAX_RESPONSE_BYTES);
    if (text === undefined) throw new Unreachable();
    return JSON.parse(text);
  } catch (error) {
    if (signal?.aborted) throw new Cancelled();
    throw error instanceof Unreachable ? error : new Unreachable();
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    signal?.removeEventListener("abort", abort);
  }
}

interface Query {
  readonly ecosystem: AdvisoryDependency["ecosystem"];
  readonly name: string;
  readonly version: string;
}

/** Asks `/v1/querybatch` for every query (following page tokens) → advisory ids per query. */
async function queryIds(
  queries: readonly Query[],
  base: string,
  fetcher: AdvisoryFetch,
  signal: AbortSignal | undefined,
): Promise<string[][]> {
  const ids: string[][] = queries.map(() => []);
  for (let start = 0; start < queries.length; start += BATCH) {
    let pending = queries.slice(start, start + BATCH).map((query, offset) => ({
      index: start + offset,
      query,
      token: undefined as string | undefined,
    }));
    for (let page = 0; pending.length > 0; page += 1) {
      if (page >= MAX_PAGES) throw new Unreachable();
      const body = JSON.stringify({
        queries: pending.map(({ query, token }) => ({
          package: { name: query.name, ecosystem: ECOSYSTEMS[query.ecosystem] },
          version: query.version,
          ...(token === undefined ? {} : { page_token: token }),
        })),
      });
      const answer = await request(
        fetcher,
        `${base}/v1/querybatch`,
        { method: "POST", headers: { "content-type": "application/json" }, body },
        signal,
      );
      if (!isObject(answer) || !Array.isArray(answer.results)) throw new Unreachable();
      const results = answer.results;
      if (results.length !== pending.length) throw new Unreachable();
      const next: typeof pending = [];
      for (const [position, entry] of pending.entries()) {
        const result = results[position];
        if (!isObject(result)) throw new Unreachable();
        const vulns = result.vulns ?? [];
        if (!Array.isArray(vulns)) throw new Unreachable();
        for (const vuln of vulns) {
          if (!isObject(vuln) || typeof vuln.id !== "string" || !ADVISORY_ID.test(vuln.id))
            throw new Unreachable();
          const list = ids[entry.index] as string[];
          if (!list.includes(vuln.id)) list.push(vuln.id);
        }
        const token = result.next_page_token;
        if (typeof token === "string" && token.length > 0) next.push({ ...entry, token });
        else if (token !== undefined && token !== null && token !== "") throw new Unreachable();
      }
      pending = next;
    }
  }
  return ids;
}

/** Compares dotted numeric release versions; undefined when either is not purely numeric. */
function compareNumeric(left: string, right: string): number | undefined {
  const numeric = /^\d+(?:\.\d+)*$/;
  if (!numeric.test(left) || !numeric.test(right)) return undefined;
  const a = left.split(".").map(Number);
  const b = right.split(".").map(Number);
  for (let index = 0; index < Math.max(a.length, b.length); index += 1) {
    const difference = (a[index] ?? 0) - (b[index] ?? 0);
    if (difference !== 0) return Math.sign(difference);
  }
  return 0;
}

/**
 * The fixed version the record supplies for this package: the only distinct `fixed` event, or
 * with several, the lowest release above the checked version when every candidate compares
 * numerically. Otherwise none: a fix is never guessed.
 */
function fixedIn(record: Record<string, Json>, query: Query): string | undefined {
  const fixes = new Set<string>();
  const affected = Array.isArray(record.affected) ? record.affected : [];
  for (const entry of affected) {
    if (!isObject(entry) || !isObject(entry.package)) continue;
    const pkg = entry.package;
    if (pkg.ecosystem !== ECOSYSTEMS[query.ecosystem]) continue;
    const same =
      query.ecosystem === "npm"
        ? pkg.name === query.name
        : typeof pkg.name === "string" && normalPypi(pkg.name) === normalPypi(query.name);
    if (!same || !Array.isArray(entry.ranges)) continue;
    for (const range of entry.ranges) {
      if (!isObject(range) || !Array.isArray(range.events)) continue;
      for (const event of range.events)
        if (isObject(event) && typeof event.fixed === "string" && event.fixed.length > 0)
          fixes.add(event.fixed);
    }
  }
  const all = [...fixes];
  if (all.length === 1) return all[0];
  if (all.length === 0) return undefined;
  const above = all.filter((fix) => compareNumeric(fix, query.version) === 1);
  if (above.length === 0 || all.some((fix) => compareNumeric(fix, query.version) === undefined))
    return undefined;
  return above.sort((a, b) => compareNumeric(a, b) as number)[0];
}

const normalPypi = (name: string) => name.toLowerCase().replace(/[-_.]+/g, "-");

function advisoryOf(record: unknown, id: string, query: Query): Advisory | null {
  if (!isObject(record) || record.id !== id) throw new Unreachable();
  if (typeof record.withdrawn === "string" && record.withdrawn.length > 0) return null;
  const specific = isObject(record.database_specific) ? record.database_specific : {};
  const severity = typeof specific.severity === "string" ? specific.severity : undefined;
  const text =
    typeof record.summary === "string" && record.summary.trim().length > 0
      ? record.summary
      : typeof record.details === "string" && record.details.trim().length > 0
        ? record.details
        : undefined;
  const fix = fixedIn(record, query);
  return Object.freeze({
    id,
    ...(severity === undefined ? {} : { severity: sanitizeText(severity, 32) }),
    ...(text === undefined
      ? {}
      : { summary: sanitizeText(text.trim(), limits.output.findingText) }),
    ...(fix === undefined ? {} : { fixedIn: sanitizeText(fix, 128) }),
  });
}

const checkedAtOf = (date: Date) => `${date.toISOString().slice(0, 19)}Z`;

/**
 * Checks dependencies against live advisories (OSV by default). Never signed, never part of a
 * scan and never changes a score. Packages under `internalScopes` and versions that are not
 * exact are never sent; whether to call it for private content is the caller's choice.
 * Returns one result per dependency, in order. An unreachable or malformed service answer
 * still returns `status: ok` with every entry `not-checked` ("advisory service unreachable").
 * Browser-safe: uses only `fetch`.
 */
export async function checkAdvisories(
  dependencies: readonly AdvisoryDependency[],
  options: CheckAdvisoriesOptions = {},
): Promise<CheckAdvisoriesResult> {
  const valid = validDependencies(dependencies);
  if ("status" in valid) return valid;
  const scopes = options.internalScopes ?? [];
  if (
    !Array.isArray(scopes) ||
    scopes.some((scope) => typeof scope !== "string" || !NPM_SCOPE_PATTERN.test(scope))
  )
    return invalid("internalScopes must be npm scopes such as @acme");
  let base = osvEndpoint;
  if (options.endpoint !== undefined) {
    let url: URL;
    try {
      url = new URL(options.endpoint);
    } catch {
      return invalid("endpoint must be an http(s) URL");
    }
    if (
      (url.protocol !== "https:" && url.protocol !== "http:") ||
      url.username !== "" ||
      url.password !== "" ||
      url.search !== "" ||
      url.hash !== ""
    )
      return invalid("endpoint must be an http(s) URL without credentials, query or fragment");
    base = url.href.replace(/\/+$/, "");
  }
  const fetcher: AdvisoryFetch | undefined =
    options.fetch ?? (typeof fetch === "function" ? (url, init) => fetch(url, init) : undefined);
  const checkedAt = checkedAtOf((options.now ?? (() => new Date()))());
  const echo = (dependency: AdvisoryDependency): Echo =>
    Object.freeze({
      ecosystem: dependency.ecosystem,
      name: dependency.name,
      version: dependency.version,
      ...(dependency.file === undefined ? {} : { file: dependency.file }),
    });

  // Decide locally what may be sent; one query per distinct exact package version.
  const queries: Query[] = [];
  const keyOf = (query: Query) => `${query.ecosystem}\u0000${query.name}\u0000${query.version}`;
  const queryIndex = new Map<string, number>();
  const plan = valid.map((dependency) => {
    if (isInternal(dependency, scopes)) return { reason: "internal scope" as const };
    const version = exactVersion(dependency.ecosystem, dependency.version);
    if (version === undefined) return { reason: "no exact version" as const };
    const query = { ecosystem: dependency.ecosystem, name: dependency.name, version };
    const key = keyOf(query);
    if (!queryIndex.has(key)) {
      queryIndex.set(key, queries.length);
      queries.push(query);
    }
    return { query: queryIndex.get(key) as number };
  });

  let found: (readonly Advisory[])[] | undefined;
  if (queries.length > 0) {
    try {
      if (fetcher === undefined) throw new Unreachable();
      const ids = await queryIds(queries, base, fetcher, options.signal);
      const records = new Map<string, unknown>();
      for (const id of [...new Set(ids.flat())]) {
        records.set(
          id,
          await request(
            fetcher,
            `${base}/v1/vulns/${encodeURIComponent(id)}`,
            { method: "GET" },
            options.signal,
          ),
        );
      }
      found = queries.map((query, index) =>
        (ids[index] as string[])
          .map((id) => advisoryOf(records.get(id), id, query))
          .filter((advisory): advisory is Advisory => advisory !== null),
      );
    } catch (error) {
      if (error instanceof Cancelled)
        return Object.freeze({
          status: "refused" as const,
          reason: "cancelled",
          detail: "the advisory check was cancelled",
        });
      found = undefined;
    }
  }

  const results = valid.map((dependency, index): AdvisoryResult => {
    const step = plan[index] as { reason: NotCheckedReason } | { query: number };
    if ("reason" in step)
      return Object.freeze({ ...echo(dependency), state: "not-checked", reason: step.reason });
    const advisories = found?.[step.query];
    if (advisories === undefined)
      return Object.freeze({
        ...echo(dependency),
        state: "not-checked",
        reason: "advisory service unreachable",
      });
    if (advisories.length === 0) return Object.freeze({ ...echo(dependency), state: "none-known" });
    return Object.freeze({
      ...echo(dependency),
      state: "vulnerable",
      code: advisoryCodes[0],
      advisories: Object.freeze([...advisories]),
    });
  });
  return Object.freeze({ status: "ok" as const, checkedAt, results: Object.freeze(results) });
}
