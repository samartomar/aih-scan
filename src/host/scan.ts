import { createHash } from "node:crypto";
import { mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  assertOutputAbsent,
  ExclusiveOutputError,
  safeOutputParents,
  writeNewSafeOutput,
} from "../cli/exclusive-output.js";
import type { Problem } from "../contracts/formats.js";
import { keyFolderName, treeKeyOf } from "../contracts/git-tree.js";
import { limits } from "../contracts/limits.js";
import { remoteMcpFile } from "../contracts/remote-mcp.js";
import { type Coverage, type SummaryLabel, scoring } from "../contracts/risk.js";
import { type Dependency, type Kind, routeFile, type ToolId } from "../contracts/routing.js";
import {
  type ScanRequest,
  type SourceDescriptor,
  validateRequest,
  validateSource,
} from "../contracts/validate.js";
import { acquireGit } from "./acquire-git.js";
import { acquireNpm, type FetchLike, readNpmFile } from "./acquire-npm.js";
import { assessItem, routeFiles } from "./assess.js";
import { ciscoAdapter } from "./cisco.js";
import { discoverItems } from "./discover.js";
import { cloneCommit } from "./inventory.js";
import { type AiSetup, skillSpectorAdapter, skillSpectorAiSetup } from "./skillspector.js";
import { readFolder, type SnapshotFile, writeSnapshot } from "./snapshot.js";
import type { ToolAdapter } from "./tools.js";
import { trustLintAdapter } from "./trust-lint-tool.js";

export interface ScanOptions {
  /** A new folder (it must not exist) that receives the summaries and SARIF. */
  readonly outDir: string;
  /** Cancels the scan; results that finished are kept and the run is `cancelled`. */
  readonly signal?: AbortSignal;
  /** npm scopes treated as internal by the dependency-confusion check. */
  readonly internalScopes?: readonly string[];
}

/**
 * The source pin a result read: unsigned, outside the summary and SARIF. `item` is the
 * source-relative path of a discovered item (`.` for the whole source or the remaining files).
 * Remote addresses of local clones and credentials are never recorded.
 */
export type SourcePin =
  | Readonly<{ type: "folder"; path: string; item?: string; commit?: string }>
  | Readonly<{ type: "git"; repo: string; ref?: string; commit: string; item: string }>
  | Readonly<{ type: "npm"; package: string; version: string; tarballSha256: string }>
  | Readonly<{
      type: "npm-file";
      path: string;
      package: string;
      version: string;
      tarballSha256: string;
    }>
  | Readonly<{ type: "remote"; url: string }>;

/** What a source-route result is: a discovered item's kind, or the remaining files. */
export type ResultKind = Kind | "remaining-files";

export type ScanItemResult =
  | Readonly<{
      path: string;
      label?: string;
      kind?: ResultKind;
      scanKey: string;
      status: "ok";
      summaryPath: string;
      sarifPaths: readonly string[];
      source: SourcePin;
      /** Unsigned notes: why a tool did not run or was incomplete, AI availability. */
      notes?: readonly string[];
    }>
  | Readonly<{
      path: string;
      label?: string;
      kind?: ResultKind;
      status: "refused" | "invalid" | "cancelled";
      reason: string;
      detail?: string;
      source: SourcePin;
    }>;

/**
 * The source route's roll-up, unsigned and outside every summary. Its label is the highest
 * risk label of the scanned results (the remaining files count as one more item); NOT ASSESSED
 * when no result has a risk label, never SAFE. It is `partial` when a result is partial or when
 * kinds were filtered out ("not selected"); each selected result keeps its own coverage.
 */
export interface Rollup {
  readonly label: SummaryLabel;
  readonly coverage: Coverage;
  readonly reason?: string;
  /** Results scanned, the remaining files included. */
  readonly items: number;
  readonly partial: number;
  readonly notAssessed: number;
  /** Items found, by kind (selected or not). */
  readonly found: Readonly<Partial<Record<Kind, number>>>;
  /** Items and remaining files not scanned because of `kinds`. */
  readonly notSelected: Readonly<Partial<Record<ResultKind, number>>>;
  /** Files outside every item. */
  readonly remainingFiles: number;
}

/** How the source was obtained: `fetched` sources were downloaded before the scan, which is itself offline. */
export interface Acquisition {
  readonly type: SourceDescriptor["type"];
  readonly fetched: boolean;
}

/**
 * AI mode only: whether the caller's existing SkillSpector AI settings were usable. With
 * `available`, SkillSpector sent the scanned content to that AI; otherwise the scan stayed
 * static ("AI not available here") and `reason` says why. Never holds a credential.
 */
export type AiAvailability =
  | Readonly<{ status: "available"; provider: string; via: "cli" | "local" | "provider" }>
  | Readonly<{ status: "not-available"; reason: string }>;

type Extras = Readonly<{ rollup?: Rollup; acquisition?: Acquisition; ai?: AiAvailability }>;

export type ScanResult =
  | (Readonly<{ status: "ok"; results: readonly ScanItemResult[] }> & Extras)
  /** At least one item could not be scanned; the others were written. */
  | (Readonly<{
      status: "refused";
      reason: "items-not-scanned";
      results: readonly ScanItemResult[];
    }> &
      Extras)
  | (Readonly<{ status: "cancelled"; results: readonly ScanItemResult[] }> & Extras)
  | (Problem & Readonly<{ results: readonly ScanItemResult[] }> & Extras);

interface Written {
  readonly summaryPath: string;
  readonly sarifPaths: readonly string[];
  readonly label: SummaryLabel;
  readonly coverage: Coverage;
  readonly reason?: string;
  readonly notes: readonly string[];
}

/** An output folder shared by several scans of one run (the CLI's several targets). */
export interface SharedOutput {
  readonly outDir: string;
  dir?: string;
  readonly written: Map<string, Written>;
}

/** Internal seams for controlled adapters, environments and deterministic tests. */
export interface ScanInternals {
  readonly adapters?: Partial<Record<ToolId, ToolAdapter>>;
  readonly now?: () => Date;
  readonly timeoutMs?: number;
  readonly snapshotParent?: string;
  /** The HTTPS client for npm registry acquisition (a local stub in tests). */
  readonly fetch?: FetchLike;
  readonly sharedOutput?: SharedOutput;
  /** The environment analyzers are found in and AI settings are read from (default `process.env`). */
  readonly env?: Readonly<Record<string, string | undefined>>;
}

/** The AI availability `scan` reports for `mode: ai`, from the caller's SkillSpector settings. */
export function aiAvailability(setup: AiSetup): AiAvailability {
  return setup.available
    ? Object.freeze({ status: "available" as const, provider: setup.provider, via: setup.via })
    : Object.freeze({ status: "not-available" as const, reason: setup.reason });
}

const none: readonly ScanItemResult[] = Object.freeze([]);
const problem = (status: Problem["status"], reason: string, detail: string, extras: Extras = {}) =>
  Object.freeze({ status, reason, detail, results: none, ...extras }) as ScanResult;

function prepareOutput(outDir: unknown): string | ScanResult {
  if (typeof outDir !== "string" || outDir.length === 0)
    return problem("invalid", "out-dir", "outDir must be a new folder path");
  const target = resolve(outDir);
  try {
    assertOutputAbsent(target, "output folder");
    safeOutputParents(target);
    mkdirSync(target, { mode: 0o755 });
    return target;
  } catch (error) {
    if (error instanceof ExclusiveOutputError && error.problem === "exists")
      return problem(
        "refused",
        "output-exists",
        "the output folder already exists; Scan writes only into a new folder",
      );
    return problem("refused", "output-unavailable", "the output folder could not be created");
  }
}

interface Prepared {
  readonly path: string;
  readonly label?: string;
  readonly kind?: ResultKind;
  readonly files: readonly SnapshotFile[];
  readonly scanKey: string;
  readonly source: SourcePin;
}

type Entry = Prepared | ScanItemResult;
type Phase1 =
  | Readonly<{
      entries: Entry[];
      rollup?: Omit<Rollup, "label" | "coverage" | "reason" | "items" | "partial" | "notAssessed">;
      acquisition?: Acquisition;
    }>
  | ScanResult;

const labelOf = (label: string | undefined) => (label === undefined ? {} : { label });
const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");

/** Items route: each folder read as handed over, before anything is scanned. */
async function prepareItems(valid: ScanRequest, signal: AbortSignal): Promise<Phase1> {
  const items = valid.items ?? [];
  if (items.length > limits.input.items)
    return problem("refused", "items", `more than ${limits.input.items} items`);
  const pinOf = (path: string): SourcePin => Object.freeze({ type: "folder" as const, path });
  const entries: Entry[] = [];
  let usedBytes = 0;
  let usedFiles = 0;
  for (const entry of items) {
    if (signal.aborted) break;
    const read = readFolder(entry.path, {
      ...(entry.executable === undefined ? {} : { executable: entry.executable }),
      signal,
    });
    if (read.status !== "ok") {
      if (read.status === "refused" && read.reason === "cancelled") break;
      entries.push(
        Object.freeze({
          path: entry.path,
          ...labelOf(entry.label),
          status: read.status,
          reason: read.reason,
          detail: read.detail,
          source: pinOf(entry.path),
        }),
      );
      continue;
    }
    usedFiles += read.files.length;
    usedBytes += read.files.reduce((sum, file) => sum + file.bytes.length, 0);
    if (usedFiles > limits.input.files)
      return problem("refused", "files", `the request holds more than ${limits.input.files} files`);
    if (usedBytes > limits.input.sourceBytes)
      return problem(
        "refused",
        "source-size",
        `the request holds more than ${limits.input.sourceBytes} bytes`,
      );
    entries.push({
      path: entry.path,
      ...labelOf(entry.label),
      files: read.files,
      scanKey: await treeKeyOf(read.files),
      source: pinOf(entry.path),
    });
  }
  return { entries };
}

interface Acquired {
  readonly files: readonly SnapshotFile[];
  readonly pin: (item: string) => SourcePin;
  readonly fetched: boolean;
  /** The source is one item of this kind at this source-relative path (no discovery). */
  readonly single?: Readonly<{ kind: Kind; path: string }>;
}

async function acquire(
  source: SourceDescriptor,
  signal: AbortSignal,
  internals: ScanInternals,
): Promise<Acquired | ScanResult> {
  const acquisition = { acquisition: { type: source.type, fetched: false } };
  switch (source.type) {
    case "folder": {
      const read = readFolder(source.path, { signal });
      if (read.status !== "ok")
        return read.status === "refused" && read.reason === "cancelled"
          ? Object.freeze({ status: "cancelled" as const, results: none, ...acquisition })
          : problem(read.status, read.reason, read.detail, acquisition);
      const commit = cloneCommit(source.path);
      return {
        files: read.files,
        fetched: false,
        pin: (item) =>
          Object.freeze({
            type: "folder" as const,
            path: source.path,
            item,
            ...(commit === undefined ? {} : { commit }),
          }),
      };
    }
    case "remote": {
      const file = remoteMcpFile(source.url);
      return {
        files: [Object.freeze({ ...file, sha256: sha256(file.bytes) })],
        fetched: false,
        single: { kind: "mcp", path: "." },
        pin: () => Object.freeze({ type: "remote" as const, url: source.url }),
      };
    }
    case "npm":
    case "npm-file": {
      const read =
        source.type === "npm"
          ? await acquireNpm(source, signal, internals.fetch)
          : await readNpmFile(source.path, signal);
      const record = { acquisition: { type: source.type, fetched: source.type === "npm" } };
      if (read.status === "cancelled")
        return Object.freeze({ status: "cancelled" as const, results: none, ...record });
      if (read.status !== "ok") return problem("refused", read.reason, read.detail, record);
      const pin: SourcePin =
        source.type === "npm"
          ? Object.freeze({
              type: "npm" as const,
              package: read.package,
              version: read.version,
              tarballSha256: read.tarballSha256,
            })
          : Object.freeze({
              type: "npm-file" as const,
              path: source.path,
              package: read.package,
              version: read.version,
              tarballSha256: read.tarballSha256,
            });
      return {
        files: read.files,
        fetched: source.type === "npm",
        single: { kind: "mcp", path: "." },
        pin: () => pin,
      };
    }
    case "git": {
      const read = await acquireGit(source, signal);
      const record = { acquisition: { type: "git" as const, fetched: true } };
      if (read.status === "cancelled")
        return Object.freeze({ status: "cancelled" as const, results: none, ...record });
      if (read.status !== "ok") return problem(read.status, read.reason, read.detail, record);
      return {
        files: read.files,
        fetched: true,
        ...(source.kind !== undefined && source.path !== undefined
          ? { single: { kind: source.kind, path: source.path } }
          : {}),
        pin: (item) =>
          Object.freeze({
            type: "git" as const,
            repo: source.repo,
            ...(read.ref === undefined ? {} : { ref: read.ref }),
            commit: read.commit,
            item,
          }),
      };
    }
  }
}

/** The dependencies a source declares, read by the same acquisition and routing as `scan`. */
export type SourceDependencies =
  | Readonly<{
      status: "ok";
      /** In source file order; `file` is the source-relative path. */
      dependencies: readonly Dependency[];
      acquisition: Acquisition;
    }>
  | Readonly<{ status: "cancelled"; acquisition?: Acquisition }>
  | (Problem & Readonly<{ acquisition?: Acquisition }>);

/**
 * Acquires a source exactly as `scan` does (nothing supplied is run) and lists the
 * dependencies its files declare (`package.json`, `requirements*.txt`, `npx`/`uvx` MCP
 * entries). Used by the CLI `advisories` command; not part of the public host entry.
 */
export async function sourceDependencies(
  source: unknown,
  signal: AbortSignal = new AbortController().signal,
  internals: ScanInternals = {},
): Promise<SourceDependencies> {
  const checked = validateSource(source);
  if (checked.status !== "ok") return checked;
  const acquired = await acquire(checked.source, signal, internals);
  if ("status" in acquired) {
    const acquisition =
      acquired.acquisition === undefined ? {} : { acquisition: acquired.acquisition };
    if (acquired.status === "cancelled")
      return Object.freeze({ status: "cancelled" as const, ...acquisition });
    const failed = acquired as Problem;
    return Object.freeze({
      status: failed.status,
      reason: failed.reason,
      ...(failed.detail === undefined ? {} : { detail: failed.detail }),
      ...acquisition,
    }) as SourceDependencies;
  }
  const dependencies: Dependency[] = [];
  for (const file of acquired.files)
    dependencies.push(...routeFile(file.path, file.bytes).dependencies);
  return Object.freeze({
    status: "ok" as const,
    dependencies: Object.freeze(dependencies),
    acquisition: Object.freeze({ type: checked.source.type, fetched: acquired.fetched }),
  });
}

/** Source route: acquire, discover (or take the one named item), filter by kinds and key every item. */
async function prepareSource(
  valid: ScanRequest,
  signal: AbortSignal,
  internals: ScanInternals,
): Promise<Phase1> {
  const source = valid.source as SourceDescriptor;
  const acquired = await acquire(source, signal, internals);
  if ("status" in acquired) return acquired;
  const acquisition: Acquisition = { type: source.type, fetched: acquired.fetched };
  let items: { kind: Kind; path: string; files: readonly SnapshotFile[] }[];
  let remaining: readonly SnapshotFile[] = [];
  if (acquired.single !== undefined) {
    const { kind, path } = acquired.single;
    const one = acquired.files.length === 1 && acquired.files[0]?.path === path;
    const folder =
      path === "." ? "" : one ? path.slice(0, Math.max(0, path.lastIndexOf("/"))) : path;
    const cut = folder === "" ? 0 : folder.length + 1;
    items = [
      {
        kind,
        path,
        files: acquired.files.map((file) => Object.freeze({ ...file, path: file.path.slice(cut) })),
      },
    ];
  } else {
    const discovery = discoverItems(acquired.files);
    items = [...discovery.items];
    remaining = discovery.remaining;
  }
  if (items.length > limits.input.items)
    return problem("refused", "items", `more than ${limits.input.items} items were found`, {
      acquisition,
    });
  const selected = valid.kinds === undefined ? undefined : new Set<string>(valid.kinds);
  const found: Partial<Record<Kind, number>> = {};
  const notSelected: Partial<Record<ResultKind, number>> = {};
  const entries: Entry[] = [];
  for (const item of items) {
    found[item.kind] = (found[item.kind] ?? 0) + 1;
    if (selected !== undefined && !selected.has(item.kind)) {
      notSelected[item.kind] = (notSelected[item.kind] ?? 0) + 1;
      continue;
    }
    if (signal.aborted) break;
    entries.push({
      path: item.path,
      kind: item.kind,
      files: item.files,
      scanKey: await treeKeyOf(item.files),
      source: acquired.pin(item.path),
    });
  }
  if (remaining.length > 0) {
    if (selected !== undefined) notSelected["remaining-files"] = 1;
    else if (!signal.aborted)
      entries.push({
        path: ".",
        kind: "remaining-files",
        files: remaining,
        scanKey: await treeKeyOf(remaining),
        source: acquired.pin("."),
      });
  }
  return {
    entries,
    acquisition,
    rollup: {
      found: Object.freeze(found),
      notSelected: Object.freeze(notSelected),
      remainingFiles: remaining.length,
    },
  };
}

function rollupOf(
  base: NonNullable<Extract<Phase1, { entries: Entry[] }>["rollup"]>,
  results: readonly ScanItemResult[],
  written: ReadonlyMap<string, Written>,
): Rollup {
  const outcomes = results.flatMap((entry) =>
    entry.status === "ok" ? [written.get(entry.scanKey) as Written] : [],
  );
  const order = scoring.order as readonly string[];
  let label: SummaryLabel = "NOT ASSESSED";
  for (const outcome of outcomes)
    if (
      outcome.label !== "NOT ASSESSED" &&
      (label === "NOT ASSESSED" || order.indexOf(outcome.label) > order.indexOf(label))
    )
      label = outcome.label;
  const reasons = new Set<string>();
  for (const outcome of outcomes)
    for (const reason of outcome.reason?.split(", ") ?? []) if (reason) reasons.add(reason);
  if (Object.keys(base.notSelected).length > 0) reasons.add("not selected");
  return Object.freeze({
    label,
    coverage: reasons.size > 0 ? ("partial" as const) : ("complete" as const),
    ...(reasons.size > 0 ? { reason: [...reasons].sort().join(", ") } : {}),
    items: outcomes.length,
    partial: outcomes.filter((outcome) => outcome.coverage === "partial").length,
    notAssessed: outcomes.filter((outcome) => outcome.label === "NOT ASSESSED").length,
    ...base,
  });
}

/**
 * Scans what it is given. With `items`, one result per folder as handed over. With a `source`
 * (folder, public Git repository or item, npm package or tarball, remote MCP configuration), one
 * result per item found by the `aih-scan-routing/1` layouts, one for the remaining files and a
 * roll-up; npm, npm-file and remote sources are one MCP item, and a Git source naming a path and
 * kind is that one item. Every item is read into a Scan-owned read-only snapshot (links, hard
 * links, special files, invalid names and limit breaches refused before anything is scanned),
 * keyed by its Git tree hash exactly as if handed over as a folder, and assessed once per
 * distinct key. Git and npm sources are fetched before the scan; the scan itself runs nothing
 * supplied and, in static mode, makes no network call. Results echo the unsigned request label
 * and source pin; neither appears in the summary or SARIF.
 */
export function scan(request: unknown, options: ScanOptions): Promise<ScanResult> {
  return scanWith(request, options);
}

/** {@link scan} with internal seams (adapters, environment, fixed clock, tool timeout). Not exported publicly. */
export async function scanWith(
  request: unknown,
  options: ScanOptions,
  internals: ScanInternals = {},
): Promise<ScanResult> {
  if (typeof options !== "object" || options === null)
    return problem("invalid", "out-dir", "options must be { outDir }");
  const checked = validateRequest(request);
  if (checked.status !== "ok") return Object.freeze({ ...checked, results: none });
  const valid: ScanRequest = checked.request;
  const signal = options.signal ?? new AbortController().signal;
  const phase1 =
    valid.source !== undefined
      ? await prepareSource(valid, signal, internals)
      : await prepareItems(valid, signal);
  if ("status" in phase1) return phase1;
  const env = internals.env ?? process.env;
  const mode = valid.mode ?? "static";
  const aiSetup = mode === "ai" ? skillSpectorAiSetup(env) : undefined;
  const extras: { acquisition?: Acquisition; ai?: AiAvailability } = {
    ...(phase1.acquisition === undefined ? {} : { acquisition: phase1.acquisition }),
    ...(aiSetup === undefined ? {} : { ai: aiAvailability(aiSetup) }),
  };
  const cancelledEarly = signal.aborted;
  const shared = internals.sharedOutput;
  let outDir: string;
  if (shared?.dir !== undefined) outDir = shared.dir;
  else {
    const prepared = prepareOutput(shared?.outDir ?? options.outDir);
    if (typeof prepared !== "string") return Object.freeze({ ...prepared, ...extras });
    outDir = prepared;
    if (shared !== undefined) shared.dir = prepared;
  }

  // Phase 2: assess each distinct key once.
  const adapters = new Map<ToolId, ToolAdapter>([
    ["aih-trust-lint", internals.adapters?.["aih-trust-lint"] ?? trustLintAdapter],
    [
      "skillspector",
      internals.adapters?.skillspector ??
        skillSpectorAdapter({ env, ...(aiSetup === undefined ? {} : { ai: aiSetup }) }),
    ],
    ["cisco", internals.adapters?.cisco ?? ciscoAdapter({ env })],
  ]);
  const written = shared?.written ?? new Map<string, Written>();
  const results: ScanItemResult[] = [];
  let cancelled = cancelledEarly;
  for (const entry of phase1.entries) {
    if (!("files" in entry)) {
      results.push(entry);
      continue;
    }
    const echo = {
      path: entry.path,
      ...labelOf(entry.label),
      ...(entry.kind === undefined ? {} : { kind: entry.kind }),
      source: entry.source,
    };
    let output = written.get(entry.scanKey);
    if (output === undefined) {
      if (signal.aborted) {
        cancelled = true;
        results.push(Object.freeze({ ...echo, status: "cancelled" as const, reason: "cancelled" }));
        continue;
      }
      const snapshot = writeSnapshot(entry.files, internals.snapshotParent);
      try {
        const assessment = await assessItem(
          {
            scanKey: entry.scanKey,
            files: entry.files,
            routed: routeFiles(entry.files),
            snapshotRoot: snapshot.root,
          },
          adapters,
          {
            origin: valid.origin,
            mode,
            tools: valid.tools,
            internalScopes: options.internalScopes ?? [],
            signal,
            now: internals.now ?? (() => new Date()),
            timeoutMs: internals.timeoutMs ?? limits.tool.timeoutMs,
          },
        );
        if (signal.aborted) {
          cancelled = true;
          results.push(
            Object.freeze({ ...echo, status: "cancelled" as const, reason: "cancelled" }),
          );
          continue;
        }
        const folder = join(outDir, keyFolderName(entry.scanKey));
        mkdirSync(join(folder, "sarif"), { recursive: true });
        const summaryPath = join(folder, "summary.json");
        for (const document of assessment.sarif)
          writeNewSafeOutput(join(folder, ...document.path.split("/")), document.bytes, {
            label: "SARIF output",
            maximumBytes: limits.output.sarifBytes,
          });
        writeNewSafeOutput(summaryPath, assessment.summaryBytes, {
          label: "summary output",
          maximumBytes: limits.output.summaryBytes,
        });
        const summary = assessment.summary;
        output = Object.freeze({
          summaryPath,
          sarifPaths: Object.freeze(
            assessment.sarif.map((document) => join(folder, ...document.path.split("/"))),
          ),
          label: summary.label,
          coverage: summary.coverage,
          ...(summary.reason === undefined ? {} : { reason: summary.reason }),
          notes: assessment.notes,
        });
        written.set(entry.scanKey, output);
      } finally {
        snapshot.dispose();
      }
    }
    results.push(
      Object.freeze({
        ...echo,
        scanKey: entry.scanKey,
        status: "ok" as const,
        summaryPath: output.summaryPath,
        sarifPaths: output.sarifPaths,
        ...(output.notes.length === 0 ? {} : { notes: output.notes }),
      }),
    );
  }
  const frozen = Object.freeze(results);
  const rollup =
    phase1.rollup === undefined ? {} : { rollup: rollupOf(phase1.rollup, frozen, written) };
  const tail = { results: frozen, ...rollup, ...extras };
  if (cancelled) return Object.freeze({ status: "cancelled" as const, ...tail });
  if (frozen.some((result) => result.status !== "ok"))
    return Object.freeze({
      status: "refused" as const,
      reason: "items-not-scanned" as const,
      ...tail,
    });
  return Object.freeze({ status: "ok" as const, ...tail });
}
