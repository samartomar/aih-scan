import { mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  assertOutputAbsent,
  ExclusiveOutputError,
  safeOutputParents,
  writeNewSafeOutput,
} from "../cli/exclusive-output.js";
import type { Problem } from "../contracts/formats.js";
import { keyFolderName, scanKeyOf } from "../contracts/git-tree.js";
import { limits } from "../contracts/limits.js";
import type { ToolId } from "../contracts/routing.js";
import { type ScanRequest, type SourceDescriptor, validateRequest } from "../contracts/validate.js";
import { assessItem, routeFiles } from "./assess.js";
import { readFolder, type SnapshotFile, writeSnapshot } from "./snapshot.js";
import { type ToolAdapter, unavailableCisco, unavailableSkillSpector } from "./tools.js";
import { trustLintAdapter } from "./trust-lint-tool.js";

export interface ScanOptions {
  /** A new folder (it must not exist) that receives the summaries and SARIF. */
  readonly outDir: string;
  /** Cancels the scan; results that finished are kept and the run is `cancelled`. */
  readonly signal?: AbortSignal;
  /** npm scopes treated as internal by the dependency-confusion check. */
  readonly internalScopes?: readonly string[];
}

/** The source pin a result read: unsigned, outside the summary. */
export type SourcePin = Readonly<{ type: "folder"; path: string }>;

export type ScanItemResult =
  | Readonly<{
      path: string;
      label?: string;
      scanKey: string;
      status: "ok";
      summaryPath: string;
      sarifPaths: readonly string[];
      source: SourcePin;
    }>
  | Readonly<{
      path: string;
      label?: string;
      status: "refused" | "invalid" | "cancelled";
      reason: string;
      detail?: string;
      source: SourcePin;
    }>;

export type ScanResult =
  | Readonly<{ status: "ok"; results: readonly ScanItemResult[] }>
  /** At least one item could not be scanned; the others were written. */
  | Readonly<{ status: "refused"; reason: "items-not-scanned"; results: readonly ScanItemResult[] }>
  | Readonly<{ status: "cancelled"; results: readonly ScanItemResult[] }>
  | (Problem & Readonly<{ results: readonly ScanItemResult[] }>);

/** Internal seams for adapters landing in later slices and for deterministic tests. */
export interface ScanInternals {
  readonly adapters?: Partial<Record<ToolId, ToolAdapter>>;
  readonly now?: () => Date;
  readonly timeoutMs?: number;
  readonly snapshotParent?: string;
}

const none: readonly ScanItemResult[] = Object.freeze([]);
const problem = (status: Problem["status"], reason: string, detail: string) =>
  Object.freeze({ status, reason, detail, results: none }) as ScanResult;

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
  readonly index: number;
  readonly path: string;
  readonly label?: string;
  readonly files: readonly SnapshotFile[];
  readonly scanKey: string;
}

/**
 * Scans what it is given. With `items`, one result per folder: each folder is read into a
 * Scan-owned read-only snapshot (links, hard links, special files, invalid names and limit
 * breaches refuse that folder before anything is scanned), keyed by its Git tree hash, and
 * assessed once per distinct key. Request-wide limits refuse the whole request. Results echo the
 * unsigned request label and source pin; neither appears in the summary or SARIF.
 */
export function scan(request: unknown, options: ScanOptions): Promise<ScanResult> {
  return scanWith(request, options);
}

/** {@link scan} with internal seams (later-slice adapters, fixed clock, tool timeout). Not exported publicly. */
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
  if (valid.source !== undefined)
    return problem(
      "refused",
      "unsupported-source",
      `the ${(valid.source as SourceDescriptor).type} source route is not available in this build`,
    );
  const items = valid.items ?? [];
  if (items.length > limits.input.items)
    return problem("refused", "items", `more than ${limits.input.items} items`);
  const signal = options.signal ?? new AbortController().signal;
  const pinOf = (path: string): SourcePin => Object.freeze({ type: "folder" as const, path });
  const labelOf = (label: string | undefined) => (label === undefined ? {} : { label });

  // Phase 1: read every folder before anything is scanned.
  const prepared: (Prepared | ScanItemResult)[] = [];
  let usedBytes = 0;
  let usedFiles = 0;
  for (const [index, entry] of items.entries()) {
    if (signal.aborted) break;
    const read = readFolder(entry.path, {
      ...(entry.executable === undefined ? {} : { executable: entry.executable }),
      signal,
    });
    if (read.status !== "ok") {
      if (read.status === "refused" && read.reason === "cancelled") break;
      prepared.push(
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
    prepared.push({
      index,
      path: entry.path,
      ...labelOf(entry.label),
      files: read.files,
      scanKey: await scanKeyOf(read.files),
    });
  }
  const cancelledEarly = signal.aborted;
  const outDir = prepareOutput(options.outDir);
  if (typeof outDir !== "string") return outDir;

  // Phase 2: assess each distinct key once.
  const adapters = new Map<ToolId, ToolAdapter>([
    ["aih-trust-lint", internals.adapters?.["aih-trust-lint"] ?? trustLintAdapter],
    ["skillspector", internals.adapters?.skillspector ?? unavailableSkillSpector],
    ["cisco", internals.adapters?.cisco ?? unavailableCisco],
  ]);
  const written = new Map<string, { summaryPath: string; sarifPaths: readonly string[] }>();
  const results: ScanItemResult[] = [];
  let cancelled = cancelledEarly;
  for (const entry of prepared) {
    if (!("files" in entry)) {
      results.push(entry);
      continue;
    }
    const echo = { path: entry.path, ...labelOf(entry.label), source: pinOf(entry.path) };
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
            mode: valid.mode ?? "static",
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
        output = Object.freeze({
          summaryPath,
          sarifPaths: Object.freeze(
            assessment.sarif.map((document) => join(folder, ...document.path.split("/"))),
          ),
        });
        written.set(entry.scanKey, output);
      } finally {
        snapshot.dispose();
      }
    }
    results.push(
      Object.freeze({ ...echo, scanKey: entry.scanKey, status: "ok" as const, ...output }),
    );
  }
  const frozen = Object.freeze(results);
  if (cancelled) return Object.freeze({ status: "cancelled" as const, results: frozen });
  if (frozen.some((result) => result.status !== "ok"))
    return Object.freeze({
      status: "refused" as const,
      reason: "items-not-scanned" as const,
      results: frozen,
    });
  return Object.freeze({ status: "ok" as const, results: frozen });
}
