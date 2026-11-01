import { formatProblem, formats, type Problem } from "./formats.js";
import { SCAN_KEY_PATTERN } from "./git-tree.js";
import { limits } from "./limits.js";
import { type Coverage, type FindingPart, type SummaryLabel, storedLabel } from "./risk.js";
import { type Kind, kinds, optionalTools, type ToolId } from "./routing.js";
import { codePointLength, hasUnsafeCharacters, isWellFormedText, pathProblem } from "./text.js";

/* ------------------------------------------------------------------ types */

export type Origin = "published" | "local";
export type ScanMode = "static" | "ai";

export type SourceDescriptor =
  | Readonly<{ format?: typeof formats.source; type: "folder"; path: string }>
  | Readonly<{
      format?: typeof formats.source;
      type: "git";
      repo: string;
      ref?: string;
      path?: string;
      kind?: Kind;
    }>
  | Readonly<{
      format?: typeof formats.source;
      type: "npm";
      package: string;
      version: string;
      kind?: "mcp";
    }>
  | Readonly<{ format?: typeof formats.source; type: "npm-file"; path: string; kind?: "mcp" }>
  | Readonly<{ format?: typeof formats.source; type: "remote"; url: string; kind?: "mcp" }>;

export interface RequestItem {
  /** A host folder, as handed over. */
  readonly path: string;
  /** Item-relative paths to record as `100755` when the disk cannot say so. */
  readonly executable?: readonly string[];
  /** The caller's unsigned request label; echoed only in the scan result. */
  readonly label?: string;
}

export interface ScanRequest {
  readonly format: typeof formats.request;
  readonly source?: SourceDescriptor;
  readonly items?: readonly RequestItem[];
  readonly origin: Origin;
  readonly kinds?: readonly Kind[];
  readonly tools?: readonly ToolId[];
  readonly mode?: ScanMode;
}

export type FileMode = "100644" | "100755";
export type ToolResult = "pass" | "warn" | "fail" | "not-run" | "not-applicable";
export type SeverityCountKey = "critical" | "high" | "medium" | "low" | "info";

export interface SummaryFile {
  readonly path: string;
  readonly mode: FileMode;
  readonly part: FindingPart;
  readonly sha256: string;
}

export interface SummaryTool {
  readonly tool: string;
  readonly version: string;
  readonly mode: ScanMode;
  readonly ai?: Readonly<{ via: "cli" | "local" | "provider"; provider: string; model: string }>;
  readonly result: ToolResult;
  readonly reason?: string;
  readonly counts: Readonly<Partial<Record<SeverityCountKey, number>>>;
  readonly suppressed?: readonly Readonly<{ count: number; reason: string }>[];
}

export interface SummaryDependency {
  readonly ecosystem: "npm" | "pypi";
  readonly name: string;
  readonly version: string | null;
  readonly file: string;
}

export interface Summary {
  readonly format: typeof formats.summary;
  readonly scanKey: string;
  readonly revision: number;
  readonly origin: Origin;
  readonly scannedAt: string;
  readonly scanner: string;
  readonly routing: typeof formats.routing;
  readonly scoring: typeof formats.scoring;
  readonly score: number;
  readonly label: SummaryLabel;
  readonly coverage: Coverage;
  readonly reason?: string;
  readonly files: readonly SummaryFile[];
  readonly tools: readonly SummaryTool[];
  readonly notAnalysed: readonly Readonly<{ path: string; secretsChecked: boolean }>[];
  readonly sarif: readonly Readonly<{ path: string; sha256: string }>[];
  readonly dependencies: readonly SummaryDependency[];
}

export interface Withdrawal {
  readonly format: typeof formats.withdrawn;
  readonly scanKey: string;
  readonly throughRevision: number;
  readonly at: string;
  readonly reason: string;
}

/* ------------------------------------------------------------- machinery */

class Invalid extends Error {
  constructor(readonly result: Problem) {
    super(result.detail ?? result.reason);
  }
}

const invalid = (detail: string, reason = "schema"): never => {
  throw new Invalid(Object.freeze({ status: "invalid" as const, reason, detail }));
};
const refuse = (reason: string, detail: string): never => {
  throw new Invalid(Object.freeze({ status: "refused" as const, reason, detail }));
};

type Obj = Record<string, unknown>;

function object(value: unknown, at: string): Obj {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    invalid(`${at} must be an object`);
  // Plain objects from any realm: Object.prototype of that realm, or no prototype.
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== null && Object.getPrototypeOf(prototype) !== null)
    invalid(`${at} must be a plain object`);
  return value as Obj;
}

function keys(
  value: Obj,
  at: string,
  required: readonly string[],
  optional: readonly string[] = [],
): void {
  for (const key of required) if (!Object.hasOwn(value, key)) invalid(`${at}.${key} is required`);
  for (const key of Object.keys(value))
    if (!required.includes(key) && !optional.includes(key))
      invalid(`${at} has an unknown field ${JSON.stringify(key).slice(0, 80)}`);
}

function text(value: unknown, at: string, max: number, min = 1): string {
  if (typeof value !== "string") return invalid(`${at} must be a string`);
  if (!isWellFormedText(value)) invalid(`${at} is not valid text`);
  if (hasUnsafeCharacters(value))
    invalid(`${at} contains control, bidirectional or zero-width characters`);
  const length = codePointLength(value);
  if (length < min || length > max) invalid(`${at} must be ${min}-${max} characters`);
  return value;
}

function oneOf<T extends string>(value: unknown, at: string, allowed: readonly T[]): T {
  if (typeof value !== "string" || !(allowed as readonly string[]).includes(value))
    invalid(`${at} must be one of ${allowed.join(", ")}`);
  return value as T;
}

function integer(value: unknown, at: string, min: number, max = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min || value > max)
    invalid(`${at} must be an integer from ${min} to ${max}`);
  return value as number;
}

function array(value: unknown, at: string, max: number, min = 0): unknown[] {
  if (!Array.isArray(value)) return invalid(`${at} must be an array`);
  if (value.length < min || value.length > max) invalid(`${at} must have ${min}-${max} entries`);
  return value;
}

function unique<T>(values: readonly T[], at: string): void {
  if (new Set(values).size !== values.length) invalid(`${at} must not repeat entries`);
}

const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/;
function timestamp(value: unknown, at: string): string {
  if (typeof value !== "string" || !TIMESTAMP.test(value) || Number.isNaN(Date.parse(value)))
    invalid(`${at} must be a UTC RFC 3339 timestamp`);
  return value as string;
}

function scanKey(value: unknown, at: string): string {
  if (typeof value !== "string" || !SCAN_KEY_PATTERN.test(value))
    invalid(`${at} must be a git-sha1: or git-sha256: scan key`);
  return value as string;
}

function sha256(value: unknown, at: string): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value))
    invalid(`${at} must be a lowercase sha256`);
  return value as string;
}

/** A content path inside an item: unsafe spellings are refused, not invalid. */
function contentPath(value: unknown, at: string): string {
  if (typeof value !== "string") return invalid(`${at} must be a string`);
  const problem = pathProblem(value, limits.input.pathLength, limits.input.depth);
  if (problem !== undefined) refuse("unsafe-path", `${at}: ${problem}`);
  return value;
}

function hostPath(value: unknown, at: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 4096 ||
    value.includes("\0")
  )
    invalid(`${at} must be a non-empty path`);
  if (!isWellFormedText(value as string)) invalid(`${at} is not valid text`);
  return value as string;
}

function webUrl(value: unknown, at: string, schemes: readonly string[]): string {
  const spelled = text(value, at, 2048);
  let url: URL;
  try {
    url = new URL(spelled);
  } catch {
    return invalid(`${at} must be an absolute URL`);
  }
  if (!schemes.includes(url.protocol)) invalid(`${at} must use ${schemes.join(" or ")}`);
  if (url.username !== "" || url.password !== "") invalid(`${at} must not carry credentials`);
  if (url.hostname === "") invalid(`${at} must name a host`);
  return spelled;
}

function run<T>(body: () => T): T | Problem {
  try {
    return body();
  } catch (error) {
    if (error instanceof Invalid) return error.result;
    return Object.freeze({
      status: "invalid" as const,
      reason: "schema",
      detail: "input could not be validated",
    });
  }
}

/* -------------------------------------------------------------- sources */

const SOURCE_FIELDS = {
  folder: { required: ["path"], optional: [] },
  git: { required: ["repo"], optional: ["ref", "path", "kind"] },
  npm: { required: ["package", "version"], optional: ["kind"] },
  "npm-file": { required: ["path"], optional: ["kind"] },
  remote: { required: ["url"], optional: ["kind"] },
} as const;

const NPM_NAME = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/;
const GIT_REF = /^(?!-)(?!.*\.\.)(?!.*\/\/)[A-Za-z0-9._/@+-]{1,255}$/;

function source(value: unknown, at: string): SourceDescriptor {
  const descriptor = object(value, at);
  if (Object.hasOwn(descriptor, "format")) {
    const problem = formatProblem(descriptor.format, formats.source, at);
    if (problem !== undefined) throw new Invalid(problem);
  }
  const type = oneOf(
    descriptor.type,
    `${at}.type`,
    Object.keys(SOURCE_FIELDS) as (keyof typeof SOURCE_FIELDS)[],
  );
  const fields = SOURCE_FIELDS[type];
  keys(descriptor, at, ["type", ...fields.required], ["format", ...fields.optional]);
  const kindOf = (allowed: readonly Kind[]) =>
    descriptor.kind === undefined ? {} : { kind: oneOf(descriptor.kind, `${at}.kind`, allowed) };
  const format = descriptor.format === undefined ? {} : { format: formats.source };
  switch (type) {
    case "folder":
      return Object.freeze({ ...format, type, path: hostPath(descriptor.path, `${at}.path`) });
    case "git": {
      const repo = webUrl(descriptor.repo, `${at}.repo`, ["https:"]);
      const ref =
        descriptor.ref === undefined
          ? {}
          : {
              ref: GIT_REF.test(String(descriptor.ref))
                ? (descriptor.ref as string)
                : invalid(`${at}.ref is not a valid ref name`),
            };
      const path =
        descriptor.path === undefined ? {} : { path: contentPath(descriptor.path, `${at}.path`) };
      return Object.freeze({ ...format, type, repo, ...ref, ...path, ...kindOf(kinds) });
    }
    case "npm": {
      const name = text(descriptor.package, `${at}.package`, 214);
      if (!NPM_NAME.test(name)) invalid(`${at}.package is not an npm package name`);
      const version = text(descriptor.version, `${at}.version`, 256);
      if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version))
        invalid(`${at}.version must be an exact version`);
      return Object.freeze({
        ...format,
        type,
        package: name,
        version,
        ...kindOf(["mcp"]),
      }) as SourceDescriptor;
    }
    case "npm-file":
      return Object.freeze({
        ...format,
        type,
        path: hostPath(descriptor.path, `${at}.path`),
        ...kindOf(["mcp"]),
      }) as SourceDescriptor;
    case "remote":
      return Object.freeze({
        ...format,
        type,
        url: webUrl(descriptor.url, `${at}.url`, ["https:", "http:"]),
        ...kindOf(["mcp"]),
      }) as SourceDescriptor;
  }
}

/** Validates an `aih-scan-source/1` descriptor. */
export function validateSource(
  value: unknown,
): Readonly<{ status: "ok"; source: SourceDescriptor }> | Problem {
  return run(() => Object.freeze({ status: "ok" as const, source: source(value, "source") }));
}

/* -------------------------------------------------------------- request */

function item(value: unknown, at: string): RequestItem {
  const entry = object(value, at);
  keys(entry, at, ["path"], ["executable", "label"]);
  const result: { path: string; executable?: readonly string[]; label?: string } = {
    path: hostPath(entry.path, `${at}.path`),
  };
  if (entry.executable !== undefined) {
    const list = array(entry.executable, `${at}.executable`, limits.input.files).map(
      (path, index) => contentPath(path, `${at}.executable[${index}]`),
    );
    unique(list, `${at}.executable`);
    result.executable = Object.freeze(list);
  }
  if (entry.label !== undefined)
    result.label = text(entry.label, `${at}.label`, limits.output.label);
  return Object.freeze(result);
}

/** Validates an `aih-scan-request/1` document. */
export function validateRequest(
  value: unknown,
): Readonly<{ status: "ok"; request: ScanRequest }> | Problem {
  return run(() => {
    const request = object(value, "request");
    const problem = formatProblem(request.format, formats.request, "request");
    if (problem !== undefined) throw new Invalid(problem);
    keys(request, "request", ["format", "origin"], ["source", "items", "kinds", "tools", "mode"]);
    const hasSource = Object.hasOwn(request, "source");
    const hasItems = Object.hasOwn(request, "items");
    if (hasSource === hasItems) invalid("request must have exactly one of source or items");
    const result: {
      format: typeof formats.request;
      origin: Origin;
      source?: SourceDescriptor;
      items?: readonly RequestItem[];
      kinds?: readonly Kind[];
      tools?: readonly ToolId[];
      mode?: ScanMode;
    } = {
      format: formats.request,
      origin: oneOf(request.origin, "request.origin", ["published", "local"]),
    };
    if (hasSource) result.source = source(request.source, "request.source");
    if (hasItems) {
      const entries = array(request.items, "request.items", Number.MAX_SAFE_INTEGER, 1);
      if (entries.length > limits.input.items)
        refuse("items", `request.items exceeds the ${limits.input.items}-item limit`);
      result.items = Object.freeze(
        entries.map((entry, index) => item(entry, `request.items[${index}]`)),
      );
    }
    if (request.kinds !== undefined) {
      const list = array(request.kinds, "request.kinds", kinds.length, 1).map((kind, index) =>
        oneOf(kind, `request.kinds[${index}]`, kinds),
      );
      unique(list, "request.kinds");
      result.kinds = Object.freeze(list);
    }
    if (request.tools !== undefined) {
      const list = array(request.tools, "request.tools", optionalTools.length).map((tool, index) =>
        oneOf(tool, `request.tools[${index}]`, optionalTools),
      );
      unique(list, "request.tools");
      result.tools = Object.freeze(list);
    }
    if (request.mode !== undefined)
      result.mode = oneOf<ScanMode>(request.mode, "request.mode", ["static", "ai"]);
    return Object.freeze({ status: "ok" as const, request: Object.freeze(result) as ScanRequest });
  });
}

/* -------------------------------------------------------------- summary */

const PARTS = ["config", "dependencies", "code", "text", "none"] as const;
const LABELS = ["SAFE", "CAUTION", "DO NOT INSTALL", "NOT ASSESSED"] as const;
const COUNT_KEYS = ["critical", "high", "medium", "low", "info"] as const;

function summaryTool(value: unknown, at: string): SummaryTool {
  const tool = object(value, at);
  keys(tool, at, ["tool", "version", "mode", "result", "counts"], ["ai", "reason", "suppressed"]);
  const result: {
    tool: string;
    version: string;
    mode: ScanMode;
    result: ToolResult;
    counts: Partial<Record<SeverityCountKey, number>>;
    ai?: SummaryTool["ai"];
    reason?: string;
    suppressed?: SummaryTool["suppressed"];
  } = {
    tool: text(tool.tool, `${at}.tool`, limits.output.ruleId),
    version: text(tool.version, `${at}.version`, 128),
    mode: oneOf(tool.mode, `${at}.mode`, ["static", "ai"]),
    result: oneOf(tool.result, `${at}.result`, [
      "pass",
      "warn",
      "fail",
      "not-run",
      "not-applicable",
    ]),
    counts: {},
  };
  const counts = object(tool.counts, `${at}.counts`);
  keys(counts, `${at}.counts`, [], COUNT_KEYS);
  for (const key of COUNT_KEYS)
    if (counts[key] !== undefined)
      result.counts[key] = integer(counts[key], `${at}.counts.${key}`, 1);
  result.counts = Object.freeze(result.counts);
  if (tool.ai !== undefined) {
    const ai = object(tool.ai, `${at}.ai`);
    keys(ai, `${at}.ai`, ["via", "provider", "model"]);
    result.ai = Object.freeze({
      via: oneOf(ai.via, `${at}.ai.via`, ["cli", "local", "provider"]),
      provider: text(ai.provider, `${at}.ai.provider`, 128),
      model: text(ai.model, `${at}.ai.model`, 256),
    });
  }
  if (tool.reason !== undefined)
    result.reason = text(tool.reason, `${at}.reason`, limits.output.reason);
  if ((result.result === "not-run") !== (result.reason !== undefined))
    invalid(`${at}.reason is required exactly when the tool did not run`);
  if (tool.suppressed !== undefined)
    result.suppressed = Object.freeze(
      array(tool.suppressed, `${at}.suppressed`, 10_000).map((entry, index) => {
        const suppressed = object(entry, `${at}.suppressed[${index}]`);
        keys(suppressed, `${at}.suppressed[${index}]`, ["count", "reason"]);
        return Object.freeze({
          count: integer(suppressed.count, `${at}.suppressed[${index}].count`, 1),
          reason: text(
            suppressed.reason,
            `${at}.suppressed[${index}].reason`,
            limits.output.reason,
          ),
        });
      }),
    );
  return Object.freeze(result);
}

function summary(value: unknown): Summary {
  const document = object(value, "summary");
  const problem = formatProblem(document.format, formats.summary, "summary");
  if (problem !== undefined) throw new Invalid(problem);
  keys(
    document,
    "summary",
    [
      "format",
      "scanKey",
      "revision",
      "origin",
      "scannedAt",
      "scanner",
      "routing",
      "scoring",
      "score",
      "label",
      "coverage",
      "files",
      "tools",
      "notAnalysed",
      "sarif",
      "dependencies",
    ],
    ["reason"],
  );
  for (const [field, expected] of [
    ["routing", formats.routing],
    ["scoring", formats.scoring],
  ] as const) {
    const versionProblem = formatProblem(document[field], expected, `summary.${field}`);
    if (versionProblem !== undefined) throw new Invalid(versionProblem);
  }
  const files = array(document.files, "summary.files", limits.input.files).map((entry, index) => {
    const at = `summary.files[${index}]`;
    const file = object(entry, at);
    keys(file, at, ["path", "mode", "part", "sha256"]);
    return Object.freeze({
      path: contentPath(file.path, `${at}.path`),
      mode: oneOf(file.mode, `${at}.mode`, ["100644", "100755"]),
      part: oneOf(file.part, `${at}.part`, PARTS),
      sha256: sha256(file.sha256, `${at}.sha256`),
    });
  });
  const paths = new Set(files.map((file) => file.path));
  if (paths.size !== files.length) invalid("summary.files must not repeat a path");
  for (const path of paths) {
    const segments = path.split("/");
    for (let depth = 1; depth < segments.length; depth += 1)
      if (paths.has(segments.slice(0, depth).join("/")))
        invalid("summary.files has a path that is both a file and a folder");
  }
  const notAnalysed = array(document.notAnalysed, "summary.notAnalysed", limits.input.files).map(
    (entry, index) => {
      const at = `summary.notAnalysed[${index}]`;
      const record = object(entry, at);
      keys(record, at, ["path", "secretsChecked"]);
      if (typeof record.secretsChecked !== "boolean")
        invalid(`${at}.secretsChecked must be a boolean`);
      return Object.freeze({
        path: contentPath(record.path, `${at}.path`),
        secretsChecked: record.secretsChecked as boolean,
      });
    },
  );
  const unrouted = new Set(files.filter((file) => file.part === "none").map((file) => file.path));
  if (
    notAnalysed.length !== unrouted.size ||
    notAnalysed.some((entry) => !unrouted.has(entry.path))
  )
    invalid("summary.notAnalysed must list exactly the files with part none");
  const tools = array(document.tools, "summary.tools", 64).map((entry, index) =>
    summaryTool(entry, `summary.tools[${index}]`),
  );
  unique(
    tools.map((tool) => tool.tool),
    "summary.tools[].tool",
  );
  const sarif = array(document.sarif, "summary.sarif", 64).map((entry, index) => {
    const at = `summary.sarif[${index}]`;
    const record = object(entry, at);
    keys(record, at, ["path", "sha256"]);
    return Object.freeze({
      path: contentPath(record.path, `${at}.path`),
      sha256: sha256(record.sha256, `${at}.sha256`),
    });
  });
  const dependencies = array(
    document.dependencies,
    "summary.dependencies",
    limits.input.files * 16,
  ).map((entry, index) => {
    const at = `summary.dependencies[${index}]`;
    const record = object(entry, at);
    keys(record, at, ["ecosystem", "name", "version", "file"]);
    return Object.freeze({
      ecosystem: oneOf(record.ecosystem, `${at}.ecosystem`, ["npm", "pypi"]),
      name: text(record.name, `${at}.name`, 256),
      version: record.version === null ? null : text(record.version, `${at}.version`, 256),
      file: contentPath(record.file, `${at}.file`),
    });
  });
  for (const dependency of dependencies)
    if (!paths.has(dependency.file))
      invalid("summary.dependencies must name a file of the summary");
  const score = integer(document.score, "summary.score", 0, 100);
  const coverage = oneOf(document.coverage, "summary.coverage", ["complete", "partial"]);
  const label = oneOf(document.label, "summary.label", LABELS);
  const reason =
    document.reason === undefined
      ? undefined
      : text(document.reason, "summary.reason", limits.output.reason);
  const result: { -readonly [K in keyof Summary]: Summary[K] } = {
    format: formats.summary,
    scanKey: scanKey(document.scanKey, "summary.scanKey"),
    revision: integer(document.revision, "summary.revision", 1),
    origin: oneOf(document.origin, "summary.origin", ["published", "local"]),
    scannedAt: timestamp(document.scannedAt, "summary.scannedAt"),
    scanner: text(document.scanner, "summary.scanner", 128),
    routing: formats.routing,
    scoring: formats.scoring,
    score,
    label,
    coverage,
    ...(reason === undefined ? {} : { reason }),
    files: Object.freeze(files),
    tools: Object.freeze(tools),
    notAnalysed: Object.freeze(notAnalysed),
    sarif: Object.freeze(sarif),
    dependencies: Object.freeze(dependencies),
  };
  if ((coverage === "partial") !== (result.reason !== undefined))
    invalid("summary.reason is required exactly when coverage is partial");
  const routable = files.some((file) => file.part !== "none");
  if (storedLabel({ score, coverage, routable }) !== label)
    invalid("summary.label does not follow from score, coverage and routable content", "label");
  return Object.freeze(result) as Summary;
}

/** Validates a parsed `aih-scan-summary/1` object. Unsafe paths are `refused` (`unsafe-path`). */
export function validateSummary(
  value: unknown,
): Readonly<{ status: "ok"; summary: Summary }> | Problem {
  return run(() => Object.freeze({ status: "ok" as const, summary: summary(value) }));
}

/** Validates a parsed `aih-scan-withdrawn/1` object. */
export function validateWithdrawn(
  value: unknown,
): Readonly<{ status: "ok"; withdrawn: Withdrawal }> | Problem {
  return run(() => {
    const document = object(value, "withdrawn");
    const problem = formatProblem(document.format, formats.withdrawn, "withdrawn");
    if (problem !== undefined) throw new Invalid(problem);
    keys(document, "withdrawn", ["format", "scanKey", "throughRevision", "at", "reason"]);
    return Object.freeze({
      status: "ok" as const,
      withdrawn: Object.freeze({
        format: formats.withdrawn,
        scanKey: scanKey(document.scanKey, "withdrawn.scanKey"),
        throughRevision: integer(document.throughRevision, "withdrawn.throughRevision", 1),
        at: timestamp(document.at, "withdrawn.at"),
        reason: text(document.reason, "withdrawn.reason", limits.output.reason),
      }),
    });
  });
}
