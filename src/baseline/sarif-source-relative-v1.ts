import { assertSafeRelativePosixPathV1 } from "../contract/strict-json-v1.js";

/**
 * Rewrites the artifact URIs of one analyzer's SARIF so they are relative to the declared
 * source root, with forward slashes, whatever root the analyzer actually saw.
 *
 * Analyzers print targets as they were given: `/aih/source/...` inside the namespace
 * profile, `/scan/...` inside the SkillSpector container, and the absolute path of Scan's
 * private, deleted-after-the-run snapshot under a host profile (on Windows with
 * backslashes, and possibly in either the 8.3 short or the long spelling). None of those
 * locate anything for a consumer, so every artifact URI is rewritten against the roots the
 * analyzer was given. A URI that is outside every root, escapes with `..`, names the root
 * itself or cannot be decoded is refused, never guessed. A `uriBaseId` is resolved through
 * its run's `originalUriBaseIds` before the URI is related to the root, so a base outside
 * the root (or an unknown base) fails closed; afterwards the maps are removed, because they
 * could only describe the private root, and every reference to a removed base goes with them.
 *
 * The rewritten document, not the analyzer's raw bytes, is what the observation's annex
 * digest is taken over; the profile documents say so.
 */

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

export type SourceRelativeSarifV1 = Readonly<{
  document: Record<string, unknown>;
  /** Artifact URIs that were rewritten (already-relative URIs count too). */
  rewritten: number;
  /** `originalUriBaseIds` maps that were removed. */
  removedBaseUris: number;
}>;

function fail(message: string): never {
  throw new TypeError(`aih-scan SARIF artifact URI: ${message}`);
}

type Root = Readonly<{ spelling: string; windows: boolean }>;

function roots(values: readonly string[]): Root[] {
  if (values.length === 0) fail("no source root to relate URIs to");
  return values.map((value) => {
    const spelling = value.replaceAll("\\", "/").replace(/\/+$/u, "");
    const windows = /^[A-Za-z]:\//u.test(spelling);
    if (!windows && !spelling.startsWith("/")) fail(`source root ${value} is not absolute`);
    return { spelling, windows };
  });
}

function decodedPath(uri: string): string {
  if (!/^file:/iu.test(uri)) return uri;
  if (!/^file:\/\/\//iu.test(uri) || uri.includes("?") || uri.includes("#"))
    fail(`${JSON.stringify(uri)} is a file URL with an authority, query or fragment`);
  let path: string;
  try {
    path = decodeURIComponent(uri.slice("file://".length));
  } catch {
    fail(`${JSON.stringify(uri)} cannot be percent-decoded`);
  }
  // file:///C:/x decodes to /C:/x; the drive path is the absolute Windows path.
  return /^\/[A-Za-z]:\//u.test(path) ? path.slice(1) : path;
}

/**
 * One URI relative to the declared source root. With `allowRoot`, the root itself maps to
 * the empty string (Cisco reports a top-level skill directory that way). With
 * `allowDirectory` (S2g: notification and run-artifact locations only), a URI ending in
 * exactly one `/` names a directory: the path before that slash must pass every rule a file
 * path passes, and the result keeps its trailing slash (`node_modules/`). The root itself is
 * never a directory URI.
 */
function relativeTo(
  uri: string,
  candidates: readonly Root[],
  allowRoot = false,
  allowDirectory = false,
): string {
  if (typeof uri !== "string" || uri.length === 0) fail("an empty artifact URI");
  if (uri.includes("\0")) fail("an artifact URI holds a NUL character");
  if (allowDirectory && uri.endsWith("/")) {
    const trimmed = uri.slice(0, -1);
    if (trimmed === "" || trimmed === "." || trimmed.endsWith("/") || /^file:\/*$/iu.test(trimmed))
      fail(`${JSON.stringify(uri)} does not name a directory under the source root`);
    return `${relativeTo(trimmed, candidates)}/`;
  }
  const path = decodedPath(uri).replaceAll("\\", "/");
  const absolute = path.startsWith("/") || /^[A-Za-z]:\//u.test(path);
  let relative: string;
  if (absolute) {
    const root = candidates.find((entry) => {
      const [left, right] = entry.windows
        ? [path.toLowerCase(), entry.spelling.toLowerCase()]
        : [path, entry.spelling];
      return left === right || left.startsWith(`${right}/`);
    });
    if (root === undefined) fail(`${JSON.stringify(uri)} is outside the declared source root`);
    relative = path.slice(root.spelling.length).replace(/^\/+/u, "");
    if (relative === "") {
      if (allowRoot) return "";
      fail(`${JSON.stringify(uri)} names the source root itself, not a file under it`);
    }
  } else relative = path.startsWith("./") ? path.slice(2) : path;
  try {
    return assertSafeRelativePosixPathV1(relative, "SARIF artifact URI");
  } catch {
    fail(`${JSON.stringify(uri)} does not resolve to a safe path under the source root`);
  }
}

function clone(value: unknown): Json {
  return JSON.parse(JSON.stringify(value)) as Json;
}

function isRecord(value: unknown): value is Record<string, Json> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** One artifact location, and whether it may name a directory (S2g). */
type FoundLocation = Readonly<{ location: Record<string, Json>; directory: boolean }>;

const NOTIFICATION_KEYS: ReadonlySet<string> = new Set([
  "toolExecutionNotifications",
  "toolConfigurationNotifications",
]);

/**
 * Whether a location at `path` (property names and array indices from a run) may name a
 * directory: anything under `invocations[i].toolExecutionNotifications` or
 * `invocations[i].toolConfigurationNotifications`, and a run artifact's own `location`
 * (`artifacts[i].location`). Result locations, related locations, code flows and any
 * notification nested elsewhere must name files.
 */
function directoryScope(path: readonly (string | number)[]): boolean {
  if (path[0] === "invocations" && typeof path[1] === "number")
    return typeof path[2] === "string" && NOTIFICATION_KEYS.has(path[2]);
  return (
    path.length === 3 &&
    path[0] === "artifacts" &&
    typeof path[1] === "number" &&
    path[2] === "location"
  );
}

/**
 * Every SARIF `artifactLocation`, every result's `analysisTarget` (an artifact location
 * too, S2i), and every run artifact's `location`, in the document.
 * With `run`, the document is one SARIF run, and the locations its notifications and run
 * artifacts hold may name directories ({@link directoryScope}); otherwise none may.
 */
function artifactLocations(document: Json, run = false): FoundLocation[] {
  const found: FoundLocation[] = [];
  // `key` names the property holding `value`; `owner` names the nearest property above it,
  // so an entry of `artifacts: [{ location }]` sees its location with owner "artifacts".
  const visit = (
    value: Json,
    key: string | undefined,
    owner: string | undefined,
    path: readonly (string | number)[],
  ): void => {
    if (Array.isArray(value)) {
      value.forEach((item, index) => {
        visit(item, undefined, key ?? owner, [...path, index]);
      });
      return;
    }
    if (!isRecord(value)) return;
    if (
      key === "artifactLocation" ||
      key === "analysisTarget" ||
      (key === "location" && owner === "artifacts")
    )
      found.push({ location: value, directory: run && directoryScope(path) });
    for (const [childKey, child] of Object.entries(value))
      visit(child, childKey, key ?? owner, [...path, childKey]);
  };
  visit(document, undefined, undefined, []);
  return found;
}

/** The analyzer's conventional name for the root it was given; it may go undeclared. */
const SOURCE_ROOT_BASE_ID = "%SRCROOT%";

/**
 * Where a `uriBaseId` points: an absolute location, or a path relative to the root the
 * analyzer was given. A `file:` base is kept URI-encoded, so a relative reference is joined
 * to it in URI space and the joined URI is percent-decoded exactly once, in `relativeTo`;
 * containment is decided on that decoded path. A base given as a plain path is taken
 * literally, as a plain artifact path is.
 */
type Base = Readonly<{ absolute: string }> | Readonly<{ underRoot: string }>;

function isAbsoluteLocation(uri: string): boolean {
  const path = decodedPath(uri).replaceAll("\\", "/");
  return path.startsWith("/") || /^[A-Za-z]:\//u.test(path);
}

function joined(base: Base, uri: string): string {
  const reference = uri.startsWith("./") ? uri.slice(2) : uri;
  return "absolute" in base ? `${base.absolute}${reference}` : `${base.underRoot}${reference}`;
}

/**
 * Resolves a run's `uriBaseId`s through its `originalUriBaseIds`, following chained bases.
 * An undeclared `%SRCROOT%` is the root the analyzer was given; any other undeclared id, a
 * cycle, a base without a directory URI (ending in `/`) or a relative base naming no base of
 * its own is refused. Whether the resolved location lies inside the source root is decided
 * afterwards, for the joined URI.
 */
function baseResolver(declared: Json | undefined): (id: string) => Base {
  if (declared !== undefined && !isRecord(declared)) fail("originalUriBaseIds is not an object");
  const resolved = new Map<string, Base>();
  const resolve = (id: string, seen: readonly string[]): Base => {
    const known = resolved.get(id);
    if (known !== undefined) return known;
    if (seen.includes(id)) fail(`base ${id} refers back to itself`);
    const entry = declared !== undefined && Object.hasOwn(declared, id) ? declared[id] : undefined;
    let base: Base;
    if (entry === undefined) {
      if (id !== SOURCE_ROOT_BASE_ID) fail(`base ${id} is not declared in originalUriBaseIds`);
      base = { underRoot: "" };
    } else {
      if (!isRecord(entry) || typeof entry.uri !== "string" || !entry.uri.endsWith("/"))
        fail(`base ${id} has no directory URI`);
      const uri = entry.uri;
      if (uri.includes("\0")) fail(`base ${id} holds a NUL character`);
      if (/^[A-Za-z][A-Za-z0-9+.-]+:/u.test(uri) && !/^file:/iu.test(uri))
        fail(`base ${id} is not a file location`);
      if (isAbsoluteLocation(uri))
        base = { absolute: /^file:/iu.test(uri) ? uri : uri.replaceAll("\\", "/") };
      else if (entry.uriBaseId === undefined) fail(`base ${id} is relative and names no base`);
      else if (typeof entry.uriBaseId !== "string") fail(`base ${id} names a malformed base`);
      else {
        const parent = resolve(entry.uriBaseId, [...seen, id]);
        base =
          "absolute" in parent
            ? { absolute: joined(parent, uri) }
            : { underRoot: joined(parent, uri) };
      }
    }
    resolved.set(id, base);
    return base;
  };
  return (id) => resolve(id, []);
}

type Normalization = { rewritten: number; removedBaseUris: number };

function normalizeScope(
  scope: Json,
  declared: Json | undefined,
  candidates: readonly Root[],
  settled: ReadonlySet<object>,
  counts: Normalization,
  run = false,
): void {
  const base = baseResolver(declared);
  for (const { location, directory } of artifactLocations(scope, run)) {
    const baseId = location.uriBaseId;
    if (baseId !== undefined && typeof baseId !== "string")
      fail("an artifact uriBaseId is not a string");
    if ("uri" in location) {
      const uri = location.uri;
      if (typeof uri !== "string") fail("an artifact URI is not a string");
      if (!settled.has(location)) {
        const target =
          baseId === undefined || isAbsoluteLocation(uri) ? uri : joined(base(baseId), uri);
        location.uri = relativeTo(target, candidates, false, directory);
      }
      counts.rewritten += 1;
    } else if (baseId !== undefined) base(baseId);
    // Every URI is now relative to the declared source root, which is what an undeclared
    // %SRCROOT% names; a reference to any other (removed) base is obsolete.
    if (baseId !== undefined && baseId !== SOURCE_ROOT_BASE_ID) delete location.uriBaseId;
  }
}

function normalize(
  document: Record<string, unknown>,
  sourceRoots: readonly string[],
  settled: ReadonlySet<object> = new Set(),
  copy: Json = clone(document),
): SourceRelativeSarifV1 {
  const candidates = roots(sourceRoots);
  const counts: Normalization = { rewritten: 0, removedBaseUris: 0 };
  if (isRecord(copy)) {
    const { runs, ...rest } = copy;
    if (Array.isArray(runs))
      for (const run of runs) {
        if (!isRecord(run)) {
          normalizeScope(run, undefined, candidates, settled, counts);
          continue;
        }
        normalizeScope(run, run.originalUriBaseIds, candidates, settled, counts, true);
        if ("originalUriBaseIds" in run) {
          delete run.originalUriBaseIds;
          counts.removedBaseUris += 1;
        }
      }
    else if (runs !== undefined) normalizeScope(runs, undefined, candidates, settled, counts);
    normalizeScope(rest, undefined, candidates, settled, counts);
  }
  return Object.freeze({
    document: copy as Record<string, unknown>,
    rewritten: counts.rewritten,
    removedBaseUris: counts.removedBaseUris,
  });
}

/**
 * Rewrites every artifact URI of `document` relative to one of `sourceRoots`, resolving each
 * `uriBaseId` through its run's `originalUriBaseIds` first, so a base outside the source root
 * fails closed instead of being discarded.
 */
export function sourceRelativeSarifV1(
  document: Record<string, unknown>,
  sourceRoots: readonly string[],
): SourceRelativeSarifV1 {
  return normalize(document, sourceRoots);
}

/** Where one artifact location of a run points once its `uriBaseId` is resolved. */
export type SarifLocationTargetV1 =
  /** No base, the analyzer's own `%SRCROOT%` (or a chain rooted there), or an absolute URI. */
  | Readonly<{ kind: "analyzer-relative"; uri: unknown; directory: boolean }>
  /** A base resolving to an absolute location inside the source root, related to it. */
  | Readonly<{ kind: "source-relative"; uri: string; directory: boolean }>;

/**
 * Rewrites every artifact location of one SARIF run in place (the run must be a mutable
 * JSON value) under the base rules {@link sourceRelativeSarifV1} applies: each `uriBaseId`
 * is resolved through the run's `originalUriBaseIds`, following chains, and an undeclared
 * id other than `%SRCROOT%`, a cycle or a malformed base throws, even on a location without
 * a URI. A relative URI under a base resolving to an absolute location is related to
 * `sourceRoots` (a location outside them throws) and handed to `rewrite` as
 * `source-relative`; every other URI goes as `analyzer-relative`, joined to its base chain
 * when that chain is rooted at the analyzer's own `%SRCROOT%`. Afterwards every reference to
 * a base other than `%SRCROOT%` and the run's `originalUriBaseIds` are removed, so no stale
 * base survives the rewrite. Throws `TypeError`.
 */
export function rewriteSarifRunLocationsV1(
  run: Record<string, unknown>,
  sourceRoots: readonly string[],
  rewrite: (target: SarifLocationTargetV1) => unknown,
): void {
  const candidates = roots(sourceRoots);
  const base = baseResolver(run.originalUriBaseIds as Json | undefined);
  for (const { location, directory } of artifactLocations(run as Json, true)) {
    const baseId = location.uriBaseId;
    if (baseId !== undefined && typeof baseId !== "string")
      fail("an artifact uriBaseId is not a string");
    const resolved = baseId === undefined ? undefined : base(baseId);
    if ("uri" in location) {
      const uri: unknown = location.uri;
      let target: SarifLocationTargetV1;
      if (resolved === undefined) target = { kind: "analyzer-relative", uri, directory };
      else if (typeof uri !== "string") fail("an artifact URI is not a string");
      else if (isAbsoluteLocation(uri)) target = { kind: "analyzer-relative", uri, directory };
      else if ("absolute" in resolved)
        target = {
          kind: "source-relative",
          uri: relativeTo(joined(resolved, uri), candidates, false, directory),
          directory,
        };
      else target = { kind: "analyzer-relative", uri: joined(resolved, uri), directory };
      location.uri = rewrite(target) as Json;
    }
    if (baseId !== undefined && baseId !== SOURCE_ROOT_BASE_ID) delete location.uriBaseId;
  }
  delete run.originalUriBaseIds;
}

type CiscoFinding = Readonly<{ skill: string; ruleId: string; file: string; line: number | null }>;

function ciscoFail(message: string): never {
  throw new TypeError(`aih-scan Cisco SARIF: ${message}`);
}

function ciscoFindings(
  report: Record<string, unknown>,
  candidates: readonly Root[],
): CiscoFinding[] {
  const results = report.results;
  if (!Array.isArray(results)) ciscoFail("the JSON report holds no results list");
  const findings: CiscoFinding[] = [];
  for (const entry of results) {
    if (!isRecord(entry) || typeof entry.skill_path !== "string" || !Array.isArray(entry.findings))
      ciscoFail("a JSON report skill entry is malformed");
    let skill: string;
    try {
      skill = relativeTo(entry.skill_path, candidates, true);
    } catch {
      ciscoFail(`skill path ${JSON.stringify(entry.skill_path)} is outside the source root`);
    }
    for (const finding of entry.findings) {
      if (
        !isRecord(finding) ||
        typeof finding.rule_id !== "string" ||
        typeof finding.file_path !== "string" ||
        !(
          finding.line_number === null ||
          finding.line_number === undefined ||
          Number.isSafeInteger(finding.line_number)
        )
      )
        ciscoFail("a JSON report finding is malformed");
      let file: string;
      try {
        file = relativeTo(finding.file_path, [], false);
      } catch {
        ciscoFail(`finding path ${JSON.stringify(finding.file_path)} is not a relative path`);
      }
      findings.push({
        skill,
        ruleId: finding.rule_id,
        file,
        line: typeof finding.line_number === "number" ? finding.line_number : null,
      });
    }
  }
  return findings;
}

/**
 * The source-relative identity of one original Cisco location. Cisco writes URIs relative
 * to the skill directory it scanned, which is what its undeclared `%SRCROOT%` names; any
 * other base is resolved through the run's `originalUriBaseIds` first, so an undeclared,
 * cyclic or malformed base, or one that resolves outside the source root, fails closed. An
 * absolute URI is not a Cisco location and fails too.
 */
function ciscoLocationIdentity(
  target: Record<string, Json>,
  skill: string,
  base: (id: string) => Base,
  candidates: readonly Root[],
  index: number,
): string {
  const uri = target.uri as string;
  const baseId = target.uriBaseId;
  try {
    if (baseId !== undefined && typeof baseId !== "string")
      fail("an artifact uriBaseId is not a string");
    if (isAbsoluteLocation(uri)) fail(`${JSON.stringify(uri)} is not relative`);
    const resolved = baseId === undefined ? { underRoot: "" } : base(baseId);
    if ("absolute" in resolved) return relativeTo(joined(resolved, uri), candidates);
    const relative = relativeTo(joined(resolved, uri), [], false);
    return skill === "" ? relative : `${skill}/${relative}`;
  } catch (error) {
    ciscoFail(`SARIF result ${index} location: ${(error as Error).message}`);
  }
}

/**
 * Cisco `scan-all` merges every skill's results into one SARIF run whose URIs are relative
 * to each skill's own directory, so `SKILL.md` can mean any skill. Its JSON report lists the
 * same findings in the same order under each skill's absolute path. Each SARIF result is
 * paired with its JSON finding (rule, file and line must agree, or the run fails closed) and
 * rewritten as `<skill directory relative to the source root>/<file>`, and so is its
 * `analysisTarget` (S2i). Every location's base is validated before it is settled (`ciscoLocationIdentity`); a declared base must resolve
 * to the file the paired JSON finding names.
 */
export function ciscoSourceRelativeSarifV1(
  sarif: Record<string, unknown>,
  report: Record<string, unknown>,
  sourceRoots: readonly string[],
): SourceRelativeSarifV1 {
  const candidates = roots(sourceRoots);
  const findings = ciscoFindings(report, candidates);
  const copy = clone(sarif);
  if (!isRecord(copy) || !Array.isArray(copy.runs)) ciscoFail("the SARIF log holds no runs");
  const results: { result: Record<string, Json>; base: (id: string) => Base }[] = [];
  // Result locations this mapper settles from the JSON report; their bases are not re-applied.
  const settled = new Set<object>();
  for (const run of copy.runs) {
    if (!isRecord(run)) ciscoFail("a SARIF run is malformed");
    // A run without a results list is never skipped (S2f): it proves no analysis.
    if (!Array.isArray(run.results)) ciscoFail("a SARIF results list is malformed");
    let base: (id: string) => Base;
    try {
      base = baseResolver(run.originalUriBaseIds);
    } catch (error) {
      ciscoFail((error as Error).message);
    }
    for (const result of run.results) {
      if (!isRecord(result)) ciscoFail("a SARIF result is malformed");
      results.push({ result, base });
    }
  }
  if (results.length !== findings.length)
    ciscoFail(
      `the SARIF report holds ${results.length} results but the JSON report ${findings.length} findings`,
    );
  results.forEach(({ result, base }, index) => {
    const finding = findings[index] as CiscoFinding;
    const locations = result.locations;
    if (!Array.isArray(locations) || locations.length === 0)
      ciscoFail(`SARIF result ${index} has no location`);
    const first = locations[0];
    const physical = isRecord(first) ? first.physicalLocation : undefined;
    const artifact = isRecord(physical) ? physical.artifactLocation : undefined;
    const region = isRecord(physical) ? physical.region : undefined;
    if (!isRecord(artifact) || typeof artifact.uri !== "string")
      ciscoFail(`SARIF result ${index} has no artifact URI`);
    const identity = ciscoLocationIdentity(artifact, finding.skill, base, candidates, index);
    const expected = finding.skill === "" ? finding.file : `${finding.skill}/${finding.file}`;
    const line = isRecord(region) && typeof region.startLine === "number" ? region.startLine : null;
    if (result.ruleId !== finding.ruleId || identity !== expected || line !== finding.line)
      ciscoFail(
        `SARIF result ${index} (${String(result.ruleId)} ${identity}:${String(line)}) does not match JSON finding ${index} (${finding.ruleId} ${expected}:${String(finding.line)})`,
      );
    // Every other location inside the result (further locations, related locations, code
    // flows, the analysis target, S2i) is relative to the same skill directory (U1e review
    // P2), never to the root.
    for (const { location: target } of artifactLocations(result)) {
      if (typeof target.uri !== "string") continue;
      target.uri =
        target === artifact
          ? identity
          : ciscoLocationIdentity(target, finding.skill, base, candidates, index);
      settled.add(target);
    }
  });
  // A location outside every result (a run artifact, a notification) names no skill, so a
  // URI relative to the analyzer's %SRCROOT% (the skill it scanned) cannot be resolved; only
  // an absolute URI or one under a base that resolves inside the source root stays.
  for (const run of copy.runs as Record<string, Json>[]) {
    const base = baseResolver(run.originalUriBaseIds);
    for (const { location } of artifactLocations(run, true)) {
      if (settled.has(location) || typeof location.uri !== "string") continue;
      const baseId = location.uriBaseId;
      if (isAbsoluteLocation(location.uri) && baseId === undefined) continue;
      let resolved: Base;
      try {
        if (baseId !== undefined && typeof baseId !== "string")
          fail("an artifact uriBaseId is not a string");
        resolved = baseId === undefined ? { underRoot: "" } : base(baseId);
      } catch (error) {
        ciscoFail(`a run location: ${(error as Error).message}`);
      }
      if (!("absolute" in resolved))
        ciscoFail(
          `run location ${JSON.stringify(location.uri)} is relative to a skill directory but belongs to no result, so it names no skill`,
        );
    }
  }
  return normalize(copy, sourceRoots, settled, copy);
}
