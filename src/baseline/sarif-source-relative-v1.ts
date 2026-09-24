import { assertSafeRelativePosixPathV1 } from "../contract/strict-json-v1.js";
import {
  assertCiscoAnalyzersCompleteV1,
  CISCO_SKILL_LOAD_FALLBACK_RULE_V1,
  type CiscoSkillAnalyzersV1,
  ciscoFailedAnalyzersV1,
  ciscoSkillLabelV1,
} from "./cisco-analyzer-failures-v1.js";

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
 * What a value handed to {@link artifactLocations} is: one SARIF run, one result, or
 * anything else (a log's other members, a run's shared `threadFlowLocations` or `graphs`).
 */
type LocationScope = "run" | "result" | "detached";

/**
 * Whether the property at `path` (ending in `analysisTarget`) is a result's own analysis
 * target, its only schema position (U1g, review of S2i P2).
 */
function resultTargetPosition(path: readonly (string | number)[], scope: LocationScope): boolean {
  if (scope === "result") return path.length === 1;
  return (
    scope === "run" && path.length === 3 && path[0] === "results" && typeof path[1] === "number"
  );
}

/**
 * Every SARIF `artifactLocation`, a result's `analysisTarget` (an artifact location too,
 * S2i), and every run artifact's `location`, in `document`.
 * U1g (review of S2i, P2): `analysisTarget` is recognized only at `result.analysisTarget`,
 * its one schema position, and nothing inside a `properties` bag is ever visited: a property
 * bag is the analyzer's own data, never normalized, rewritten or refused. An
 * `artifactLocation` or result `analysisTarget` that is not an object fails closed.
 * In a `run` scope, the locations its notifications and run artifacts hold may name
 * directories ({@link directoryScope}); otherwise none may.
 */
function artifactLocations(document: Json, scope: LocationScope): FoundLocation[] {
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
    const located =
      key === "artifactLocation" || (key === "analysisTarget" && resultTargetPosition(path, scope));
    if (!isRecord(value)) {
      if (located) fail(`${key} is not an object`);
      return;
    }
    if (located || (key === "location" && owner === "artifacts"))
      found.push({ location: value, directory: scope === "run" && directoryScope(path) });
    for (const [childKey, child] of Object.entries(value))
      if (childKey !== "properties") visit(child, childKey, key ?? owner, [...path, childKey]);
  };
  visit(document, undefined, undefined, []);
  return found;
}

/**
 * U1g: every artifact location inside one SARIF result by the rules of the source-relative
 * normalization ({@link artifactLocations}): its `locations`, related locations, code flows,
 * stacks, fixes, attachments, its `analysisTarget` (only at that position), never a property
 * bag. The shard binding and the win32 D1 binder enumerate exactly these. Throws `TypeError`
 * on an artifact location that is not an object.
 */
export function sarifResultArtifactLocationsV1(result: unknown): Record<string, unknown>[] {
  return artifactLocations(result as Json, "result").map(({ location }) => location);
}

/**
 * U1g: every artifact location of one SARIF run, results and run artifacts included, by the
 * same rules ({@link artifactLocations}). Throws `TypeError` like
 * {@link sarifResultArtifactLocationsV1}.
 */
export function sarifRunArtifactLocationsV1(run: unknown): Record<string, unknown>[] {
  return artifactLocations(run as Json, "run").map(({ location }) => location);
}

/**
 * U1g: every artifact location inside a value that is neither a run nor a result (a run's
 * shared `threadFlowLocations` or `graphs`); no `analysisTarget` is one there.
 */
export function sarifDetachedArtifactLocationsV1(value: unknown): Record<string, unknown>[] {
  return artifactLocations(value as Json, "detached").map(({ location }) => location);
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

/**
 * U1g (review of S2i, P1; S2h for the shard): the file one `artifactLocation` names, or why
 * it names none. A `uri` names itself. An `index` must be a non-negative safe integer naming
 * an object of `run.artifacts` whose `location.uri` is a string (and whose own
 * `location.index`, if present, is that index); the artifact's URI is then the file. A `uri`
 * given beside an `index` must equal the artifact's URI. A location with neither names no
 * file. Every path resolves indices through this one rule, after its run is normalized, so
 * both URIs are compared in their normalized, source-relative form.
 */
export function sarifArtifactLocationTargetV1(
  artifactLocation: unknown,
  artifacts: unknown,
): Readonly<{ uri: string } | { problem: string }> {
  if (!isRecord(artifactLocation)) return { problem: "an artifact location is not an object" };
  const { uri, index } = artifactLocation;
  if (uri !== undefined && typeof uri !== "string")
    return { problem: "an artifact location URI is not a string" };
  if (index === undefined)
    return typeof uri === "string" ? { uri } : { problem: "an artifact location names no file" };
  if (typeof index !== "number" || !Number.isSafeInteger(index) || index < 0)
    return { problem: `artifact index ${JSON.stringify(index)} is malformed` };
  const artifact: unknown = Array.isArray(artifacts) ? artifacts[index] : undefined;
  const location = isRecord(artifact) ? artifact.location : undefined;
  if (!isRecord(location) || typeof location.uri !== "string")
    return { problem: `artifact index ${index} resolves to no run artifact URI` };
  if (location.index !== undefined && location.index !== index)
    return { problem: `artifact index ${index} resolves to an artifact that names another index` };
  if (uri !== undefined && uri !== location.uri)
    return {
      problem: `URI ${JSON.stringify(uri)} and artifact index ${index} (${JSON.stringify(location.uri)}) disagree`,
    };
  return { uri: location.uri };
}

/**
 * U1i (review of U1h, P1): the URIs of every ancestor of run artifact `index`, nearest first.
 * An artifact lies inside its `parentIndex` artifact, and that one inside its own, so a
 * location that names an artifact also reaches every ancestor. Each `parentIndex` must be a
 * non-negative safe integer naming an object of `run.artifacts` whose `location.uri` is a
 * string (and whose own `location.index`, if present, is that index); a chain that returns
 * to an artifact already on it is a cycle. Anything else is the problem returned.
 */
function artifactAncestry(
  index: number,
  artifacts: unknown,
): Readonly<{ uris: string[] } | { problem: string }> {
  const list: readonly unknown[] = Array.isArray(artifacts) ? artifacts : [];
  const seen = new Set<number>([index]);
  const uris: string[] = [];
  let current = index;
  for (;;) {
    const entry = list[current];
    const parent = isRecord(entry) ? entry.parentIndex : undefined;
    if (parent === undefined) return { uris };
    const at = `run artifact ${current} parentIndex`;
    if (typeof parent !== "number" || !Number.isSafeInteger(parent) || parent < 0)
      return { problem: `${at} ${JSON.stringify(parent)} is malformed` };
    if (seen.has(parent)) return { problem: `${at} ${parent} forms a cycle` };
    const owner = list[parent];
    const location = isRecord(owner) ? owner.location : undefined;
    if (!isRecord(location) || typeof location.uri !== "string")
      return { problem: `${at} ${parent} resolves to no run artifact URI` };
    if (location.index !== undefined && location.index !== parent)
      return { problem: `${at} ${parent} resolves to an artifact that names another index` };
    seen.add(parent);
    uris.push(location.uri);
    current = parent;
  }
}

/**
 * U1i (review of U1h, P1): every file one `artifactLocation` reaches: the file it names
 * ({@link sarifArtifactLocationTargetV1}) and, when it names a run artifact by `index`, every
 * ancestor of that artifact ({@link artifactAncestry}). Per-result containment and the
 * sealed-file binding apply to each of them.
 */
export function sarifArtifactLocationFilesV1(
  artifactLocation: unknown,
  artifacts: unknown,
): Readonly<{ uris: string[] } | { problem: string }> {
  const target = sarifArtifactLocationTargetV1(artifactLocation, artifacts);
  if ("problem" in target) return target;
  const index = isRecord(artifactLocation) ? artifactLocation.index : undefined;
  if (typeof index !== "number") return { uris: [target.uri] };
  const ancestry = artifactAncestry(index, artifacts);
  return "problem" in ancestry ? ancestry : { uris: [target.uri, ...ancestry.uris] };
}

/** The object `owner[key][index]` a reference names; anything else throws `TypeError`. */
function referencedEntry(
  owner: Json,
  key: "threadFlowLocations" | "graphs",
  index: Json | undefined,
  what: string,
): Record<string, Json> {
  if (typeof index !== "number" || !Number.isSafeInteger(index) || index < 0)
    fail(`${what} ${JSON.stringify(index)} is malformed`);
  const list = isRecord(owner) ? owner[key] : undefined;
  const entry = Array.isArray(list) ? list[index] : undefined;
  if (!isRecord(entry)) fail(`${what} ${index} resolves to no ${key} entry`);
  return entry;
}

function arrayOrNone(value: Json | undefined, what: string): Json[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) fail(`${what} is not an array`);
  return value;
}

/**
 * U1h (review of U1g, P1): every artifact location inside the run-level objects one result
 * references, resolved for that result: `run.threadFlowLocations[i]` through a thread-flow
 * location's `index` (in `codeFlows[].threadFlows[].locations[]`), and `run.graphs[i]` through
 * a graph traversal's `runGraphIndex`. A traversal must name exactly one of `runGraphIndex`
 * and `resultGraphIndex`, and a `resultGraphIndex` must name one of the result's own `graphs`
 * (whose locations are the result's own). A reference that is malformed, out of range or
 * names nothing, a shared thread-flow location that names another index, and a code flow,
 * thread flow or traversal list that is not an array throw `TypeError`. No other SARIF
 * reference from a result reaches an artifact location: addresses, logical locations, rules,
 * taxa and web requests hold none, and `provenance.invocationIndex` names the tool's
 * invocation, not a location of the result.
 */
export function sarifResultSharedArtifactLocationsV1(
  result: unknown,
  run: unknown,
): Record<string, unknown>[] {
  if (!isRecord(result)) fail("a SARIF result is not an object");
  const reached = new Set<Record<string, Json>>();
  for (const codeFlow of arrayOrNone(result.codeFlows, "codeFlows")) {
    if (!isRecord(codeFlow)) fail("a code flow is not an object");
    for (const threadFlow of arrayOrNone(codeFlow.threadFlows, "threadFlows")) {
      if (!isRecord(threadFlow)) fail("a thread flow is not an object");
      for (const step of arrayOrNone(threadFlow.locations, "a thread flow's locations")) {
        if (!isRecord(step)) fail("a thread-flow location is not an object");
        if (step.index === undefined) continue;
        const what = "thread-flow location index";
        const entry = referencedEntry(run as Json, "threadFlowLocations", step.index, what);
        if (entry.index !== undefined && entry.index !== step.index)
          fail(`${what} ${String(step.index)} resolves to an entry that names another index`);
        reached.add(entry);
      }
    }
  }
  for (const traversal of arrayOrNone(result.graphTraversals, "graphTraversals")) {
    if (!isRecord(traversal)) fail("a graph traversal is not an object");
    const { runGraphIndex, resultGraphIndex } = traversal;
    if ((runGraphIndex === undefined) === (resultGraphIndex === undefined))
      fail("a graph traversal must name exactly one of runGraphIndex and resultGraphIndex");
    if (runGraphIndex !== undefined)
      reached.add(referencedEntry(run as Json, "graphs", runGraphIndex, "run graph index"));
    else referencedEntry(result, "graphs", resultGraphIndex, "result graph index");
  }
  return [...reached].flatMap((entry) =>
    artifactLocations(entry, "detached").map(({ location }) => location),
  );
}

/**
 * U1j: the source-relative directory an absolute Cisco JSON report `skill_path` names,
 * related to `sourceRoots` by the rule every Cisco location uses (a Windows root matches
 * ignoring case; the root itself is ""). A relative, unsafe or outside path throws
 * `TypeError`.
 */
export function sourceRelativeSkillDirectoryV1(
  path: string,
  sourceRoots: readonly string[],
): string {
  const spelling = decodedPath(path).replaceAll("\\", "/");
  if (!spelling.startsWith("/") && !/^[A-Za-z]:\//u.test(spelling))
    fail(`${JSON.stringify(path)} is not an absolute skill path`);
  return relativeTo(path, roots(sourceRoots), true);
}

/**
 * Whether source-relative `path` lies in source-relative `directory` ("" is the root, which
 * holds everything). A nested skill's directory lies inside its parent's.
 */
export function sarifPathInsideDirectoryV1(directory: string, path: string): boolean {
  return directory === "" || path.startsWith(`${directory}/`);
}

/**
 * U1h: the source-relative file every artifact location one result of a normalized run
 * reaches names: its own ({@link sarifResultArtifactLocationsV1}) and those of the shared
 * objects it references ({@link sarifResultSharedArtifactLocationsV1}), each resolved by
 * {@link sarifArtifactLocationFilesV1}, with the ancestry of every artifact it names by index
 * (U1i). Throws `TypeError` on anything unresolved.
 */
export function sarifResultFilesV1(result: unknown, run: unknown): string[] {
  const artifacts = isRecord(run) ? run.artifacts : undefined;
  return [
    ...sarifResultArtifactLocationsV1(result),
    ...sarifResultSharedArtifactLocationsV1(result, run),
  ].flatMap((location) => {
    const files = sarifArtifactLocationFilesV1(location, artifacts);
    if ("problem" in files) fail(files.problem);
    return files.uris;
  });
}

/**
 * U1g (review of S2i, P1): every `index` of an already normalized scope resolves by
 * {@link sarifArtifactLocationTargetV1} against the run's own `artifacts`; outside a run no
 * index can resolve. A run artifact's own location may name only its own index, and U1i:
 * every run artifact's `parentIndex` chain must resolve, without a cycle
 * ({@link artifactAncestry}), whether or not a result references it. Throws `TypeError`
 * (stage `output` for every caller).
 */
function assertArtifactIndices(scope: Json, kind: LocationScope): void {
  const artifacts = kind === "run" && isRecord(scope) ? scope.artifacts : undefined;
  const own = new Map<object, number>();
  if (Array.isArray(artifacts))
    artifacts.forEach((artifact, index) => {
      if (isRecord(artifact) && isRecord(artifact.location)) own.set(artifact.location, index);
      const ancestry = artifactAncestry(index, artifacts);
      if ("problem" in ancestry) fail(ancestry.problem);
    });
  for (const { location } of artifactLocations(scope, kind)) {
    if (location.index === undefined) continue;
    const position = own.get(location);
    if (position !== undefined && location.index !== position)
      fail(`run artifact ${position} names artifact index ${JSON.stringify(location.index)}`);
    const target = sarifArtifactLocationTargetV1(location, artifacts);
    if ("problem" in target) fail(target.problem);
  }
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
  for (const { location, directory } of artifactLocations(scope, run ? "run" : "detached")) {
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
  assertArtifactIndices(scope, run ? "run" : "detached");
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
  for (const { location, directory } of artifactLocations(run as Json, "run")) {
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
  assertArtifactIndices(run as Json, "run");
}

type CiscoFinding = Readonly<{
  /** The index of the reporting skill's entry in the JSON report's `results`. */
  entry: number;
  skill: string;
  ruleId: string;
  /** `null` for a skill-level finding (`"file_path": null`, D28): the skill's own SKILL.md. */
  file: string | null;
  line: number | null;
  /** The finding's `id` when it is a string: with `ruleId`, its D28 pairing identity. */
  id: string | undefined;
}>;

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
  for (const [index, entry] of results.entries()) {
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
        !(typeof finding.file_path === "string" || finding.file_path === null) ||
        !(
          finding.line_number === null ||
          finding.line_number === undefined ||
          Number.isSafeInteger(finding.line_number)
        )
      )
        ciscoFail("a JSON report finding is malformed");
      let file: string | null = null;
      if (finding.file_path === null) {
        // D28: a skill-level finding is paired by its identity, so it must have one, and it
        // names no line.
        const position = findings.length;
        if (typeof finding.id !== "string")
          ciscoFail(`skill-level finding ${position} ("file_path": null) has no string id`);
        if (finding.line_number !== null && finding.line_number !== undefined)
          ciscoFail(`skill-level finding ${position} ("file_path": null) names a line`);
      } else
        try {
          file = relativeTo(finding.file_path, [], false);
        } catch {
          ciscoFail(`finding path ${JSON.stringify(finding.file_path)} is not a relative path`);
        }
      findings.push({
        entry: index,
        skill,
        ruleId: finding.rule_id,
        file,
        line: typeof finding.line_number === "number" ? finding.line_number : null,
        id: typeof finding.id === "string" ? finding.id : undefined,
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
 * Coordinator decision D28 (U1h): a Cisco JSON finding with `"file_path": null` is accepted
 * only as a skill-level finding at the reporting skill's own SKILL.md, and only through a
 * bijective pairing; returns the location its counterpart must name, which is that SKILL.md.
 *
 * - Its SARIF counterpart (the result at the same position) must carry the same identity:
 *   JSON `(rule_id, id)` is SARIF `(ruleId, fingerprints.primaryLocationLineHash)`. Otherwise
 *   the finding has no counterpart and the run fails.
 * - That identity must occur exactly once among the JSON findings and exactly once among the
 *   SARIF results. Any duplicate fails, across skills too (U1i): a base the analyzer supplies
 *   cannot disambiguate an identity D28 requires to be unique.
 * - The counterpart's own location must resolve to exactly `<skill>/SKILL.md` (the caller's
 *   identity check); every other location, index and (on win32) D1 rule then applies to it
 *   as to any result. Scan never writes a location for a finding without a counterpart.
 *
 * The pairing proves no analysis: completion is decided separately and is not changed here.
 */
function ciscoSkillLevelFindingV1(
  finding: CiscoFinding,
  result: Record<string, Json>,
  identity: string,
  index: number,
  identities: Readonly<{
    fingerprint: string | undefined;
    json: ReadonlyMap<string, number>;
    sarif: ReadonlyMap<string, number>;
    key: (ruleId: unknown, id: unknown) => string;
  }>,
): string {
  const named = `(${finding.ruleId}, ${String(finding.id)})`;
  if (result.ruleId !== finding.ruleId || identities.fingerprint !== finding.id)
    ciscoFail(
      `JSON skill-level finding ${index} ${named} has no SARIF counterpart: SARIF result ${index} is (${String(result.ruleId)}, ${String(identities.fingerprint)})`,
    );
  const key = identities.key(finding.ruleId, finding.id);
  const json = identities.json.get(key) ?? 0;
  const sarif = identities.sarif.get(key) ?? 0;
  if (json !== 1 || sarif !== 1)
    ciscoFail(
      `skill-level finding identity ${named} is not unique across the paired reports (JSON ${json}, SARIF ${sarif})`,
    );
  const manifest = finding.skill === "" ? "SKILL.md" : `${finding.skill}/SKILL.md`;
  if (identity !== manifest)
    ciscoFail(
      `JSON skill-level finding ${index} ${named}: its SARIF counterpart names ${identity}, not the reporting skill's ${manifest}`,
    );
  return manifest;
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
  const results: {
    result: Record<string, Json>;
    base: (id: string) => Base;
    run: Record<string, Json>;
  }[] = [];
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
      results.push({ result, base, run });
    }
  }
  if (results.length !== findings.length)
    ciscoFail(
      `the SARIF report holds ${results.length} results but the JSON report ${findings.length} findings`,
    );
  // D28: the pairing identities, JSON (rule_id, id) and SARIF (ruleId,
  // fingerprints.primaryLocationLineHash), counted across the paired reports.
  const identityKey = (ruleId: unknown, id: unknown) => JSON.stringify([ruleId, id]);
  const fingerprintOf = (result: Record<string, Json>) =>
    isRecord(result.fingerprints) && typeof result.fingerprints.primaryLocationLineHash === "string"
      ? result.fingerprints.primaryLocationLineHash
      : undefined;
  const count = (keys: readonly string[]) => {
    const counts = new Map<string, number>();
    for (const key of keys) counts.set(key, (counts.get(key) ?? 0) + 1);
    return counts;
  };
  const jsonIdentities = count(
    findings.flatMap(({ ruleId, id }) => (id === undefined ? [] : [identityKey(ruleId, id)])),
  );
  const sarifIdentities = count(
    results.flatMap(({ result }) => {
      const fingerprint = fingerprintOf(result);
      return fingerprint === undefined ? [] : [identityKey(result.ruleId, fingerprint)];
    }),
  );
  // U1k (review of U1j, P2): the same identities counted in each reporting skill (results are
  // paired with findings by position, so a result belongs to its finding's skill).
  const skillKey = (entry: number, ruleId: unknown, id: unknown) =>
    JSON.stringify([entry, ruleId, id]);
  const jsonInSkill = count(
    findings.flatMap(({ entry, ruleId, id }) =>
      id === undefined ? [] : [skillKey(entry, ruleId, id)],
    ),
  );
  const sarifInSkill = count(
    results.flatMap(({ result }, index) => {
      const fingerprint = fingerprintOf(result);
      return fingerprint === undefined
        ? []
        : [skillKey((findings[index] as CiscoFinding).entry, result.ruleId, fingerprint)];
    }),
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
    const expected =
      finding.file === null
        ? ciscoSkillLevelFindingV1(finding, result, identity, index, {
            fingerprint: fingerprintOf(result),
            json: jsonIdentities,
            sarif: sarifIdentities,
            key: identityKey,
          })
        : finding.skill === ""
          ? finding.file
          : `${finding.skill}/${finding.file}`;
    const line = isRecord(region) && typeof region.startLine === "number" ? region.startLine : null;
    if (result.ruleId !== finding.ruleId || identity !== expected || line !== finding.line)
      ciscoFail(
        `SARIF result ${index} (${String(result.ruleId)} ${identity}:${String(line)}) does not match JSON finding ${index} (${finding.ruleId} ${expected}:${String(finding.line)})`,
      );
    // U1k (review of U1j, P2): Cisco gives every finding its D28 identity on both sides (JSON
    // `id`, SARIF `fingerprints.primaryLocationLineHash`), so a paired result must carry its
    // finding's identity, or both none; same-shaped results (rule, file and line alike) can
    // no longer be reordered or substituted. A skill-level finding was checked by D28 above.
    const fingerprint = fingerprintOf(result);
    if (finding.file !== null && fingerprint !== finding.id)
      ciscoFail(
        `SARIF result ${index} (${String(result.ruleId)}, ${String(fingerprint)}) does not carry the identity of JSON finding ${index} (${finding.ruleId}, ${String(finding.id)})`,
      );
    // U1k: a SKILL_LOAD_FALLBACK_USED finding, whatever its file_path, pairs by an identity
    // unique in its skill on both sides, as a job's or the OCI capture's does (a job report is
    // one skill). Real Cisco repeats the fallback identity across skills, so it is not counted
    // across the report.
    if (finding.ruleId === CISCO_SKILL_LOAD_FALLBACK_RULE_V1) {
      const named = `(${finding.ruleId}, ${String(finding.id)})`;
      if (finding.id === undefined)
        ciscoFail(`JSON ${finding.ruleId} finding ${index} has no string id`);
      const key = skillKey(finding.entry, finding.ruleId, finding.id);
      const jsonCount = jsonInSkill.get(key) ?? 0;
      const sarifCount = sarifInSkill.get(key) ?? 0;
      if (jsonCount !== 1 || sarifCount !== 1)
        ciscoFail(
          `${finding.ruleId} identity ${named} of JSON finding ${index} is not unique in the reporting skill ${finding.skill === "" ? "." : finding.skill} (JSON ${jsonCount}, SARIF ${sarifCount})`,
        );
    }
    // Every other location inside the result (further locations, related locations, code
    // flows, the analysis target, S2i) is relative to the same skill directory (U1e review
    // P2), never to the root.
    for (const { location: target } of artifactLocations(result, "result")) {
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
    for (const { location } of artifactLocations(run, "run")) {
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
  const normalized = normalize(copy, sourceRoots, settled, copy);
  // U1g (review of S2i, P1): every location a result carries (by URI or by index, once the
  // run is normalized and its indices resolved) must name a file inside the directory of the
  // skill that reported it. A relative URI was already read in that skill's directory; a
  // based URI or an index could still name a sibling skill's file. A nested skill's file is
  // inside its parent's directory, which Cisco's scan of the parent covers, so it is kept.
  // U1h (review of U1g, P1): so must every location of the run's shared thread-flow
  // locations and graphs the result references, resolved for this result.
  const shown = (directory: string) => (directory === "" ? "." : directory);
  results.forEach(({ result, run }, index) => {
    const skill = (findings[index] as CiscoFinding).skill;
    let files: string[];
    try {
      files = sarifResultFilesV1(result, run);
    } catch (error) {
      ciscoFail(`SARIF result ${index} location: ${(error as Error).message}`);
    }
    for (const file of files)
      if (!sarifPathInsideDirectoryV1(skill, file))
        ciscoFail(
          `SARIF result ${index} names ${JSON.stringify(file)}, which is not in the reporting skill ${shown(skill)}`,
        );
  });
  return normalized;
}

/**
 * One SARIF result as the fallback pairing reads it (U1j): its rule, its D28 identity
 * fingerprint (`fingerprints.primaryLocationLineHash`) and its first location's
 * source-relative URI. Kept before any projection drops the fingerprint.
 */
export type CiscoSarifResultIdentityV1 = Readonly<{
  ruleId: unknown;
  fingerprint: unknown;
  uri: unknown;
}>;

/** {@link CiscoSarifResultIdentityV1} of every result of a source-relative SARIF log, in order. */
export function ciscoSarifResultIdentitiesV1(log: unknown): CiscoSarifResultIdentityV1[] {
  const runs = isRecord(log) && Array.isArray(log.runs) ? log.runs : [];
  return runs.flatMap((run: unknown) =>
    (isRecord(run) && Array.isArray(run.results) ? run.results : []).map((result: unknown) => {
      const value = isRecord(result) ? result : {};
      const fingerprints = isRecord(value.fingerprints) ? value.fingerprints : {};
      const locations = Array.isArray(value.locations) ? value.locations : [];
      const physical = isRecord(locations[0]) ? locations[0].physicalLocation : undefined;
      const artifact = isRecord(physical) ? physical.artifactLocation : undefined;
      return {
        ruleId: value.ruleId,
        fingerprint: fingerprints.primaryLocationLineHash,
        uri: isRecord(artifact) ? artifact.uri : undefined,
      };
    }),
  );
}

/** How one skill's SKILL_LOAD_FALLBACK_USED findings pair ({@link ciscoFallbackPairingV1}). */
export type CiscoFallbackPairingV1 = Readonly<{
  fallbackFindings: number;
  fallbackCounterparts: number;
  fallbackDetail?: string;
}>;

/**
 * The one fallback pairing (U1j for a job and the OCI capture; U1k for each `scan-all` skill):
 * each JSON SKILL_LOAD_FALLBACK_USED finding of one skill counts only with the one SARIF
 * result of that skill paired with it by the D28 identity, JSON `(rule_id, id)` = SARIF
 * `(ruleId, fingerprints.primaryLocationLineHash)`, unique among the skill's JSON findings and
 * among its SARIF results, and located in `skill`. A rule-name match or a position is not a
 * counterpart: an unrelated SARIF fallback result, a finding with no string id, one identity
 * carried by several JSON findings (so they would share one SARIF result) or by several SARIF
 * results, or a counterpart outside the skill leaves the finding unpaired, with the first
 * reason in `fallbackDetail`.
 */
export function ciscoFallbackPairingV1(
  findings: readonly unknown[],
  sarifResults: readonly CiscoSarifResultIdentityV1[],
  skill: string,
): CiscoFallbackPairingV1 {
  const records = findings.filter(isRecord);
  const key = (ruleId: unknown, id: unknown) => JSON.stringify([ruleId, id]);
  const count = (keys: readonly string[]) => {
    const counts = new Map<string, number>();
    for (const entry of keys) counts.set(entry, (counts.get(entry) ?? 0) + 1);
    return counts;
  };
  const json = count(
    records.flatMap((finding) =>
      typeof finding.id === "string" ? [key(finding.rule_id, finding.id)] : [],
    ),
  );
  const sarif = count(
    sarifResults.flatMap((result) =>
      typeof result.fingerprint === "string" ? [key(result.ruleId, result.fingerprint)] : [],
    ),
  );
  const rule = CISCO_SKILL_LOAD_FALLBACK_RULE_V1;
  let fallbackFindings = 0;
  let fallbackCounterparts = 0;
  let fallbackDetail: string | undefined;
  for (const finding of records) {
    if (finding.rule_id !== rule) continue;
    fallbackFindings += 1;
    const named = `(${rule}, ${String(finding.id)})`;
    if (typeof finding.id !== "string") {
      fallbackDetail ??= `its ${rule} finding has no string id, so no SARIF counterpart`;
      continue;
    }
    const identity = key(rule, finding.id);
    const jsonCount = json.get(identity) ?? 0;
    const sarifCount = sarif.get(identity) ?? 0;
    if (sarifCount === 0) {
      fallbackDetail ??= `its ${rule} finding ${named} has no SARIF counterpart in that skill`;
      continue;
    }
    if (jsonCount !== 1 || sarifCount !== 1) {
      fallbackDetail ??= `its ${rule} identity ${named} is not unique across the paired reports (JSON ${jsonCount}, SARIF ${sarifCount})`;
      continue;
    }
    const counterpart = sarifResults.find(
      (result) => key(result.ruleId, result.fingerprint) === identity,
    );
    const uri = counterpart?.uri;
    if (typeof uri !== "string" || !sarifPathInsideDirectoryV1(skill, uri)) {
      fallbackDetail ??= `its ${rule} finding ${named}: its SARIF counterpart names ${JSON.stringify(uri)}, which is not in that skill`;
      continue;
    }
    fallbackCounterparts += 1;
  }
  return fallbackDetail === undefined
    ? { fallbackFindings, fallbackCounterparts }
    : { fallbackFindings, fallbackCounterparts, fallbackDetail };
}

/**
 * U1i, coordinator decision D30 (revised 20:58Z): Cisco `scan-all` is complete only when every
 * `analyzers_failed` entry of its JSON report is the documented `skill_loader` fallback
 * (`assertCiscoAnalyzersCompleteV1`). The report lists them per skill, under `results[i]`; an
 * entry at the report's top level names no skill and is never the fallback. A malformed
 * `analyzers_failed` fails at `output` before any skill is judged.
 *
 * U1k (review of U1j, P2): a skill's SKILL_LOAD_FALLBACK_USED finding counts only with its
 * identity counterpart ({@link ciscoFallbackPairingV1}, the rule jobs and the OCI capture use)
 * among that skill's part of `normalized` (the document {@link ciscoSourceRelativeSarifV1}
 * returned for the same reports, whose results follow the findings skill by skill), never
 * with the result that merely sits at its position.
 */
export function assertCiscoScanAllAnalyzersCompleteV1(
  report: Record<string, unknown>,
  normalized: Record<string, unknown>,
  sourceRoots: readonly string[],
): void {
  const candidates = roots(sourceRoots);
  const results = report.results;
  if (!Array.isArray(results)) ciscoFail("the JSON report holds no results list");
  const sarifResults = ciscoSarifResultIdentitiesV1(normalized);
  const skills: CiscoSkillAnalyzersV1[] = [
    {
      label: "at the report's top level",
      failed: ciscoFailedAnalyzersV1(report.analyzers_failed, "the top level"),
      fallbackFindings: 0,
      fallbackCounterparts: 0,
    },
  ];
  let position = 0;
  results.forEach((entry: unknown, index) => {
    if (!isRecord(entry) || typeof entry.skill_path !== "string" || !Array.isArray(entry.findings))
      ciscoFail("a JSON report skill entry is malformed");
    let skill: string;
    try {
      skill = relativeTo(entry.skill_path, candidates, true);
    } catch {
      ciscoFail(`skill path ${JSON.stringify(entry.skill_path)} is outside the source root`);
    }
    const failed = ciscoFailedAnalyzersV1(entry.analyzers_failed, `results[${index}]`);
    // The skill's own part of the SARIF: the results paired with its findings.
    const part = sarifResults.slice(position, position + entry.findings.length);
    position += entry.findings.length;
    skills.push({
      label: `in ${ciscoSkillLabelV1(skill)}`,
      failed,
      ...ciscoFallbackPairingV1(entry.findings, part, skill),
    });
  });
  assertCiscoAnalyzersCompleteV1(skills);
}
