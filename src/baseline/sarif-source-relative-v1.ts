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
 * itself or cannot be decoded is refused, never guessed. `originalUriBaseIds` entries are
 * removed, because they could only describe the private root.
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
 * the empty string (Cisco reports a top-level skill directory that way).
 */
function relativeTo(uri: string, candidates: readonly Root[], allowRoot = false): string {
  if (typeof uri !== "string" || uri.length === 0) fail("an empty artifact URI");
  if (uri.includes("\0")) fail("an artifact URI holds a NUL character");
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

/** Every SARIF `artifactLocation`, and every run artifact's `location`, in the document. */
function artifactLocations(document: Json): Record<string, Json>[] {
  const found: Record<string, Json>[] = [];
  // `key` names the property holding `value`; `owner` names the nearest property above it,
  // so an entry of `artifacts: [{ location }]` sees its location with owner "artifacts".
  const visit = (value: Json, key: string | undefined, owner: string | undefined): void => {
    if (Array.isArray(value)) {
      for (const item of value) visit(item, undefined, key ?? owner);
      return;
    }
    if (!isRecord(value)) return;
    if (key === "artifactLocation" || (key === "location" && owner === "artifacts"))
      found.push(value);
    for (const [childKey, child] of Object.entries(value)) visit(child, childKey, key ?? owner);
  };
  visit(document, undefined, undefined);
  return found;
}

function removeBaseUris(document: Json): number {
  let removed = 0;
  if (isRecord(document) && Array.isArray(document.runs))
    for (const run of document.runs)
      if (isRecord(run) && "originalUriBaseIds" in run) {
        delete run.originalUriBaseIds;
        removed += 1;
      }
  return removed;
}

/** Rewrites every artifact URI of `document` relative to one of `sourceRoots`. */
export function sourceRelativeSarifV1(
  document: Record<string, unknown>,
  sourceRoots: readonly string[],
): SourceRelativeSarifV1 {
  const candidates = roots(sourceRoots);
  const copy = clone(document);
  const removedBaseUris = removeBaseUris(copy);
  let rewritten = 0;
  for (const location of artifactLocations(copy)) {
    if (!("uri" in location)) continue;
    const uri = location.uri;
    if (typeof uri !== "string") fail("an artifact URI is not a string");
    location.uri = relativeTo(uri, candidates);
    rewritten += 1;
  }
  return Object.freeze({
    document: copy as Record<string, unknown>,
    rewritten,
    removedBaseUris,
  });
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
 * Cisco `scan-all` merges every skill's results into one SARIF run whose URIs are relative
 * to each skill's own directory, so `SKILL.md` can mean any skill. Its JSON report lists the
 * same findings in the same order under each skill's absolute path. Each SARIF result is
 * paired with its JSON finding (rule, file and line must agree, or the run fails closed) and
 * rewritten as `<skill directory relative to the source root>/<file>`.
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
  const results: Record<string, Json>[] = [];
  for (const run of copy.runs) {
    if (!isRecord(run)) ciscoFail("a SARIF run is malformed");
    if (run.results === undefined) continue;
    if (!Array.isArray(run.results)) ciscoFail("a SARIF results list is malformed");
    for (const result of run.results) {
      if (!isRecord(result)) ciscoFail("a SARIF result is malformed");
      results.push(result);
    }
  }
  if (results.length !== findings.length)
    ciscoFail(
      `the SARIF report holds ${results.length} results but the JSON report ${findings.length} findings`,
    );
  results.forEach((result, index) => {
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
    let file: string;
    try {
      file = relativeTo(artifact.uri, [], false);
    } catch {
      ciscoFail(`SARIF result ${index} URI ${JSON.stringify(artifact.uri)} is not relative`);
    }
    const line = isRecord(region) && typeof region.startLine === "number" ? region.startLine : null;
    if (result.ruleId !== finding.ruleId || file !== finding.file || line !== finding.line)
      ciscoFail(
        `SARIF result ${index} (${String(result.ruleId)} ${file}:${String(line)}) does not match JSON finding ${index} (${finding.ruleId} ${finding.file}:${String(finding.line)})`,
      );
    for (const location of locations) {
      const entry = isRecord(location) ? location.physicalLocation : undefined;
      const target = isRecord(entry) ? entry.artifactLocation : undefined;
      if (!isRecord(target) || typeof target.uri !== "string") continue;
      const relative = relativeTo(target.uri, [], false);
      target.uri = finding.skill === "" ? relative : `${finding.skill}/${relative}`;
    }
  });
  const normalized = sourceRelativeSarifV1(copy as Record<string, unknown>, sourceRoots);
  return normalized;
}
