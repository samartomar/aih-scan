import { assertSafeRelativePosixPathV1 } from "../contract/strict-json-v1.js";
import {
  sarifArtifactLocationTargetV1,
  sarifDetachedArtifactLocationsV1,
  sarifResultArtifactLocationsV1,
  sarifResultSharedArtifactLocationsV1,
  sarifRunArtifactLocationsV1,
} from "./sarif-source-relative-v1.js";

/**
 * Binds Cisco skill-scanner result paths to sealed files on Windows (owner decision D1).
 *
 * skill-scanner 2.1.0 resolves every path through `resolve_path_within_root`
 * (`skill_scanner/utils/file_utils.py`), which returns `Path(os.path.normcase(realpath))`.
 * On Windows `normcase` lowercases the whole path, so a finding on `skills/Injected/SKILL.md`
 * is reported as `skills/injected/skill.md`. On win32 only, a reported path that is not
 * exactly a sealed file is bound to the UNIQUE sealed file whose whole source-relative path
 * is equal ignoring case, and the sealed file's real name replaces the reported one. No
 * match leaves the path as reported, so the caller's sealed-file check fails it at `output`
 * as before; more than one match fails here. An exact match always wins. On every other
 * platform nothing is rebound.
 *
 * "Equal ignoring case" is `a.toLowerCase() === b.toLowerCase()` over both whole paths, code
 * unit for code unit: the locale-independent Unicode default lowercase mapping (full
 * mapping, SpecialCasing included), which is what Python's `str.lower()` inside `normcase`
 * applies. Limits: it is not Unicode case folding (`ß` never equals `SS`), it does not
 * normalize (an NFD spelling never equals an NFC one), it is not NTFS's own upcase table,
 * and Node's ICU and Python may carry different Unicode versions, so a character whose
 * mapping differs between them does not bind. Every such miss fails closed; a mapping that
 * makes two sealed files equal (for example KELVIN SIGN and `k`) is an ambiguity and fails.
 *
 * Only a path whose original identity was verified may reach the binder (U1e review P1): the
 * analyzer's own URI, checked safe before it was prefixed with its skill directory, never a
 * substitute or placeholder. An unsafe original fails at `output` before this runs.
 */
export function ciscoSealedPathBinderV1(
  sealedPaths: Iterable<string>,
  platform: NodeJS.Platform,
): (path: string) => string {
  const sealed = new Set(sealedPaths);
  if (platform !== "win32") return (path) => path;
  const byFold = new Map<string, string[]>();
  for (const path of sealed) {
    const fold = path.toLowerCase();
    const matches = byFold.get(fold);
    if (matches === undefined) byFold.set(fold, [path]);
    else matches.push(path);
  }
  return (path) => {
    if (sealed.has(path)) return path;
    try {
      assertSafeRelativePosixPathV1(path, "Cisco result path");
    } catch {
      return path;
    }
    const matches = byFold.get(path.toLowerCase()) ?? [];
    if (matches.length > 1)
      throw new TypeError(
        `aih-scan Cisco SARIF: ${path} matches ${matches.length} sealed files ignoring case`,
      );
    return matches[0] ?? path;
  };
}

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

function record(value: unknown): Record<string, Json> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, Json>)
    : undefined;
}

/**
 * Applies {@link ciscoSealedPathBinderV1} to a copy of a source-relative Cisco SARIF log.
 * U1g: it rebinds every artifact location of every run by the one enumeration the
 * normalizers use (`sarifRunArtifactLocationsV1`: results' locations, related locations,
 * code flows, stacks, fixes, analysis targets, run artifacts, shared thread-flow locations
 * and graphs; never a property bag), so it rebinds exactly what
 * {@link unboundCiscoSarifResultV1} then binds. Malformed parts are left for the caller's
 * own validation to refuse.
 */
export function bindCiscoSarifToSealedFilesV1(
  document: Record<string, unknown>,
  sealedPaths: Iterable<string>,
  platform: NodeJS.Platform,
): Readonly<{ document: Record<string, unknown>; rebound: number }> {
  const copy = JSON.parse(JSON.stringify(document)) as Record<string, Json>;
  if (platform !== "win32") return { document: copy, rebound: 0 };
  const bind = ciscoSealedPathBinderV1(sealedPaths, platform);
  let rebound = 0;
  const rebind = (artifactLocation: unknown) => {
    const target = record(artifactLocation);
    if (target === undefined || typeof target.uri !== "string") return;
    const bound = bind(target.uri);
    if (bound === target.uri) return;
    target.uri = bound;
    rebound += 1;
  };
  const runs = Array.isArray(copy.runs) ? copy.runs : [];
  for (const run of runs) {
    if (record(run) === undefined) continue;
    for (const location of sarifRunArtifactLocationsV1(run)) rebind(location);
  }
  return { document: copy, rebound };
}

/** A SARIF location's `physicalLocation.artifactLocation`, when it has one. */
function locationArtifactV1(location: unknown): unknown {
  return record(record(location)?.physicalLocation)?.artifactLocation;
}

/**
 * The one Cisco result binding (S2g for the shard; U1g for every Cisco run): the tree hashes
 * prove the input did not change, not that the results name files the analyzer received.
 * Every result of a normalized (and on Windows D1-bound) Cisco SARIF log must carry at least
 * one location; every one of its `locations` must name, by `uri`, a file of `sealedFiles`
 * (exact, case-sensitive, root-relative); every other artifact location of the result (S2h:
 * related locations, code flows, stacks, fixes, the analysis target; never a property bag)
 * and of the run's shared `threadFlowLocations` and `graphs` must name such a file too, by
 * `uri` or by `index` (`sarifArtifactLocationTargetV1`). U1h: each result's references to
 * those shared objects are resolved for that result (`sarifResultSharedArtifactLocationsV1`),
 * and a malformed, out-of-range or ambiguous one is refused. `owner` names the file set in the
 * reason: "job" for a shard job, "subject" for a `runDetectorV1` run. Returns why a result
 * is unbound, or `undefined` when all are bound.
 */
export function unboundCiscoSarifResultV1(
  log: Readonly<{ runs?: readonly unknown[] }>,
  sealedFiles: ReadonlySet<string>,
  owner: "job" | "subject",
): string | undefined {
  const unbound = (where: string, artifactLocation: unknown, artifacts: unknown) => {
    const target = sarifArtifactLocationTargetV1(artifactLocation, artifacts);
    if ("problem" in target) return `${where}: ${target.problem}`;
    return sealedFiles.has(target.uri)
      ? undefined
      : `${where} names ${JSON.stringify(target.uri)}, which is not a sealed file of the ${owner}`;
  };
  let index = 0;
  for (const run of log.runs ?? []) {
    const runRecord = record(run) ?? {};
    for (const shared of ["threadFlowLocations", "graphs"])
      for (const artifactLocation of sarifDetachedArtifactLocationsV1(runRecord[shared] ?? [])) {
        const problem = unbound(`SARIF run ${shared}`, artifactLocation, runRecord.artifacts);
        if (problem !== undefined) return problem;
      }
    for (const result of Array.isArray(runRecord.results) ? runRecord.results : []) {
      const { locations: rawLocations, analysisTarget } = record(result) ?? {};
      const locations = Array.isArray(rawLocations) ? rawLocations : [];
      const primary = new Set(locations.map(locationArtifactV1));
      if (locations.length === 0)
        return `SARIF result ${index} names no sealed file of the ${owner} (no location)`;
      for (const location of locations) {
        const artifactLocation = record(locationArtifactV1(location));
        if (artifactLocation === undefined || typeof artifactLocation.uri !== "string")
          return `SARIF result ${index} names no sealed file of the ${owner} (a location has no URI)`;
        const problem = unbound(`SARIF result ${index}`, artifactLocation, runRecord.artifacts);
        if (problem !== undefined) return problem;
      }
      if (analysisTarget !== undefined) {
        const problem = unbound(
          `SARIF result ${index} analysis target`,
          analysisTarget,
          runRecord.artifacts,
        );
        if (problem !== undefined) return problem;
      }
      for (const artifactLocation of sarifResultArtifactLocationsV1(result)) {
        if (primary.has(artifactLocation) || artifactLocation === analysisTarget) continue;
        const problem = unbound(
          `SARIF result ${index} related location`,
          artifactLocation,
          runRecord.artifacts,
        );
        if (problem !== undefined) return problem;
      }
      // U1h (review of U1g, P1): the shared thread-flow locations and graphs this result
      // references, resolved for this result; an unresolved reference is refused.
      let shared: Record<string, unknown>[];
      try {
        shared = sarifResultSharedArtifactLocationsV1(result, runRecord);
      } catch (error) {
        return `SARIF result ${index}: ${error instanceof Error ? error.message : "a shared reference is unresolved"}`;
      }
      for (const artifactLocation of shared) {
        const problem = unbound(
          `SARIF result ${index} shared location`,
          artifactLocation,
          runRecord.artifacts,
        );
        if (problem !== undefined) return problem;
      }
      index += 1;
    }
  }
  return undefined;
}
