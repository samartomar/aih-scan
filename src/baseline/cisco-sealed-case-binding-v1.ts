import { assertSafeRelativePosixPathV1 } from "../contract/strict-json-v1.js";

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
 * Applies {@link ciscoSealedPathBinderV1} to a copy of a source-relative Cisco SARIF log:
 * every result's `locations` and `relatedLocations`, and every run artifact's location.
 * Malformed parts are left for the caller's own validation to refuse.
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
    const runRecord = record(run);
    if (runRecord === undefined) continue;
    for (const artifact of Array.isArray(runRecord.artifacts) ? runRecord.artifacts : [])
      rebind(record(artifact)?.location);
    for (const result of Array.isArray(runRecord.results) ? runRecord.results : []) {
      const resultRecord = record(result);
      if (resultRecord === undefined) continue;
      for (const key of ["locations", "relatedLocations"] as const) {
        const locations = resultRecord[key];
        for (const location of Array.isArray(locations) ? locations : [])
          rebind(record(record(location)?.physicalLocation)?.artifactLocation);
      }
    }
  }
  return { document: copy, rebound };
}
