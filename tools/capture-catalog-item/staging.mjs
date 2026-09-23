/**
 * Staging and coverage diagnostics for `tools/capture-catalog-item.mjs`: write every
 * served file of a validated source closure under its published path, re-verify each
 * written copy, select the declared skill root as the capture source root, and record
 * the staged closure and what the mount cannot cover in `source-closure.json`.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve, sep } from "node:path";
import {
  canonicalBytes,
  MAX_SOURCE_FILE_BYTES,
  own,
  refuse,
  regularBytes,
  SOURCE_CLOSURE_RECORD_PROTOCOL,
  sha256Hex,
} from "./common.mjs";
import { readServedSourceClosure } from "./catalog.mjs";
import { log } from "./report.mjs";

/** The helper's own diagnostic record of the staged closure; never part of the bundle. */
const SOURCE_CLOSURE_RECORD_NAME = "source-closure.json";
/** The Catalog material root kind the capture mounts. */
const SKILL_MATERIAL_ROOT_KIND = "skill";

/**
 * The staged path of one published path, proven to stay inside the staging root.
 * The grammar above already rejects `..`; this is the second, filesystem-level
 * check, so a path that somehow survived it cannot make the run write outside itself.
 */
function stagedPathWithin(stageRoot, relativePath, label) {
  const root = resolve(stageRoot);
  const target = relativePath === "." ? root : resolve(root, ...relativePath.split("/"));
  if (target !== root && !target.startsWith(`${root}${sep}`))
    refuse(`${label} escapes the staged closure root: ${relativePath}`);
  return target;
}

/**
 * A verbatim copy of what the installed package returned, limited to plain JSON
 * data. A getter, a class instance or a function is refused rather than serialized
 * into a record this helper would then be reporting as fact.
 */
function plainJsonCopy(value, label, depth = 0) {
  if (depth > 16) refuse(`${label} is nested too deeply`);
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) refuse(`${label} carries a non-finite number`);
    return value;
  }
  if (Array.isArray(value))
    return value.map((item, index) => plainJsonCopy(item, `${label}[${index}]`, depth + 1));
  if (typeof value === "object") {
    const copy = {};
    for (const key of Object.keys(value))
      copy[key] = plainJsonCopy(own(value, key), `${label}.${key}`, depth + 1);
    return copy;
  }
  refuse(`${label} must be plain JSON data; found ${typeof value}`);
}

const optionalText = (value) => (typeof value === "string" && value !== "" ? value : null);

/**
 * The run directory's diagnostic record of the staged source, written during
 * preparation so a run that stops at any later gate still carries it. It is the
 * helper's own record: not signed evidence, not a capture bundle, not authority,
 * and never part of `bundle/`.
 */
function writeSourceClosureRecord(runRoot, { selection, catalog, item }) {
  const path = join(runRoot, SOURCE_CLOSURE_RECORD_NAME);
  writeFileSync(
    path,
    canonicalBytes({
      protocol: SOURCE_CLOSURE_RECORD_PROTOCOL,
      authority: "diagnostic-record-not-evidence",
      statement:
        "Written by tools/capture-catalog-item.mjs to record which Catalog source files were " +
        "staged and which of them this capture covers. It is not signed evidence, not a capture " +
        "bundle and not an authority, and it seals nothing.",
      selection: { collectionId: selection.collectionId, subjectId: selection.subjectId },
      catalog: {
        name: catalog.name,
        version: catalog.version,
        tarball: {
          flag: catalog.tarball.flag,
          path: catalog.tarball.path,
          sha256: catalog.tarball.sha256,
        },
      },
      closure: {
        ...item.closure,
        /* The complete served file list, as published, before any selection. */
        files: item.stagedFiles.map((file) => ({
          path: file.publishedPath,
          sha256: `sha256:${file.sha256}`,
          byteLength: file.byteLength,
        })),
        /* Catalog declares this value; nothing here recomputes it or seals it. */
        declaredTreeDigest: {
          value: item.closure.declaredTreeDigest,
          reproduced: false,
          note: "recorded as Catalog declares it; never presented as the capture seal",
        },
      },
      stagedFiles: item.stagedFiles.map((file) => ({
        publishedPath: file.publishedPath,
        stagedPath: file.stagedPath,
        sha256: `sha256:${file.sha256}`,
        byteLength: file.byteLength,
      })),
      selectedSkillRoot: {
        declaredPath: item.skillRoot.declaredPath,
        stagedPath: item.sourceRoot,
        marker: item.skillRoot.marker,
        declaredFiles: item.skillRoot.files,
        declaredExcludes: item.skillRoot.excludes,
        selectedPaths: item.selectedClosurePaths,
      },
      pathMapping: item.stagedFiles.map((file) => {
        const selected = item.files.find((entry) => entry.publishedPath === file.publishedPath);
        return {
          publishedPath: file.publishedPath,
          stagedPath: file.stagedPath,
          selectedPath: selected === undefined ? null : selected.path,
        };
      }),
      coverage: {
        mountedRoot: item.sourceRoot,
        selectedPaths: item.selectedClosurePaths,
        coveredPublishedPaths: item.skillRoot.files,
        uncoveredPublishedPaths: item.uncoveredPublishedPaths,
        statement:
          `The capture requested from this run mounts ${item.sourceRoot} and covers the selected ` +
          "paths listed here only. A scan of a skill root does not cover the rest of the closure, " +
          "and no seal it produces is the complete closure, its declaredTreeDigest or the entry " +
          "subjectDigest.",
      },
      sealScope: {
        requestPath: join(runRoot, "capture-request.json"),
        selectedPaths: item.selectedClosurePaths,
        statement:
          "A capture bundle produced from this request seals the mounted source root over the " +
          "selected paths above, and describes this scan of this root only.",
      },
    }),
    { flag: "wx" },
  );
  log(`diagnostic      ${path} (not evidence; the staged closure and its coverage)`);
  return path;
}

/**
 * Stages a validated source closure: every served file under its published path,
 * each written copy re-read and re-hashed, the declared skill root selected as the
 * capture source root, and the files outside it recorded as uncovered, never as
 * covered. Writes `source-closure.json` and returns the staged item.
 */
function stageSourceClosure(runRoot, served, catalog) {
  const {
    selection,
    closure,
    entry,
    files,
    byPath,
    materialRoots,
    declaredPath,
    marker,
    skillFiles,
    declaredExcludes,
  } = served;
  /* Only now is anything written. */
  const stageRoot = join(runRoot, "source");
  mkdirSync(stageRoot, { recursive: true, mode: 0o700 });
  const stagedFiles = files.map((file) => {
    const target = stagedPathWithin(stageRoot, file.publishedPath, "a published source path");
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, file.bytes, { flag: "wx" });
    const written = regularBytes(target, `staged ${file.publishedPath}`, 1, MAX_SOURCE_FILE_BYTES);
    if (sha256Hex(written) !== file.sha256)
      refuse(`the staged copy of ${file.publishedPath} changed as it was written`);
    log(`closure file    ${file.publishedPath} sha256:${file.sha256} (${file.byteLength} bytes)`);
    return {
      publishedPath: file.publishedPath,
      stagedPath: target,
      sha256: file.sha256,
      byteLength: file.byteLength,
    };
  });
  const sourceRoot = stagedPathWithin(stageRoot, declaredPath, "the declared skill material root");
  const selectedFiles = skillFiles.map((publishedPath) => {
    const file = byPath.get(publishedPath);
    return {
      publishedPath,
      path: declaredPath === "." ? publishedPath : publishedPath.slice(declaredPath.length + 1),
      sha256: file.sha256,
      byteLength: file.byteLength,
    };
  });
  const selectedClosurePaths = selectedFiles.map((file) => file.path).sort();
  const selectedPublished = new Set(skillFiles);
  const uncoveredPublishedPaths = stagedFiles
    .filter((file) => !selectedPublished.has(file.publishedPath))
    .map((file) => ({
      publishedPath: file.publishedPath,
      stagedPath: file.stagedPath,
      declaredExcluded: declaredExcludes.includes(file.publishedPath),
      reason: `outside the mounted skill root ${declaredPath}, so this capture does not cover it`,
    }));

  log(
    `closure         ${selection.collectionId}/${selection.subjectId} entry ${entry.entryId} ` +
      `(${stagedFiles.length} published files, format ${closure.format} v${closure.version})`,
  );
  log(
    `declared root   ${declaredPath} (kind ${SKILL_MATERIAL_ROOT_KIND}, marker ${marker}, ` +
      `${selectedFiles.length} files)`,
  );
  log(`source root     ${sourceRoot} (covers ${selectedClosurePaths.join(", ")})`);
  if (uncoveredPublishedPaths.length > 0)
    log(`uncovered       ${uncoveredPublishedPaths.map((file) => file.publishedPath).join(", ")}`);

  const item = {
    sourceRoot,
    selectedClosurePaths,
    /* The staged files this capture covers, with paths relative to the mounted root. */
    files: selectedFiles,
    entry: plainJsonCopy(entry, "the source closure entry"),
    closure: {
      format: closure.format,
      version: closure.version,
      collection: plainJsonCopy(closure.collection, "the source closure collection"),
      entry: plainJsonCopy(entry, "the source closure entry"),
      asset: plainJsonCopy(closure.asset, "the source closure asset"),
      assessment: plainJsonCopy(closure.assessment, "the source closure assessment"),
      source: plainJsonCopy(closure.source, "the source closure source"),
      root: optionalText(closure.root),
      declaredTreeDigest: optionalText(closure.declaredTreeDigest),
      materialRoots: plainJsonCopy(materialRoots, "the source closure material roots"),
    },
    skillRoot: { declaredPath, marker, files: [...skillFiles], excludes: [...declaredExcludes] },
    stagedFiles,
    uncoveredPublishedPaths,
  };
  return { item, recordPath: writeSourceClosureRecord(runRoot, { selection, catalog, item }) };
}

/**
 * Reads the item's original source closure from the installed package's public
 * `readCatalogSourceClosureV1` and stages it, then selects the skill material root
 * that Catalog declares as the capture source root.
 *
 * The entry identity is the one that reader returns for the requested collection
 * and subject: no entry id comes from the operator, and none is defaulted, so the
 * staged source is the one the current collection view serves.
 *
 * Every served file is re-hashed against its own declared digest before it is
 * written, and the written copy is re-read and re-hashed after staging. Selection
 * is by declaration alone — the material root whose kind is `skill` — so a closure
 * that declares none, or more than one, is refused, and a `SKILL.md` found anywhere
 * else in the tree is never selected in its place. Files outside that root stay
 * staged outside the mounted root and are recorded as uncovered, never as covered.
 */
export function readCatalogSourceClosure(reader, options, runRoot, catalog) {
  return stageSourceClosure(runRoot, readServedSourceClosure(reader, options), catalog);
}
