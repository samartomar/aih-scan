/**
 * Public Catalog reading for `tools/capture-catalog-item.mjs`: install the exact
 * supplied tarballs into a fresh consumer, import only their public entry points, and
 * read and validate the item's source closure through `readCatalogSourceClosureV1`.
 * Validation here writes nothing; staging is `staging.mjs`.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  assertOutsideGitRepository,
  DIGEST,
  jsonFile,
  MAX_SOURCE_FILE_BYTES,
  reasonOf,
  refuse,
  regularBytes,
  sha256Hex,
} from "./common.mjs";
import { appendProcessLog, log } from "./report.mjs";

/** The Catalog material root that names the skill directory to mount, and its marker. */
const SKILL_MATERIAL_ROOT_KIND = "skill";
const SOURCE_CLOSURE_FORMAT = "aih-catalog-source-closure";
const MAX_TARBALL_BYTES = 512 * 1024 * 1024;
const MAX_SOURCE_FILES = 4096;
const INSTALL_TIMEOUT_MS = 15 * 60 * 1000;
const CONSUMER_PACKAGE_JSON = `${JSON.stringify({
  name: "aih-scan-catalog-capture-consumer",
  private: true,
  type: "module",
  version: "0.0.0",
})}\n`;
/** The only import surface used from the installed packages: their public entry points. */
const READER_MODULE = `import { readCatalogSourceClosureV1 } from "@aihq/catalog";
import {
  createDetectorRegistrationV1,
  readScanCaptureBundleV2,
} from "@aihq/scan";

export {
  createDetectorRegistrationV1,
  readCatalogSourceClosureV1,
  readScanCaptureBundleV2,
};
`;

/**
 * npm is resolved the way this repository's other tools resolve it: through an
 * absolute `npm_execpath`, otherwise through the CLI shipped with the running
 * Node. A bare `npm` spawn is a shell shim on some hosts and not an executable,
 * and this install must work on the operator's Linux host and in a direct
 * repository check alike.
 */
export function npmCliPath(environment = process.env) {
  const fromEnvironment = environment.npm_execpath;
  if (
    typeof fromEnvironment === "string" &&
    isAbsolute(fromEnvironment) &&
    basename(fromEnvironment) === "npm-cli.js" &&
    existsSync(fromEnvironment)
  )
    return fromEnvironment;
  const nodeDirectory = dirname(process.execPath);
  for (const candidate of [
    join(nodeDirectory, "node_modules", "npm", "bin", "npm-cli.js"),
    resolve(nodeDirectory, "..", "lib", "node_modules", "npm", "bin", "npm-cli.js"),
  ])
    if (existsSync(candidate)) return candidate;
  refuse("the npm CLI entrypoint is unavailable; set npm_execpath or install npm beside Node");
}

/**
 * npm exports its whole effective configuration into the environment of the
 * processes it spawns. The consumer install must not inherit that: an exported
 * `allow-scripts` conflicts with the `--ignore-scripts` this install requires
 * (npm refuses with EALLOWSCRIPTS), and an exported registry, prefix or offline
 * setting would change what gets installed and therefore what the run proves.
 * Everything npm needs to run and to reach the network is preserved.
 */
export function installEnvironment(environment = process.env) {
  const kept = {};
  for (const [key, value] of Object.entries(environment)) {
    if (value === undefined) continue;
    const name = key.toUpperCase();
    if (
      name.startsWith("NPM_CONFIG_") ||
      name.startsWith("NPM_LIFECYCLE_") ||
      name.startsWith("NPM_PACKAGE_")
    )
      continue;
    kept[key] = value;
  }
  return kept;
}

export function installConsumer(options) {
  const consumerRoot =
    options.consumerRoot === undefined
      ? mkdtempSync(join(tmpdir(), "aih-scan-catalog-capture-"))
      : resolve(options.consumerRoot);
  assertOutsideGitRepository(consumerRoot, "consumer root");
  if (options.consumerRoot !== undefined) {
    if (existsSync(consumerRoot) && readdirSync(consumerRoot).length > 0)
      refuse(`--consumer-root must be empty: ${consumerRoot}`);
    mkdirSync(consumerRoot, { recursive: true, mode: 0o700 });
  }
  /*
   * The tarball bytes are read and hashed before installation, so the run keeps
   * the exact package checkpoint identities it consumed, not just their versions.
   */
  const tarballs = [
    { flag: "--catalog-tarball", path: resolve(options.catalogTarball) },
    { flag: "--scan-tarball", path: resolve(options.scanTarball) },
  ].map((tarball) => ({
    ...tarball,
    sha256: `sha256:${sha256Hex(regularBytes(tarball.path, tarball.flag, 1, MAX_TARBALL_BYTES))}`,
  }));
  for (const tarball of tarballs)
    log(`tarball         ${tarball.flag} ${tarball.sha256} ${tarball.path}`);
  writeFileSync(join(consumerRoot, "package.json"), CONSUMER_PACKAGE_JSON, { flag: "wx" });
  writeFileSync(join(consumerRoot, "reader.mjs"), READER_MODULE, { flag: "wx" });
  log(`consumer        ${consumerRoot}`);
  const npmCli = npmCliPath();
  log(`npm             ${npmCli}`);
  const installed = spawnSync(
    process.execPath,
    [
      npmCli,
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "--save-exact",
      "--loglevel",
      "error",
      ...tarballs.map((tarball) => tarball.path),
    ],
    { cwd: consumerRoot, encoding: "utf8", env: installEnvironment(), timeout: INSTALL_TIMEOUT_MS },
  );
  appendProcessLog("npm install --ignore-scripts", installed);
  if (installed.error !== undefined)
    refuse(`npm install could not run: ${installed.error.message}`);
  if (installed.status !== 0)
    refuse("npm install of the supplied tarballs failed; see execution.log");
  return { consumerRoot, tarballs };
}

export function installedPackage(consumerRoot, name) {
  const root = join(consumerRoot, "node_modules", ...name.split("/"));
  const metadata = jsonFile(join(root, "package.json"), `${name} package.json`, 2, 1024 * 1024);
  if (metadata.name !== name) refuse(`${name} is not installed at ${root}`);
  log(`installed       ${name}@${metadata.version}`);
  return { root, version: metadata.version };
}

/**
 * The consumer's reader module resolves bare specifiers against the installed
 * tarballs, so this is also the first real proof that both tarballs were packed
 * from the commits under test with their build output present.
 */
export async function importReader(consumerRoot) {
  try {
    return await import(pathToFileURL(join(consumerRoot, "reader.mjs")).href);
  } catch (error) {
    refuse(
      `the installed packages do not expose the public entry points this tool needs: ${reasonOf(error)}. ` +
        "Check that each tarball was packed from the commit under test with dist/ built: @aihq/scan builds in prepack, @aihq/catalog has no prepack and must be built before packing",
    );
  }
}

/* ---------- the published source closure: paths, selection, staging ---------- */

/**
 * A path as Catalog publishes it: relative, POSIX, and free of empty, `.` and `..`
 * segments, so it can only name a file below the closure root it was served from.
 */
function closureRelativePath(path, label) {
  if (typeof path !== "string" || path === "") refuse(`${label} must be a non-empty string`);
  if (path.includes("\0")) refuse(`${label} must not contain a NUL byte`);
  if (path.startsWith("/")) refuse(`${label} must be relative to the closure root: ${path}`);
  if (path.includes("\\")) refuse(`${label} must use POSIX separators: ${path}`);
  if (path.split("/").some((segment) => segment === "" || segment === "." || segment === ".."))
    refuse(`${label} must not contain empty, '.' or '..' segments: ${path}`);
  return path;
}

/** A declared material root path. `.` names the closure root itself. */
const materialRootPath = (path, label) =>
  path === "." ? "." : closureRelativePath(path, label);

/** Whether a published path lies at or below a declared material root path. */
const isWithinRoot = (publishedPath, rootPath) =>
  rootPath === "." || publishedPath.startsWith(`${rootPath}/`);

/**
 * Reads the item's original source closure from the installed package's public
 * `readCatalogSourceClosureV1` and validates all of it before anything is written:
 * every served file's bytes against its own declared digest, its path grammar, and
 * the single `skill` material root the closure declares. Selection is by
 * declaration alone, so a closure that declares none, or more than one, is refused
 * and a `SKILL.md` found anywhere else is never selected in its place.
 *
 * The entry identity is the one that reader returns for the requested collection
 * and subject: no entry id comes from the operator, and none is defaulted.
 */
export function readServedSourceClosure(reader, options) {
  if (typeof reader.readCatalogSourceClosureV1 !== "function")
    refuse(
      "the installed @aihq/catalog does not expose readCatalogSourceClosureV1; pack a Catalog " +
        "commit that publishes the source-closure reader",
    );
  const selection = { collectionId: options.collectionId, subjectId: options.subjectId };
  let result;
  try {
    result = reader.readCatalogSourceClosureV1({
      collectionId: selection.collectionId,
      subjectId: selection.subjectId,
    });
  } catch (error) {
    refuse(
      `readCatalogSourceClosureV1 refused ${selection.collectionId}/${selection.subjectId}: ${reasonOf(error)}`,
    );
  }
  if (typeof result !== "object" || result === null)
    refuse("readCatalogSourceClosureV1 returned no result object");
  if (result.state !== "verified")
    refuse(
      `the installed catalog serves no verified source closure for ` +
        `${selection.collectionId}/${selection.subjectId}: state ${JSON.stringify(result.state)}` +
        (typeof result.reason === "string" ? `, reason ${result.reason}` : "") +
        (typeof result.path === "string" ? ` (${result.path})` : "") +
        ". A subject whose material is not published source files is refused by Catalog itself, and " +
        "this helper never substitutes the item's assessment artifacts for its source",
    );
  const closure = result.closure;
  if (typeof closure !== "object" || closure === null)
    refuse("the verified source closure carries no closure document");
  if (closure.format !== SOURCE_CLOSURE_FORMAT)
    refuse(
      `source closure format must be ${SOURCE_CLOSURE_FORMAT}; it is ${JSON.stringify(closure.format)}`,
    );
  if (closure.version !== 1)
    refuse(`source closure version must be 1; it is ${JSON.stringify(closure.version)}`);
  const entry = closure.entry;
  if (
    typeof entry !== "object" ||
    entry === null ||
    typeof entry.entryId !== "string" ||
    entry.entryId === ""
  )
    refuse("the source closure carries no entry identity");

  /* The whole served file list is validated before any of it is written. */
  const served = closure.files;
  if (!Array.isArray(served) || served.length === 0)
    refuse(`the source closure for ${selection.collectionId}/${selection.subjectId} serves no files`);
  if (served.length > MAX_SOURCE_FILES)
    refuse(`the source closure serves more than ${MAX_SOURCE_FILES} files`);
  const files = [];
  const byPath = new Map();
  for (const file of served) {
    if (typeof file !== "object" || file === null)
      refuse("a source closure file entry is not an object");
    const publishedPath = closureRelativePath(file.path, "a source closure file path");
    if (byPath.has(publishedPath)) refuse(`the source closure publishes ${publishedPath} twice`);
    if (!(file.bytes instanceof Uint8Array))
      refuse(`source closure file ${publishedPath} carries no bytes`);
    const bytes = Buffer.from(file.bytes);
    if (!Number.isSafeInteger(file.byteLength) || bytes.length !== file.byteLength)
      refuse(
        `source closure file ${publishedPath} declares ${JSON.stringify(file.byteLength)} bytes ` +
          `but serves ${bytes.length}`,
      );
    if (bytes.length === 0 || bytes.length > MAX_SOURCE_FILE_BYTES)
      refuse(
        `source closure file ${publishedPath} must be between 1 and ${MAX_SOURCE_FILE_BYTES} bytes`,
      );
    if (typeof file.sha256 !== "string" || !DIGEST.test(`sha256:${file.sha256}`))
      refuse(`source closure file ${publishedPath} declares no sha256 digest`);
    const recomputed = sha256Hex(bytes);
    if (recomputed !== file.sha256)
      refuse(
        `the installed catalog served ${publishedPath} with bytes that do not match its declared ` +
          `digest: sha256:${recomputed} != sha256:${file.sha256}`,
      );
    const staged = { publishedPath, sha256: file.sha256, byteLength: bytes.length, bytes };
    files.push(staged);
    byPath.set(publishedPath, staged);
  }

  /* Selection is by Catalog's declaration, never by searching the tree. */
  const materialRoots = closure.materialRoots;
  if (!Array.isArray(materialRoots) || materialRoots.length === 0)
    refuse("the source closure declares no material roots");
  const declaredKinds = materialRoots
    .map((root) => (typeof root === "object" && root !== null ? String(root.kind) : "malformed"))
    .join(", ");
  const skillRoots = materialRoots.filter(
    (root) => typeof root === "object" && root !== null && root.kind === SKILL_MATERIAL_ROOT_KIND,
  );
  if (skillRoots.length === 0)
    refuse(
      `the source closure for ${selection.collectionId}/${selection.subjectId} declares no ` +
        `'${SKILL_MATERIAL_ROOT_KIND}' material root (declared kinds: ${declaredKinds}); this helper ` +
        "mounts a declared skill root and never discovers one in the staged tree",
    );
  if (skillRoots.length > 1)
    refuse(
      `the source closure declares ${skillRoots.length} '${SKILL_MATERIAL_ROOT_KIND}' material ` +
        `roots (${skillRoots.map((root) => JSON.stringify(root.path)).join(", ")}); the skill root ` +
        "is ambiguous, so none is selected and none is guessed",
    );
  const [declaredRoot] = skillRoots;
  const declaredPath = materialRootPath(declaredRoot.path, "the declared skill material root path");
  if (typeof declaredRoot.marker !== "string" || declaredRoot.marker === "")
    refuse(`the declared skill material root ${declaredPath} carries no marker`);
  const marker = closureRelativePath(declaredRoot.marker, "the declared skill material root marker");
  if (!Array.isArray(declaredRoot.files) || declaredRoot.files.length === 0)
    refuse(`the declared skill material root ${declaredPath} lists no files`);
  const skillFiles = declaredRoot.files.map((path) =>
    closureRelativePath(path, "a declared skill material root file path"),
  );
  if (new Set(skillFiles).size !== skillFiles.length)
    refuse(`the declared skill material root ${declaredPath} lists a file twice`);
  for (const path of skillFiles) {
    if (!byPath.has(path))
      refuse(`the declared skill material root ${declaredPath} names ${path}, which the closure does not serve`);
    if (!isWithinRoot(path, declaredPath))
      refuse(`the declared skill material root ${declaredPath} names ${path}, which lies outside it`);
  }
  const markerPath = declaredPath === "." ? marker : `${declaredPath}/${marker}`;
  if (!skillFiles.includes(markerPath))
    refuse(
      `the declared skill material root ${declaredPath} does not list its own marker ${markerPath} ` +
        "among the files it declares",
    );
  const declaredExcludes = (Array.isArray(declaredRoot.excludes) ? declaredRoot.excludes : []).map(
    (path) => closureRelativePath(path, "a declared skill material root exclusion"),
  );
  for (const excluded of declaredExcludes)
    if (isWithinRoot(excluded, declaredPath))
      refuse(
        `the declared skill material root ${declaredPath} excludes ${excluded}, which lies inside ` +
          "that root: a capture of this root would cover it, so the declared exclusion is false",
      );

  return {
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
  };
}
