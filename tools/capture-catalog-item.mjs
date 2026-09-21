#!/usr/bin/env node
/**
 * Produces real Scanner output for one published Catalog item by running the
 * existing, documented capture command — it adds no scanning API and changes no
 * capture behavior.
 *
 * Fixed order of operations:
 *   1. refuse unless this host is Linux on the Node architecture the adapter
 *      supports (`linux/x64`, which is OCI `linux/amd64`) with the Docker the
 *      broker can reach;
 *   2. install the exact Catalog and Scan tarballs with `--ignore-scripts` into a
 *      fresh consumer outside every Git repository;
 *   3. read the item's original source closure through `@aihq/catalog`'s public
 *      source-closure reader, selected by collection and subject. The entry
 *      identity is the one that reader returns, never a packaged default id;
 *   4. stage every file of that closure under the path Catalog publishes it at and
 *      re-verify every declared sha256, then select the skill material root Catalog
 *      declares and mount that directory as the capture source root;
 *   5. validate the operator's detector registration, canonical OCI layout, local
 *      image identity, SBOM and provenance through the installed package's public
 *      API, and cross-check them against each other;
 *   6. write the capture request the packaged `aih-scan capture` command requires:
 *      `sourceRoot` is the declared skill root and `selectedClosurePaths` are
 *      relative to that root;
 *   7. refuse unless the staged root is a skill root the registered route can load:
 *      the broker mounts the request's `sourceRoot` at `/source`, so its own top
 *      level must hold the item's original `SKILL.md`. Suitability is read from the
 *      staged source material, never from the item's Catalog subject kind label,
 *      and a verified digest proves published bytes, not a skill source;
 *   8. if `--prepare-only` was not given: run the packaged command and keep its
 *      capture bundle. A capture that yields no verified bundle is a failure and is
 *      recorded as one, never as an empty scan.
 *
 * Every value that describes the detector runtime is an operator input. This tool
 * derives none of them and refuses instead: a registration, an OCI layout and its
 * image ID, an SBOM and a provenance document must all be supplied, and each one
 * is checked against the others before anything runs. The built-in `detector.cisco`
 * request is deliberately not offered here: its identity values come from CI
 * context, so a non-CI operator could only produce them by inventing them.
 *
 * Scanner output is evidence only. It is never qualification, approval, admission
 * or an effect. Signing is a separate step and is not performed here.
 *
 * Source selection. The source is not inferred from the item index and never from a
 * packaged default entry id: the helper calls the installed package's public
 * `readCatalogSourceClosureV1({ collectionId, subjectId })` and takes the entry,
 * subject digest, source revision and file list from the closure it returns. Every
 * file of that closure is staged under its published path and re-hashed, so a
 * served byte that does not match its declared sha256 stops the run before it is
 * written. The capture source root is then the `skill` material root Catalog
 * declares — not a directory the helper goes looking for. A closure that declares
 * no skill material root, or more than one, is refused rather than guessed at, and
 * a nested `SKILL.md` is never discovered and never substituted. Files that fall
 * outside the declared skill root stay staged, outside the mounted root, and are
 * recorded as uncovered: a scan of the skill root does not cover them.
 *
 * Diagnostic record. `source-closure.json` records the complete closure, the
 * selected skill root, the mapping from every published path to its staged path
 * and to the path the capture selects, and the files the mount cannot cover. It is
 * a diagnostic record written by this helper: it is not signed evidence, not a
 * capture bundle and not authority. A capture bundle seals the mounted root over
 * the selected paths only; that seal is not the closure's declaredTreeDigest, not
 * the four-file closure and not the entry's subjectDigest.
 *
 * Suitability. The only route this tool runs is `cisco-oci-v1`, which loads the
 * skill from the root the broker mounts at `/source`, so the staged root must be
 * the declared skill root itself, holding its own `SKILL.md` at the top level. An
 * item whose matter is an assessment closure rather than source files is refused
 * by the source reader itself, and its assessment artifacts (`closure.json`,
 * `profile.json`, `prose.md`, `recipe.json`) are never staged as a source. Nothing
 * is renamed, generated or substituted to make a root fit.
 *
 * Failure records. A run that stops after its run directory exists keeps its input
 * records and an explicit `capture-failure.json`: the phase, the reason, the exit
 * status and the streams a capture command actually wrote, the selected source
 * root, and the file paths the capture was asked to cover. Fields the phase never
 * produced stay null and output is never reconstructed. `findingsProduced` is
 * deliberately not `false` for a capture that ran and failed, or for a bundle that
 * failed validation: this helper does not inspect detector output, so it records
 * the answer as unknown. Only a run in which no capture process existed at all
 * records false.
 *
 * This helper belongs to one Scan commit and is not present at every package
 * checkpoint, so it must be run from the checkout that holds it, and the two
 * package checkpoints must be packed in their own `git archive` trees. Switching
 * a shared checkout to a package commit deletes this file; see the Checkouts
 * block in `--help`.
 *
 * `--prepare-only` proves preparation: that the supplied tarballs install, that
 * the item's published bytes verify, that the operator's detector inputs agree and
 * that the staged root is a skill root. It is never evidence that a detector ran.
 * Genuine execution is the capture bundle that only a Linux x64 host with the
 * loaded image can produce; a zero-finding or successfully signed result is not a
 * clean scan by itself.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";

/** The collection view and subject this helper reads a source closure for. */
const DEFAULT_COLLECTION_ID = "aih-core";
const DEFAULT_SUBJECT_ID = "governance-quality";
const USAGE = `Usage:
  node tools/capture-catalog-item.mjs \\
    --catalog-tarball <@aihq/catalog-*.tgz> \\
    --scan-tarball <aihq-scan-*.tgz> \\
    --output <new-or-empty-directory> \\
    --registration <DetectorRegistrationV1 authoring JSON> \\
    --layout <canonical CiscoOciLayoutV1 JSON> \\
    --image-id <docker image inspect --format '{{.Id}}' output> \\
    --sbom <SPDX JSON> \\
    --provenance <in-toto JSON> \\
    [--detector-id <detector.*>] [--collection-id <id>] [--subject-id <id>]
    [--consumer-root <empty-dir>] [--prepare-only]

  --catalog-tarball  npm pack output of the Catalog commit under test.
  --scan-tarball     npm pack output of the Scan commit under test.
  --output           New or empty run directory. It receives source/ (the complete
                     published closure under its own paths), detector/,
                     capture-request.json, source-closure.json, preflight.json,
                     execution.log and bundle/, plus capture-failure.json whenever
                     the run stops after preparation without a verified bundle.
  --registration     The organization's own DetectorRegistrationV1 authoring document
                     (README "Capture"). Nothing here is derived or defaulted.
  --layout           Canonical CiscoOciLayoutV1 JSON for the loaded detector image,
                     produced by: node tools/verify-cisco-oci-candidate.mjs \\
                       --metadata <buildx metadata> --layout-root <oci layout dir> \\
                       --image-id <config id file> --summary <summary out> \\
                       --canonical-layout <this file>
  --image-id         File holding 'docker image inspect --format {{.Id}} local.invalid/aih-scan/cisco'.
  --sbom             The exact SPDX bytes whose sha256 the registration declares.
  --provenance       The exact in-toto bytes whose sha256 the registration declares.
  --detector-id      Required only when the registration declares more than one entry.
  --collection-id    Collection view the source closure is read from. Default: ${DEFAULT_COLLECTION_ID}.
  --subject-id       Subject whose source closure is read. Default: ${DEFAULT_SUBJECT_ID}.
                     The entry id and every digest come from what the public
                     readCatalogSourceClosureV1 returns for this pair; no entry id
                     is defaulted or supplied by the operator.
  --consumer-root    Fresh install directory. Default: a new mkdtemp under the system temp root.
  --prepare-only     Validate everything, write the request, pass the subject and
                     Docker gates, and stop before capture.

Source selection. The item's original source is read through the installed
package's public readCatalogSourceClosureV1(collectionId, subjectId). Every file of
the returned closure is staged under the path Catalog publishes it at, re-hashed,
and its declared digest verified before it is written. The capture source root is
the 'skill' material root Catalog declares; a closure with no declared skill root,
or with more than one, is refused rather than guessed at, and a nested SKILL.md is
never discovered and never substituted for a declaration. Files outside that root,
such as aih-packs.json, stay outside the mounted root and are recorded as
uncovered: a scan of the skill root does not cover them.

Diagnostic record. source-closure.json records the complete closure, the selected
skill root, every published-to-staged-to-selected path mapping and the files the
mount cannot cover. It is this helper's own diagnostic: not signed evidence, not a
capture bundle and not authority. The capture seal covers the selected paths only
and is never the closure's declaredTreeDigest or the entry's subjectDigest.

Suitability. cisco-oci-v1 loads the skill from the root the broker mounts at
/source, so the mounted root must hold the declared skill's SKILL.md at its top
level. Suitability is read from the staged material, never from the item's Catalog
subject kind label: an item labelled 'agent' may be a skill pack, while
closure.json, profile.json, prose.md and recipe.json are assessment artifacts and
are never staged as a source — Catalog's own source reader refuses a subject whose
material is not source files. A run that reaches the Docker gate records the
accepted skill entry, the covered published paths and the uncovered ones in
preflight.json. A refusal before capture names the reason in execution.log and
leaves the selected root and the covered paths in capture-request.json and
source-closure.json; a failed capture additionally leaves capture-failure.json with
the command, the exit status, the streams that exist, that root and those paths.
findingsProduced stays null — unknown — for any capture that ran and failed or
whose bundle failed validation, because this helper does not inspect detector
output; it is false only when no capture process existed at all. No failed run is
recorded as an empty scan.

Checkouts. This file exists only in some Scan commits. Run it from the checkout
that holds it, at the reviewed helper commit, and record that commit separately
from the two package checkpoint identities. Do not switch, reset or clean that
checkout: packing an older package checkpoint would delete this file. Build each
package checkpoint in its own extraction instead, then pass the two tarballs here:

  git -C <catalog-checkout> archive --format=tar <catalog-commit> | \\
    (mkdir -p /tmp/aih-catalog-build && tar -x -C /tmp/aih-catalog-build)
  cd /tmp/aih-catalog-build && npm ci && npm run build && npm pack

  git -C <scan-checkout> archive --format=tar <scan-commit> | \\
    (mkdir -p /tmp/aih-scan-build && tar -x -C /tmp/aih-scan-build)
  cd /tmp/aih-scan-build && npm ci && npm pack

@aihq/catalog has no prepack script, so its dist/ must be built before packing;
@aihq/scan builds itself in prepack. The produced tarball names carry each
package version, and both tarball hashes plus both installed versions are written
to preflight.json.

Running it here proves preparation only. The detector runs only when all of these
hold: Node reports linux/x64 (OCI amd64), PATH=/usr/bin:/bin reaches
/usr/bin/docker or /bin/docker, that daemon reports Linux amd64 on its default
socket (the broker passes no DOCKER_HOST/DOCKER_CONTEXT), and the image is loaded
under the exact config digest the layout declares.
`;

const DETECTOR_ID = /^detector\.[a-z0-9][a-z0-9.-]*$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const REFERENCE_NAME = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const ADAPTER_CAPABILITY = "cisco-oci-v1";
/** The skill entry the scanner loads from the capture root; never renamed or generated. */
const SKILL_ENTRY = "SKILL.md";
/** The Catalog material root that names the skill directory to mount, and its marker. */
const SKILL_MATERIAL_ROOT_KIND = "skill";
const SOURCE_CLOSURE_FORMAT = "aih-catalog-source-closure";
/** The helper's own diagnostic record of the staged closure; never part of the bundle. */
const SOURCE_CLOSURE_RECORD_NAME = "source-closure.json";
const SOURCE_CLOSURE_RECORD_PROTOCOL = "CatalogSourceClosureCaptureRecordV1";
/** Collection and subject ids are Catalog's own lowercase id grammar. */
const CATALOG_ID = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json";
const MAX_TARBALL_BYTES = 512 * 1024 * 1024;
const MAX_LAYOUT_BYTES = 4 * 1024 * 1024;
const MAX_REGISTRATION_BYTES = 512 * 1024;
const MAX_ANNEX_BYTES = 16 * 1024 * 1024;
/** Bounds on the source closure a package may serve and on one of its files. */
const MAX_SOURCE_FILE_BYTES = 16 * 1024 * 1024;
const MAX_SOURCE_FILES = 4096;
/** Bound on the staged-tree walk that reports a nested SKILL.md, never selects one. */
const MAX_STAGED_TREE_DIRECTORIES = 256;
/** Bound on each stream kept in capture-failure.json; the full text stays in execution.log. */
const MAX_FAILURE_STREAM_CHARACTERS = 64 * 1024;
const INSTALL_TIMEOUT_MS = 15 * 60 * 1000;
const DOCKER_TIMEOUT_MS = 120_000;
const CAPTURE_TIMEOUT_MS = 30 * 60 * 1000;

/** The broker spawns bare `docker` with this exact environment, so preflight uses it too. */
const BROKER_PATH = "/usr/bin:/bin";
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

class Refusal extends Error {}
/** Every refusal names the missing or unacceptable input. Nothing is substituted. */
const refuse = (reason) => {
  throw new Refusal(reason);
};

const reasonOf = (error) => (error instanceof Error ? error.message : String(error));
const sha256Hex = (bytes) => createHash("sha256").update(bytes).digest("hex");

/* ---------- canonical JSON, mirroring @aihq/scan's own rules ---------- */

const own = (value, key) => {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !("value" in descriptor)) refuse("canonical JSON own data");
  return descriptor.value;
};
const canonicalText = (value) => {
  if (value === null || typeof value === "boolean" || typeof value === "number")
    return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalText).join(",")}]`;
  if (typeof value === "object")
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalText(own(value, key))}`)
      .join(",")}}`;
  return refuse("canonical JSON value");
};
const canonicalBytes = (value) => Buffer.from(canonicalText(value), "utf8");

/* ---------- bounded input readers ---------- */

function regularBytes(path, label, minimum, maximum) {
  if (typeof path !== "string" || !isAbsolute(path) || path.includes("\0"))
    refuse(`${label} must be an absolute path`);
  let stat;
  try {
    stat = lstatSync(path);
  } catch {
    refuse(`${label} is missing: ${path}`);
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1)
    refuse(`${label} must be a regular unlinked file: ${path}`);
  if (stat.size < minimum || stat.size > maximum)
    refuse(`${label} must be between ${minimum} and ${maximum} bytes: ${path}`);
  const bytes = readFileSync(path);
  if (bytes.length !== stat.size) refuse(`${label} changed while reading: ${path}`);
  return bytes;
}

function textFile(path, label, minimum, maximum) {
  const bytes = regularBytes(path, label, minimum, maximum);
  const text = bytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(bytes)) refuse(`${label} must be UTF-8: ${path}`);
  return text;
}

function jsonFile(path, label, minimum, maximum) {
  const text = textFile(path, label, minimum, maximum);
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    refuse(`${label} must be JSON: ${path}`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed))
    refuse(`${label} must be a JSON object: ${path}`);
  return parsed;
}

/** No Git repository may contain the consumer install or the produced run. */
function assertOutsideGitRepository(path, label) {
  let current = resolve(path);
  for (;;) {
    if (existsSync(join(current, ".git"))) refuse(`${label} must be outside every Git repository`);
    const parent = dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

function exactKeys(value, fields, label) {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.keys(value).length !== fields.length ||
    fields.some((field) => !Object.hasOwn(value, field))
  )
    refuse(`${label} fields`);
}

/** Computed fields the package returns but never accepts back as input. */
function computedWireFields(document) {
  const found = new Set();
  if (Object.hasOwn(document, "registrationSha256")) found.add("registrationSha256");
  const entries = Array.isArray(document.registrations) ? document.registrations : [];
  for (const entry of entries) {
    if (typeof entry !== "object" || entry === null) continue;
    if (Object.hasOwn(entry, "registrationEntrySha256")) found.add("registrationEntrySha256");
    const detector = entry.detector;
    if (
      typeof detector === "object" &&
      detector !== null &&
      Object.hasOwn(detector, "scannerManifestEntrySha256")
    )
      found.add("scannerManifestEntrySha256");
  }
  return [...found];
}

/* ---------- arguments ---------- */

const VALUE_FLAGS = new Map([
  ["--catalog-tarball", "catalogTarball"],
  ["--scan-tarball", "scanTarball"],
  ["--output", "output"],
  ["--registration", "registration"],
  ["--layout", "layout"],
  ["--image-id", "imageId"],
  ["--sbom", "sbom"],
  ["--provenance", "provenance"],
  ["--detector-id", "detectorId"],
  ["--collection-id", "collectionId"],
  ["--subject-id", "subjectId"],
  ["--consumer-root", "consumerRoot"],
]);
const BOOLEAN_FLAGS = new Map([["--prepare-only", "prepareOnly"]]);
const REQUIRED_FLAGS = [
  "--catalog-tarball",
  "--scan-tarball",
  "--output",
  "--registration",
  "--layout",
  "--image-id",
  "--sbom",
  "--provenance",
];

/**
 * Names the producing command for every missing operator input, so an absent
 * detector runtime is never silently replaced by a default.
 */
const ORIGIN_OF_FLAG = {
  "--registration": "the organization's own DetectorRegistrationV1 authoring JSON (README section Capture)",
  "--layout": "node tools/verify-cisco-oci-candidate.mjs ... --canonical-layout <file>",
  "--image-id": "docker image inspect --format '{{.Id}}' local.invalid/aih-scan/cisco > <file>",
  "--sbom": "the SPDX bytes whose sha256 your registration declares",
  "--provenance": "the in-toto bytes whose sha256 your registration declares",
};

function parseArguments(argv) {
  if (argv.length === 1 && (argv[0] === "--help" || argv[0] === "-h")) {
    process.stdout.write(USAGE);
    process.exit(0);
  }
  const values = {};
  const seen = new Set();
  for (let index = 0; index < argv.length; index += 1) {
    const name = argv[index];
    if (BOOLEAN_FLAGS.has(name)) {
      if (seen.has(name)) refuse(`duplicate argument ${name}`);
      seen.add(name);
      values[BOOLEAN_FLAGS.get(name)] = true;
      continue;
    }
    const key = VALUE_FLAGS.get(name);
    if (key === undefined) refuse(`unknown argument ${name}; run with --help`);
    if (seen.has(name)) refuse(`duplicate argument ${name}`);
    const value = argv[index + 1];
    if (typeof value !== "string" || value.startsWith("--")) refuse(`${name} requires a value`);
    seen.add(name);
    values[key] = value;
    index += 1;
  }
  const missing = REQUIRED_FLAGS.filter((name) => !seen.has(name));
  if (missing.length > 0) {
    const origins = missing
      .filter((name) => ORIGIN_OF_FLAG[name] !== undefined)
      .map((name) => `\n  ${name}: supply ${ORIGIN_OF_FLAG[name]}`)
      .join("");
    refuse(`missing required argument(s) ${missing.join(", ")}; run with --help${origins}`);
  }
  values.collectionId ??= DEFAULT_COLLECTION_ID;
  values.subjectId ??= DEFAULT_SUBJECT_ID;
  if (!CATALOG_ID.test(values.collectionId)) refuse("--collection-id grammar");
  if (!CATALOG_ID.test(values.subjectId)) refuse("--subject-id grammar");
  if (values.detectorId !== undefined && !DETECTOR_ID.test(values.detectorId))
    refuse("--detector-id grammar");
  return values;
}

/* ---------- run log ---------- */

let logPath;
const log = (message) => {
  const line = `${message}\n`;
  process.stdout.write(line);
  if (logPath !== undefined) writeFileSync(logPath, line, { flag: "a" });
};

function appendProcessLog(label, result) {
  const body =
    `\n===== ${label} =====\n` +
    `finished ${new Date().toISOString()}\n` +
    `exit     ${result.status}\n` +
    (result.error === undefined ? "" : `error    ${result.error.message}\n`) +
    (result.signal === null || result.signal === undefined ? "" : `signal   ${result.signal}\n`) +
    (result.stdout ? `--- stdout ---\n${result.stdout}\n` : "") +
    (result.stderr ? `--- stderr ---\n${result.stderr}\n` : "");
  if (logPath === undefined) process.stdout.write(body);
  else writeFileSync(logPath, body, { flag: "a" });
}

/* ---------- phases ---------- */

/**
 * Node and OCI/Docker spell the same target architecture differently: Node
 * reports `x64` and never `amd64`, while the adapter, the registration, the OCI
 * layout and the daemon report `amd64` and never `x64`. The two vocabularies are
 * mapped here explicitly and never mixed; see `assertPlatform`'s return value.
 */
const OCI_ARCHITECTURE_BY_NODE_ARCHITECTURE = new Map([["x64", "amd64"]]);

/**
 * The host gate. It takes an explicit descriptor so both outcomes are testable
 * without a Linux host, a daemon or an image: this function never touches the
 * filesystem, Docker or a detector.
 */
function assertPlatform(descriptor = { platform: process.platform, arch: process.arch }) {
  if (
    descriptor.platform !== "linux" ||
    OCI_ARCHITECTURE_BY_NODE_ARCHITECTURE.get(descriptor.arch) !== "amd64"
  )
    refuse(
      "the cisco-oci-v1 adapter supports only Linux amd64, which Node reports as linux/x64; " +
        `this Node host reports ${descriptor.platform}/${descriptor.arch}`,
    );
  return {
    /* What Node reports, in Node's vocabulary. */
    node: { os: descriptor.platform, architecture: descriptor.arch },
    /* What the adapter, registration, layout and daemon require, in OCI's. */
    oci: { os: "linux", architecture: "amd64" },
  };
}

function createRunDirectory(output) {
  const runRoot = resolve(output);
  assertOutsideGitRepository(runRoot, "--output");
  if (existsSync(runRoot)) {
    const stat = lstatSync(runRoot);
    if (!stat.isDirectory() || stat.isSymbolicLink())
      refuse(`--output must be a real directory: ${runRoot}`);
    if (readdirSync(runRoot).length > 0) refuse(`--output must be new or empty: ${runRoot}`);
  } else {
    mkdirSync(runRoot, { recursive: true, mode: 0o700 });
  }
  logPath = join(runRoot, "execution.log");
  writeFileSync(logPath, "", { flag: "w" });
  return runRoot;
}

/**
 * npm is resolved the way this repository's other tools resolve it: through an
 * absolute `npm_execpath`, otherwise through the CLI shipped with the running
 * Node. A bare `npm` spawn is a shell shim on some hosts and not an executable,
 * and this install must work on the operator's Linux host and in a direct
 * repository check alike.
 */
function npmCliPath(environment = process.env) {
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
function installEnvironment(environment = process.env) {
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

function installConsumer(options) {
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

function installedPackage(consumerRoot, name) {
  const root = join(consumerRoot, "node_modules", ...name.split("/"));
  const metadata = jsonFile(join(root, "package.json"), `${name} package.json`, 2, 1024 * 1024);
  if (metadata.name !== name) refuse(`${name} is not installed at ${root}`);
  log(`installed       ${name}@${metadata.version}`);
  return { root, version: metadata.version };
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

/** Whether a published path lies at or below a declared material root path. */
const isWithinRoot = (publishedPath, rootPath) =>
  rootPath === "." || publishedPath.startsWith(`${rootPath}/`);

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
function readCatalogSourceClosure(reader, options, runRoot, catalog) {
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

/** Top-level entries of the staged root, with directories marked, for a refusal message. */
function stagedTopLevelEntries(sourceRoot) {
  return readdirSync(sourceRoot, { withFileTypes: true })
    .map((entry) => (entry.isDirectory() ? `${entry.name}/` : entry.name))
    .sort();
}

/**
 * Relative paths of `SKILL.md` files below the staged root. Reported only: the
 * broker mounts exactly one root, so a nested skill is never selected in its place.
 * Directories are walked in a bounded breadth-first order and symbolic links are
 * ignored, so a hostile or cyclic tree cannot stall the refusal.
 */
function nestedSkillPaths(sourceRoot) {
  const nested = [];
  const queue = [[sourceRoot, ""]];
  let visited = 0;
  while (queue.length > 0 && visited < MAX_STAGED_TREE_DIRECTORIES) {
    const [directory, prefix] = queue.shift();
    visited += 1;
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const relative = prefix === "" ? entry.name : `${prefix}/${entry.name}`;
      if (entry.isDirectory()) queue.push([join(directory, entry.name), relative]);
      else if (entry.isFile() && entry.name === SKILL_ENTRY) nested.push(relative);
    }
  }
  return nested.sort();
}

function notSkillRootReason(item, itemId) {
  const topLevel = stagedTopLevelEntries(item.sourceRoot);
  const stagedPaths = item.files.map((file) => file.path).sort();
  const nested = nestedSkillPaths(item.sourceRoot);
  return (
    `catalog item ${itemId} is not a skill source for ${ADAPTER_CAPABILITY}: the broker mounts the ` +
    `capture source root at /source and the scanner loads the skill from that root, but ` +
    `${item.sourceRoot} holds no staged ${SKILL_ENTRY} at its top level ` +
    `(top-level entries: ${topLevel.join(", ") || "none"}; staged files: ${stagedPaths.join(", ") || "none"}). ` +
    `This root is the skill material root the source closure declares, and the entry the route loads ` +
    `is read from the staged bytes: a verified digest proves these are the published bytes, not that ` +
    `they are the skill entry this route can load` +
    (nested.length === 0
      ? ""
      : `. ${nested.length} nested ${SKILL_ENTRY} path(s) exist under this root (${nested.join(", ")}); ` +
        `none is selected, because the request binds this one root and a nested skill would cover only ` +
        `that directory and not the rest of the staged closure`) +
    "."
  );
}

/**
 * The registered `cisco-oci-v1` route mounts the capture `sourceRoot` at `/source`
 * and loads the skill from that root, so the staged root must itself be the skill
 * root: its own top level must hold the declared skill's `SKILL.md`, byte for byte
 * as published.
 *
 * Suitability is read from the staged source material — the declared file paths and
 * the staged bytes — and never from the item's Catalog subject kind label. An item
 * labelled `agent` whose material is a skill pack passes; an item labelled `skill`
 * whose material is an assessment closure never reaches this gate, because Catalog's
 * source reader refuses that subject and its assessment artifacts are never staged
 * as a source.
 *
 * Only this root is considered, and it is the root Catalog declared rather than one
 * this helper found. A nested `SKILL.md` is named in the refusal and never selected
 * or copied: the request's `sourceRoot` and `selectedClosurePaths` bind this root,
 * and scanning a nested directory would not cover the rest of the staged closure.
 * Nothing is renamed and no `SKILL.md` is generated.
 */
function assertSkillSourceRoot(item) {
  const itemId = item.entry.entryId;
  const declared = item.files.find((file) => file.path === SKILL_ENTRY);
  if (declared === undefined) refuse(notSkillRootReason(item, itemId));
  const stagedPath = join(item.sourceRoot, SKILL_ENTRY);
  let bytes;
  try {
    bytes = regularBytes(stagedPath, `staged ${SKILL_ENTRY}`, 1, MAX_SOURCE_FILE_BYTES);
  } catch (error) {
    refuse(`catalog item ${itemId} declares ${SKILL_ENTRY} but the staged copy is unusable: ${reasonOf(error)}`);
  }
  const recomputed = sha256Hex(bytes);
  if (recomputed !== declared.sha256)
    refuse(
      `the staged ${SKILL_ENTRY} of catalog item ${itemId} no longer matches its published digest: ` +
        `sha256:${recomputed} != sha256:${declared.sha256}`,
    );
  return {
    publishedPath: declared.publishedPath,
    path: SKILL_ENTRY,
    sha256: declared.sha256,
    byteLength: declared.byteLength,
  };
}

/**
 * Validates the operator's detector identity against the installed package's own
 * rules and against the other operator inputs. It chooses nothing.
 */
function readDetectorInputs(reader, options, runRoot) {
  const registrationInput = jsonFile(options.registration, "--registration", 2, MAX_REGISTRATION_BYTES);
  let registration;
  try {
    registration = reader.createDetectorRegistrationV1(registrationInput);
  } catch (error) {
    /*
     * `createDetectorRegistrationV1` input is strict and the CLI revalidates the
     * request's registration with it, so a document carrying computed wire fields
     * cannot be resubmitted. Name them instead of failing later inside capture.
     */
    const wireFields = computedWireFields(registrationInput);
    refuse(
      `--registration is not a valid DetectorRegistrationV1 authoring input: ${reasonOf(error)}` +
        (wireFields.length === 0
          ? ""
          : `. It carries computed field(s) ${wireFields.join(", ")}; supply the authoring document without computed fields (README section Capture)`),
    );
  }
  const entries = registration.registrations;
  let selected;
  if (options.detectorId !== undefined) {
    selected = entries.find((entry) => entry.detector.detectorId === options.detectorId);
    if (selected === undefined) refuse(`--registration declares no ${options.detectorId} entry`);
  } else if (entries.length === 1) {
    selected = entries[0];
  } else {
    refuse(`--detector-id is required because --registration declares ${entries.length} entries`);
  }
  if (
    selected.adapterCapability !== ADAPTER_CAPABILITY ||
    selected.broker.capability !== ADAPTER_CAPABILITY
  )
    refuse(`the only executable capture capability is ${ADAPTER_CAPABILITY}`);
  const detectorId = selected.detector.detectorId;
  const platform = selected.detector.supportedPlatforms[0];
  if (
    selected.detector.supportedPlatforms.length !== 1 ||
    platform.os !== "linux" ||
    platform.architecture !== "amd64"
  )
    refuse("the registered detector must support exactly Linux amd64");
  log(
    `registration    ${detectorId} sha256:${registration.registrationSha256} ` +
      `(${entries.length} entr${entries.length === 1 ? "y" : "ies"})`,
  );

  const layoutInput = jsonFile(options.layout, "--layout", 2, MAX_LAYOUT_BYTES);
  exactKeys(
    layoutInput,
    [
      "protocol",
      "manifestDigestSha256",
      "configDigestSha256",
      "logicalReference",
      "manifestPlatform",
      "manifestDescriptor",
    ],
    "--layout",
  );
  if (layoutInput.protocol !== "CiscoOciLayoutV1") refuse("--layout protocol");
  if (!DIGEST.test(layoutInput.manifestDigestSha256) || !DIGEST.test(layoutInput.configDigestSha256))
    refuse("--layout digests");
  if (layoutInput.manifestDigestSha256 === layoutInput.configDigestSha256)
    refuse("--layout manifest and config digests must differ");
  /*
   * CiscoOciLayoutV1 fixes this image name, so a detector image published under any
   * other name cannot satisfy the canonical layout at all. Refuse it here rather
   * than in the middle of capture.
   */
  if (
    layoutInput.logicalReference !==
    `local.invalid/aih-scan/cisco@${layoutInput.manifestDigestSha256}`
  )
    refuse(
      "--layout logical reference must be 'local.invalid/aih-scan/cisco@<manifestDigestSha256>'; CiscoOciLayoutV1 fixes that image name",
    );
  exactKeys(layoutInput.manifestPlatform, ["architecture", "os"], "--layout manifestPlatform");
  if (
    layoutInput.manifestPlatform.os !== "linux" ||
    layoutInput.manifestPlatform.architecture !== "amd64"
  )
    refuse("--layout manifestPlatform");
  const descriptor = layoutInput.manifestDescriptor;
  exactKeys(
    descriptor,
    ["mediaType", "digest", "size", "platform", "annotations"],
    "--layout manifestDescriptor",
  );
  if (
    descriptor.mediaType !== MANIFEST_MEDIA_TYPE ||
    descriptor.digest !== layoutInput.manifestDigestSha256 ||
    !Number.isSafeInteger(descriptor.size) ||
    descriptor.size < 0
  )
    refuse("--layout manifestDescriptor");
  exactKeys(descriptor.platform, ["architecture", "os"], "--layout descriptor platform");
  if (descriptor.platform.os !== "linux" || descriptor.platform.architecture !== "amd64")
    refuse("--layout descriptor platform");
  exactKeys(
    descriptor.annotations,
    ["org.opencontainers.image.ref.name"],
    "--layout descriptor annotations",
  );
  if (!REFERENCE_NAME.test(descriptor.annotations["org.opencontainers.image.ref.name"]))
    refuse("--layout descriptor annotation name");
  if (layoutInput.logicalReference !== selected.runtime.sourceReference)
    refuse("--layout logical reference does not match the registration runtime source reference");
  if (layoutInput.manifestDigestSha256 !== `sha256:${selected.runtime.sourceSha256}`)
    refuse("--layout manifest digest does not match the registration runtime source digest");
  if (layoutInput.configDigestSha256 !== `sha256:${selected.runtime.configSha256}`)
    refuse("--layout config digest does not match the registration runtime config digest");
  log(`layout          ${layoutInput.logicalReference} config ${layoutInput.configDigestSha256}`);

  const imageId = textFile(options.imageId, "--image-id", 2, 128).trim();
  if (!DIGEST.test(imageId)) refuse("--image-id must hold one 'sha256:<64 hex>' image ID");
  if (imageId !== layoutInput.configDigestSha256)
    refuse("--image-id does not match the config digest the layout declares");

  const annexInputs = [
    {
      flag: "--sbom",
      path: options.sbom,
      descriptorId: "annex.sbom",
      declared: selected.detector.sbom.sha256,
    },
    {
      flag: "--provenance",
      path: options.provenance,
      descriptorId: "annex.provenance",
      declared: selected.detector.provenance.sha256,
    },
  ];
  const annex = annexInputs.map((input) => {
    const bytes = regularBytes(input.path, input.flag, 1, MAX_ANNEX_BYTES);
    const recomputed = sha256Hex(bytes);
    if (recomputed !== input.declared)
      refuse(
        `${input.flag} sha256 ${recomputed} does not match the registered ${input.descriptorId} digest ${input.declared}`,
      );
    return { descriptorId: input.descriptorId, source: input.path, sha256: recomputed };
  });

  const detectorRoot = join(runRoot, "detector");
  mkdirSync(join(detectorRoot, "annex"), { recursive: true });
  writeFileSync(join(detectorRoot, "layout-v1.json"), canonicalBytes(layoutInput));
  writeFileSync(join(detectorRoot, "image-id.txt"), `${imageId}\n`);
  const annexFiles = annex.map((entry) => {
    const target = join(detectorRoot, "annex", `${entry.descriptorId}.bin`);
    copyFileSync(entry.source, target);
    if (sha256Hex(readFileSync(target)) !== entry.sha256)
      refuse(`${entry.descriptorId} copy changed`);
    log(`detector input  ${entry.descriptorId} sha256:${entry.sha256}`);
    return { descriptorId: entry.descriptorId, path: target };
  });
  return {
    /* The request carries the authoring document: the CLI revalidates it strictly. */
    registrationInput,
    registrationRecord: registration,
    detectorId,
    layout: layoutInput,
    annexFiles,
  };
}

function dockerPreflight(layout) {
  /*
   * The broker spawns bare `docker` with exactly this environment and an empty
   * DOCKER_CONFIG, so no DOCKER_HOST or DOCKER_CONTEXT from the operator's shell
   * can reach it. The preflight mirrors that, and would otherwise accept a daemon
   * the real capture cannot see.
   */
  const clientRoot = mkdtempSync(join(tmpdir(), "aih-scan-capture-preflight-"));
  const home = join(clientRoot, "home");
  const dockerConfig = join(clientRoot, "docker-config");
  mkdirSync(home, { recursive: true, mode: 0o700 });
  mkdirSync(dockerConfig, { recursive: true, mode: 0o700 });
  const environment = { PATH: BROKER_PATH, HOME: home, DOCKER_CONFIG: dockerConfig };
  const run = (argv, label) => {
    const result = spawnSync(argv[0], argv.slice(1), {
      encoding: "utf8",
      env: environment,
      timeout: DOCKER_TIMEOUT_MS,
      maxBuffer: 16 * 1024 * 1024,
    });
    if (result.error !== undefined)
      refuse(
        `${label} could not run: ${result.error.message}; the broker spawns bare 'docker' with PATH=${BROKER_PATH}`,
      );
    return result;
  };
  try {
    const serverOs = run(["docker", "version", "--format", "{{.Server.Os}}"], "docker version");
    const serverArch = run(["docker", "version", "--format", "{{.Server.Arch}}"], "docker version");
    if (serverOs.status !== 0 || serverArch.status !== 0)
      refuse(
        `no Docker daemon answered on the default socket with PATH=${BROKER_PATH}: ` +
          `${`${serverOs.stderr}${serverArch.stderr}`.trim() || "no diagnostic output"}`,
      );
    const os = serverOs.stdout.trim();
    const architecture = serverArch.stdout.trim();
    if (os !== "linux" || architecture !== "amd64")
      refuse(`the Docker daemon must be Linux amd64; it reports ${os}/${architecture}`);
    const inspected = run(
      ["docker", "image", "inspect", "--format", "{{.Id}}", layout.configDigestSha256],
      "docker image inspect",
    );
    const reported = inspected.stdout.trim();
    if (inspected.status !== 0 || reported !== layout.configDigestSha256)
      refuse(
        `the detector image ${layout.configDigestSha256} is not loaded in this daemon` +
          (reported === "" ? "" : `; it reported ${reported}`),
      );
    log(`docker          linux/amd64, image ${layout.configDigestSha256} loaded`);
    return { os, architecture, imageId: reported };
  } finally {
    rmSync(clientRoot, { recursive: true, force: true });
  }
}

/**
 * The run directory's record of a stop that produced no verified bundle. It keeps
 * only what the phase actually made available: the reason, the capture command when
 * one was built, the exit status and the streams the command really wrote, the
 * selected source root and the file paths this capture was asked to cover. A field
 * the phase never produced stays null — no output is reconstructed, a failed run is
 * never recorded as an empty successful scan, and the full streams remain in
 * execution.log rather than being truncated away here.
 *
 * `findingsProduced` answers only what this helper can establish. A capture that ran
 * and failed, and a bundle that failed its own reader, may have written detector
 * output this helper never inspects: there the answer is null and the basis says so.
 * Only a run in which no capture process existed at all records false.
 */
function writeCaptureFailure(runRoot, prepared, failure) {
  const excerpt = (text) => {
    if (typeof text !== "string") return { characters: 0, text: null, truncated: false };
    return text.length <= MAX_FAILURE_STREAM_CHARACTERS
      ? { characters: text.length, text, truncated: false }
      : {
          characters: text.length,
          text: text.slice(-MAX_FAILURE_STREAM_CHARACTERS),
          truncated: true,
        };
  };
  const stdout = excerpt(failure.stdout);
  const stderr = excerpt(failure.stderr);
  const bundlePath = join(runRoot, "bundle");
  const executionLog = join(runRoot, "execution.log");
  writeFileSync(
    join(runRoot, "capture-failure.json"),
    canonicalBytes({
      protocol: "CatalogItemCaptureFailureV1",
      outcome: "failed",
      phase: failure.phase,
      reason: failure.reason,
      captureCommand: failure.captureCommand ?? null,
      exitCode: failure.exitCode ?? null,
      signal: failure.signal ?? null,
      spawnError: failure.spawnError ?? null,
      stdout: stdout.text,
      stdoutCharacters: stdout.characters,
      stdoutTruncated: stdout.truncated,
      stderr: stderr.text,
      stderrCharacters: stderr.characters,
      stderrTruncated: stderr.truncated,
      bundleDirectory: bundlePath,
      bundlePresent: existsSync(bundlePath),
      /* This record exists only because no verified bundle was produced. */
      bundleVerified: false,
      /*
       * Whether a capture process existed at all, and then whether it is known to
       * have produced no findings. Unknown, not false, once a capture process has
       * existed: a failed command and a bundle that fails validation may each have
       * written detector output, and this helper does not read detector output to
       * find out.
       */
      captureProcessExisted: failure.captureProcessExisted === true,
      findingsProduced: failure.captureProcessExisted === true ? null : false,
      findingsProducedBasis:
        failure.captureProcessExisted === true
          ? "capture-output-not-inspected"
          : "no-capture-process-existed",
      sourceRoot: prepared === undefined ? null : prepared.item.sourceRoot,
      coveredFilePaths: prepared === undefined ? null : [...prepared.item.selectedClosurePaths],
      sourceClosureRecord: prepared === undefined ? null : prepared.sourceClosurePath,
      captureRequestPath: prepared === undefined ? null : prepared.requestPath,
      executionLog,
    }),
  );
  if (existsSync(executionLog))
    writeFileSync(executionLog, `\n${failure.phase} failure: ${failure.reason}\n`, { flag: "a" });
}

/**
 * Runs one step and, if it refuses, records the refusal in the run directory before
 * it propagates. These phases all run before any capture command exists, so a
 * failure during preparation has no staged root to name yet and no capture process
 * to have produced findings: those fields are recorded as null and false rather
 * than guessed.
 */
async function recordFailure(phase, runRoot, prepared, step) {
  try {
    return await step();
  } catch (error) {
    writeCaptureFailure(runRoot, prepared, {
      captureCommand: null,
      captureProcessExisted: false,
      exitCode: null,
      phase,
      reason: reasonOf(error),
      signal: null,
      spawnError: null,
      stderr: null,
      stdout: null,
    });
    throw error;
  }
}

/**
 * Runs the packaged capture command and returns its outcome instead of throwing: a
 * capture that produced no verified bundle must still be recorded with the exit
 * status and the streams the command actually wrote. Every failed attempt is
 * written to the run directory before it is returned.
 */
function attemptCapture(prepared, runRoot) {
  const bundlePath = join(runRoot, "bundle");
  const captureCommand = [
    process.execPath,
    prepared.cliEntry,
    "capture",
    "--request",
    prepared.requestPath,
    "--output",
    bundlePath,
  ];
  const failed = (phase, reason, result, captureProcessExisted) => {
    const failure = {
      outcome: "failed",
      phase,
      reason,
      captureCommand,
      /*
       * Whether a capture process existed decides what this run may claim about
       * findings: with a process, its output was not inspected and stays unknown.
       */
      captureProcessExisted,
      exitCode: result === undefined || typeof result.status !== "number" ? null : result.status,
      signal: result === undefined ? null : (result.signal ?? null),
      spawnError: result === undefined || result.error === undefined ? null : result.error.message,
      stdout: result === undefined ? null : result.stdout,
      stderr: result === undefined ? null : result.stderr,
    };
    writeCaptureFailure(runRoot, prepared, failure);
    return failure;
  };
  if (existsSync(bundlePath))
    return failed(
      "capture",
      `capture bundle directory already exists: ${bundlePath}`,
      undefined,
      false,
    );
  const result = spawnSync(process.execPath, captureCommand.slice(1), {
    encoding: "utf8",
    env: process.env,
    timeout: CAPTURE_TIMEOUT_MS,
    maxBuffer: 64 * 1024 * 1024,
  });
  appendProcessLog("aih-scan capture", result);
  if (result.error !== undefined)
    return failed("capture", `capture could not run: ${result.error.message}`, result, true);
  if (result.status !== 0)
    return failed(
      "capture",
      `capture exited ${result.status}: ${
        (result.stderr ?? "").trim().slice(0, 2000) || "no diagnostic output"
      }; full output is in execution.log`,
      result,
      true,
    );
  let bundle;
  try {
    bundle = prepared.reader.readScanCaptureBundleV2({ bundleDirectory: bundlePath });
  } catch (error) {
    return failed(
      "bundle",
      `the produced bundle failed its own reader: ${reasonOf(error)}`,
      result,
      true,
    );
  }
  const manifest = JSON.parse(readFileSync(join(bundlePath, "bundle.json"), "utf8"));
  log(`bundle          ${bundlePath}`);
  log(`candidate       sha256:${manifest.candidate.candidateSha256}`);
  log(
    `annexes         ${bundle.annexArtifacts
      .map((entry) => `${entry.descriptorId}:${entry.sha256}`)
      .join(" ")}`,
  );
  return { outcome: "captured", bundlePath, candidateSha256: manifest.candidate.candidateSha256 };
}

/**
 * Everything the command does after preparation, in this order: refuse a subject the
 * registered route cannot load, refuse a host or daemon the broker cannot reach,
 * record the preflight, then either stop (`--prepare-only`) or capture.
 *
 * The order is the point. A subject the scanner cannot load is refused before the
 * Docker gate and before any container exists, and this function is separate from
 * `main` so that order is observable on a host whose platform gate would otherwise
 * refuse first. Every failure from here on leaves capture-failure.json behind.
 */
async function runPreparedCapture(options, runRoot, platform, prepared) {
  const skill = await recordFailure("subject", runRoot, prepared, () =>
    assertSkillSourceRoot(prepared.item),
  );
  log(`skill root      ${prepared.item.sourceRoot} (${skill.path} sha256:${skill.sha256})`);
  const docker = await recordFailure("host", runRoot, prepared, () =>
    dockerPreflight(prepared.detector.layout),
  );
  writePreflight(runRoot, platform, docker, prepared, skill);
  if (options.prepareOnly === true) {
    log("prepare-only    capture not attempted; this is preparation, not detector output");
    return {
      outcome: "prepared",
      requestPath: prepared.requestPath,
      captureCommand: `aih-scan capture --request ${prepared.requestPath} --output ${join(runRoot, "bundle")}`,
    };
  }
  const attempt = attemptCapture(prepared, runRoot);
  if (attempt.outcome !== "captured") refuse(attempt.reason);
  return {
    outcome: "captured",
    bundlePath: attempt.bundlePath,
    candidateSha256: attempt.candidateSha256,
    executionLog: logPath,
  };
}

/**
 * The consumer's reader module resolves bare specifiers against the installed
 * tarballs, so this is also the first real proof that both tarballs were packed
 * from the commits under test with their build output present.
 */
async function importReader(consumerRoot) {
  try {
    return await import(pathToFileURL(join(consumerRoot, "reader.mjs")).href);
  } catch (error) {
    refuse(
      `the installed packages do not expose the public entry points this tool needs: ${reasonOf(error)}. ` +
        "Check that each tarball was packed from the commit under test with dist/ built: @aihq/scan builds in prepack, @aihq/catalog has no prepack and must be built before packing",
    );
  }
}

/**
 * Steps 2 to 6 of the fixed order: the whole platform-independent preparation,
 * exactly as the command runs it. It stops before the subject gate, before the host
 * gate's Docker check and before capture, so it is also the surface a test can drive
 * against supplied tarballs without pretending a detector ran.
 *
 * Preparation stages the published source closure under its own paths, selects the
 * skill material root Catalog declares and writes the request. `runPreparedCapture`
 * then refuses a subject the registered route cannot load, using the staged material
 * this function wrote and the digests it verified.
 */
async function prepareCapture(options, runRoot) {
  const consumer = installConsumer(options);
  const catalog = installedPackage(consumer.consumerRoot, "@aihq/catalog");
  const scan = installedPackage(consumer.consumerRoot, "@aihq/scan");
  const reader = await importReader(consumer.consumerRoot);
  const cliEntry = join(consumer.consumerRoot, "node_modules", "@aihq", "scan", "dist", "cli.js");
  regularBytes(cliEntry, "packaged aih-scan CLI", 1, 16 * 1024 * 1024);
  const catalogTarball = consumer.tarballs.find((entry) => entry.flag === "--catalog-tarball");
  if (catalogTarball === undefined)
    refuse("the installed catalog tarball is missing from the consumer's own record");

  const source = readCatalogSourceClosure(reader, options, runRoot, {
    name: "@aihq/catalog",
    version: catalog.version,
    tarball: catalogTarball,
  });
  const item = source.item;
  const detector = readDetectorInputs(reader, options, runRoot);

  const request = {
    registration: detector.registrationInput,
    detectorId: detector.detectorId,
    layout: detector.layout,
    sourceRoot: item.sourceRoot,
    selectedClosurePaths: item.selectedClosurePaths,
    annexFiles: detector.annexFiles.map((entry) => ({
      descriptorId: entry.descriptorId,
      path: entry.path,
    })),
  };
  const requestPath = join(runRoot, "capture-request.json");
  writeFileSync(requestPath, canonicalBytes(request), { flag: "wx" });
  log(`request         ${requestPath}`);
  return {
    consumerRoot: consumer.consumerRoot,
    tarballs: consumer.tarballs,
    packages: [
      { name: "@aihq/catalog", version: catalog.version },
      { name: "@aihq/scan", version: scan.version },
    ],
    reader,
    cliEntry,
    item,
    sourceClosurePath: source.recordPath,
    detector,
    request,
    requestPath,
  };
}

function writePreflight(runRoot, platform, docker, prepared, skill) {
  const { item } = prepared;
  writeFileSync(
    join(runRoot, "preflight.json"),
    canonicalBytes({
      protocol: "CatalogItemCapturePreflightV1",
      /* Node's vocabulary and OCI's, labelled separately rather than merged. */
      platform,
      docker,
      tarballs: prepared.tarballs,
      packages: prepared.packages,
      detectorId: prepared.detector.detectorId,
      registrationSha256: prepared.detector.registrationRecord.registrationSha256,
      manifestDigestSha256: prepared.detector.layout.manifestDigestSha256,
      configDigestSha256: prepared.detector.layout.configDigestSha256,
      logicalReference: prepared.detector.layout.logicalReference,
      /* The closure this capture was staged from, as the public reader returned it. */
      sourceClosure: {
        record: prepared.sourceClosurePath,
        protocol: SOURCE_CLOSURE_RECORD_PROTOCOL,
        collection: item.closure.collection,
        entryId: item.entry.entryId,
        entrySubject: item.entry.subject,
        source: item.closure.source,
        declaredTreeDigest: item.closure.declaredTreeDigest,
        declaredSkillRoot: item.skillRoot.declaredPath,
        declaredMarker: item.skillRoot.marker,
      },
      sourceRoot: item.sourceRoot,
      selectedClosurePaths: item.selectedClosurePaths,
      coveredPublishedPaths: item.skillRoot.files,
      uncoveredPublishedPaths: item.uncoveredPublishedPaths,
      /* Which staged file the scanner loads as the skill, beside what the mount covers. */
      skill,
    }),
  );
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const platform = assertPlatform();
  const runRoot = createRunDirectory(options.output);
  const prepared = await recordFailure("preparation", runRoot, undefined, () =>
    prepareCapture(options, runRoot),
  );
  const outcome = await runPreparedCapture(options, runRoot, platform, prepared);
  process.stdout.write(`${JSON.stringify(outcome)}\n`);
}

/* Importable for direct preparation checks; the command runs only as the entry point. */
export {
  assertPlatform,
  assertSkillSourceRoot,
  attemptCapture,
  createRunDirectory,
  installEnvironment,
  npmCliPath,
  prepareCapture,
  readCatalogSourceClosure,
  readDetectorInputs,
  runPreparedCapture,
};

const isEntryPoint =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isEntryPoint) {
  try {
    await main();
  } catch (error) {
    process.stderr.write(
      `${error instanceof Refusal ? "refused" : "failed"}: ${reasonOf(error)}\n`,
    );
    process.exitCode = 1;
  }
}
