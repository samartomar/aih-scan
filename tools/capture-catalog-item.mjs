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
 *   3. read the item's published artifact bytes through `@aihq/catalog`'s public
 *      content reader and re-verify every declared sha256;
 *   4. validate the operator's detector registration, canonical OCI layout, local
 *      image identity, SBOM and provenance through the installed package's public
 *      API, and cross-check them against each other;
 *   5. write the capture request the packaged `aih-scan capture` command requires;
 *   6. run that command and keep its capture bundle and execution log.
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
 * This helper belongs to one Scan commit and is not present at every package
 * checkpoint, so it must be run from the checkout that holds it, and the two
 * package checkpoints must be packed in their own `git archive` trees. Switching
 * a shared checkout to a package commit deletes this file; see the Checkouts
 * block in `--help`.
 *
 * `--prepare-only` proves preparation: that the supplied tarballs install, that
 * the item's published bytes verify, and that the operator's detector inputs
 * agree. It is never evidence that a detector ran. Genuine execution is the
 * capture bundle that only a Linux x64 host with the loaded image can produce;
 * a zero-finding or successfully signed result is not a clean scan by itself.
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
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const DEFAULT_ITEM = "agent.aih.governance-quality";
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
    [--detector-id <detector.*>] [--item <entryId>] [--consumer-root <empty-dir>] [--prepare-only]

  --catalog-tarball  npm pack output of the Catalog commit under test.
  --scan-tarball     npm pack output of the Scan commit under test.
  --output           New or empty run directory. It receives source/, detector/,
                     capture-request.json, catalog-item.json, preflight.json,
                     execution.log and bundle/.
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
  --item             Catalog entry id. Default: ${DEFAULT_ITEM}.
  --consumer-root    Fresh install directory. Default: a new mkdtemp under the system temp root.
  --prepare-only     Validate everything, write the request, and stop before capture.

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
const ITEM_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const ARTIFACT_NAMES = ["closure", "profile", "prose", "recipe"];
const MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json";
const MAX_TARBALL_BYTES = 512 * 1024 * 1024;
const MAX_LAYOUT_BYTES = 4 * 1024 * 1024;
const MAX_REGISTRATION_BYTES = 512 * 1024;
const MAX_INDEX_BYTES = 64 * 1024 * 1024;
const MAX_ANNEX_BYTES = 16 * 1024 * 1024;
const MAX_ITEM_ARTIFACT_BYTES = 1024 * 1024;
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
const READER_MODULE = `import { createRequire } from "node:module";
import { readCatalogContentV1 } from "@aihq/catalog";
import {
  createDetectorRegistrationV1,
  readScanCaptureBundleV2,
} from "@aihq/scan";

const require = createRequire(import.meta.url);
/** Public subpath export; resolves to defaults/catalog-index-v1.json. */
const catalogIndexPath = require.resolve("@aihq/catalog/catalog-index.json");

export {
  catalogIndexPath,
  createDetectorRegistrationV1,
  readCatalogContentV1,
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
  ["--item", "item"],
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
  values.item ??= DEFAULT_ITEM;
  if (!ITEM_ID.test(values.item)) refuse("--item grammar");
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

async function readCatalogItem(reader, catalogRoot, runRoot, itemId) {
  const indexBytes = regularBytes(reader.catalogIndexPath, "catalog index", 1, MAX_INDEX_BYTES);
  const content = reader.readCatalogContentV1({
    bytes: indexBytes,
    input: { root: catalogRoot, verifyArtifacts: true },
  });
  if (content === undefined) refuse("the installed catalog index was refused by the public reader");
  const entry = content.entries.find((candidate) => candidate.entryId === itemId);
  if (entry === undefined) refuse(`the installed catalog publishes no entry ${itemId}`);
  const sourceRoot = join(runRoot, "source");
  const files = [];
  for (const name of ARTIFACT_NAMES) {
    const artifact = entry.artifacts[name];
    if (artifact === undefined) refuse(`catalog item ${itemId} declares no ${name} artifact`);
    if (artifact.state !== "verified")
      refuse(`catalog ${name} artifact is ${artifact.state}, not verified`);
    const recomputed = sha256Hex(artifact.bytes);
    if (recomputed !== artifact.sha256)
      refuse(`catalog ${name} artifact does not match its declared digest`);
    if (artifact.byteLength > MAX_ITEM_ARTIFACT_BYTES)
      refuse(`catalog ${name} artifact exceeds the scan bound`);
    const target = join(sourceRoot, ...artifact.path.split("/"));
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, artifact.bytes, { flag: "wx" });
    files.push({
      name,
      path: artifact.path,
      sha256: artifact.sha256,
      byteLength: artifact.byteLength,
    });
    log(`artifact        ${name} sha256:${artifact.sha256} (${artifact.byteLength} bytes)`);
  }
  if (files.length === 0) refuse(`catalog item ${itemId} publishes no artifacts`);
  const selectedClosurePaths = files.map((file) => file.path).sort();
  log(`source root     ${sourceRoot} (${selectedClosurePaths.length} published files)`);
  writeFileSync(
    join(runRoot, "catalog-item.json"),
    canonicalBytes({
      protocol: "CatalogItemCaptureSubjectV1",
      catalogIndexSha256: content.digest,
      catalogPackage: `${content.package.name}@${content.package.version}`,
      organizationAdmission: content.organizationAdmission,
      entryId: entry.entryId,
      subject: entry.subject,
      artifacts: files,
    }),
  );
  return { sourceRoot, selectedClosurePaths, content, entry, files };
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

function runCapture(reader, runRoot, cliEntry, requestPath) {
  const bundlePath = join(runRoot, "bundle");
  if (existsSync(bundlePath)) refuse(`capture bundle directory already exists: ${bundlePath}`);
  const result = spawnSync(
    process.execPath,
    [cliEntry, "capture", "--request", requestPath, "--output", bundlePath],
    { encoding: "utf8", env: process.env, timeout: CAPTURE_TIMEOUT_MS, maxBuffer: 64 * 1024 * 1024 },
  );
  appendProcessLog("aih-scan capture", result);
  if (result.error !== undefined) refuse(`capture could not run: ${result.error.message}`);
  if (result.status !== 0)
    refuse(
      `capture exited ${result.status}: ` +
        `${(result.stderr ?? "").trim().slice(0, 2000) || "no diagnostic output"}; full output is in execution.log`,
    );
  let bundle;
  try {
    bundle = reader.readScanCaptureBundleV2({ bundleDirectory: bundlePath });
  } catch (error) {
    refuse(`the produced bundle failed its own reader: ${reasonOf(error)}`);
  }
  const manifest = JSON.parse(readFileSync(join(bundlePath, "bundle.json"), "utf8"));
  log(`bundle          ${bundlePath}`);
  log(`candidate       sha256:${manifest.candidate.candidateSha256}`);
  log(
    `annexes         ${bundle.annexArtifacts
      .map((entry) => `${entry.descriptorId}:${entry.sha256}`)
      .join(" ")}`,
  );
  return { bundlePath, candidateSha256: manifest.candidate.candidateSha256 };
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
 * Steps 2 to 5 of the fixed order: the whole platform-independent preparation,
 * exactly as the command runs it. It stops before the host gate's Docker check
 * and before capture, so it is also the surface a test can drive against
 * supplied tarballs without pretending a detector ran.
 */
async function prepareCapture(options, runRoot) {
  const consumer = installConsumer(options);
  const catalog = installedPackage(consumer.consumerRoot, "@aihq/catalog");
  const scan = installedPackage(consumer.consumerRoot, "@aihq/scan");
  const reader = await importReader(consumer.consumerRoot);
  const cliEntry = join(consumer.consumerRoot, "node_modules", "@aihq", "scan", "dist", "cli.js");
  regularBytes(cliEntry, "packaged aih-scan CLI", 1, 16 * 1024 * 1024);

  const item = await readCatalogItem(reader, catalog.root, runRoot, options.item);
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
    detector,
    request,
    requestPath,
  };
}

function writePreflight(runRoot, platform, docker, prepared) {
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
      catalogIndexSha256: prepared.item.content.digest,
      entryId: prepared.item.entry.entryId,
      subjectDigest: prepared.item.entry.subject.subjectDigest,
      artifacts: prepared.item.files,
    }),
  );
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const platform = assertPlatform();
  const runRoot = createRunDirectory(options.output);
  const prepared = await prepareCapture(options, runRoot);
  const docker = dockerPreflight(prepared.detector.layout);
  writePreflight(runRoot, platform, docker, prepared);
  if (options.prepareOnly === true) {
    log("prepare-only    capture not attempted; this is preparation, not detector output");
    process.stdout.write(
      `${JSON.stringify({
        outcome: "prepared",
        requestPath: prepared.requestPath,
        captureCommand: `aih-scan capture --request ${prepared.requestPath} --output ${join(runRoot, "bundle")}`,
      })}\n`,
    );
    return;
  }
  const captured = runCapture(prepared.reader, runRoot, prepared.cliEntry, prepared.requestPath);
  process.stdout.write(
    `${JSON.stringify({
      outcome: "captured",
      bundlePath: captured.bundlePath,
      candidateSha256: captured.candidateSha256,
      executionLog: logPath,
    })}\n`,
  );
}

/* Importable for direct preparation checks; the command runs only as the entry point. */
export {
  assertPlatform,
  createRunDirectory,
  installEnvironment,
  npmCliPath,
  prepareCapture,
  readCatalogItem,
  readDetectorInputs,
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
