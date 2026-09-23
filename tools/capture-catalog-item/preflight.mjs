/**
 * Preflight gates for `tools/capture-catalog-item.mjs`: the host platform, the
 * subject (the staged root must itself be a skill root the registered route loads),
 * and the Docker daemon and image the broker will reach. Each gate refuses; none
 * selects, renames or generates anything to pass.
 */
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ADAPTER_CAPABILITY,
  MAX_SOURCE_FILE_BYTES,
  reasonOf,
  refuse,
  regularBytes,
  SKILL_ENTRY,
  sha256Hex,
} from "./common.mjs";
import { log } from "./report.mjs";

/** Bound on the staged-tree walk that reports a nested SKILL.md, never selects one. */
const MAX_STAGED_TREE_DIRECTORIES = 256;
const DOCKER_TIMEOUT_MS = 120_000;
/** The broker spawns bare `docker` with this exact environment, so preflight uses it too. */
const BROKER_PATH = "/usr/bin:/bin";

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
export function assertPlatform(descriptor = { platform: process.platform, arch: process.arch }) {
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
export function assertSkillSourceRoot(item) {
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

export function dockerPreflight(layout) {
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
