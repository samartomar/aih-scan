/**
 * Labelled stub packages for `tools/capture-catalog-item.mjs`.
 *
 * Nothing here proves anything about the published `@aihq/catalog` or `@aihq/scan`.
 * These are stubs, so the helper's own preparation and subject gate can be driven
 * on any host, including one that is not Linux and has no Docker:
 *
 * - the stub Catalog answers `readCatalogContentV1` from a fixture descriptor the
 *   caller writes, so the bytes it "publishes" are the caller's fixture bytes;
 * - the stub Scan exports only the two names the helper imports, and its CLI entry
 *   point records that it was spawned and then exits nonzero, so a suite can assert
 *   that no capture subprocess exists at all;
 * - no detector runs, no capture bundle exists and no finding is produced.
 *
 * The stub Catalog's artifact `state` is always `"verified"` and its digests are
 * computed over the fixture bytes: that is the point of these fixtures, since an
 * unsuitable source must be refused even when every published digest verifies.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { installEnvironment, npmCliPath } from "../../tools/capture-catalog-item.mjs";

/** The stub Catalog reads the fixture descriptor from this variable. */
export const FIXTURE_CATALOG_CONTENT_ENV = "AIH_SCAN_FIXTURE_CATALOG_CONTENT";
/** The stub CLI appends its argv here when it is spawned; a suite asserts it stays absent. */
export const FIXTURE_CLI_MARKER_ENV = "AIH_SCAN_FIXTURE_CLI_MARKER";
/** When set to a line count, the stub CLI writes that many stderr lines before refusing. */
export const FIXTURE_CLI_LOUD_ENV = "AIH_SCAN_FIXTURE_CLI_LOUD";

/** The four artifact slots the current public Catalog reader exposes. */
export const FIXTURE_ARTIFACT_SLOTS = ["closure", "profile", "prose", "recipe"] as const;
export type FixtureArtifactSlotV1 = (typeof FIXTURE_ARTIFACT_SLOTS)[number];

export type FixtureSourceFileV1 = Readonly<{
  artifact: FixtureArtifactSlotV1;
  /** The relative path the stub Catalog publishes this slot under. */
  path: string;
  content: string;
}>;

export type FixtureCatalogV1 = Readonly<{
  entryId: string;
  /** Recorded verbatim, so a test can prove the kind label decides nothing. */
  subject: Readonly<Record<string, unknown>>;
  files: readonly FixtureSourceFileV1[];
}>;

export type StubPackagesV1 = Readonly<{ catalogTarball: string; scanTarball: string }>;

const CATALOG_STUB = `import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

/** Stub catalog: it publishes exactly the fixture bytes its descriptor names. */
export const readCatalogContentV1 = () => {
  const descriptorPath = process.env["${FIXTURE_CATALOG_CONTENT_ENV}"];
  if (typeof descriptorPath !== "string" || descriptorPath === "")
    throw new Error("stub catalog: ${FIXTURE_CATALOG_CONTENT_ENV} is not set");
  const descriptor = JSON.parse(readFileSync(descriptorPath, "utf8"));
  const artifacts = {};
  for (const [slot, source] of Object.entries(descriptor.artifactSources)) {
    const bytes = readFileSync(source.source);
    artifacts[slot] = {
      state: "verified",
      path: source.path,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      byteLength: bytes.length,
      bytes,
    };
  }
  return {
    digest: descriptor.indexIdentity,
    package: { name: "@aihq/catalog", version: "0.0.0-fixture" },
    organizationAdmission: "fixture-organization-admission",
    entries: [{ entryId: descriptor.entryId, subject: descriptor.subject, artifacts }],
  };
};
`;

const SCAN_STUB = `import { createHash } from "node:crypto";

/** Stub scanner: it validates no registration and produces no bundle. */
export const createDetectorRegistrationV1 = (value) => {
  if (typeof value !== "object" || value === null || !Array.isArray(value.registrations))
    throw new Error("stub scanner: registration input");
  return {
    registrations: value.registrations,
    registrationSha256: createHash("sha256").update(JSON.stringify(value)).digest("hex"),
  };
};

export const readScanCaptureBundleV2 = () => {
  throw new Error("stub scanner: no capture bundle exists in this fixture");
};
`;

const SCAN_CLI_STUB = `import { appendFileSync } from "node:fs";

/** Stub capture CLI: it records that it was spawned, then refuses. */
const marker = process.env["${FIXTURE_CLI_MARKER_ENV}"];
if (typeof marker === "string" && marker !== "")
  appendFileSync(marker, process.argv.slice(2).join(" ") + "\\n");
const loud = Number.parseInt(process.env["${FIXTURE_CLI_LOUD_ENV}"] ?? "0", 10);
let noise = "";
if (Number.isFinite(loud) && loud > 0)
  for (let index = 0; index < loud; index += 1) noise += "fixture-noise-" + index + "\\n";
process.stderr.write(noise + "stub capture CLI: no detector and no bundle exist in this fixture\\n");
process.exitCode = 9;
`;

function runNpm(args: readonly string[], cwd: string): void {
  const result = spawnSync(process.execPath, [npmCliPath(), ...args], {
    cwd,
    encoding: "utf8",
    env: installEnvironment(),
    timeout: 5 * 60_000,
  });
  if (result.error !== undefined)
    throw new Error(`fixture npm ${args[0]} could not run: ${result.error.message}`);
  if (result.status !== 0)
    throw new Error(
      `fixture npm ${args[0]} exited ${result.status}: ${(result.stderr ?? "").slice(-2000)}`,
    );
}

function writeJson(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

/** Packs the two stub packages once; every case then installs them like real tarballs. */
export function packStubPackages(workRoot: string): StubPackagesV1 {
  const packed = join(workRoot, "stub-tarballs");
  const catalogRoot = join(workRoot, "stub-src", "catalog");
  const scanRoot = join(workRoot, "stub-src", "scan");
  mkdirSync(packed, { recursive: true });
  writeJson(join(catalogRoot, "package.json"), {
    name: "@aihq/catalog",
    version: "0.0.0-fixture",
    type: "module",
    exports: { ".": "./index.mjs", "./catalog-index.json": "./catalog-index.json" },
  });
  writeFileSync(
    join(catalogRoot, "catalog-index.json"),
    `${JSON.stringify({ protocol: "FixtureCatalogIndexV1" })}\n`,
  );
  writeFileSync(join(catalogRoot, "index.mjs"), CATALOG_STUB);
  writeJson(join(scanRoot, "package.json"), {
    name: "@aihq/scan",
    version: "0.0.0-fixture",
    type: "module",
    exports: { ".": "./index.mjs" },
  });
  writeFileSync(join(scanRoot, "index.mjs"), SCAN_STUB);
  mkdirSync(join(scanRoot, "dist"), { recursive: true });
  writeFileSync(join(scanRoot, "dist", "cli.js"), SCAN_CLI_STUB);
  runNpm(["pack", "--pack-destination", packed, "--loglevel", "error"], catalogRoot);
  runNpm(["pack", "--pack-destination", packed, "--loglevel", "error"], scanRoot);
  const tarballs = readdirSync(packed).filter((name) => name.endsWith(".tgz"));
  const only = (prefix: string): string => {
    const matches = tarballs.filter((name) => name.startsWith(prefix));
    if (matches.length !== 1)
      throw new Error(`fixture npm pack produced ${matches.length} ${prefix} tarballs`);
    const [match] = matches;
    if (match === undefined) throw new Error(`fixture npm pack produced no ${prefix} tarball`);
    return join(packed, match);
  };
  return { catalogTarball: only("aihq-catalog-"), scanTarball: only("aihq-scan-") };
}

/**
 * Writes one fixture item's published bytes and the descriptor the stub Catalog
 * answers from. Paths are preserved exactly as given: a fixture that publishes a
 * nested skill keeps it nested.
 */
export function writeFixtureCatalog(caseRoot: string, fixture: FixtureCatalogV1): string {
  const published = join(caseRoot, "fixture-published");
  const artifactSources: Record<string, { path: string; source: string }> = {};
  for (const file of fixture.files) {
    if (file.path.startsWith("/") || file.path.split("/").includes(".."))
      throw new Error(`fixture path must stay inside the item: ${file.path}`);
    if (artifactSources[file.artifact] !== undefined)
      throw new Error(`fixture declares the ${file.artifact} slot twice`);
    const target = join(published, ...file.path.split("/"));
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, file.content);
    artifactSources[file.artifact] = { path: file.path, source: target };
  }
  const descriptor = join(caseRoot, "fixture-catalog-content.json");
  writeJson(descriptor, {
    protocol: "FixtureCatalogContentV1",
    entryId: fixture.entryId,
    subject: fixture.subject,
    indexIdentity: "fixture-catalog-index-v1",
    artifactSources,
  });
  return descriptor;
}

/** The digest the stub Catalog will report for fixture bytes. */
export const fixtureSha256 = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");
