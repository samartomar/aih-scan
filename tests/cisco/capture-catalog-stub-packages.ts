/**
 * Labelled stub packages for `tools/capture-catalog-item.mjs`.
 *
 * Nothing here proves anything about the published `@aihq/catalog` or `@aihq/scan`.
 * These are stubs, so the helper's own preparation, source selection and subject
 * gate can be driven on any host, including one that is not Linux and has no Docker:
 *
 * - the stub Catalog answers `readCatalogSourceClosureV1` from a fixture descriptor
 *   the caller writes, so the closure it "serves" is the caller's fixture closure,
 *   and it records the arguments it was called with;
 * - the stub Scan exports only the names the helper imports, and its CLI entry point
 *   records that it was spawned and then exits nonzero, so a suite can assert that
 *   no capture subprocess exists at all;
 * - no detector runs, no capture bundle exists and no finding is produced.
 *
 * The stub Catalog's `state` is `"verified"` and its digests are computed over the
 * fixture bytes: that is the point of these fixtures, since a source that is not the
 * declared skill root must be refused even when every served digest verifies.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { installEnvironment, npmCliPath } from "../../tools/capture-catalog-item.mjs";

/** The stub Catalog reads the fixture descriptor from this variable. */
export const FIXTURE_CATALOG_CONTENT_ENV = "AIH_SCAN_FIXTURE_CATALOG_CONTENT";
/** The stub Catalog appends each reader call here, so a suite can read the request. */
export const FIXTURE_CLOSURE_CALL_ENV = "AIH_SCAN_FIXTURE_CLOSURE_CALL";
/** The stub CLI appends its argv here when it is spawned; a suite asserts it stays absent. */
export const FIXTURE_CLI_MARKER_ENV = "AIH_SCAN_FIXTURE_CLI_MARKER";
/** When set to a line count, the stub CLI writes that many stderr lines before refusing. */
export const FIXTURE_CLI_LOUD_ENV = "AIH_SCAN_FIXTURE_CLI_LOUD";

export type FixtureClosureFileV1 = Readonly<{
  /** The path the fixture closure publishes this file at, relative to its root. */
  path: string;
  content: string;
  /** Declared instead of the true digest, so a case can serve bytes that do not verify. */
  declareSha256?: string;
  /** Declared instead of the true length, so a case can serve a wrong length. */
  declareByteLength?: number;
}>;

export type FixtureClosureV1 = Readonly<{
  /** Omitted means served; any other value is returned verbatim with its reason. */
  state?: string;
  reason?: string;
  entryId?: string;
  /** Recorded verbatim, so a test can prove the kind label decides nothing. */
  subject?: Readonly<Record<string, unknown>>;
  /** Declared material roots, passed through verbatim. */
  materialRoots?: readonly Readonly<Record<string, unknown>>[];
  /** Used only when `materialRoots` is omitted: one declared skill root here. */
  skillRootPath?: string;
  skillMarker?: string;
  declaredTreeDigest?: string;
  files: readonly FixtureClosureFileV1[];
}>;

export type StubPackagesV1 = Readonly<{ catalogTarball: string; scanTarball: string }>;

const CATALOG_STUB = `import { createHash } from "node:crypto";
import { appendFileSync, readFileSync } from "node:fs";

/** Stub catalog: it serves exactly the fixture closure its descriptor names. */
export const readCatalogSourceClosureV1 = (request) => {
  const calls = process.env["${FIXTURE_CLOSURE_CALL_ENV}"];
  if (typeof calls === "string" && calls !== "")
    appendFileSync(calls, JSON.stringify(request) + "\\n");
  const descriptorPath = process.env["${FIXTURE_CATALOG_CONTENT_ENV}"];
  if (typeof descriptorPath !== "string" || descriptorPath === "")
    throw new Error("stub catalog: ${FIXTURE_CATALOG_CONTENT_ENV} is not set");
  const descriptor = JSON.parse(readFileSync(descriptorPath, "utf8"));
  if (descriptor.state !== "verified")
    return {
      state: descriptor.state,
      ...(descriptor.reason === undefined ? {} : { reason: descriptor.reason }),
    };
  const files = Object.entries(descriptor.fileSources).map(([path, source]) => {
    const bytes = readFileSync(source.source);
    return {
      path,
      sha256: source.declareSha256 ?? createHash("sha256").update(bytes).digest("hex"),
      byteLength: source.declareByteLength ?? bytes.length,
      /* A plain Uint8Array, as the real reader serves: never a Buffer. */
      bytes: new Uint8Array(bytes),
    };
  });
  return { state: "verified", closure: { ...descriptor.closure, files } };
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
    exports: { ".": "./index.mjs" },
  });
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

/** A path the fixture may declare but never write through, so hostile shapes stay data. */
function isUnsafePath(path: string): boolean {
  return (
    path.startsWith("/") ||
    path.includes("\\") ||
    path.split("/").some((segment) => segment === "" || segment === "." || segment === "..")
  );
}

/**
 * Writes one fixture closure's bytes and the descriptor the stub Catalog answers
 * from. Published paths are preserved exactly as given, including a path a case
 * declares deliberately to prove it is refused: bytes for such a path are written
 * under a neutral name, because the fixture must not follow a hostile path itself.
 */
export function writeFixtureClosure(caseRoot: string, fixture: FixtureClosureV1): string {
  const published = join(caseRoot, "fixture-published");
  const fileSources: Record<
    string,
    { source: string; declareSha256?: string; declareByteLength?: number }
  > = {};
  fixture.files.forEach((file, index) => {
    if (fileSources[file.path] !== undefined)
      throw new Error(`fixture publishes ${file.path} twice`);
    const target = isUnsafePath(file.path)
      ? join(published, `declared-unsafe-${index}`)
      : join(published, ...file.path.split("/"));
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, file.content);
    const source: { source: string; declareSha256?: string; declareByteLength?: number } = {
      source: target,
    };
    if (file.declareSha256 !== undefined) source.declareSha256 = file.declareSha256;
    if (file.declareByteLength !== undefined) source.declareByteLength = file.declareByteLength;
    fileSources[file.path] = source;
  });
  const paths = fixture.files.map((file) => file.path);
  const materialRoots =
    fixture.materialRoots ??
    (() => {
      const declared: Record<string, unknown>[] = [
        { kind: "closure", path: ".", files: paths, excludes: [] },
      ];
      const skillRootPath = fixture.skillRootPath;
      if (skillRootPath !== undefined) {
        const prefix = `${skillRootPath}/`;
        declared.push({
          kind: "skill",
          path: skillRootPath,
          marker: fixture.skillMarker ?? "SKILL.md",
          files: paths.filter((path) => path.startsWith(prefix)),
          excludes: paths.filter((path) => !path.startsWith(prefix)),
        });
      }
      return declared;
    })();
  const descriptor = join(caseRoot, "fixture-source-closure.json");
  writeJson(descriptor, {
    protocol: "FixtureCatalogSourceClosureV1",
    state: fixture.state ?? "verified",
    ...(fixture.reason === undefined ? {} : { reason: fixture.reason }),
    closure: {
      format: "aih-catalog-source-closure",
      version: 1,
      collection: { id: "aih-core", release: "0.6.2-fixture" },
      entry: {
        entryId: fixture.entryId ?? "agent.aih.governance-quality.core-0-6-2",
        subject: fixture.subject ?? {
          id: "governance-quality",
          kind: "agent",
          sourceDigest: `sha256:${"0".repeat(64)}`,
          subjectDigest: `sha256:${"1".repeat(64)}`,
        },
      },
      asset: {
        assetId: "aih/package:skill-pack/governance-quality",
        sourceRevisionId: "package:@aihq/core@0.6.2",
      },
      assessment: {
        profile: {
          path: "defaults/workbench/aih-core-0.6.2/agent.aih.governance-quality.core-0-6-2/artifacts/profile.json",
          sha256: "2".repeat(64),
        },
      },
      source: {
        host: "github.com",
        repository: "samartomar/ai-harness",
        revision: "5".repeat(40),
      },
      root: `defaults/sources/github.com/samartomar/ai-harness/${"5".repeat(40)}`,
      materialRoots,
      declaredTreeDigest: fixture.declaredTreeDigest ?? `sha256:${"a".repeat(64)}`,
    },
    fileSources,
  });
  return descriptor;
}

/** The digest the stub Catalog will report for fixture bytes. */
export const fixtureSha256 = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");
