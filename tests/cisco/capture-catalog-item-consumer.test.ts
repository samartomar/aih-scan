/**
 * Supplied-tarball consumer proof for `tools/capture-catalog-item.mjs`.
 *
 * Supply the real built packages produced from the two package checkpoint
 * commits — each packed in its own `git archive` build tree, never by switching
 * the checkout that holds this tool — and point this suite at them:
 *
 *   AIH_SCAN_CATALOG_TARBALL=/abs/aihq-catalog-<version>.tgz \
 *   AIH_SCAN_SCAN_TARBALL=/abs/aihq-scan-<version>.tgz \
 *   npx vitest run tests/cisco/capture-catalog-item-consumer.test.ts
 *
 * Without both variables the suite is skipped and preparation stays unverified.
 * A local directory dependency, an `npm link` or a copied reader string proves
 * nothing here: only the packed files are installed, with `--ignore-scripts`,
 * into a consumer outside every Git repository.
 *
 * These tests never run a detector, never read a capture bundle, never produce
 * findings and never claim a capture. The detector identity, layout, image ID
 * and annex bytes are the labelled fixtures from `capture-catalog-fixtures.ts`,
 * because no real operator inputs exist in this repository.
 */
import { createHash } from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type {
  CatalogCaptureOptionsV1,
  CatalogCapturePreparedV1,
} from "../../tools/capture-catalog-item.mjs";
import {
  createRunDirectory,
  prepareCapture,
  readCatalogItem,
} from "../../tools/capture-catalog-item.mjs";
import {
  FIXTURE_ITEM_ID,
  fixtureOptions,
  writeDetectorInputFixtures,
} from "./capture-catalog-fixtures.js";

const suppliedCatalogTarball = process.env.AIH_SCAN_CATALOG_TARBALL;
const suppliedScanTarball = process.env.AIH_SCAN_SCAN_TARBALL;
const supplied = suppliedCatalogTarball !== undefined && suppliedScanTarball !== undefined;

function requireSupplied(value: string | undefined, name: string): string {
  if (value === undefined) throw new Error(`${name} is required by this suite`);
  return value;
}

function insideGitRepository(path: string): boolean {
  for (let current = resolve(path); ; ) {
    if (existsSync(join(current, ".git"))) return true;
    const parent = dirname(current);
    if (parent === current) return false;
    current = parent;
  }
}

function walkFiles(directory: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) found.push(...walkFiles(path));
    else found.push(path);
  }
  return found.sort();
}

const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");

describe.skipIf(!supplied)(
  "supplied-tarball consumer preparation (set AIH_SCAN_CATALOG_TARBALL and AIH_SCAN_SCAN_TARBALL)",
  () => {
    let root = "";
    let prepared: CatalogCapturePreparedV1 | undefined;
    let runRoot = "";

    const preparation = (): CatalogCapturePreparedV1 => {
      if (prepared === undefined) throw new Error("preparation did not run");
      return prepared;
    };
    const catalogRoot = () => join(preparation().consumerRoot, "node_modules", "@aihq", "catalog");

    beforeAll(async () => {
      root = mkdtempSync(join(tmpdir(), "aih-scan-capture-consumer-"));
      const paths = writeDetectorInputFixtures(root);
      const options: CatalogCaptureOptionsV1 = fixtureOptions(root, paths, {
        catalogTarball: requireSupplied(suppliedCatalogTarball, "AIH_SCAN_CATALOG_TARBALL"),
        consumerRoot: join(root, "consumer"),
        output: join(root, "run"),
        scanTarball: requireSupplied(suppliedScanTarball, "AIH_SCAN_SCAN_TARBALL"),
      });
      runRoot = createRunDirectory(options.output);
      try {
        prepared = await prepareCapture(options, runRoot);
      } catch (error) {
        // The run directory is temporary, so surface the tool's own log before it is removed.
        const logFile = join(runRoot, "execution.log");
        if (existsSync(logFile)) console.error(readFileSync(logFile, "utf8").slice(-8000));
        throw error;
      }
    }, 30 * 60_000);

    afterAll(() => {
      if (root !== "") rmSync(root, { force: true, recursive: true });
    });

    it("installs both supplied tarballs with --ignore-scripts into a consumer outside every Git repository", () => {
      const result = preparation();
      expect(insideGitRepository(result.consumerRoot)).toBe(false);
      expect(insideGitRepository(runRoot)).toBe(false);
      expect(existsSync(result.cliEntry)).toBe(true);
      const consumer = JSON.parse(
        readFileSync(join(result.consumerRoot, "package.json"), "utf8"),
      ) as { dependencies?: Record<string, string> };
      for (const name of ["@aihq/catalog", "@aihq/scan"])
        expect(consumer.dependencies?.[name]).toMatch(/\.tgz$/);
    });

    it("records the exact tarball hashes and the installed versions it consumed", () => {
      const result = preparation();
      const expected = new Map([
        ["--catalog-tarball", suppliedCatalogTarball],
        ["--scan-tarball", suppliedScanTarball],
      ]);
      expect(result.tarballs).toHaveLength(2);
      for (const tarball of result.tarballs) {
        const path = requireSupplied(expected.get(tarball.flag), tarball.flag);
        expect(tarball.path).toBe(resolve(path));
        expect(tarball.sha256).toBe(`sha256:${sha256(readFileSync(path))}`);
      }
      expect(result.packages.map((entry) => entry.name).sort()).toEqual([
        "@aihq/catalog",
        "@aihq/scan",
      ]);
      for (const entry of result.packages) {
        expect(entry.version).toMatch(/^\d+\.\d+\.\d+/);
        const metadata = JSON.parse(
          readFileSync(
            join(result.consumerRoot, "node_modules", ...entry.name.split("/"), "package.json"),
            "utf8",
          ),
        ) as { version: string };
        expect(entry.version).toBe(metadata.version);
        console.log(`installed ${entry.name}@${entry.version}`);
      }
      for (const tarball of result.tarballs)
        console.log(`recorded ${tarball.flag} ${tarball.sha256} ${tarball.path}`);
    });

    it("stages every published artifact byte-for-byte under its declared digest", () => {
      const result = preparation();
      const artifacts = result.item.files;
      expect(artifacts.map((artifact) => artifact.name).sort()).toEqual([
        "closure",
        "profile",
        "prose",
        "recipe",
      ]);
      const staged = walkFiles(result.item.sourceRoot);
      expect(staged).toHaveLength(artifacts.length);
      const relative = (path: string) =>
        path
          .slice(result.item.sourceRoot.length + 1)
          .split(sep)
          .join("/");
      expect(staged.map(relative).sort()).toEqual(
        artifacts.map((artifact) => artifact.path).sort(),
      );
      for (const artifact of artifacts) {
        const declared = result.item.entry.artifacts[artifact.name];
        expect(declared?.state).toBe("verified");
        expect(declared?.sha256).toBe(artifact.sha256);
        const bytes = readFileSync(join(result.item.sourceRoot, ...artifact.path.split("/")));
        expect(sha256(bytes)).toBe(artifact.sha256);
        expect(Buffer.compare(bytes, Buffer.from(declared?.bytes ?? Buffer.alloc(0)))).toBe(0);
      }
      expect(result.item.selectedClosurePaths).toEqual(
        artifacts.map((artifact) => artifact.path).sort(),
      );
    });

    it("writes exactly the registered capture request and stops before the Docker gate and capture", () => {
      const result = preparation();
      expect(Object.keys(result.request).sort()).toEqual([
        "annexFiles",
        "detectorId",
        "layout",
        "registration",
        "selectedClosurePaths",
        "sourceRoot",
      ]);
      const onDisk = JSON.parse(readFileSync(result.requestPath, "utf8")) as {
        registration: Record<string, unknown>;
        sourceRoot: string;
      };
      expect(onDisk).toEqual(result.request);
      // The authoring document travels to the CLI; computed wire fields would be rejected there.
      expect(onDisk.registration).not.toHaveProperty("registrationSha256");
      expect(onDisk.sourceRoot).toBe(result.item.sourceRoot);
      expect(existsSync(join(runRoot, "bundle"))).toBe(false);
      expect(existsSync(join(runRoot, "preflight.json"))).toBe(false);
    });

    it("refuses an entry the installed catalog does not publish", async () => {
      const absentRun = createRunDirectory(join(root, "run-absent-entry"));
      await expect(
        readCatalogItem(
          preparation().reader,
          catalogRoot(),
          absentRun,
          "agent.aih.fixture-absent-entry",
        ),
      ).rejects.toThrow(/publishes no entry agent\.aih\.fixture-absent-entry/);
    });

    it("refuses a tampered artifact instead of staging it", async () => {
      const tampered = join(root, "tampered-catalog");
      // The installed catalog package carries every published item, so this copy is large.
      cpSync(catalogRoot(), tampered, { recursive: true });
      const [firstArtifact] = preparation().item.files;
      if (firstArtifact === undefined) throw new Error("the item published no artifact");
      const artifactPath = join(tampered, ...firstArtifact.path.split("/"));
      const bytes = readFileSync(artifactPath);
      bytes[0] = (bytes[0] ?? 0) === 0x7b ? 0x5b : 0x7b;
      writeFileSync(artifactPath, bytes);
      const tamperedRun = createRunDirectory(join(root, "run-tampered-artifact"));
      await expect(
        readCatalogItem(preparation().reader, tampered, tamperedRun, FIXTURE_ITEM_ID),
      ).rejects.toThrow(/artifact is unverified, not verified/);
    }, 120_000);
  },
);
