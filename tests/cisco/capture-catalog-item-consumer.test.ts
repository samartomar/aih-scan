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
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type {
  CatalogCaptureCatalogRefV1,
  CatalogCaptureOptionsV1,
  CatalogCapturePreparedV1,
  CatalogCaptureReaderV1,
} from "../../tools/capture-catalog-item.mjs";
import {
  createRunDirectory,
  prepareCapture,
  readCatalogSourceClosure,
} from "../../tools/capture-catalog-item.mjs";
import { fixtureOptions, writeDetectorInputFixtures } from "./capture-catalog-fixtures.js";

const suppliedCatalogTarball = process.env.AIH_SCAN_CATALOG_TARBALL;
const suppliedScanTarball = process.env.AIH_SCAN_SCAN_TARBALL;
const supplied = suppliedCatalogTarball !== undefined && suppliedScanTarball !== undefined;

/** The declared skill root the governance-quality collection publishes. */
const SKILL_ROOT = "packs/governance-quality/aih-gov-doctor";
/** The entry identity the reader returned before this flow read the closure. */
const PREVIOUS_DEFAULT_ENTRY = "agent.aih.governance-quality";

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

/** The served closure, read again from the installed package for these assertions. */
type ServedClosureV1 = Readonly<{
  entryId: string;
  files: readonly Readonly<{
    path: string;
    sha256: string;
    byteLength: number;
    bytes: Uint8Array;
  }>[];
}>;

describe.skipIf(!supplied)(
  "supplied-tarball consumer preparation (set AIH_SCAN_CATALOG_TARBALL and AIH_SCAN_SCAN_TARBALL)",
  () => {
    let root = "";
    let options: CatalogCaptureOptionsV1;
    let prepared: CatalogCapturePreparedV1 | undefined;
    let runRoot = "";
    let served: ServedClosureV1 | undefined;

    const preparation = (): CatalogCapturePreparedV1 => {
      if (prepared === undefined) throw new Error("preparation did not run");
      return prepared;
    };
    const servedClosure = (): ServedClosureV1 => {
      if (served === undefined) throw new Error("the reader did not answer");
      return served;
    };
    const catalogRef = (): CatalogCaptureCatalogRefV1 => {
      const result = preparation();
      const tarball = result.tarballs.find((entry) => entry.flag === "--catalog-tarball");
      const version = result.packages.find((entry) => entry.name === "@aihq/catalog")?.version;
      if (tarball === undefined || version === undefined)
        throw new Error("the installed catalog tarball is missing from the record");
      return { name: "@aihq/catalog", tarball, version };
    };
    const stagedRoot = (): string => join(runRoot, "source");
    const relativeToStaged = (path: string): string =>
      relative(stagedRoot(), path).split(sep).join("/");

    beforeAll(async () => {
      root = mkdtempSync(join(tmpdir(), "aih-scan-capture-consumer-"));
      const paths = writeDetectorInputFixtures(root);
      options = fixtureOptions(root, paths, {
        catalogTarball: requireSupplied(suppliedCatalogTarball, "AIH_SCAN_CATALOG_TARBALL"),
        consumerRoot: join(root, "consumer"),
        output: join(root, "run"),
        scanTarball: requireSupplied(suppliedScanTarball, "AIH_SCAN_SCAN_TARBALL"),
      });
      runRoot = createRunDirectory(options.output);
      try {
        prepared = await prepareCapture(options, runRoot);
        const answer = prepared.reader.readCatalogSourceClosureV1({
          collectionId: options.collectionId,
          subjectId: options.subjectId,
        });
        if (answer.state !== "verified") throw new Error(`the reader answered ${answer.state}`);
        served = { entryId: answer.closure.entry.entryId, files: answer.closure.files };
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

    it("stages the whole served closure under its published paths, byte for byte", () => {
      const result = preparation();
      const closure = servedClosure();
      const published = closure.files.map((file) => file.path).sort();

      /* Every served file is staged under its own published path, byte for byte. */
      const staged = walkFiles(stagedRoot()).map(relativeToStaged);
      expect(staged).toEqual(published);
      expect(result.item.stagedFiles.map((file) => file.publishedPath).sort()).toEqual(published);
      for (const file of result.item.stagedFiles) {
        const bytes = readFileSync(file.stagedPath);
        const servedFile = closure.files.find((entry) => entry.path === file.publishedPath);
        expect(servedFile).toBeDefined();
        expect(sha256(bytes)).toBe(file.sha256);
        expect(sha256(bytes)).toBe(servedFile?.sha256);
        expect(Buffer.compare(bytes, Buffer.from(servedFile?.bytes ?? Buffer.alloc(0)))).toBe(0);
        console.log(`staged ${file.publishedPath} sha256:${file.sha256}`);
      }
    });

    it("selects the declared skill root, and takes the entry identity from the reader", () => {
      const result = preparation();
      const closure = servedClosure();

      expect(result.item.skillRoot.declaredPath).toBe(SKILL_ROOT);
      expect(result.item.sourceRoot).toBe(join(stagedRoot(), ...SKILL_ROOT.split("/")));
      expect(result.item.selectedClosurePaths).toEqual(["LICENSE", "SKILL.md", "profile.json"]);
      expect(result.item.entry.entryId).toBe(closure.entryId);
      /* The entry that names the skill's own source, not the assessment entry. */
      expect(result.item.entry.entryId).not.toBe(PREVIOUS_DEFAULT_ENTRY);
      console.log(`entry ${result.item.entry.entryId}`);

      /* The mounted root holds exactly the selected files, and nothing else. */
      expect(
        walkFiles(result.item.sourceRoot).map((path) =>
          relative(result.item.sourceRoot, path).split(sep).join("/"),
        ),
      ).toEqual(["LICENSE", "SKILL.md", "profile.json"]);
      expect(readFileSync(join(result.item.sourceRoot, "SKILL.md")).length).toBe(
        result.item.files.find((file) => file.path === "SKILL.md")?.byteLength,
      );
    });

    it("records the file the mounted root cannot cover instead of implying coverage", () => {
      const result = preparation();
      expect(result.item.uncoveredPublishedPaths.map((file) => file.publishedPath)).toEqual([
        "aih-packs.json",
      ]);
      /* It is staged, outside the root the capture mounts. */
      expect(existsSync(join(stagedRoot(), "aih-packs.json"))).toBe(true);
      expect(existsSync(join(result.item.sourceRoot, "aih-packs.json"))).toBe(false);

      const record = JSON.parse(readFileSync(result.sourceClosurePath, "utf8")) as {
        authority: string;
        closure: {
          declaredTreeDigest: { reproduced: boolean; value: string };
          files: readonly { path: string }[];
        };
        coverage: {
          selectedPaths: readonly string[];
          uncoveredPublishedPaths: readonly { publishedPath: string }[];
        };
      };
      expect(record.authority).toBe("diagnostic-record-not-evidence");
      expect(record.closure.files.map((file) => file.path).sort()).toEqual(
        servedClosure()
          .files.map((file) => file.path)
          .sort(),
      );
      expect(record.coverage.selectedPaths).toEqual(["LICENSE", "SKILL.md", "profile.json"]);
      expect(record.coverage.uncoveredPublishedPaths.map((file) => file.publishedPath)).toEqual([
        "aih-packs.json",
      ]);
      /* Catalog's own tree digest is recorded as declared, never as reproduced here. */
      expect(record.closure.declaredTreeDigest.reproduced).toBe(false);
      console.log(`closure tree digest declared ${record.closure.declaredTreeDigest.value}`);
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
        selectedClosurePaths: readonly string[];
      };
      expect(onDisk).toEqual(result.request);
      // The authoring document travels to the CLI; computed wire fields would be rejected there.
      expect(onDisk.registration).not.toHaveProperty("registrationSha256");
      expect(onDisk.sourceRoot).toBe(result.item.sourceRoot);
      expect(onDisk.selectedClosurePaths).toEqual(["LICENSE", "SKILL.md", "profile.json"]);
      expect(existsSync(join(runRoot, "bundle"))).toBe(false);
      expect(existsSync(join(runRoot, "preflight.json"))).toBe(false);
    });

    it("refuses a subject the installed catalog does not serve, and stages nothing", async () => {
      const absentRun = createRunDirectory(join(root, "run-absent-subject"));
      let reason = "";
      try {
        readCatalogSourceClosure(
          preparation().reader,
          { ...options, subjectId: "fixture-absent-subject" },
          absentRun,
          catalogRef(),
        );
      } catch (error) {
        reason = error instanceof Error ? error.message : String(error);
      }
      expect(reason).toMatch(
        /serves no verified source closure for aih-core\/fixture-absent-subject/,
      );
      expect(existsSync(join(absentRun, "source"))).toBe(false);
      expect(existsSync(join(absentRun, "source-closure.json"))).toBe(false);
    });

    it("refuses source bytes the reader serves that no longer match their declared digest", () => {
      const real = preparation().reader;
      const tampering = {
        ...real,
        readCatalogSourceClosureV1: (request: { collectionId: string; subjectId: string }) => {
          const answer = real.readCatalogSourceClosureV1(request);
          if (answer.state !== "verified") return answer;
          return {
            state: "verified",
            closure: {
              ...answer.closure,
              files: answer.closure.files.map((file) => {
                if (!file.path.endsWith("SKILL.md")) return file;
                const bytes = Buffer.from(file.bytes);
                bytes[0] = (bytes[0] ?? 0) === 0x2d ? 0x23 : 0x2d;
                return { ...file, bytes: new Uint8Array(bytes) };
              }),
            },
          };
        },
      } as unknown as CatalogCaptureReaderV1;
      const tamperedRun = createRunDirectory(join(root, "run-tampered-source"));
      expect(() => readCatalogSourceClosure(tampering, options, tamperedRun, catalogRef())).toThrow(
        /served .*SKILL\.md with bytes that do not match its declared digest/,
      );
      expect(existsSync(join(tamperedRun, "source"))).toBe(false);
    }, 120_000);
  },
);
