/**
 * The source-closure path of `tools/capture-catalog-item.mjs`.
 *
 * These run the production helper against labelled stub packages whose Catalog
 * answers a fixture source closure. No detector runs, no bundle exists and nothing
 * here is a finding: the subject is that the helper stages what the closure reader
 * served, selects the skill root the closure *declares*, and refuses everything
 * else — before any container or capture process could exist.
 *
 * The fixture closure is the real governance-quality shape: four published files,
 * one declared `skill` material root holding three of them.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type {
  CatalogCaptureCatalogRefV1,
  CatalogCaptureOptionsV1,
  CatalogCapturePreparedV1,
  CatalogCaptureReaderV1,
} from "../../tools/capture-catalog-item.mjs";
import {
  assertPlatform,
  assertSkillSourceRoot,
  attemptCapture,
  createRunDirectory,
  prepareCapture,
  readCatalogSourceClosure,
  runPreparedCapture,
} from "../../tools/capture-catalog-item.mjs";
import {
  FIXTURE_COLLECTION_ID,
  FIXTURE_ENTRY_ID,
  FIXTURE_SUBJECT_ID,
  fixtureOptions,
  writeDetectorInputFixtures,
} from "./capture-catalog-fixtures.js";
import {
  FIXTURE_CATALOG_CONTENT_ENV,
  FIXTURE_CLI_LOUD_ENV,
  FIXTURE_CLI_MARKER_ENV,
  FIXTURE_CLOSURE_CALL_ENV,
  type FixtureClosureFileV1,
  type FixtureClosureV1,
  fixtureSha256,
  packStubPackages,
  type StubPackagesV1,
  writeFixtureClosure,
} from "./capture-catalog-stub-packages.js";

/** The declared skill root of the governance-quality closure, exactly as published. */
const SKILL_ROOT = "packs/governance-quality/aih-gov-doctor";
const SKILL_BYTES =
  "---\nname: fixture-governance-quality\n---\n\n# fixture skill\n\nFixture bytes for preparation checks only; no detector reads this file.\n";
const LICENSE_BYTES = "Fixture licence bytes for preparation checks only.\n";
const PROFILE_BYTES = '{"protocol":"fixture-skill-profile"}\n';
const PACKS_BYTES = '{"protocol":"fixture-aih-packs"}\n';

const PLATFORM = assertPlatform({ arch: "x64", platform: "linux" });

/** The four published files of the governance-quality closure, in Catalog's shape. */
const governanceFiles = (): readonly FixtureClosureFileV1[] => [
  { content: PACKS_BYTES, path: "aih-packs.json" },
  { content: LICENSE_BYTES, path: `${SKILL_ROOT}/LICENSE` },
  { content: SKILL_BYTES, path: `${SKILL_ROOT}/SKILL.md` },
  { content: PROFILE_BYTES, path: `${SKILL_ROOT}/profile.json` },
];

/** The same closure with the declared skill root that the real collection declares. */
const governanceClosure = (): FixtureClosureV1 => ({
  files: governanceFiles(),
  skillRootPath: SKILL_ROOT,
});

const publishedPaths = (files: readonly FixtureClosureFileV1[]): readonly string[] =>
  files.map((file) => file.path);

type ClosureCaseV1 = Readonly<{
  caseRoot: string;
  /** Where the stub Catalog appends each `readCatalogSourceClosureV1` call. */
  calls: string;
  /** Where the stub capture CLI appends its argv if it is ever spawned. */
  marker: string;
  options: CatalogCaptureOptionsV1;
  runRoot: string;
  restore: () => void;
}>;

let stubPackages: StubPackagesV1;
const temporaryRoots: string[] = [];

beforeAll(() => {
  const workRoot = mkdtempSync(join(tmpdir(), "aih-scan-closure-packages-"));
  temporaryRoots.push(workRoot);
  stubPackages = packStubPackages(workRoot);
}, 5 * 60_000);

afterAll(() => {
  while (temporaryRoots.length > 0) {
    const root = temporaryRoots.pop();
    if (root !== undefined) rmSync(root, { force: true, recursive: true });
  }
});

/** One fixture case: its own tree, its own stub-package install and its own run root. */
function closureCase(
  fixture: FixtureClosureV1,
  overrides: Partial<CatalogCaptureOptionsV1> = {},
): ClosureCaseV1 {
  const caseRoot = mkdtempSync(join(tmpdir(), "aih-scan-closure-"));
  temporaryRoots.push(caseRoot);
  const paths = writeDetectorInputFixtures(caseRoot);
  const descriptor = writeFixtureClosure(caseRoot, fixture);
  const calls = join(caseRoot, "closure-calls.jsonl");
  const marker = join(caseRoot, "capture-cli-argv.txt");
  const saved = new Map<string, string | undefined>();
  for (const [name, value] of [
    [FIXTURE_CATALOG_CONTENT_ENV, descriptor],
    [FIXTURE_CLOSURE_CALL_ENV, calls],
    [FIXTURE_CLI_MARKER_ENV, marker],
  ] as const) {
    saved.set(name, process.env[name]);
    process.env[name] = value;
  }
  const options = fixtureOptions(caseRoot, paths, {
    catalogTarball: stubPackages.catalogTarball,
    scanTarball: stubPackages.scanTarball,
    ...overrides,
  });
  return {
    calls,
    caseRoot,
    marker,
    options,
    restore: () => {
      for (const [name, value] of saved) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    },
    runRoot: createRunDirectory(options.output),
  };
}

/** Prepares one case and always restores the fixture environment the case set. */
async function prepare(caseV1: ClosureCaseV1): Promise<CatalogCapturePreparedV1> {
  try {
    return await prepareCapture(caseV1.options, caseV1.runRoot);
  } finally {
    caseV1.restore();
  }
}

/** The refusal message a fixture must produce; a fixture that is accepted fails here. */
async function refusalReason(caseV1: ClosureCaseV1): Promise<string> {
  try {
    await prepare(caseV1);
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  throw new Error(`this fixture must be refused, but preparation accepted it`);
}

/** The stage of one published path inside the run's staged closure. */
const stagedPath = (caseV1: ClosureCaseV1, publishedPath: string): string =>
  join(caseV1.runRoot, "source", ...publishedPath.split("/"));

/** The refused message of one step that must refuse, so a run cannot pass silently. */
async function refusalOfStep(step: () => Promise<unknown>): Promise<string> {
  try {
    await step();
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  throw new Error("this step must refuse, but it completed");
}

/** Runs a step with extra environment, restoring exactly what was set. */
function withEnvironment<T>(values: Readonly<Record<string, string>>, step: () => T): T {
  const saved = new Map<string, string | undefined>();
  for (const [name, value] of Object.entries(values)) {
    saved.set(name, process.env[name]);
    process.env[name] = value;
  }
  try {
    return step();
  } finally {
    for (const [name, value] of saved) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

const readJson = (path: string): Record<string, unknown> =>
  JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;

describe("published source closure staging", () => {
  it("stages every published file and selects the skill root the closure declares", async () => {
    const caseV1 = closureCase(governanceClosure());
    const prepared = await prepare(caseV1);
    const { item } = prepared;

    /* Selection comes from the declaration, not from a search of the staged tree. */
    expect(item.skillRoot.declaredPath).toBe(SKILL_ROOT);
    expect(item.skillRoot.marker).toBe("SKILL.md");
    expect(item.skillRoot.excludes).toEqual(["aih-packs.json"]);
    expect(item.sourceRoot).toBe(stagedPath(caseV1, SKILL_ROOT));
    expect(item.selectedClosurePaths).toEqual(["LICENSE", "SKILL.md", "profile.json"]);

    /* All four published files are staged, each under its own published path. */
    for (const file of governanceFiles())
      expect(readFileSync(stagedPath(caseV1, file.path), "utf8")).toBe(file.content);
    expect(item.stagedFiles.map((file) => file.publishedPath)).toEqual(
      publishedPaths(governanceFiles()),
    );

    /* The request binds that root and exactly those relative paths. */
    expect(prepared.request.sourceRoot).toBe(item.sourceRoot);
    expect(prepared.request.selectedClosurePaths).toEqual(["LICENSE", "SKILL.md", "profile.json"]);
    expect(prepared.request.detectorId).toBe("detector.fixture.organization");

    /* And the declared root is a skill root for the registered route. */
    expect(assertSkillSourceRoot(item)).toEqual({
      byteLength: Buffer.byteLength(SKILL_BYTES),
      path: "SKILL.md",
      publishedPath: `${SKILL_ROOT}/SKILL.md`,
      sha256: fixtureSha256(Buffer.from(SKILL_BYTES)),
    });
  });

  it("asks the catalog for the collection and subject, and takes the entry identity from it", async () => {
    const caseV1 = closureCase(governanceClosure());
    const prepared = await prepare(caseV1);
    expect(readFileSync(caseV1.calls, "utf8").trim().split("\n")).toEqual([
      JSON.stringify({ collectionId: FIXTURE_COLLECTION_ID, subjectId: FIXTURE_SUBJECT_ID }),
    ]);
    expect(prepared.item.entry.entryId).toBe(FIXTURE_ENTRY_ID);
    expect(prepared.item.entry.subject).toMatchObject({ id: "governance-quality", kind: "agent" });

    /* A different subject is asked for by name, and its own entry comes back. */
    const other = closureCase(
      {
        entryId: "agent.aih.review-quality.core-0-6-2",
        files: governanceFiles(),
        skillRootPath: SKILL_ROOT,
      },
      { subjectId: "review-quality" },
    );
    const preparedOther = await prepare(other);
    expect(readFileSync(other.calls, "utf8").trim()).toBe(
      JSON.stringify({ collectionId: FIXTURE_COLLECTION_ID, subjectId: "review-quality" }),
    );
    expect(preparedOther.item.entry.entryId).toBe("agent.aih.review-quality.core-0-6-2");
  });

  it("selects the declared root, never a nested SKILL.md that merely looks like one", async () => {
    const caseV1 = closureCase({
      files: [
        { content: PACKS_BYTES, path: "aih-packs.json" },
        { content: LICENSE_BYTES, path: "packs/a/LICENSE" },
        { content: "declared skill\n", path: "packs/a/SKILL.md" },
        { content: "decoy skill\n", path: "packs/b/SKILL.md" },
      ],
      skillRootPath: "packs/a",
    });
    const prepared = await prepare(caseV1);

    expect(prepared.item.sourceRoot).toBe(stagedPath(caseV1, "packs/a"));
    expect(prepared.item.selectedClosurePaths).toEqual(["LICENSE", "SKILL.md"]);
    expect(readFileSync(join(prepared.item.sourceRoot, "SKILL.md"), "utf8")).toBe(
      "declared skill\n",
    );
    expect(assertSkillSourceRoot(prepared.item).publishedPath).toBe("packs/a/SKILL.md");

    /* The decoy is staged as published and recorded as uncovered, never selected. */
    expect(readFileSync(stagedPath(caseV1, "packs/b/SKILL.md"), "utf8")).toBe("decoy skill\n");
    expect(prepared.item.uncoveredPublishedPaths.map((file) => file.publishedPath)).toEqual([
      "aih-packs.json",
      "packs/b/SKILL.md",
    ]);
  });

  it("refuses a closure that declares no skill material root, and discovers none", async () => {
    const caseV1 = closureCase({ files: governanceFiles() });
    const reason = await refusalReason(caseV1);

    expect(reason).toContain("declares no 'skill' material root");
    expect(reason).toContain("declared kinds: closure");
    expect(reason).toContain("never discovers one in the staged tree");
    /* A nested SKILL.md exists in this fixture, and nothing was staged from it. */
    expect(existsSync(join(caseV1.runRoot, "source"))).toBe(false);
  });

  it("refuses an ambiguous closure that declares more than one skill material root", async () => {
    const files: readonly FixtureClosureFileV1[] = [
      { content: PACKS_BYTES, path: "aih-packs.json" },
      { content: "a\n", path: "packs/a/SKILL.md" },
      { content: "b\n", path: "packs/b/SKILL.md" },
    ];
    const caseV1 = closureCase({
      files,
      materialRoots: [
        { excludes: [], files: publishedPaths(files), kind: "closure", path: "." },
        {
          excludes: [],
          files: ["packs/a/SKILL.md"],
          kind: "skill",
          marker: "SKILL.md",
          path: "packs/a",
        },
        {
          excludes: [],
          files: ["packs/b/SKILL.md"],
          kind: "skill",
          marker: "SKILL.md",
          path: "packs/b",
        },
      ],
    });
    const reason = await refusalReason(caseV1);

    expect(reason).toContain("declares 2 'skill' material roots");
    expect(reason).toContain('("packs/a", "packs/b")');
    expect(reason).toContain("ambiguous, so none is selected and none is guessed");
    expect(existsSync(join(caseV1.runRoot, "source"))).toBe(false);
  });

  it("refuses served bytes that do not match the digest published for them", async () => {
    const files = governanceFiles().map((file) =>
      file.path === `${SKILL_ROOT}/SKILL.md` ? { ...file, declareSha256: "f".repeat(64) } : file,
    );
    const caseV1 = closureCase({ files, skillRootPath: SKILL_ROOT });
    const reason = await refusalReason(caseV1);

    expect(reason).toContain(
      `served ${SKILL_ROOT}/SKILL.md with bytes that do not match its declared digest`,
    );
    expect(reason).toContain(
      `sha256:${fixtureSha256(Buffer.from(SKILL_BYTES))} != sha256:${"f".repeat(64)}`,
    );
    expect(existsSync(join(caseV1.runRoot, "source"))).toBe(false);
  });

  it("refuses a served length that contradicts what the closure declares", async () => {
    const files = governanceFiles().map((file) =>
      file.path === `${SKILL_ROOT}/SKILL.md` ? { ...file, declareByteLength: 4096 } : file,
    );
    const caseV1 = closureCase({ files, skillRootPath: SKILL_ROOT });
    const reason = await refusalReason(caseV1);

    expect(reason).toContain(`declares 4096 bytes but serves ${Buffer.byteLength(SKILL_BYTES)}`);
    expect(existsSync(join(caseV1.runRoot, "source"))).toBe(false);
  });

  it("refuses every path that does not stay inside the closure it was published in", async () => {
    const shapes: readonly Readonly<{
      expected: readonly string[];
      fixture: FixtureClosureV1;
      name: string;
    }>[] = [
      {
        expected: [
          "a source closure file path must not contain empty, '.' or '..' segments: ../outside/SKILL.md",
        ],
        fixture: { files: [{ content: SKILL_BYTES, path: "../outside/SKILL.md" }] },
        name: "a published path with a `..` segment",
      },
      {
        expected: [
          "a source closure file path must be relative to the closure root: /absolute/SKILL.md",
        ],
        fixture: { files: [{ content: SKILL_BYTES, path: "/absolute/SKILL.md" }] },
        name: "an absolute published path",
      },
      {
        expected: ["a source closure file path must use POSIX separators: packs\\a\\SKILL.md"],
        fixture: { files: [{ content: SKILL_BYTES, path: "packs\\a\\SKILL.md" }] },
        name: "a published path in the host's separator",
      },
      {
        expected: [
          "the declared skill material root path must not contain empty, '.' or '..' segments: ../outside",
        ],
        fixture: {
          files: governanceFiles(),
          materialRoots: [
            { excludes: [], files: publishedPaths(governanceFiles()), kind: "closure", path: "." },
            {
              excludes: [],
              files: [`${SKILL_ROOT}/SKILL.md`],
              kind: "skill",
              marker: "SKILL.md",
              path: "../outside",
            },
          ],
        },
        name: "a declared skill root that escapes the closure",
      },
      {
        expected: ["names packs/b/SKILL.md, which lies outside it"],
        fixture: {
          files: [
            { content: "a\n", path: "packs/a/SKILL.md" },
            { content: "b\n", path: "packs/b/SKILL.md" },
          ],
          materialRoots: [
            {
              excludes: [],
              files: ["packs/a/SKILL.md", "packs/b/SKILL.md"],
              kind: "closure",
              path: ".",
            },
            {
              excludes: [],
              files: ["packs/a/SKILL.md", "packs/b/SKILL.md"],
              kind: "skill",
              marker: "SKILL.md",
              path: "packs/a",
            },
          ],
        },
        name: "a declared skill root that names a file outside itself",
      },
    ];

    for (const shape of shapes) {
      const caseV1 = closureCase(shape.fixture);
      const reason = await refusalReason(caseV1);
      for (const expected of shape.expected) expect(`${shape.name}: ${reason}`).toContain(expected);
      /* Nothing was staged, and nothing was staged outside the run either. */
      expect(`${shape.name}: ${existsSync(join(caseV1.runRoot, "source"))}`).toBe(
        `${shape.name}: false`,
      );
      expect(`${shape.name}: ${existsSync(join(caseV1.runRoot, "outside"))}`).toBe(
        `${shape.name}: false`,
      );
    }
  });

  it("refuses a declared exclusion that lies inside the declared skill root", async () => {
    const files = governanceFiles();
    const caseV1 = closureCase({
      files,
      materialRoots: [
        { excludes: [], files: publishedPaths(files), kind: "closure", path: "." },
        {
          excludes: [`${SKILL_ROOT}/LICENSE`],
          files: [`${SKILL_ROOT}/LICENSE`, `${SKILL_ROOT}/SKILL.md`, `${SKILL_ROOT}/profile.json`],
          kind: "skill",
          marker: "SKILL.md",
          path: SKILL_ROOT,
        },
      ],
    });
    const reason = await refusalReason(caseV1);

    expect(reason).toContain(`excludes ${SKILL_ROOT}/LICENSE, which lies inside that root`);
    expect(reason).toContain("the declared exclusion is false");
    expect(existsSync(join(caseV1.runRoot, "source"))).toBe(false);
  });

  it("refuses a subject the catalog itself refuses, and stages nothing", async () => {
    const caseV1 = closureCase(
      { files: governanceFiles(), reason: "member-unknown", state: "refused" },
      { subjectId: "no-such-subject" },
    );
    const reason = await refusalReason(caseV1);

    expect(reason).toContain(
      'serves no verified source closure for aih-core/no-such-subject: state "refused", reason member-unknown',
    );
    expect(reason).toContain("never substitutes the item's assessment artifacts for its source");
    expect(existsSync(join(caseV1.runRoot, "source"))).toBe(false);
    expect(readFileSync(caseV1.calls, "utf8")).toContain('"subjectId":"no-such-subject"');
  });

  it("refuses a catalog that publishes no source-closure reader, or whose reader throws", () => {
    const caseV1 = closureCase(governanceClosure());
    const catalog: CatalogCaptureCatalogRefV1 = {
      name: "@aihq/catalog",
      tarball: {
        flag: "--catalog-tarball",
        path: caseV1.options.catalogTarball,
        sha256: `sha256:${"0".repeat(64)}`,
      },
      version: "0.0.0-fixture",
    };
    try {
      const silent = {} as CatalogCaptureReaderV1;
      expect(() =>
        readCatalogSourceClosure(silent, caseV1.options, caseV1.runRoot, catalog),
      ).toThrow(/does not expose readCatalogSourceClosureV1/);
      const throwing = {
        readCatalogSourceClosureV1: () => {
          throw new Error("fixture reader failure");
        },
      } as unknown as CatalogCaptureReaderV1;
      expect(() =>
        readCatalogSourceClosure(throwing, caseV1.options, caseV1.runRoot, catalog),
      ).toThrow(/refused aih-core\/governance-quality: fixture reader failure/);
      expect(existsSync(join(caseV1.runRoot, "source"))).toBe(false);
    } finally {
      caseV1.restore();
    }
  });

  it("records the closure, the selected root and the coverage in a diagnostic record", async () => {
    const caseV1 = closureCase(governanceClosure());
    const prepared = await prepare(caseV1);
    expect(prepared.sourceClosurePath).toBe(join(caseV1.runRoot, "source-closure.json"));
    const record = readJson(prepared.sourceClosurePath);
    const closure = record.closure as Record<string, unknown>;
    const coverage = record.coverage as Record<string, unknown>;

    /* The record is the helper's diagnostic, and says so. */
    expect(record.protocol).toBe("CatalogSourceClosureCaptureRecordV1");
    expect(record.authority).toBe("diagnostic-record-not-evidence");
    expect(String(record.statement)).toContain("not signed evidence");

    /* The complete closure, before any selection. */
    expect(record.selection).toEqual({
      collectionId: FIXTURE_COLLECTION_ID,
      subjectId: FIXTURE_SUBJECT_ID,
    });
    expect(closure.format).toBe("aih-catalog-source-closure");
    expect(closure.version).toBe(1);
    expect((closure.entry as Record<string, unknown>).entryId).toBe(FIXTURE_ENTRY_ID);
    expect((closure.files as readonly Record<string, unknown>[]).map((file) => file.path)).toEqual(
      publishedPaths(governanceFiles()),
    );
    expect((closure.materialRoots as readonly unknown[]).length).toBe(2);
    /* Catalog's own tree digest is recorded as declared, never as reproduced here. */
    expect(closure.declaredTreeDigest).toEqual({
      note: expect.any(String),
      reproduced: false,
      value: `sha256:${"a".repeat(64)}`,
    });

    /* The selected root, the path mapping and what the mount cannot cover. */
    expect(record.selectedSkillRoot).toMatchObject({
      declaredExcludes: ["aih-packs.json"],
      declaredPath: SKILL_ROOT,
      declaredFiles: [
        `${SKILL_ROOT}/LICENSE`,
        `${SKILL_ROOT}/SKILL.md`,
        `${SKILL_ROOT}/profile.json`,
      ],
      marker: "SKILL.md",
      selectedPaths: ["LICENSE", "SKILL.md", "profile.json"],
      stagedPath: prepared.item.sourceRoot,
    });
    expect(record.pathMapping).toEqual(
      governanceFiles().map((file) => ({
        publishedPath: file.path,
        selectedPath:
          file.path === "aih-packs.json" ? null : file.path.slice(SKILL_ROOT.length + 1),
        stagedPath: stagedPath(caseV1, file.path),
      })),
    );
    expect(coverage.mountedRoot).toBe(prepared.item.sourceRoot);
    expect(coverage.coveredPublishedPaths).toEqual([
      `${SKILL_ROOT}/LICENSE`,
      `${SKILL_ROOT}/SKILL.md`,
      `${SKILL_ROOT}/profile.json`,
    ]);
    expect(coverage.uncoveredPublishedPaths).toEqual([
      {
        declaredExcluded: true,
        publishedPath: "aih-packs.json",
        reason: `outside the mounted skill root ${SKILL_ROOT}, so this capture does not cover it`,
        stagedPath: stagedPath(caseV1, "aih-packs.json"),
      },
    ]);
    expect(String(coverage.statement)).toContain("does not cover the rest of the closure");
    expect(String((record.sealScope as Record<string, unknown>).statement)).toContain(
      "describes this scan of this root only",
    );

    /* The excluded file is staged, and staged outside the root the capture mounts. */
    expect(existsSync(stagedPath(caseV1, "aih-packs.json"))).toBe(true);
    expect(existsSync(join(prepared.item.sourceRoot, "aih-packs.json"))).toBe(false);
  });
});

describe("capture subject gate", () => {
  it("refuses a declared root whose marker is not at its top level, before any capture", async () => {
    const files: readonly FixtureClosureFileV1[] = [
      { content: PACKS_BYTES, path: "aih-packs.json" },
      { content: LICENSE_BYTES, path: `${SKILL_ROOT}/LICENSE` },
      { content: SKILL_BYTES, path: `${SKILL_ROOT}/docs/SKILL.md` },
    ];
    const caseV1 = closureCase({
      files,
      materialRoots: [
        { excludes: [], files: publishedPaths(files), kind: "closure", path: "." },
        {
          excludes: ["aih-packs.json"],
          files: [`${SKILL_ROOT}/LICENSE`, `${SKILL_ROOT}/docs/SKILL.md`],
          kind: "skill",
          marker: "docs/SKILL.md",
          path: SKILL_ROOT,
        },
      ],
    });
    const prepared = await prepare(caseV1);
    expect(prepared.item.selectedClosurePaths).toEqual(["LICENSE", "docs/SKILL.md"]);

    const reason = await refusalOfStep(() =>
      runPreparedCapture(caseV1.options, caseV1.runRoot, PLATFORM, prepared),
    );
    expect(reason).toContain("is not a skill source for cisco-oci-v1");
    expect(reason).toContain("holds no staged SKILL.md at its top level");
    expect(reason).toContain("1 nested SKILL.md path(s) exist under this root (docs/SKILL.md)");
    expect(reason).toContain("none is selected");

    /* The refusal is recorded as a subject failure with no capture process behind it. */
    const failure = readJson(join(caseV1.runRoot, "capture-failure.json"));
    expect(failure.phase).toBe("subject");
    expect(failure.findingsProduced).toBe(false);
    expect(failure.findingsProducedBasis).toBe("no-capture-process-existed");
    expect(failure.captureCommand).toBe(null);
    expect(failure.bundlePresent).toBe(false);
    expect(failure.sourceRoot).toBe(prepared.item.sourceRoot);
    expect(failure.coveredFilePaths).toEqual(["LICENSE", "docs/SKILL.md"]);
    expect(failure.sourceClosureRecord).toBe(prepared.sourceClosurePath);
    expect(existsSync(caseV1.marker)).toBe(false);
  });

  it("refuses a staged marker that changed after preparation", async () => {
    const caseV1 = closureCase(governanceClosure());
    const prepared = await prepare(caseV1);
    writeFileSync(join(prepared.item.sourceRoot, "SKILL.md"), "mutated after preparation\n");

    const reason = await refusalOfStep(() =>
      runPreparedCapture(caseV1.options, caseV1.runRoot, PLATFORM, prepared),
    );
    expect(reason).toContain("no longer matches its published digest");
    expect(readJson(join(caseV1.runRoot, "capture-failure.json")).phase).toBe("subject");
    expect(existsSync(caseV1.marker)).toBe(false);
  });
});

describe("capture failure records", () => {
  it("records unknown findings, not none, when a capture process ran and failed", async () => {
    const caseV1 = closureCase(governanceClosure());
    const prepared = await prepare(caseV1);
    const attempt = withEnvironment({ [FIXTURE_CLI_MARKER_ENV]: caseV1.marker }, () =>
      attemptCapture(prepared, caseV1.runRoot),
    );
    if (attempt.outcome !== "failed") throw new Error("the stub capture CLI must fail");
    expect(attempt.reason).toContain("capture exited 9");
    expect(attempt.captureProcessExisted).toBe(true);

    const failure = readJson(join(caseV1.runRoot, "capture-failure.json"));
    expect(failure.phase).toBe("capture");
    expect(failure.exitCode).toBe(9);
    expect(failure.captureProcessExisted).toBe(true);
    /* The command ran, so whether it produced findings is not this helper's to claim. */
    expect(failure.findingsProduced).toBe(null);
    expect(failure.findingsProducedBasis).toBe("capture-output-not-inspected");
    expect(failure.bundleVerified).toBe(false);
    expect(failure.bundlePresent).toBe(false);
    expect(String(failure.stderr)).toContain("stub capture CLI");
    expect(failure.sourceRoot).toBe(prepared.item.sourceRoot);
    expect(failure.coveredFilePaths).toEqual(["LICENSE", "SKILL.md", "profile.json"]);
    expect(failure.sourceClosureRecord).toBe(prepared.sourceClosurePath);
    expect(failure.captureRequestPath).toBe(prepared.requestPath);

    /* The capture command really was spawned, and really was given this request. */
    expect(readFileSync(caseV1.marker, "utf8")).toContain(prepared.requestPath);
    expect(failure.captureCommand).toEqual([
      process.execPath,
      prepared.cliEntry,
      "capture",
      "--request",
      prepared.requestPath,
      "--output",
      join(caseV1.runRoot, "bundle"),
    ]);
  });

  it("keeps the whole stream in execution.log while the record carries a bounded excerpt", async () => {
    const caseV1 = closureCase(governanceClosure());
    const prepared = await prepare(caseV1);
    const attempt = withEnvironment(
      { [FIXTURE_CLI_LOUD_ENV]: "20000", [FIXTURE_CLI_MARKER_ENV]: caseV1.marker },
      () => attemptCapture(prepared, caseV1.runRoot),
    );
    if (attempt.outcome !== "failed") throw new Error("the stub capture CLI must fail");

    const failure = readJson(join(caseV1.runRoot, "capture-failure.json"));
    expect(failure.stderrTruncated).toBe(true);
    expect(failure.stderrCharacters as number).toBeGreaterThan(64 * 1024);
    expect(Buffer.byteLength(String(failure.stderr), "utf8")).toBeLessThanOrEqual(64 * 1024);
    expect(readFileSync(join(caseV1.runRoot, "execution.log"), "utf8")).toContain(
      "fixture-noise-19999",
    );
  });
});
