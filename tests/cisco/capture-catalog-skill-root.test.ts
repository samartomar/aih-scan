/**
 * The helper's subject gate for the `cisco-oci-v1` route: a staged source root the
 * scanner cannot load as a skill is refused before the Docker gate, before
 * `--prepare-only` can report success and before any capture subprocess exists.
 *
 * These tests prove preparation only, never a scan. The installed packages are the
 * labelled stubs from `capture-catalog-stub-packages.ts`; the stub CLI records its
 * own spawn and exits nonzero, so "no detector ran" is asserted rather than
 * claimed. No capture bundle, no SARIF document and no finding exists in this
 * suite. The platform descriptor below is the one the broker needs, and the
 * refusal cases never reach the host gate — which is exactly why their failure
 * message is not a Docker one.
 */
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type {
  CatalogCaptureItemV1,
  CatalogCaptureOptionsV1,
  CatalogCapturePreparedV1,
} from "../../tools/capture-catalog-item.mjs";
import {
  assertPlatform,
  assertSkillSourceRoot,
  attemptCapture,
  createRunDirectory,
  prepareCapture,
  runPreparedCapture,
} from "../../tools/capture-catalog-item.mjs";
import {
  FIXTURE_ITEM_ID,
  fixtureOptions,
  writeDetectorInputFixtures,
} from "./capture-catalog-fixtures.js";
import type { FixtureCatalogV1, StubPackagesV1 } from "./capture-catalog-stub-packages.js";
import {
  FIXTURE_CATALOG_CONTENT_ENV,
  FIXTURE_CLI_LOUD_ENV,
  FIXTURE_CLI_MARKER_ENV,
  packStubPackages,
  writeFixtureCatalog,
} from "./capture-catalog-stub-packages.js";

const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");

/** Obvious fixture bytes: never the Catalog item's own SKILL.md and never generated. */
const SKILL_FIXTURE_BYTES =
  "---\nname: fixture-governance-quality\n---\n\n# fixture skill\n\n" +
  "Fixture bytes for preparation checks only; no detector reads this file.\n";

type CaseV1 = Readonly<{
  options: CatalogCaptureOptionsV1;
  prepared: CatalogCapturePreparedV1;
  runRoot: string;
  marker: string;
}>;

/** The four published assessment artifacts, in the shape the real item publishes. */
const assessmentOnlyFixture = (): FixtureCatalogV1 => ({
  entryId: FIXTURE_ITEM_ID,
  subject: { kind: "skill", subjectDigest: `sha256:${"3".repeat(64)}` },
  files: [
    { artifact: "closure", content: '{"protocol":"fixture-closure"}\n', path: "closure.json" },
    { artifact: "profile", content: '{"protocol":"fixture-profile"}\n', path: "profile.json" },
    { artifact: "prose", content: "# fixture prose\n", path: "prose.md" },
    { artifact: "recipe", content: '{"protocol":"fixture-recipe"}\n', path: "recipe.json" },
  ],
});

/** Published material that holds no SKILL.md anywhere. */
const noSkillAnywhereFixture = (): FixtureCatalogV1 => ({
  entryId: FIXTURE_ITEM_ID,
  subject: { kind: "agent", subjectDigest: `sha256:${"4".repeat(64)}` },
  files: [
    { artifact: "closure", content: '{"protocol":"fixture-aih-packs"}\n', path: "aih-packs.json" },
    { artifact: "profile", content: '{"protocol":"fixture-profile"}\n', path: "profile.json" },
    { artifact: "prose", content: "# fixture docs\n", path: "docs/README.md" },
    { artifact: "recipe", content: "# fixture notes\n", path: "docs/notes.md" },
  ],
});

/** A root that really is the skill root: its own top level holds SKILL.md. */
const skillRootFixture = (): FixtureCatalogV1 => ({
  entryId: FIXTURE_ITEM_ID,
  // The label says "agent" while the material is a skill pack: the material decides.
  subject: { kind: "agent", subjectDigest: `sha256:${"5".repeat(64)}` },
  files: [
    { artifact: "prose", content: SKILL_FIXTURE_BYTES, path: "SKILL.md" },
    { artifact: "closure", content: '{"protocol":"fixture-aih-packs"}\n', path: "aih-packs.json" },
    { artifact: "profile", content: '{"protocol":"fixture-profile"}\n', path: "profile.json" },
    { artifact: "recipe", content: "fixture license\n", path: "LICENSE" },
  ],
});

/** The complete four-file closure whose skill is nested, as the source handoff describes. */
const nestedSkillFixture = (): FixtureCatalogV1 => ({
  entryId: FIXTURE_ITEM_ID,
  subject: { kind: "agent", subjectDigest: `sha256:${"6".repeat(64)}` },
  files: [
    { artifact: "closure", content: '{"protocol":"fixture-aih-packs"}\n', path: "aih-packs.json" },
    {
      artifact: "prose",
      content: SKILL_FIXTURE_BYTES,
      path: "packs/governance-quality/aih-gov-doctor/SKILL.md",
    },
    {
      artifact: "profile",
      content: '{"protocol":"fixture-profile"}\n',
      path: "packs/governance-quality/aih-gov-doctor/profile.json",
    },
    {
      artifact: "recipe",
      content: "fixture license\n",
      path: "packs/governance-quality/aih-gov-doctor/LICENSE",
    },
  ],
});

async function refusalOf(step: () => Promise<unknown>): Promise<string> {
  try {
    await step();
  } catch (error) {
    if (error instanceof Error) return error.message;
    throw error;
  }
  throw new Error("expected a refusal, but the step completed");
}

describe("catalog capture subject gate (stub packages, preparation only)", () => {
  let workspace = "";
  let stubs: StubPackagesV1;
  const platform = assertPlatform({ arch: "x64", platform: "linux" });

  beforeAll(() => {
    workspace = mkdtempSync(join(tmpdir(), "aih-scan-skill-root-"));
    stubs = packStubPackages(workspace);
  }, 300_000);

  afterAll(() => {
    if (workspace !== "") rmSync(workspace, { force: true, recursive: true });
  });

  /** Prepares one fixture item through the production path, with the stub tarballs. */
  async function prepareCase(
    name: string,
    fixture: FixtureCatalogV1,
    environment: Readonly<Record<string, string>> = {},
  ): Promise<CaseV1> {
    const caseRoot = join(workspace, name);
    mkdirSync(caseRoot, { recursive: true });
    process.env[FIXTURE_CATALOG_CONTENT_ENV] = writeFixtureCatalog(caseRoot, fixture);
    const marker = join(caseRoot, "capture-cli-spawned.log");
    process.env[FIXTURE_CLI_MARKER_ENV] = marker;
    delete process.env[FIXTURE_CLI_LOUD_ENV];
    for (const [key, value] of Object.entries(environment)) process.env[key] = value;
    const paths = writeDetectorInputFixtures(caseRoot);
    const options = fixtureOptions(caseRoot, paths, {
      catalogTarball: stubs.catalogTarball,
      scanTarball: stubs.scanTarball,
    });
    const runRoot = createRunDirectory(options.output);
    const prepared = await prepareCapture(options, runRoot);
    return { marker, options, prepared, runRoot };
  }

  function failureRecord(runRoot: string): Record<string, unknown> {
    return JSON.parse(readFileSync(join(runRoot, "capture-failure.json"), "utf8")) as Record<
      string,
      unknown
    >;
  }

  it("refuses an assessment-only item whose every published digest verifies", async () => {
    const prepared = await prepareCase("assessment-only", assessmentOnlyFixture());
    const staged = (path: string) => join(prepared.runRoot, "source", path);

    // Preparation verified and staged all four published artifacts, byte for byte.
    expect(prepared.prepared.item.files.map((file) => file.path).sort()).toEqual([
      "closure.json",
      "profile.json",
      "prose.md",
      "recipe.json",
    ]);
    for (const file of prepared.prepared.item.files) {
      const bytes = readFileSync(join(prepared.runRoot, "source", file.path));
      expect(sha256(bytes)).toBe(file.sha256);
    }

    const message = await refusalOf(() =>
      runPreparedCapture(prepared.options, prepared.runRoot, platform, prepared.prepared),
    );
    expect(message).toMatch(/is not a skill source for cisco-oci-v1/);
    expect(message).toMatch(/no staged SKILL\.md at its top level/);
    expect(message).toContain(prepared.prepared.item.sourceRoot);
    // Verified digests prove these are the published bytes, not that they are a skill.
    expect(message).toMatch(/a verified digest proves these are the published bytes/);

    // Nothing ran and nothing was renamed: the refusal is the whole outcome.
    expect(existsSync(join(prepared.runRoot, "bundle"))).toBe(false);
    expect(existsSync(join(prepared.runRoot, "preflight.json"))).toBe(false);
    expect(existsSync(prepared.marker)).toBe(false);
    expect(existsSync(staged("SKILL.md"))).toBe(false);
    expect(readFileSync(staged("prose.md"), "utf8")).toBe("# fixture prose\n");

    // The input record and the failure record stay in the run directory.
    expect(existsSync(join(prepared.runRoot, "capture-request.json"))).toBe(true);
    expect(existsSync(join(prepared.runRoot, "catalog-item.json"))).toBe(true);
    const record = failureRecord(prepared.runRoot);
    expect(record.protocol).toBe("CatalogItemCaptureFailureV1");
    expect(record.phase).toBe("subject");
    expect(record.reason).toBe(message);
    expect(record.exitCode).toBeNull();
    expect(record.stdout).toBeNull();
    expect(record.stderr).toBeNull();
    expect(record.spawnError).toBeNull();
    expect(record.captureCommand).toBeNull();
    expect(record.bundlePresent).toBe(false);
    expect(record.bundleVerified).toBe(false);
    expect(record.findingsProduced).toBe(false);
    expect(record.sourceRoot).toBe(prepared.prepared.item.sourceRoot);
    expect(record.coveredFilePaths).toEqual(prepared.prepared.item.selectedClosurePaths);
    expect(readFileSync(join(prepared.runRoot, "execution.log"), "utf8")).toMatch(
      /subject failure: catalog item .* is not a skill source/,
    );
  }, 300_000);

  it("refuses published material that holds no SKILL.md anywhere", async () => {
    const prepared = await prepareCase("no-skill", noSkillAnywhereFixture());
    const message = await refusalOf(() =>
      runPreparedCapture(prepared.options, prepared.runRoot, platform, prepared.prepared),
    );
    expect(message).toMatch(/no staged SKILL\.md at its top level/);
    expect(message).toContain("docs/README.md");
    // Nothing nested to report, and the message does not pretend otherwise.
    expect(message).not.toMatch(/nested SKILL\.md path/);
    expect(existsSync(prepared.marker)).toBe(false);
    expect(failureRecord(prepared.runRoot).phase).toBe("subject");
  }, 300_000);

  it("prepares a root that is the skill root, and leaves the bytes it published untouched", async () => {
    const prepared = await prepareCase("skill-root", skillRootFixture());
    const stagedSkill = join(prepared.runRoot, "source", "SKILL.md");

    // Preparation succeeded and staged the item's own SKILL.md, not generated bytes.
    expect(prepared.prepared.item.selectedClosurePaths).toEqual([
      "LICENSE",
      "SKILL.md",
      "aih-packs.json",
      "profile.json",
    ]);
    expect(readFileSync(stagedSkill, "utf8")).toBe(SKILL_FIXTURE_BYTES);
    const request = JSON.parse(
      readFileSync(join(prepared.runRoot, "capture-request.json"), "utf8"),
    ) as Record<string, unknown>;
    expect(request.sourceRoot).toBe(prepared.prepared.item.sourceRoot);
    expect(request.selectedClosurePaths).toEqual(prepared.prepared.item.selectedClosurePaths);

    // The subject gate accepts this root and names the artifact it will load.
    expect(assertSkillSourceRoot(prepared.prepared.item)).toEqual({
      artifact: "prose",
      byteLength: Buffer.byteLength(SKILL_FIXTURE_BYTES, "utf8"),
      path: "SKILL.md",
      sha256: sha256(Buffer.from(SKILL_FIXTURE_BYTES, "utf8")),
    });

    // Preparation is where this suite stops: no bundle, no preflight record, no capture.
    expect(existsSync(join(prepared.runRoot, "bundle"))).toBe(false);
    expect(existsSync(join(prepared.runRoot, "preflight.json"))).toBe(false);
    expect(existsSync(join(prepared.runRoot, "capture-failure.json"))).toBe(false);
    expect(existsSync(prepared.marker)).toBe(false);
  }, 300_000);

  it("refuses a closure whose skill is nested, and never selects that nested directory", async () => {
    const prepared = await prepareCase("nested-skill", nestedSkillFixture());
    const nested = "packs/governance-quality/aih-gov-doctor/SKILL.md";
    const message = await refusalOf(() =>
      runPreparedCapture(prepared.options, prepared.runRoot, platform, prepared.prepared),
    );

    expect(message).toMatch(/is not a skill source for cisco-oci-v1/);
    expect(message).toContain(nested);
    expect(message).toMatch(/none is selected/);
    expect(message).toMatch(/not the rest of the staged closure/);
    expect(message).toContain(prepared.prepared.item.sourceRoot);

    // The nested skill stayed where it was published; no root was invented for it.
    expect(readFileSync(join(prepared.runRoot, "source", ...nested.split("/")), "utf8")).toBe(
      SKILL_FIXTURE_BYTES,
    );
    expect(existsSync(join(prepared.runRoot, "source", "SKILL.md"))).toBe(false);
    expect(existsSync(prepared.marker)).toBe(false);
    expect(failureRecord(prepared.runRoot).phase).toBe("subject");
  }, 300_000);

  it("records a failed capture with the exit status and the streams it produced", async () => {
    const prepared = await prepareCase("failed-capture", skillRootFixture());
    // The subject gate accepts this root, so this is the attempt a passing host gate would run.
    expect(assertSkillSourceRoot(prepared.prepared.item).path).toBe("SKILL.md");

    const attempt = attemptCapture(prepared.prepared, prepared.runRoot);
    if (attempt.outcome === "captured") throw new Error("the stub capture cannot produce a bundle");
    expect(attempt.exitCode).toBe(9);
    expect(attempt.reason).toMatch(/^capture exited 9: stub capture CLI/);
    // The packaged CLI entry point really was spawned; the record describes a real command.
    expect(existsSync(prepared.marker)).toBe(true);

    const record = failureRecord(prepared.runRoot);
    expect(record.protocol).toBe("CatalogItemCaptureFailureV1");
    expect(record.outcome).toBe("failed");
    expect(record.phase).toBe("capture");
    expect(record.reason).toBe(attempt.reason);
    expect(record.reason).toMatch(/full output is in execution\.log$/);
    expect(record.captureCommand).toEqual([
      process.execPath,
      prepared.prepared.cliEntry,
      "capture",
      "--request",
      prepared.prepared.requestPath,
      "--output",
      join(prepared.runRoot, "bundle"),
    ]);
    expect(record.exitCode).toBe(9);
    expect(record.signal).toBeNull();
    expect(record.spawnError).toBeNull();
    expect(record.stdout).toBe("");
    expect(record.stderr).toMatch(/stub capture CLI/);
    expect(record.stderrTruncated).toBe(false);
    expect(record.bundleDirectory).toBe(join(prepared.runRoot, "bundle"));
    expect(record.bundlePresent).toBe(false);
    expect(record.bundleVerified).toBe(false);
    expect(record.findingsProduced).toBe(false);
    expect(record.sourceRoot).toBe(prepared.prepared.item.sourceRoot);
    expect(record.coveredFilePaths).toEqual(prepared.prepared.item.selectedClosurePaths);
    expect(record.captureRequestPath).toBe(prepared.prepared.requestPath);
    expect(record.executionLog).toBe(join(prepared.runRoot, "execution.log"));
    expect(readFileSync(join(prepared.runRoot, "execution.log"), "utf8")).toMatch(
      /capture failure: capture exited 9/,
    );
  }, 300_000);

  it("keeps a bounded stream excerpt in the record and the complete stream in execution.log", async () => {
    const prepared = await prepareCase("loud-capture", skillRootFixture(), {
      [FIXTURE_CLI_LOUD_ENV]: "20000",
    });
    const attempt = attemptCapture(prepared.prepared, prepared.runRoot);
    if (attempt.outcome === "captured") throw new Error("the stub capture cannot produce a bundle");

    const record = failureRecord(prepared.runRoot);
    const excerpt = String(record.stderr);
    expect(Number(record.stderrCharacters)).toBeGreaterThan(64 * 1024);
    expect(record.stderrTruncated).toBe(true);
    expect(excerpt.length).toBe(64 * 1024);
    expect(
      excerpt.endsWith("stub capture CLI: no detector and no bundle exist in this fixture\n"),
    ).toBe(true);

    // The record is bounded; the run directory still holds every byte the command wrote.
    const executionLog = readFileSync(join(prepared.runRoot, "execution.log"), "utf8");
    expect(executionLog).toContain("fixture-noise-0\n");
    expect(executionLog).toContain("fixture-noise-19999\n");
  }, 300_000);

  it("refuses a SKILL.md at the root that is not one of the item's staged artifacts", () => {
    const caseRoot = mkdtempSync(join(tmpdir(), "aih-scan-skill-decoy-"));
    try {
      writeFileSync(join(caseRoot, "SKILL.md"), SKILL_FIXTURE_BYTES);
      const item: CatalogCaptureItemV1 = {
        content: {
          digest: "fixture-catalog-index-v1",
          entries: [],
          organizationAdmission: "fixture-organization-admission",
          package: { name: "@aihq/catalog", version: "0.0.0-fixture" },
        },
        entry: { artifacts: {}, entryId: FIXTURE_ITEM_ID, subject: { subjectDigest: "sha256:0" } },
        files: [],
        selectedClosurePaths: [],
        sourceRoot: caseRoot,
      };
      expect(() => assertSkillSourceRoot(item)).toThrow(/no staged SKILL\.md at its top level/);
    } finally {
      rmSync(caseRoot, { force: true, recursive: true });
    }
  });

  it("refuses a staged SKILL.md whose bytes no longer match its published digest", () => {
    const caseRoot = mkdtempSync(join(tmpdir(), "aih-scan-skill-mutated-"));
    try {
      const bytes = Buffer.from(SKILL_FIXTURE_BYTES, "utf8");
      writeFileSync(join(caseRoot, "SKILL.md"), bytes);
      const item: CatalogCaptureItemV1 = {
        content: {
          digest: "fixture-catalog-index-v1",
          entries: [],
          organizationAdmission: "fixture-organization-admission",
          package: { name: "@aihq/catalog", version: "0.0.0-fixture" },
        },
        entry: { artifacts: {}, entryId: FIXTURE_ITEM_ID, subject: { subjectDigest: "sha256:0" } },
        files: [
          { byteLength: bytes.length, name: "prose", path: "SKILL.md", sha256: sha256(bytes) },
        ],
        selectedClosurePaths: ["SKILL.md"],
        sourceRoot: caseRoot,
      };
      expect(assertSkillSourceRoot(item).path).toBe("SKILL.md");
      writeFileSync(join(caseRoot, "SKILL.md"), "mutated after staging\n");
      expect(() => assertSkillSourceRoot(item)).toThrow(/no longer matches its published digest/);
    } finally {
      rmSync(caseRoot, { force: true, recursive: true });
    }
  });
});
