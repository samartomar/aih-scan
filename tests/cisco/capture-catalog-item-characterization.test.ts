/**
 * Characterization of `tools/capture-catalog-item.mjs` as a whole command.
 *
 * The snapshot beside this file was recorded from the single-file helper before it was
 * split into modules, and it is the byte-level contract the split must keep: the same
 * arguments give the same stdout, stderr and exit status, the entry exports the same
 * names, and the same fixture run leaves the same files with the same bytes.
 *
 * Only host-independent behaviour is recorded. The platform gate and the Docker gate
 * answer differently on every host, so no case here reaches them through the command;
 * fixture runs drive the exported phases and stop at the subject gate or at a stub
 * capture CLI that refuses. Machine-specific values (temporary roots, the Node and npm
 * paths, stub tarball digests, timestamps and npm's own install output) are replaced by
 * named tokens, and path separators are written as `/`, so the snapshot is identical on
 * Linux, macOS and Windows. No detector runs and nothing here is a finding.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type {
  CatalogCaptureOptionsV1,
  CatalogCapturePreparedV1,
} from "../../tools/capture-catalog-item.mjs";
import * as captureTool from "../../tools/capture-catalog-item.mjs";
import { fixtureOptions, writeDetectorInputFixtures } from "./capture-catalog-fixtures.js";
import {
  FIXTURE_CATALOG_CONTENT_ENV,
  FIXTURE_CLI_LOUD_ENV,
  FIXTURE_CLI_MARKER_ENV,
  FIXTURE_CLOSURE_CALL_ENV,
  type FixtureClosureV1,
  packStubPackages,
  type StubPackagesV1,
  writeFixtureClosure,
} from "./capture-catalog-stub-packages.js";

const ENTRY = resolve(import.meta.dirname, "..", "..", "tools", "capture-catalog-item.mjs");
const SKILL_ROOT = "packs/governance-quality/aih-gov-doctor";
const PLATFORM = captureTool.assertPlatform({ arch: "x64", platform: "linux" });

let stubPackages: StubPackagesV1;
let stubRoot: string;
const temporaryRoots: string[] = [];

beforeAll(() => {
  stubRoot = mkdtempSync(join(tmpdir(), "aih-scan-characterization-packages-"));
  temporaryRoots.push(stubRoot);
  stubPackages = packStubPackages(stubRoot);
}, 5 * 60_000);

afterAll(() => {
  while (temporaryRoots.length > 0) {
    const root = temporaryRoots.pop();
    if (root !== undefined) rmSync(root, { force: true, recursive: true });
  }
});

const sha256Hex = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");

/** Machine-specific values, longest first so a root is replaced before its prefix. */
function tokens(caseRoot: string): readonly (readonly [string, string])[] {
  return (
    [
      [caseRoot, "<case>"],
      [stubRoot, "<stub-packages>"],
      [process.execPath, "<node>"],
      [captureTool.npmCliPath(), "<npm>"],
      [sha256Hex(readFileSync(stubPackages.catalogTarball)), "<catalog-tarball-sha256>"],
      [sha256Hex(readFileSync(stubPackages.scanTarball)), "<scan-tarball-sha256>"],
    ] as const
  )
    .slice()
    .sort((left, right) => right[0].length - left[0].length);
}

/** Raw text (a log line, a message): tokens replaced, then `\` separators written as `/`. */
function normalizeText(text: string, caseRoot: string): string {
  let result = text;
  for (const [value, token] of tokens(caseRoot)) result = result.split(value).join(token);
  return result
    .replaceAll("\\", "/")
    .replace(/^finished \S+$/gmu, "finished <time>")
    .replace(
      /\n===== npm install --ignore-scripts =====\n[\s\S]*?(?=^installed {7})/mu,
      "\n===== npm install --ignore-scripts =====\n<npm install output>\n",
    );
}

/** JSON text: the escaped forms of the tokens replaced, then escaped `\\` written as `/`. */
function normalizeJson(text: string, caseRoot: string): string {
  let result = text;
  for (const [value, token] of tokens(caseRoot))
    result = result.split(JSON.stringify(value).slice(1, -1)).join(token);
  return result.replaceAll("\\\\", "/");
}

/** Every file under the run directory, in code-unit order, with normalized bytes. */
function runTranscript(runRoot: string, caseRoot: string): Record<string, string> {
  const files: Record<string, string> = {};
  const walk = (directory: string, prefix: string) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const relative = prefix === "" ? entry.name : `${prefix}/${entry.name}`;
      if (entry.isDirectory()) walk(join(directory, entry.name), relative);
      else {
        const text = readFileSync(join(directory, entry.name), "utf8");
        files[relative] = relative.endsWith(".json")
          ? normalizeJson(text, caseRoot)
          : normalizeText(text, caseRoot);
      }
    }
  };
  walk(runRoot, "");
  return Object.fromEntries(
    Object.entries(files).sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0)),
  );
}

type FixtureCaseV1 = Readonly<{
  caseRoot: string;
  runRoot: string;
  options: CatalogCaptureOptionsV1;
  environment: Readonly<Record<string, string>>;
}>;

function fixtureCase(
  fixture: FixtureClosureV1,
  overrides: Partial<CatalogCaptureOptionsV1> = {},
): FixtureCaseV1 {
  const caseRoot = mkdtempSync(join(tmpdir(), "aih-scan-characterization-"));
  temporaryRoots.push(caseRoot);
  const paths = writeDetectorInputFixtures(caseRoot);
  const descriptor = writeFixtureClosure(caseRoot, fixture);
  const options = fixtureOptions(caseRoot, paths, {
    catalogTarball: stubPackages.catalogTarball,
    scanTarball: stubPackages.scanTarball,
    ...overrides,
  });
  return {
    caseRoot,
    options,
    runRoot: captureTool.createRunDirectory(options.output),
    environment: {
      [FIXTURE_CATALOG_CONTENT_ENV]: descriptor,
      [FIXTURE_CLOSURE_CALL_ENV]: join(caseRoot, "closure-calls.jsonl"),
      [FIXTURE_CLI_MARKER_ENV]: join(caseRoot, "capture-cli-argv.txt"),
    },
  };
}

/** Runs a step with the case's environment, restoring exactly what was set. */
async function withEnvironment<T>(
  values: Readonly<Record<string, string>>,
  step: () => Promise<T> | T,
): Promise<T> {
  const saved = new Map<string, string | undefined>();
  for (const [name, value] of Object.entries(values)) {
    saved.set(name, process.env[name]);
    process.env[name] = value;
  }
  try {
    return await step();
  } finally {
    for (const [name, value] of saved) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

async function refusalOf(step: () => Promise<unknown>): Promise<string> {
  try {
    await step();
  } catch (error) {
    return error instanceof Error ? `${error.constructor.name}: ${error.message}` : String(error);
  }
  throw new Error("this step must refuse, but it completed");
}

const governanceClosure = (): FixtureClosureV1 => ({
  files: [
    { content: '{"protocol":"fixture-aih-packs"}\n', path: "aih-packs.json" },
    { content: "Fixture licence bytes.\n", path: `${SKILL_ROOT}/LICENSE` },
    { content: "---\nname: fixture\n---\n\n# fixture skill\n", path: `${SKILL_ROOT}/SKILL.md` },
    { content: '{"protocol":"fixture-skill-profile"}\n', path: `${SKILL_ROOT}/profile.json` },
  ],
  skillRootPath: SKILL_ROOT,
});

const CASE_BUDGET = { timeout: 120_000 } as const;

describe("capture-catalog-item command characterization", () => {
  it("keeps its exported names", () => {
    expect(Object.keys(captureTool).sort()).toMatchSnapshot();
  });

  it("answers every argument-stage case with the same streams and exit status", () => {
    const required = [
      "--catalog-tarball",
      "c.tgz",
      "--scan-tarball",
      "s.tgz",
      "--output",
      "out",
      "--registration",
      "r.json",
      "--layout",
      "l.json",
      "--image-id",
      "i.txt",
      "--sbom",
      "sbom.json",
      "--provenance",
      "prov.json",
    ];
    const cases: Readonly<Record<string, readonly string[]>> = {
      help: ["--help"],
      "short help": ["-h"],
      "help beside another argument": ["--help", "--prepare-only"],
      "no arguments": [],
      "unknown argument": ["--bogus"],
      "duplicate value argument": ["--output", "a", "--output", "b"],
      "duplicate boolean argument": ["--prepare-only", "--prepare-only"],
      "value missing at the end": ["--output"],
      "flag given as a value": ["--output", "--layout"],
      "required operator inputs missing": required.slice(0, 6),
      "collection id grammar": [...required, "--collection-id", "Not-Lower"],
      "subject id grammar": [...required, "--subject-id", "../escape"],
      "detector id grammar": [...required, "--detector-id", "cisco"],
    };
    const cwd = mkdtempSync(join(tmpdir(), "aih-scan-characterization-cwd-"));
    temporaryRoots.push(cwd);
    const transcript = Object.fromEntries(
      Object.entries(cases).map(([name, argv]) => {
        const result = spawnSync(process.execPath, [ENTRY, ...argv], {
          cwd,
          encoding: "utf8",
          timeout: 60_000,
        });
        return [
          name,
          {
            argv,
            status: result.status,
            signal: result.signal,
            stdout: result.stdout,
            stderr: result.stderr,
          },
        ];
      }),
    );
    expect(transcript).toMatchSnapshot();
  }, 120_000);

  it(
    "leaves the same records when the subject gate refuses a prepared root",
    CASE_BUDGET,
    async () => {
      const caseV1 = fixtureCase({
        files: [
          { content: '{"protocol":"fixture-aih-packs"}\n', path: "aih-packs.json" },
          { content: "Fixture licence bytes.\n", path: "packs/no-skill/LICENSE" },
          { content: '{"protocol":"fixture-profile"}\n', path: "packs/no-skill/profile.json" },
        ],
        skillMarker: "profile.json",
        skillRootPath: "packs/no-skill",
      });
      const reason = await withEnvironment(caseV1.environment, async () => {
        const prepared = await captureTool.prepareCapture(caseV1.options, caseV1.runRoot);
        return refusalOf(() =>
          captureTool.runPreparedCapture(caseV1.options, caseV1.runRoot, PLATFORM, prepared),
        );
      });
      expect({
        reason: normalizeText(reason, caseV1.caseRoot),
        run: runTranscript(caseV1.runRoot, caseV1.caseRoot),
      }).toMatchSnapshot();
    },
  );

  it("leaves the same records when the capture command fails", CASE_BUDGET, async () => {
    const caseV1 = fixtureCase(governanceClosure());
    const attempt = await withEnvironment(
      { ...caseV1.environment, [FIXTURE_CLI_LOUD_ENV]: "3" },
      async () => {
        const prepared: CatalogCapturePreparedV1 = await captureTool.prepareCapture(
          caseV1.options,
          caseV1.runRoot,
        );
        return captureTool.attemptCapture(prepared, caseV1.runRoot);
      },
    );
    expect({
      attempt: JSON.parse(normalizeJson(JSON.stringify(attempt), caseV1.caseRoot)),
      run: runTranscript(caseV1.runRoot, caseV1.caseRoot),
    }).toMatchSnapshot();
  });

  it("refuses the same preparation inputs with the same messages", CASE_BUDGET, async () => {
    const governance = governanceClosure();
    const cases: Readonly<
      Record<string, Readonly<{ fixture: FixtureClosureV1; imageId?: string }>>
    > = {
      "no declared skill root": { fixture: { files: governance.files } },
      "served digest mismatch": {
        fixture: {
          ...governance,
          files: governance.files.map((file) =>
            file.path.endsWith("/LICENSE") ? { ...file, declareSha256: "0".repeat(64) } : file,
          ),
        },
      },
      "closure not verified": {
        fixture: { files: governance.files, reason: "fixture-refusal", state: "refused" },
      },
      "image id does not match the layout": {
        fixture: governance,
        imageId: `sha256:${"c".repeat(64)}\n`,
      },
    };
    const transcript: Record<string, unknown> = {};
    for (const [name, { fixture, imageId }] of Object.entries(cases)) {
      const caseV1 = fixtureCase(fixture);
      if (imageId !== undefined) writeFileSync(caseV1.options.imageId, imageId);
      const reason = await withEnvironment(caseV1.environment, () =>
        refusalOf(() => captureTool.prepareCapture(caseV1.options, caseV1.runRoot)),
      );
      transcript[name] = {
        reason: normalizeText(reason, caseV1.caseRoot),
        run: runTranscript(caseV1.runRoot, caseV1.caseRoot),
      };
    }
    expect(transcript).toMatchSnapshot();
  });
});
