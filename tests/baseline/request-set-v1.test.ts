import { createHash, randomUUID } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  type BaselineAnalyzerExecutionV1,
  type BaselineAnalyzerV1,
  type BaselineVetRequestV1,
  canonicalBaselineVetRequestV1Bytes,
  createBaselineVetRequestV1,
  verifyBaselineVetReceiptV1,
} from "../../src/baseline/batch-v1.js";
import { readBaselineVetBundleV1 } from "../../src/baseline/bundle-v1.js";
import {
  parseBaselineVetRequestSetArgumentsV1,
  runBaselineVetRequestSetV1,
} from "../../src/baseline/request-set-v1.js";
import { BASELINE_BATCH_EXECUTION_PROFILES_V1 } from "../../src/baseline/runtime-v1.js";
import { canonicalStrictJsonBytesV1 } from "../../src/contract/strict-json-v1.js";
import { hashComponentTreeV1, hashSourceTreeV1 } from "../../src/observation/source-hash-v1.js";
import { batchAnalyzerVersion } from "./batch-version-support.js";

/**
 * D49 [Scan: SV1]: `baseline-vet --request-set <dir> --source <dir> --output-root <new-dir>`
 * reads every `batch-NNN.request.json` of a closed directory, executes the set once, and only
 * after everything succeeded writes `<output-root>/batch-NNN.bundle` for each request.
 */

const temporaryDirectories: string[] = [];
const sha = (value: string | Uint8Array) => createHash("sha256").update(value).digest("hex");
const readText = (path: string) => readFileSync(path, "utf8");

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

function temporary(prefix: string) {
  const directory = mkdtempSync(join(tmpdir(), prefix));
  temporaryDirectories.push(directory);
  return directory;
}

const component = (root: string, id: string, content: "general" | "skill", path: string) => ({
  id,
  content,
  paths: [path],
  treeSha256: hashComponentTreeV1(root, [path]).treeSha256,
  analyzers:
    content === "skill"
      ? ["aih-native", "skillspector", "semgrep", "cisco"]
      : ["aih-native", "skillspector", "semgrep"],
});

function requestOver(root: string, components: ReturnType<typeof component>[]) {
  return createBaselineVetRequestV1({
    protocol: "BaselineVetRequestV1",
    profile: "aih-baseline-v1",
    source: {
      id: "ecc",
      owner: "affaan-m",
      repository: "everything-claude-code",
      pinnedCommit: "a".repeat(40),
      treeSha256: hashSourceTreeV1(root).treeSha256,
    },
    components,
  });
}

/** One source, three canonical request files, and a work directory for the output root. */
function requestSet() {
  const source = temporary("aih-scan-set-source-");
  mkdirSync(join(source, "rules"));
  mkdirSync(join(source, "skills", "demo"), { recursive: true });
  mkdirSync(join(source, "skills", "other"), { recursive: true });
  writeFileSync(join(source, "rules", "base.md"), "# Rule\n", "utf8");
  writeFileSync(join(source, "skills", "demo", "SKILL.md"), "# Demo\n", "utf8");
  writeFileSync(join(source, "skills", "other", "SKILL.md"), "# Other\n", "utf8");
  const requests = [
    requestOver(source, [component(source, "rules-core", "general", "rules")]),
    requestOver(source, [component(source, "skill-demo", "skill", "skills/demo")]),
    requestOver(source, [component(source, "skill-other", "skill", "skills/other")]),
  ];
  const work = temporary("aih-scan-set-work-");
  const directory = join(work, "pending");
  mkdirSync(directory);
  for (const [index, request] of requests.entries())
    writeRequest(directory, `batch-00${index + 1}.request.json`, request);
  return { source, requests, directory, outputRoot: join(work, "bundles"), work };
}

const writeRequest = (directory: string, name: string, request: BaselineVetRequestV1) =>
  writeFileSync(join(directory, name), canonicalBaselineVetRequestV1Bytes(request));

function fakeExecution(
  calls: BaselineAnalyzerV1[],
  hook: (analyzer: BaselineAnalyzerV1) => void = () => {},
): BaselineAnalyzerExecutionV1 {
  return async ({ analyzer }) => {
    calls.push(analyzer);
    hook(analyzer);
    if (analyzer === "aih-native")
      return {
        mediaType: "application/vnd.aih.baseline-native+json",
        bytes: canonicalStrictJsonBytesV1({ protocol: "BaselineNativeObservationV1", files: [] }),
        analyzerVersion: "native.0123456789ab",
        executionProfileId: "in-process-native-v1",
      };
    // Nondeterministic, as Cisco 2.1.0's endTimeUtc and SkillSpector's findingId are.
    return {
      mediaType: "application/sarif+json",
      bytes: canonicalStrictJsonBytesV1({
        version: "2.1.0",
        runs: [
          {
            tool: { driver: { name: analyzer } },
            results: [],
            invocations: [
              {
                executionSuccessful: true,
                endTimeUtc: new Date().toISOString(),
                properties: { run: randomUUID() },
              },
            ],
          },
        ],
      }),
      analyzerVersion: batchAnalyzerVersion(analyzer),
      executionProfileId: BASELINE_BATCH_EXECUTION_PROFILES_V1[analyzer],
    };
  };
}

describe("baseline-vet --request-set arguments", () => {
  it("accepts exactly the three set flags, in any order", () => {
    expect(
      parseBaselineVetRequestSetArgumentsV1([
        "--request-set",
        "pending",
        "--source",
        "src",
        "--output-root",
        "out",
      ]),
    ).toEqual({ requestSetDirectory: "pending", sourceRoot: "src", outputRoot: "out" });
    expect(
      parseBaselineVetRequestSetArgumentsV1([
        "--output-root",
        "out",
        "--request-set",
        "pending",
        "--source",
        "src",
      ]),
    ).toEqual({ requestSetDirectory: "pending", sourceRoot: "src", outputRoot: "out" });
  });

  it.each([
    ["no arguments", []],
    ["a missing flag", ["--request-set", "p", "--source", "s"]],
    ["an extra argument", ["--request-set", "p", "--source", "s", "--output-root", "o", "x"]],
    ["an unknown flag", ["--request-set", "p", "--source", "s", "--output", "o"]],
    ["a repeated flag", ["--request-set", "p", "--request-set", "q", "--output-root", "o"]],
    ["the single-request flag", ["--request", "p", "--source", "s", "--output-root", "o"]],
    ["a flag in place of a value", ["--request-set", "--source", "s", "--output-root", "o", "x"]],
    ["an empty value", ["--request-set", "", "--source", "s", "--output-root", "o"]],
    ["an inline value", ["--request-set=p", "x", "--source", "s", "--output-root", "o"]],
  ])("refuses %s", (_label, args) => {
    expect(() => parseBaselineVetRequestSetArgumentsV1(args)).toThrow(/baseline-vet usage/);
  });

  it("keeps the single-request form and documents both forms in the CLI", () => {
    const cli = readFileSync(join("src", "cli.ts"), "utf8").replace(/\r\n/gu, "\n");
    // Anything that does not start with --request is the set form, whose parser is strict.
    expect(cli).toContain('if (args[0] !== "--request") return baselineVetSet(args);');
    expect(cli).toContain(
      '    args.length !== 6 ||\n    args[0] !== "--request" ||\n    args[2] !== "--source" ||\n    args[4] !== "--output"\n  )\n    fail("baseline-vet usage");',
    );
    expect(cli).toContain(
      '"Usage: aih-scan baseline-vet --request <canonical-file> --source <directory> --output <new-directory>\\n" +',
    );
    expect(cli).toContain(
      '"       aih-scan baseline-vet --request-set <directory> --source <directory> --output-root <new-directory>\\n" +',
    );
  });
});

describe("baseline-vet --request-set execution (D49)", () => {
  it("executes each analyzer once and writes one verified bundle per request file", async () => {
    const set = requestSet();
    const calls: BaselineAnalyzerV1[] = [];
    const written = await runBaselineVetRequestSetV1({
      requestSetDirectory: set.directory,
      sourceRoot: set.source,
      outputRoot: set.outputRoot,
      readText,
      execute: fakeExecution(calls),
    });
    expect(calls).toEqual(["aih-native", "skillspector", "semgrep", "cisco"]);
    expect(written.map((item) => item.batch)).toEqual(["batch-001", "batch-002", "batch-003"]);
    expect(readdirSync(set.outputRoot).sort()).toEqual([
      "batch-001.bundle",
      "batch-002.bundle",
      "batch-003.bundle",
    ]);
    const bundles = set.requests.map((request, index) => {
      const bundle = readBaselineVetBundleV1({
        bundleDirectory: join(set.outputRoot, `batch-00${index + 1}.bundle`),
      });
      expect(verifyBaselineVetReceiptV1(request, bundle)).toEqual({ kind: "complete" });
      expect(written[index]).toEqual({
        batch: `batch-00${index + 1}`,
        requestSha256: request.requestSha256,
        receiptSha256: bundle.receipt.receiptSha256,
      });
      return bundle;
    });
    // One execution: the same annex bytes in every bundle that holds the analyzer.
    for (const analyzer of ["aih-native", "skillspector", "semgrep", "cisco"]) {
      const path = `annex/${analyzer}.json`;
      const digests = bundles.flatMap((bundle) =>
        bundle.annexArtifacts.filter((item) => item.path === path).map((item) => sha(item.bytes)),
      );
      expect(digests).toHaveLength(analyzer === "cisco" ? 2 : 3);
      expect(new Set(digests).size).toBe(1);
    }
    expect(bundles[0]?.annexArtifacts.map((item) => item.path)).not.toContain("annex/cisco.json");
  });

  it("refuses an existing output root before any analyzer runs", async () => {
    const set = requestSet();
    mkdirSync(set.outputRoot);
    const calls: BaselineAnalyzerV1[] = [];
    await expect(
      runBaselineVetRequestSetV1({
        requestSetDirectory: set.directory,
        sourceRoot: set.source,
        outputRoot: set.outputRoot,
        readText,
        execute: fakeExecution(calls),
      }),
    ).rejects.toThrow(/output root already exists/);
    expect(calls).toEqual([]);
    expect(readdirSync(set.outputRoot)).toEqual([]);
  });

  it.each<[string, (directory: string) => void, RegExp]>([
    [
      "an empty directory",
      (directory) => {
        for (const name of readdirSync(directory)) rmSync(join(directory, name));
      },
      /request set layout/,
    ],
    [
      "a foreign file",
      (directory) => writeFileSync(join(directory, "coverage-map.json"), "{}", "utf8"),
      /request set layout/,
    ],
    [
      "a misnamed request",
      (directory) => writeFileSync(join(directory, "batch-4.request.json"), "{}", "utf8"),
      /request set layout/,
    ],
    [
      "a subdirectory",
      (directory) => mkdirSync(join(directory, "batch-004.request.json")),
      /request set layout/,
    ],
    [
      "more than 1000 requests",
      (directory) => {
        for (let index = 4; index <= 1001; index += 1)
          writeFileSync(
            join(directory, `batch-${String(index).padStart(3, "0")}.request.json`),
            "{}",
          );
      },
      /request set exceeds 1000/,
    ],
    [
      "a duplicate request",
      (directory) =>
        writeFileSync(
          join(directory, "batch-004.request.json"),
          readFileSync(join(directory, "batch-001.request.json")),
        ),
      /duplicate request digest/,
    ],
    [
      "a non-canonical request",
      (directory) =>
        writeFileSync(
          join(directory, "batch-004.request.json"),
          `${readFileSync(join(directory, "batch-001.request.json"), "utf8")}\n`,
        ),
      /BaselineVetRequestV1/,
    ],
  ])("refuses %s before any analyzer runs", async (_label, mutate, message) => {
    const set = requestSet();
    mutate(set.directory);
    const calls: BaselineAnalyzerV1[] = [];
    await expect(
      runBaselineVetRequestSetV1({
        requestSetDirectory: set.directory,
        sourceRoot: set.source,
        outputRoot: set.outputRoot,
        readText,
        execute: fakeExecution(calls),
      }),
    ).rejects.toThrow(message);
    expect(calls).toEqual([]);
    expect(existsSync(set.outputRoot)).toBe(false);
  });

  it.each([
    ["a linked request file", "file"],
    ["a linked request set directory", "junction"],
  ] as const)("refuses %s before any analyzer runs", async (_label, kind) => {
    const set = requestSet();
    let requestSetDirectory = set.directory;
    try {
      if (kind === "file")
        symlinkSync(
          join(set.directory, "batch-001.request.json"),
          join(set.directory, "batch-004.request.json"),
          "file",
        );
      else {
        requestSetDirectory = join(set.work, "linked");
        symlinkSync(set.directory, requestSetDirectory, "junction");
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EPERM") return;
      throw error;
    }
    const calls: BaselineAnalyzerV1[] = [];
    await expect(
      runBaselineVetRequestSetV1({
        requestSetDirectory,
        sourceRoot: set.source,
        outputRoot: set.outputRoot,
        readText,
        execute: fakeExecution(calls),
      }),
    ).rejects.toThrow(kind === "file" ? /request set layout/ : /request set directory/);
    expect(calls).toEqual([]);
    expect(existsSync(set.outputRoot)).toBe(false);
  });

  it.each<[string, (set: ReturnType<typeof requestSet>) => void]>([
    [
      "a request file changes",
      (set) => {
        const other = set.requests[0] as BaselineVetRequestV1;
        writeRequest(set.directory, "batch-003.request.json", other);
      },
    ],
    [
      "a request file is added",
      (set) =>
        writeFileSync(
          join(set.directory, "batch-004.request.json"),
          readFileSync(join(set.directory, "batch-001.request.json")),
        ),
    ],
    ["a request file is removed", (set) => rmSync(join(set.directory, "batch-002.request.json"))],
  ])("refuses the whole set and writes nothing when %s mid-run", async (_label, mutate) => {
    const set = requestSet();
    const calls: BaselineAnalyzerV1[] = [];
    await expect(
      runBaselineVetRequestSetV1({
        requestSetDirectory: set.directory,
        sourceRoot: set.source,
        outputRoot: set.outputRoot,
        readText,
        execute: fakeExecution(calls, (analyzer) => {
          if (analyzer === "semgrep") mutate(set);
        }),
      }),
    ).rejects.toThrow(/request set changed during execution/);
    expect(calls).toEqual(["aih-native", "skillspector", "semgrep", "cisco"]);
    expect(existsSync(set.outputRoot)).toBe(false);
  });

  it("writes nothing when one analyzer fails", async () => {
    const set = requestSet();
    const calls: BaselineAnalyzerV1[] = [];
    await expect(
      runBaselineVetRequestSetV1({
        requestSetDirectory: set.directory,
        sourceRoot: set.source,
        outputRoot: set.outputRoot,
        readText,
        execute: fakeExecution(calls, (analyzer) => {
          if (analyzer === "cisco") throw new Error("cisco failed");
        }),
      }),
    ).rejects.toThrow(/cisco failed/);
    expect(existsSync(set.outputRoot)).toBe(false);
  });
});
