import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  CISCO_MULTI_SKILL_SCANNER_PROJECT_V1,
  type CiscoMultiSkillRunnerV1,
} from "../../../src/detectors/cisco-multi-skill/plan-v1.js";
import { runCiscoSourceTreeScanV1 } from "../../../src/detectors/cisco-multi-skill/scan-v1.js";
import { runCiscoShardV1 } from "../../../src/detectors/cisco-multi-skill/shard-v1.js";
import { hashComponentTreeV1 } from "../../../src/observation/source-hash-v1.js";
import { strictJsonHostileTextsV1 } from "../../support/strict-json-hostile.js";

// S2e: a Cisco job's SARIF is evidence only when it proves the job completed. Real
// skill-scanner 2.0.14 output (the linux-x64 parity transcripts) is always
// `{"version":"2.1.0","runs":[{tool:{driver},results:[…],invocations:[{executionSuccessful:true}]}]}`;
// anything short of that fails the job (C2a §3.5: lowest index, no partial SARIF), for the
// source-tree scan and the shard alike. Every location's uriBaseId is resolved before the
// job prefix is applied (the repaired `sarif-source-relative-v1` rules).

let root: string;

beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "aih-scan-cisco-job-sarif-")));
  for (const name of ["alpha", "beta"]) {
    mkdirSync(join(root, "skills", name), { recursive: true });
    writeFileSync(join(root, "skills", name, "SKILL.md"), `# ${name}\n`, "utf8");
  }
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

const DRIVER = { driver: { name: "skill-scanner", version: "1.0.0" } };
const DONE = [{ executionSuccessful: true, endTimeUtc: "2026-09-24T00:00:00Z" }];

function result(uri: unknown, extra: Record<string, unknown> = {}) {
  return {
    ruleId: "fixture",
    level: "warning",
    message: { text: "m" },
    locations: [{ physicalLocation: { artifactLocation: { uri, ...extra } } }],
  };
}

function cleanRun(results: unknown[] = []) {
  return { tool: DRIVER, results, invocations: DONE };
}

function sarif(runs: unknown[]) {
  return { version: "2.1.0", runs };
}

/** The version gate passes; each job writes `perJob(<job dir basename>)`. */
function runner(perJob: (name: string) => unknown, delays?: Record<string, number>) {
  const run: CiscoMultiSkillRunnerV1 = async (argv) => {
    if (argv.includes("--version")) return { code: 0, stdout: "skill-scanner 2.1.0\n", stderr: "" };
    const target = (argv[argv.indexOf("scan") + 1] ?? "").replaceAll("\\", "/");
    const output = argv[argv.indexOf("--output-sarif") + 1];
    if (output === undefined) return { code: 2, stdout: "", stderr: "no output path" };
    const name = target.split("/").at(-1) ?? "";
    await new Promise((resolve) => setTimeout(resolve, delays?.[name] ?? 0));
    const body = perJob(name);
    writeFileSync(
      output,
      typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body),
    );
    return { code: 0, stdout: "", stderr: "" };
  };
  return run;
}

function tree(run: CiscoMultiSkillRunnerV1) {
  return runCiscoSourceTreeScanV1({
    run,
    platform: "linux",
    env: {},
    sourceRoot: root,
    selectedClosurePaths: ["skills/alpha/SKILL.md", "skills/beta/SKILL.md"],
    detectorOptions: { concurrency: 2 },
  });
}

function shard(run: CiscoMultiSkillRunnerV1) {
  const lock = createHash("sha256")
    .update(readFileSync(join(CISCO_MULTI_SKILL_SCANNER_PROJECT_V1, "uv.lock")))
    .digest("hex");
  return runCiscoShardV1({
    run,
    platform: "linux",
    env: {},
    sourceRoot: root,
    jobs: ["skills/alpha", "skills/beta"].map((path) => ({
      id: createHash("sha256").update(path).digest("hex"),
      path,
      inputSha256: hashComponentTreeV1(root, [path]).treeSha256,
    })),
    expected: { analyzerVersion: "2.1.0", lockSha256: lock },
    concurrency: 2,
  });
}

const BOTH = [
  ["source-tree", tree],
  ["shard", shard],
] as const;

describe.each(BOTH)("Cisco job SARIF completion evidence (%s)", (_label, execute) => {
  const failsWith = async (body: unknown, stage: string, detail: RegExp) => {
    const outcome = await execute(
      runner((name) => (name === "alpha" ? body : sarif([cleanRun()]))),
    );
    expect(outcome).toMatchObject({ kind: "failed", stage });
    expect(outcome).not.toHaveProperty("outputs");
    expect(outcome).not.toHaveProperty("sarifText");
    expect(outcome.kind === "failed" ? outcome.detail : "").toMatch(detail);
  };

  it("fails a job whose SARIF holds no runs (reviewer reproduction)", async () => {
    await failsWith({ runs: [] }, "output", /version 2\.1\.0/);
    await failsWith(sarif([]), "output", /no runs/);
  });

  it("fails a job whose invocation reports executionSuccessful: false (reviewer reproduction)", async () => {
    await failsWith(
      sarif([{ tool: DRIVER, results: [], invocations: [{ executionSuccessful: false }] }]),
      "execution",
      /did not complete successfully/,
    );
  });

  it("fails a job without a successful invocation", async () => {
    await failsWith(sarif([{ tool: DRIVER, results: [] }]), "output", /no invocation/);
    await failsWith(
      sarif([{ tool: DRIVER, results: [], invocations: [] }]),
      "output",
      /no invocation/,
    );
    await failsWith(
      sarif([{ tool: DRIVER, results: [], invocations: [{ endTimeUtc: "x" }] }]),
      "execution",
      /did not complete successfully/,
    );
    await failsWith(
      sarif([
        { tool: DRIVER, results: [], invocations: [...DONE, { executionSuccessful: false }] },
      ]),
      "execution",
      /did not complete successfully/,
    );
  });

  it("fails a job whose invocation carries an error notification", async () => {
    for (const key of ["toolExecutionNotifications", "toolConfigurationNotifications"]) {
      await failsWith(
        sarif([
          {
            tool: DRIVER,
            results: [],
            invocations: [
              { executionSuccessful: true, [key]: [{ level: "error", message: { text: "boom" } }] },
            ],
          },
        ]),
        "execution",
        /error notification/,
      );
    }
  });

  it("fails a job whose SARIF version is not 2.1.0", async () => {
    await failsWith({ runs: [cleanRun()] }, "output", /version 2\.1\.0/);
    await failsWith({ version: "2.0.0", runs: [cleanRun()] }, "output", /version 2\.1\.0/);
  });

  it("fails a run without a tool driver or a results array", async () => {
    await failsWith(sarif([{ results: [], invocations: DONE }]), "output", /tool driver/);
    await failsWith(
      sarif([{ tool: { driver: {} }, results: [], invocations: DONE }]),
      "output",
      /tool driver/,
    );
    await failsWith(sarif([{ tool: DRIVER, invocations: DONE }]), "output", /results/);
    await failsWith(sarif([{ tool: DRIVER, results: {}, invocations: DONE }]), "output", /results/);
    await failsWith(sarif([cleanRun([null])]), "output", /result 0 is malformed/);
    await failsWith(sarif(["run"]), "output", /run 0 is malformed/);
  });

  it("reports the lowest-index job's failure even when a later job fails first", async () => {
    const outcome = await execute(
      runner(
        (name) =>
          name === "alpha"
            ? sarif([{ tool: DRIVER, results: [], invocations: [{ executionSuccessful: false }] }])
            : { runs: [] },
        { alpha: 40, beta: 0 },
      ),
    );
    expect(outcome).toMatchObject({ kind: "failed", stage: "execution" });
    expect(outcome.kind === "failed" ? outcome.detail : "").toMatch(/did not complete/);
  });

  it("keeps a complete job's SARIF", async () => {
    const outcome = await execute(runner(() => sarif([cleanRun([result("SKILL.md")])])));
    expect(outcome.kind).toBe("completed");
  });

  // S2h (review of S2g): JSON.parse kept the last of two keys, so a failed invocation and a
  // forged completion key could both be hidden behind a later duplicate.
  const clean = JSON.stringify({ tool: DRIVER, results: [] });
  it("fails a job whose invocation repeats executionSuccessful (reviewer reproduction)", async () => {
    await failsWith(
      `{"version":"2.1.0","runs":[${clean.slice(0, -1)},"invocations":[{"executionSuccessful":false,"executionSuccessful":true}]}]}`,
      "output",
      /duplicate JSON object key/,
    );
  });

  it("fails a job whose invocation repeats properties to erase a forgery (reviewer reproduction)", async () => {
    await failsWith(
      `{"version":"2.1.0","runs":[${clean.slice(0, -1)},"invocations":[{"executionSuccessful":true,"properties":{"aihScanCompletionV1":{}},"properties":{}}]}]}`,
      "output",
      /duplicate JSON object key/,
    );
  });

  // The shard attaches completion evidence itself; the source-tree scan leaves it to
  // runDetectorV1, which uses the same attachScanCompletionV1.
  it.runIf(_label === "shard")(
    "fails a job whose invocation carries properties: null (reviewer reproduction)",
    async () => {
      await failsWith(
        sarif([
          {
            tool: DRIVER,
            results: [],
            invocations: [{ executionSuccessful: true, properties: null }],
          },
        ]),
        "output",
        /properties that are not an object/,
      );
    },
  );

  it("fails a job whose SARIF repeats a key anywhere, or is not one strict JSON text", async () => {
    const body = JSON.stringify(sarif([cleanRun()]));
    await failsWith(`{"version":"2.1.0",${body.slice(1)}`, "output", /duplicate JSON object key/);
    await failsWith(
      body.replace('"results":[]', '"results":[],"results":[]'),
      "output",
      /duplicate/,
    );
    await failsWith(`${String.fromCharCode(0xfeff)}${body}`, "output", /invalid JSON/);
    await failsWith(`${body}{}`, "output", /invalid JSON/);
    await failsWith(`${body} trailing`, "output", /invalid JSON/);
    // An invalid byte inside a string would have been repaired to U+FFFD and accepted.
    const [head, tail] = body.split('"skill-scanner"');
    await failsWith(
      Buffer.concat([
        Buffer.from(`${head}"skill-scanner`),
        Buffer.from([0xff]),
        Buffer.from(`"${tail}`),
      ]),
      "output",
      /UTF-8/,
    );
  });

  // S2i (review of S2h): a lossy number fails in every spelling, not only as a bare integer.
  it("fails a job whose SARIF holds a number no double carries, however it is spelled", async () => {
    const located = (line: string) =>
      JSON.stringify(sarif([cleanRun([result("SKILL.md")])])).replace(
        '"physicalLocation":{',
        `"physicalLocation":{"region":{"startLine":${line}},`,
      );
    for (const line of ["9007199254740993", "9007199254740993e0", "9007199254740993.0", "-0"])
      await failsWith(located(line), "output", /invalid JSON/);
  });
});

describe.each(BOTH)("Cisco job uriBaseId resolution (%s)", (_label, execute) => {
  const failsWith = async (run: Record<string, unknown>, detail: RegExp) => {
    const outcome = await execute(
      runner((name) => (name === "alpha" ? sarif([run]) : sarif([cleanRun()]))),
    );
    expect(outcome).toMatchObject({ kind: "failed", stage: "output" });
    expect(outcome.kind === "failed" ? outcome.detail : "").toMatch(detail);
  };

  const uris = async (run: Record<string, unknown>) => {
    const outcome = await execute(
      runner((name) => (name === "alpha" ? sarif([run]) : sarif([cleanRun()]))),
    );
    if (outcome.kind !== "completed") throw new Error(JSON.stringify(outcome));
    const texts =
      "outputs" in outcome
        ? outcome.outputs.map((output) => Buffer.from(output.sarif).toString("utf8"))
        : [outcome.sarifText];
    const runs = texts.flatMap((text) => (JSON.parse(text) as { runs: unknown[] }).runs);
    return runs[0] as {
      originalUriBaseIds?: unknown;
      results: Array<{
        locations: Array<{ physicalLocation: { artifactLocation: Record<string, unknown> } }>;
        relatedLocations?: Array<{
          physicalLocation: { artifactLocation: Record<string, unknown> };
        }>;
      }>;
    };
  };

  it("fails a base that resolves outside the source root (reviewer reproduction)", async () => {
    await failsWith(
      {
        ...cleanRun([result("SKILL.md", { uriBaseId: "OUT" })]),
        originalUriBaseIds: { OUT: { uri: "file:///outside/" } },
      },
      /outside the declared source root/,
    );
  });

  it("fails an undeclared or malformed base", async () => {
    await failsWith(cleanRun([result("SKILL.md", { uriBaseId: "NOPE" })]), /not declared/);
    await failsWith(
      {
        ...cleanRun([result("SKILL.md", { uriBaseId: "LOOP" })]),
        originalUriBaseIds: { LOOP: { uri: "a/", uriBaseId: "LOOP" } },
      },
      /refers back to itself/,
    );
    await failsWith(cleanRun([result("SKILL.md", { uriBaseId: 7 })]), /uriBaseId is not a string/);
  });

  it("validates bases on every location, not only the first", async () => {
    await failsWith(
      {
        ...cleanRun([
          {
            ...result("SKILL.md"),
            relatedLocations: [
              { physicalLocation: { artifactLocation: { uri: "x.md", uriBaseId: "OUT" } } },
            ],
          },
        ]),
        originalUriBaseIds: { OUT: { uri: "file:///outside/" } },
      },
      /outside the declared source root/,
    );
  });

  it("relates an absolute base inside the root, then drops the base references", async () => {
    // S2g: a shard result's related location must name a sealed file of its job.
    mkdirSync(join(root, "skills", "alpha", "notes", "docs"), { recursive: true });
    writeFileSync(join(root, "skills", "alpha", "notes", "docs", "x.md"), "x\n", "utf8");
    const jobDir = `${pathToFileURL(join(root, "skills", "alpha")).href}/`;
    const run = await uris({
      ...cleanRun([
        {
          ...result("SKILL.md", { uriBaseId: "JOB" }),
          relatedLocations: [
            { physicalLocation: { artifactLocation: { uri: "docs/x.md", uriBaseId: "DOCS" } } },
          ],
        },
      ]),
      originalUriBaseIds: { JOB: { uri: jobDir }, DOCS: { uri: "notes/", uriBaseId: "%SRCROOT%" } },
    });
    expect(run.originalUriBaseIds).toBeUndefined();
    expect(run.results[0]?.locations[0]?.physicalLocation.artifactLocation).toEqual({
      uri: "skills/alpha/SKILL.md",
    });
    expect(run.results[0]?.relatedLocations?.[0]?.physicalLocation.artifactLocation).toEqual({
      uri: "skills/alpha/notes/docs/x.md",
    });
  });

  it("keeps the analyzer's %SRCROOT% reference on a prefixed URI", async () => {
    const run = await uris(cleanRun([result("SKILL.md", { uriBaseId: "%SRCROOT%" })]));
    expect(run.results[0]?.locations[0]?.physicalLocation.artifactLocation).toEqual({
      uri: "skills/alpha/SKILL.md",
      uriBaseId: "%SRCROOT%",
    });
  });
});

// S2i (review of S2h): a result's `analysisTarget` is an artifact location. It is
// normalized exactly like every other one (base resolution, job prefix, index kept for
// the shard's resolution through the normalized run artifacts) before anything binds it.
describe.each(BOTH)("Cisco job analysisTarget normalization (%s)", (label, execute) => {
  const outcomeOf = (analysisTarget: unknown, run: Record<string, unknown> = {}) =>
    execute(
      runner((name) =>
        name === "alpha"
          ? sarif([{ ...cleanRun([{ ...result("SKILL.md"), analysisTarget }]), ...run }])
          : sarif([cleanRun()]),
      ),
    );
  const targetOf = async (analysisTarget: unknown, run: Record<string, unknown> = {}) => {
    const outcome = await outcomeOf(analysisTarget, run);
    if (outcome.kind !== "completed") throw new Error(JSON.stringify(outcome));
    const text =
      "outputs" in outcome
        ? Buffer.from(outcome.outputs[0]?.sarif ?? new Uint8Array()).toString("utf8")
        : outcome.sarifText;
    const log = JSON.parse(text) as { runs: { results: { analysisTarget?: unknown }[] }[] };
    return log.runs[0]?.results[0]?.analysisTarget;
  };
  const rootBase = () => ({ ROOT: { uri: `${pathToFileURL(root).href}/` } });

  it("prefixes a job-relative analysis target with the job directory (reviewer case)", async () => {
    expect(await targetOf({ uri: "SKILL.md" })).toEqual({ uri: "skills/alpha/SKILL.md" });
  });

  it("relates a root-based analysis target to the root, not the job", async () => {
    expect(
      await targetOf(
        { uri: "skills/alpha/SKILL.md", uriBaseId: "ROOT" },
        { originalUriBaseIds: rootBase() },
      ),
    ).toEqual({ uri: "skills/alpha/SKILL.md" });
  });

  it("reads a root-relative spelling as job-relative (reviewer case)", async () => {
    const outcome = await outcomeOf({ uri: "skills/alpha/SKILL.md" });
    if (label === "shard") {
      expect(outcome).toMatchObject({ kind: "failed", stage: "output" });
      expect(outcome.kind === "failed" ? outcome.detail : "").toMatch(
        /skills\/alpha\/skills\/alpha\/SKILL\.md/,
      );
    } else
      expect(await targetOf({ uri: "skills/alpha/SKILL.md" })).toEqual({
        uri: "skills/alpha/skills/alpha/SKILL.md",
      });
  });

  it("fails an analysis target whose base is undeclared or outside the root", async () => {
    for (const [analysisTarget, run] of [
      [{ uri: "SKILL.md", uriBaseId: "NOPE" }, {}],
      [{ index: 0, uriBaseId: "NOPE" }, {}],
      [
        { uri: "SKILL.md", uriBaseId: "OUT" },
        { originalUriBaseIds: { OUT: { uri: "file:///outside/" } } },
      ],
      [{ uri: "../beta/SKILL.md" }, {}],
    ] as const) {
      const outcome = await outcomeOf(analysisTarget, run);
      expect(outcome).toMatchObject({ kind: "failed", stage: "output" });
      expect(outcome.kind === "failed" ? outcome.detail : "").toMatch(/detector SARIF location/);
    }
  });
});

// U1g (review of S2i, P2): only `result.analysisTarget` is an analysis target. A property
// bag is the analyzer's own data: it never fails a job and is never rewritten.
describe.each(BOTH)("Cisco job property bags (%s)", (_label, execute) => {
  const bag = () => ({
    analysisTarget: { uri: "SKILL.md" },
    artifactLocation: { uri: "SKILL.md" },
    escaping: { analysisTarget: { uri: "../example" } },
  });

  it("completes and keeps every property bag exactly as the analyzer wrote it", async () => {
    const outcome = await execute(
      runner((name) =>
        name === "alpha"
          ? sarif([
              {
                ...cleanRun([{ ...result("SKILL.md"), properties: bag() }]),
                properties: bag(),
              },
            ])
          : sarif([cleanRun()]),
      ),
    );
    if (outcome.kind !== "completed") throw new Error(JSON.stringify(outcome));
    const text =
      "outputs" in outcome
        ? Buffer.from(outcome.outputs[0]?.sarif ?? new Uint8Array()).toString("utf8")
        : outcome.sarifText;
    const log = JSON.parse(text) as {
      runs: { properties: unknown; results: { properties: unknown }[] }[];
    };
    const alpha = log.runs.find((run) => run.results.length > 0);
    expect(alpha?.properties).toEqual(bag());
    expect(alpha?.results[0]?.properties).toEqual(bag());
  });
});

// U1g (review of S2i, P1): the source-tree scan resolves artifact indices exactly as the
// shard does, through the one shared rule of the job normalization.
describe.each(BOTH)("Cisco job artifact indices (%s)", (_label, execute) => {
  const outcomeOf = (analysisTarget: unknown, artifacts: unknown[]) =>
    execute(
      runner((name) =>
        name === "alpha"
          ? sarif([{ ...cleanRun([{ ...result("SKILL.md"), analysisTarget }]), artifacts }])
          : sarif([cleanRun()]),
      ),
    );

  it("fails a URI and an index that name different files (reviewer case)", async () => {
    const outcome = await outcomeOf({ uri: "SKILL.md", index: 0 }, [
      { location: { uri: "guide.md" } },
    ]);
    expect(outcome).toMatchObject({ kind: "failed", stage: "output" });
    expect(outcome.kind === "failed" ? outcome.detail : "").toMatch(/disagree/);
  });

  it("fails a missing or malformed index", async () => {
    for (const analysisTarget of [{ index: 0 }, { index: -1 }, { uri: "SKILL.md", index: 2 }]) {
      const outcome = await outcomeOf(analysisTarget, []);
      expect(outcome, JSON.stringify(analysisTarget)).toMatchObject({
        kind: "failed",
        stage: "output",
      });
      expect(outcome.kind === "failed" ? outcome.detail : "").toMatch(/artifact index/);
    }
  });

  it("keeps an index that names the same job file as its URI", async () => {
    const outcome = await outcomeOf({ uri: "SKILL.md", index: 0 }, [
      { location: { uri: "SKILL.md" } },
    ]);
    expect(outcome.kind === "failed" ? outcome.detail : outcome.kind).toBe("completed");
  });
});

// U1g: every Cisco 2.1.0 source-tree or shard job's SARIF is read only through the one strict
// parser; each of its refusals fails the job at output.
describe.each(BOTH)("Cisco job strict analyzer output (%s, U1g)", (_label, execute) => {
  const valid = JSON.stringify(sarif([cleanRun([result("SKILL.md")])]));
  it.each(
    strictJsonHostileTextsV1(valid),
  )("fails a job whose SARIF holds %s", async (_name, hostile, reason) => {
    const outcome = await execute(
      runner((name) => (name === "alpha" ? hostile : sarif([cleanRun()]))),
    );
    expect(outcome).toMatchObject({ kind: "failed", stage: "output" });
    expect(outcome.kind === "failed" ? outcome.detail : "").toMatch(reason);
  });
});
