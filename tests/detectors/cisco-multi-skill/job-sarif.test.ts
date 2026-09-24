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
    if (argv.includes("--version"))
      return { code: 0, stdout: "skill-scanner 2.0.14\n", stderr: "" };
    const target = (argv[argv.indexOf("scan") + 1] ?? "").replaceAll("\\", "/");
    const output = argv[argv.indexOf("--output-sarif") + 1];
    if (output === undefined) return { code: 2, stdout: "", stderr: "no output path" };
    const name = target.split("/").at(-1) ?? "";
    await new Promise((resolve) => setTimeout(resolve, delays?.[name] ?? 0));
    const body = perJob(name);
    writeFileSync(output, typeof body === "string" ? body : JSON.stringify(body), "utf8");
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
    expected: { analyzerVersion: "2.0.14", lockSha256: lock },
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
