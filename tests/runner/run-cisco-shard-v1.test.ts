import { createHash } from "node:crypto";
import {
  appendFileSync,
  chmodSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { BaselineProcessRunnerV1 } from "../../src/baseline/runtime-v1.js";
import { resolveDetectorCapabilityV1 } from "../../src/capability/detector-capability-v1.js";
import { hashComponentTreeV1 } from "../../src/observation/source-hash-v1.js";
import { runCiscoShardV1 } from "../../src/runner/run-cisco-shard-v1.js";

/**
 * C2a §3.7 through the public boundary: one exact-source Cisco shard, its lock proven
 * against the named profile's published analyzerLock, its version gated, its job paths
 * sealed at the start and the end, the lowest-index failure reported, no partial output.
 */

const HOST = "host-process-uv-v1";
const windows = process.platform === "win32";
const roots: string[] = [];

afterEach(() => {
  vi.restoreAllMocks();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function temporary(label: string): string {
  const root = mkdtempSync(join(tmpdir(), `aih-scan-shard-${label}-`));
  roots.push(root);
  return root;
}

function baseline(skills: readonly string[] = ["a", "b", "c"]): string {
  const root = temporary("source");
  for (const skill of skills) {
    mkdirSync(join(root, "skills", skill), { recursive: true });
    writeFileSync(join(root, "skills", skill, "SKILL.md"), `# Skill ${skill}\n`);
  }
  writeFileSync(join(root, "README.md"), "# not part of any job\n");
  return realpathSync.native(root);
}

function jobsFor(root: string, skills: readonly string[] = ["a", "b", "c"]) {
  return skills.map((skill) => ({
    id: `job-${skill}`,
    path: `skills/${skill}`,
    inputSha256: hashComponentTreeV1(root, [`skills/${skill}`]).treeSha256,
  }));
}

const lockOf = (profileId: string) =>
  resolveDetectorCapabilityV1("detector.cisco")?.executionProfiles.find(
    (entry) => entry.id === profileId,
  )?.analyzerLock?.sha256 ?? "";

function hostEnv() {
  const root = temporary("host");
  const bin = join(root, "bin");
  const home = join(root, "home");
  mkdirSync(bin, { recursive: true });
  mkdirSync(join(home, "AppData", "Local"), { recursive: true });
  const uvFile = join(bin, windows ? "uv.exe" : "uv");
  writeFileSync(uvFile, "fake uv\n");
  if (!windows) chmodSync(uvFile, 0o755);
  const python = join(root, windows ? "python.exe" : "python3.12");
  writeFileSync(python, "fake python\n");
  const env: Record<string, string> = windows
    ? {
        PATH: bin,
        USERPROFILE: home,
        LOCALAPPDATA: join(home, "AppData", "Local"),
        APPDATA: join(home, "AppData", "Roaming"),
      }
    : { PATH: bin, HOME: home };
  return { env, python };
}

const ok = (stdout: string) => ({ code: 0, stdout, stderr: "", truncated: false });
const jobSarif = (skill: string) =>
  JSON.stringify({
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "skill-scanner" } },
        invocations: [{ executionSuccessful: true }],
        results: [
          {
            ruleId: `cisco.rule-${skill}`,
            message: { text: `finding in ${skill}` },
            locations: [{ physicalLocation: { artifactLocation: { uri: "SKILL.md" } } }],
          },
        ],
      },
    ],
  });

type Scan = { argv: readonly string[]; cwd: string | undefined };

function shardHost(
  python: string,
  scans: Scan[],
  onScan: (
    skill: string,
    skillDir: string,
  ) => ReturnType<BaselineProcessRunnerV1> | undefined = () => undefined,
  version = "skill-scanner 2.1.0\n",
): BaselineProcessRunnerV1 {
  return async (argv, options) => {
    if (argv[1] === "--version") return ok("uv 0.12.13 (0123456 2026-09-01 x86_64)");
    if (argv[1] === "python" && argv[2] === "find")
      return ok(argv.includes("--show-version") ? "3.12.13\n" : `${python}\n`);
    if (argv[1] === "sync") return ok("");
    if (argv.at(-1) === "--version") return ok(version);
    scans.push({ argv: [...argv], cwd: options.cwd });
    const skillDir = argv[argv.indexOf("scan") + 1] ?? "";
    const skill = skillDir.split(/[\\/]/).at(-1) ?? "";
    const special = onScan(skill, skillDir);
    if (special !== undefined) return special;
    writeFileSync(argv[argv.indexOf("--output-sarif") + 1] ?? "", jobSarif(skill));
    return ok("");
  };
}

function forbiddenRunner(record: { calls: number }): BaselineProcessRunnerV1 {
  return async (argv) => {
    record.calls += 1;
    throw new Error(`no process may be spawned here: ${argv.join(" ")}`);
  };
}

function shardRequest(root: string, extra: Record<string, unknown> = {}) {
  return {
    sourceRoot: root,
    jobs: jobsFor(root),
    expected: { analyzerVersion: "2.1.0", lockSha256: lockOf(HOST) },
    executionProfileId: HOST,
    concurrency: 2,
    ...extra,
  };
}

describe("runCiscoShardV1", () => {
  it("returns one prefixed SARIF per job, in job order, with its sha256 and the job-path seals", async () => {
    const root = baseline();
    const host = hostEnv();
    const scans: Scan[] = [];

    const outcome = await runCiscoShardV1(
      shardRequest(root, { env: host.env, runner: shardHost(host.python, scans) }),
    );

    expect(outcome.outcome).toBe("succeeded");
    if (outcome.outcome !== "succeeded") return;
    expect(outcome.executionProfile.id).toBe(HOST);
    expect(outcome.producer.name).toBe("@aihq/scan");
    expect(outcome.analyzer).toEqual({ version: "2.1.0", lockSha256: lockOf(HOST) });
    expect(outcome.outputs.map((output) => output.jobId)).toEqual(["job-a", "job-b", "job-c"]);
    for (const [index, output] of outcome.outputs.entries()) {
      const skill = ["a", "b", "c"][index];
      expect(output.sha256).toBe(createHash("sha256").update(output.sarif).digest("hex"));
      const sarif = JSON.parse(Buffer.from(output.sarif).toString("utf8"));
      expect(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toBe(
        `skills/${skill}/SKILL.md`,
      );
    }
    expect(outcome.sourceSeal.after).toBe(outcome.sourceSeal.before);
    // Each job scans its exact directory of the pinned root, from inside it.
    for (const scan of scans) expect(scan.cwd).toBe(scan.argv[scan.argv.indexOf("scan") + 1]);
  });

  it.each([
    [
      "another analyzer's lock",
      () =>
        resolveDetectorCapabilityV1("detector.semgrep")?.executionProfiles.find(
          (entry) => entry.id === HOST,
        )?.analyzerLock?.sha256 ?? "",
    ],
    ["an unrelated digest", () => "0".repeat(64)],
  ])("refuses %s under host-process-uv-v1 before anything runs", async (_label, lock) => {
    const root = baseline();
    const record = { calls: 0 };

    const outcome = await runCiscoShardV1(
      shardRequest(root, {
        expected: { analyzerVersion: "2.1.0", lockSha256: lock() },
        env: hostEnv().env,
        runner: forbiddenRunner(record),
      }),
    );

    expect(outcome).toMatchObject({ outcome: "refused", reason: "analyzer-lock-mismatch" });
    expect(record.calls).toBe(0);
  });

  it.each([
    ["linux-namespace-uv-v1", /not implemented in this build/],
    ["oci-hardened-cisco-v1", /host-process-uv-v1/],
    ["no-such-profile", /host-process-uv-v1/],
    [undefined, /host-process-uv-v1/],
  ])("refuses shard execution under %s", async (executionProfileId, detail) => {
    const record = { calls: 0 };
    const outcome = await runCiscoShardV1(
      shardRequest(baseline(), { executionProfileId, runner: forbiddenRunner(record) }),
    );
    expect(outcome).toMatchObject({ outcome: "refused", reason: "execution-profile-unavailable" });
    expect(outcome.outcome === "refused" && outcome.detail).toMatch(detail);
    expect(record.calls).toBe(0);
  });

  it.each([
    ["a dot-slash path", { path: "./skills/a" }],
    ["a parent segment", { path: "skills/../skills/a" }],
    ["an absolute path", { path: "/skills/a" }],
    ["a backslash", { path: "skills\\a" }],
    ["a trailing slash", { path: "skills/a/" }],
    ["a directory without SKILL.md", { path: "skills" }],
    ["a non-digest identity", { inputSha256: "abc" }],
  ])("refuses a job with %s before anything runs", async (_label, change) => {
    const root = baseline();
    const record = { calls: 0 };
    const [first, ...rest] = jobsFor(root);

    const outcome = await runCiscoShardV1(
      shardRequest(root, {
        jobs: [{ ...first, ...change }, ...rest],
        env: hostEnv().env,
        runner: forbiddenRunner(record),
      }),
    );

    expect(outcome).toMatchObject({ outcome: "refused", reason: "shard-request-invalid" });
    expect(record.calls).toBe(0);
  });

  it.each([
    ["duplicate job ids", (root: string) => ({ jobs: [jobsFor(root)[0], jobsFor(root)[0]] })],
    ["no jobs", () => ({ jobs: [] })],
    ["concurrency 0", () => ({ concurrency: 0 })],
    ["concurrency 65", () => ({ concurrency: 65 })],
    ["a non-array jobs field", () => ({ jobs: "skills/a" })],
  ])("refuses %s before anything runs", async (_label, change) => {
    const root = baseline();
    const record = { calls: 0 };
    const outcome = await runCiscoShardV1(
      shardRequest(root, { ...change(root), env: hostEnv().env, runner: forbiddenRunner(record) }),
    );
    expect(outcome).toMatchObject({ outcome: "refused", reason: "shard-request-invalid" });
    expect(record.calls).toBe(0);
  });

  it("refuses a request whose fields cannot be read, and never rejects", async () => {
    const hostile = shardRequest(baseline());
    Object.defineProperty(hostile, "jobs", {
      get() {
        throw new Error("hostile jobs accessor");
      },
    });
    const outcome = await runCiscoShardV1(hostile);
    expect(outcome).toMatchObject({ outcome: "refused", reason: "shard-request-invalid" });
    expect(await runCiscoShardV1(null)).toMatchObject({ outcome: "refused" });
  });

  it("gates the analyzer version before any job runs", async () => {
    const root = baseline();
    const host = hostEnv();
    const scans: Scan[] = [];
    const outcome = await runCiscoShardV1(
      shardRequest(root, {
        expected: { analyzerVersion: "2.1.0+core.1", lockSha256: lockOf(HOST) },
        env: host.env,
        runner: shardHost(host.python, scans, undefined, "skill-scanner 2.0.13\n"),
      }),
    );
    expect(outcome).toMatchObject({ outcome: "failed", failure: { stage: "availability" } });
    expect(scans).toHaveLength(0);
  });

  it("reports the lowest-index failing job and returns no partial outputs", async () => {
    const root = baseline();
    const host = hostEnv();
    const outcome = await runCiscoShardV1(
      shardRequest(root, {
        concurrency: 3,
        env: host.env,
        runner: shardHost(host.python, [], (skill) =>
          skill === "b" || skill === "c"
            ? Promise.resolve({
                code: 1,
                stdout: "",
                stderr: `job-${skill}-broke`,
                truncated: false,
              })
            : undefined,
        ),
      }),
    );
    expect(outcome).toMatchObject({ outcome: "failed", failure: { stage: "execution" } });
    if (outcome.outcome !== "failed") return;
    expect(outcome.failure.detail).toContain("job-b-broke");
    expect(outcome.failure.detail).not.toContain("job-c-broke");
    expect("outputs" in outcome).toBe(false);
    expect(outcome.executionProfile.id).toBe(HOST);
  });

  it("fails coverage when a job's source changes during the shard", async () => {
    const root = baseline();
    const host = hostEnv();
    const outcome = await runCiscoShardV1(
      shardRequest(root, {
        concurrency: 1,
        env: host.env,
        runner: shardHost(host.python, [], (skill, skillDir) => {
          if (skill === "a") appendFileSync(join(skillDir, "SKILL.md"), "changed\n");
          return undefined;
        }),
      }),
    );
    expect(outcome).toMatchObject({ outcome: "failed", failure: { stage: "coverage" } });
    expect(outcome.outcome === "failed" && outcome.failure.detail).toMatch(/source changed/);
  });

  it.each([
    ["timeout", "timed-out"],
    ["abort", "cancelled"],
  ] as const)("reports a job ended by %s as %s", async (termination, cause) => {
    const root = baseline();
    const host = hostEnv();
    const outcome = await runCiscoShardV1(
      shardRequest(root, {
        env: host.env,
        runner: shardHost(host.python, [], () =>
          Promise.resolve({ code: 1, stdout: "", stderr: "", truncated: false, termination }),
        ),
      }),
    );
    expect(outcome.outcome).toBe("failed");
    if (outcome.outcome !== "failed") return;
    expect(outcome.failure.cause).toBe(cause);
  });

  it("fails as cancelled, spawning nothing, when the signal has already fired", async () => {
    const record = { calls: 0 };
    const controller = new AbortController();
    controller.abort();
    const outcome = await runCiscoShardV1(
      shardRequest(baseline(), {
        env: hostEnv().env,
        signal: controller.signal,
        runner: forbiddenRunner(record),
      }),
    );
    expect(outcome).toMatchObject({ outcome: "failed", failure: { cause: "cancelled" } });
    expect(record.calls).toBe(0);
  });
});
