import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  CISCO_MULTI_SKILL_SCANNER_PROJECT_V1,
  type CiscoMultiSkillRunnerV1,
  collectCiscoSkillDirsV1,
} from "../../../src/detectors/cisco-multi-skill/plan-v1.js";
import {
  type CiscoShardJobV1,
  type CiscoShardManifestV1,
  ciscoShardSha256V1,
  parseCiscoShardManifestV1,
  runCiscoShardJobsV1,
  runCiscoSourceShardV1,
  verifyCiscoShardSourceV1,
} from "../../../src/detectors/cisco-multi-skill/shard-v1.js";
import { hashComponentTreeV1 } from "../../../src/observation/source-hash-v1.js";

// Parity tests for the shard EXECUTION side of Core's `detector.cisco`
// (`src/trust/detectors.ts` `runCiscoSourceShard`, `verifyCiscoShardSource`;
// `src/trust/cisco-shards.ts` `buildCiscoShardResultAsync`). Ported from
// Core's `tests/trust/cisco-shards.test.ts` execution-side cases. Shard
// manifest build and result join stay in Core; the manifests here are built
// by a test-local helper mirroring Core's builder over the engine's exported
// canonical digests, so the digests are the ones Core's join will recompute.

const SOURCE_SHA = "a".repeat(40);
const INPUT_HASHES = ["1", "2", "3"].map((value) => value.repeat(64));
const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fixtureRoot(prefix: string): string {
  const root = mkdtempSync(join(tmpdir(), prefix));
  roots.push(root);
  return root;
}

function skill(root: string, rel: string, body: string): void {
  const skillDir = join(root, rel);
  mkdirSync(skillDir, { recursive: true });
  writeFileSync(join(skillDir, "SKILL.md"), body, "utf8");
}

function bundledLockSha256(): string {
  return createHash("sha256")
    .update(readFileSync(join(CISCO_MULTI_SKILL_SCANNER_PROJECT_V1, "uv.lock")))
    .digest("hex");
}

/**
 * Test-local mirror of Core's `buildCiscoShardManifest` (which stays in Core),
 * restricted to already-valid fixture inputs and built over the engine's
 * Core-compatible canonical digest.
 */
function buildManifest(input: {
  source: { id: string; pinnedSha: string; treeSha256: string };
  analyzer: { version: string; lockSha256: string };
  policy: { version: string; profile: string };
  jobs: ReadonlyArray<{ path: string; inputSha256: string }>;
  shardCount: number;
}): CiscoShardManifestV1 {
  const jobs: CiscoShardJobV1[] = input.jobs
    .map((job) => ({
      id: ciscoShardSha256V1({ path: job.path, inputSha256: job.inputSha256 }),
      path: job.path,
      inputSha256: job.inputSha256,
    }))
    .sort((left, right) => left.path.localeCompare(right.path));
  const effectiveShardCount = Math.min(input.shardCount, jobs.length);
  const width = Math.max(3, String(effectiveShardCount).length);
  const shards = Array.from({ length: effectiveShardCount }, (_, index) => ({
    id: `${String(index + 1).padStart(width, "0")}-of-${String(effectiveShardCount).padStart(width, "0")}`,
    jobs: [] as CiscoShardJobV1[],
  }));
  for (const [index, job] of jobs.entries()) {
    const shard = shards[index % effectiveShardCount];
    if (shard === undefined) throw new Error("fixture shard assignment failed");
    shard.jobs.push(job);
  }
  const source = { ...input.source };
  const analyzer = { name: "cisco" as const, ...input.analyzer };
  const policy = { ...input.policy };
  const qualificationId = ciscoShardSha256V1({ source, analyzer, policy, jobs });
  const unsigned = {
    schemaVersion: 1 as const,
    qualificationId,
    source,
    analyzer,
    policy,
    jobs,
    shards,
  };
  return { ...unsigned, manifestSha256: ciscoShardSha256V1(unsigned) };
}

/** Mirrors Core's `buildCiscoSourceShardManifest` over a fixture tree. */
function buildSourceManifest(
  root: string,
  options: {
    shardCount: number;
    analyzer?: { version: string; lockSha256: string };
  },
): CiscoShardManifestV1 {
  const safeRoot = realpathSync(root);
  const paths = collectCiscoSkillDirsV1(safeRoot).map((entry) =>
    relative(safeRoot, entry).replace(/\\/g, "/"),
  );
  if (paths.length === 0) throw new Error("fixture tree holds no skills");
  return buildManifest({
    source: {
      id: "ecc",
      pinnedSha: SOURCE_SHA,
      treeSha256: hashComponentTreeV1(safeRoot, paths).treeSha256,
    },
    analyzer: options.analyzer ?? { version: "2.0.14", lockSha256: bundledLockSha256() },
    policy: { version: "native.test", profile: "ecc-full" },
    jobs: paths.map((path) => ({
      path,
      inputSha256: hashComponentTreeV1(safeRoot, [path]).treeSha256,
    })),
    shardCount: options.shardCount,
  });
}

function versionOkRunner(): CiscoMultiSkillRunnerV1 {
  return async () => ({ code: 0, stdout: "skill-scanner 2.0.14\n", stderr: "" });
}

/** Fixture scanner: writes one SARIF result whose message is the SKILL.md heading. */
function scanningRunner(hooks?: {
  beforeOutput?: (target: string) => void;
  invocations?: (scanCount: number) => Record<string, unknown>[];
}): CiscoMultiSkillRunnerV1 {
  let scanCount = 0;
  return async (argv) => {
    if (argv.includes("--version")) {
      return { code: 0, stdout: "skill-scanner 2.0.14\n", stderr: "" };
    }
    const scanIndex = argv.indexOf("scan");
    const outputIndex = argv.indexOf("--output-sarif");
    const target = argv[scanIndex + 1];
    const output = argv[outputIndex + 1];
    if (scanIndex < 0 || outputIndex < 0 || target === undefined || output === undefined) {
      return { code: 2, stdout: "", stderr: "unexpected fixture command" };
    }
    scanCount++;
    hooks?.beforeOutput?.(target);
    const heading = readFileSync(join(target, "SKILL.md"), "utf8").trim();
    writeFileSync(
      output,
      JSON.stringify({
        version: "2.1.0",
        runs: [
          {
            ...(hooks?.invocations === undefined
              ? {}
              : { invocations: hooks.invocations(scanCount) }),
            results: [
              {
                ruleId: "fixture",
                message: { text: heading },
                locations: [
                  {
                    physicalLocation: {
                      artifactLocation: { uri: "SKILL.md" },
                      region: { startLine: 1 },
                    },
                  },
                ],
              },
            ],
          },
        ],
      }),
      "utf8",
    );
    return { code: 0, stdout: "", stderr: "" };
  };
}

describe("runCiscoSourceShardV1", () => {
  it("runs disjoint source shards with exact input identity and prefixed evidence", async () => {
    // The execution half of Core tests/trust/cisco-shards.test.ts:212 — shard
    // results carry each shard's jobs in order with source-prefixed URIs. The
    // join-side assertions of that test stay in Core with the join.
    const root = fixtureRoot("aih-cisco-shards-");
    for (const name of ["alpha", "beta", "gamma"]) {
      skill(root, join("skills", name), `# ${name}\n`);
    }
    const plan = buildSourceManifest(root, { shardCount: 2 });

    expect(plan.shards.map((shard) => shard.jobs.map((job) => job.path))).toEqual([
      ["skills/alpha", "skills/gamma"],
      ["skills/beta"],
    ]);

    const workerResults = await Promise.all(
      [...plan.shards].reverse().map((shard) =>
        runCiscoSourceShardV1(root, plan, shard.id, {
          run: scanningRunner(),
          platform: "linux",
          env: {},
          concurrency: 2,
        }),
      ),
    );
    const byShardId = new Map(workerResults.map((result) => [result.shardId, result]));

    for (const shard of plan.shards) {
      const result = byShardId.get(shard.id);
      expect(result).toBeDefined();
      expect(result?.manifestSha256).toBe(plan.manifestSha256);
      expect(result?.qualificationId).toBe(plan.qualificationId);
      expect(result?.analyzer).toEqual(plan.analyzer);
      expect(result?.outputs.map((output) => output.path)).toEqual(
        shard.jobs.map((job) => job.path),
      );
      for (const output of result?.outputs ?? []) {
        expect(output.evidenceSha256).toBe(ciscoShardSha256V1(output.evidence));
        const evidence = output.evidence as {
          runs: Array<{
            results: Array<{
              message: { text: string };
              locations: Array<{
                physicalLocation: { artifactLocation: { uri: string } };
              }>;
            }>;
          }>;
        };
        const result0 = evidence.runs[0]?.results[0];
        expect(result0?.message.text).toBe(`# ${output.path.split("/")[1] ?? ""}`);
        expect(result0?.locations[0]?.physicalLocation.artifactLocation.uri).toBe(
          `${output.path}/SKILL.md`,
        );
      }
    }
  });

  it("refuses to run a shard after its exact source input drifts", async () => {
    // Ported from Core tests/trust/cisco-shards.test.ts:299.
    const root = fixtureRoot("aih-cisco-shards-drift-");
    skill(root, join("skills", "alpha"), "# alpha\n");
    const plan = buildSourceManifest(root, { shardCount: 1 });
    writeFileSync(join(root, "skills", "alpha", "SKILL.md"), "# changed\n", "utf8");
    const shard = plan.shards[0];
    if (shard === undefined) throw new Error("fixture shard missing");

    await expect(
      runCiscoSourceShardV1(root, plan, shard.id, {
        run: versionOkRunner(),
        platform: "linux",
        env: {},
      }),
    ).rejects.toThrow(/source tree.*exact manifest identity/i);
  });

  it("removes volatile Cisco invocation timestamps before evidence hashing", async () => {
    // Ported from Core tests/trust/cisco-shards.test.ts:324 (execution side).
    const root = fixtureRoot("aih-cisco-shards-time-");
    skill(root, join("skills", "alpha"), "# alpha\n");
    const plan = buildSourceManifest(root, { shardCount: 1 });
    const run = scanningRunner({
      invocations: (scanCount) => [
        {
          executionSuccessful: true,
          startTimeUtc: `2026-07-30T00:00:0${scanCount}Z`,
          endTimeUtc: `2026-07-30T00:00:1${scanCount}Z`,
        },
      ],
    });
    const shard = plan.shards[0];
    if (shard === undefined) throw new Error("fixture shard missing");

    const first = await runCiscoSourceShardV1(root, plan, shard.id, {
      run,
      platform: "linux",
      env: {},
    });
    const second = await runCiscoSourceShardV1(root, plan, shard.id, {
      run,
      platform: "linux",
      env: {},
    });

    expect(second.outputs[0]?.evidenceSha256).toBe(first.outputs[0]?.evidenceSha256);
    const evidence = second.outputs[0]?.evidence as {
      runs: Array<{ invocations?: Array<Record<string, unknown>> }>;
    };
    expect(evidence.runs[0]?.invocations).toEqual([{ executionSuccessful: true }]);
  });

  it("fails closed when the local analyzer lock does not match the manifest", async () => {
    const root = fixtureRoot("aih-cisco-shards-lock-");
    skill(root, join("skills", "alpha"), "# alpha\n");
    const plan = buildSourceManifest(root, {
      shardCount: 1,
      analyzer: { version: "2.0.14", lockSha256: "0".repeat(64) },
    });
    let invoked = false;
    const run: CiscoMultiSkillRunnerV1 = async () => {
      invoked = true;
      return { code: 0, stdout: "skill-scanner 2.0.14\n", stderr: "" };
    };
    const shard = plan.shards[0];
    if (shard === undefined) throw new Error("fixture shard missing");

    await expect(
      runCiscoSourceShardV1(root, plan, shard.id, { run, platform: "linux", env: {} }),
    ).rejects.toThrow(
      new RegExp(
        `Cisco shard analyzer lock does not match manifest identity: ${bundledLockSha256()}`,
      ),
    );
    expect(invoked).toBe(false);
  });

  it("takes the expected analyzer version from the manifest, build metadata dropped", async () => {
    const root = fixtureRoot("aih-cisco-shards-version-");
    skill(root, join("skills", "alpha"), "# alpha\n");
    const shard = (version: string) => {
      const plan = buildSourceManifest(root, {
        shardCount: 1,
        analyzer: { version, lockSha256: bundledLockSha256() },
      });
      const shardEntry = plan.shards[0];
      if (shardEntry === undefined) throw new Error("fixture shard missing");
      return { plan, shardId: shardEntry.id };
    };

    const pinned = shard("2.0.14+uvlock.deadbeef");
    const result = await runCiscoSourceShardV1(root, pinned.plan, pinned.shardId, {
      run: scanningRunner(),
      platform: "linux",
      env: {},
    });
    expect(result.outputs).toHaveLength(1);

    const mismatched = shard("9.9.9");
    await expect(
      runCiscoSourceShardV1(root, mismatched.plan, mismatched.shardId, {
        run: scanningRunner(),
        platform: "linux",
        env: {},
      }),
    ).rejects.toThrow(
      'Cisco shard analyzer unavailable: skill-scanner version "skill-scanner 2.0.14" does not match 9.9.9',
    );
  });

  it("detects input drift during a job's scan", async () => {
    const root = fixtureRoot("aih-cisco-shards-during-");
    skill(root, join("skills", "alpha"), "# alpha\n");
    const plan = buildSourceManifest(root, { shardCount: 1 });
    const shard = plan.shards[0];
    if (shard === undefined) throw new Error("fixture shard missing");
    const run = scanningRunner({
      beforeOutput: (target) => {
        writeFileSync(join(target, "SKILL.md"), "# mutated during scan\n", "utf8");
      },
    });

    await expect(
      runCiscoSourceShardV1(root, plan, shard.id, { run, platform: "linux", env: {} }),
    ).rejects.toThrow("Cisco shard input identity changed during scan: skills/alpha");
  });

  it("detects input drift before a later job's scan", async () => {
    const root = fixtureRoot("aih-cisco-shards-before-");
    skill(root, join("skills", "alpha"), "# alpha\n");
    skill(root, join("skills", "beta"), "# beta\n");
    const plan = buildSourceManifest(root, { shardCount: 1 });
    const shard = plan.shards[0];
    if (shard === undefined) throw new Error("fixture shard missing");
    const run = scanningRunner({
      beforeOutput: (target) => {
        if (target.endsWith("alpha")) {
          writeFileSync(join(root, "skills", "beta", "SKILL.md"), "# mutated early\n", "utf8");
        }
      },
    });

    await expect(
      runCiscoSourceShardV1(root, plan, shard.id, {
        run,
        platform: "linux",
        env: {},
        concurrency: 1,
      }),
    ).rejects.toThrow("Cisco shard input identity changed before scan: skills/beta");
  });
});

describe("runCiscoShardJobsV1", () => {
  function fakePlan(shardCount = 1): CiscoShardManifestV1 {
    return buildManifest({
      source: { id: "ecc", pinnedSha: SOURCE_SHA, treeSha256: "b".repeat(64) },
      analyzer: { version: "2.0.14", lockSha256: "c".repeat(64) },
      policy: { version: "native.test", profile: "ecc-full" },
      jobs: INPUT_HASHES.map((inputSha256, index) => ({
        path: `skills/skill-${index}`,
        inputSha256,
      })),
      shardCount,
    });
  }

  it("rejects a manifest whose identity does not match its contents", async () => {
    // The async-variant half of Core tests/trust/cisco-shards.test.ts:196.
    const plan = fakePlan();
    const shard = plan.shards[0];
    if (shard === undefined) throw new Error("fixture shard missing");

    await expect(
      runCiscoShardJobsV1(
        { ...plan, policy: { ...plan.policy, profile: "drifted" } },
        shard.id,
        async () => ({}),
      ),
    ).rejects.toThrow(/manifest identity/);
  });

  it("rejects an unexpected shard id", async () => {
    const plan = fakePlan();

    await expect(runCiscoShardJobsV1(plan, "999-of-999", async () => ({}))).rejects.toThrow(
      "unexpected Cisco shard id: 999-of-999",
    );
  });

  it("bounds worker concurrency to an integer from 1 through 64", async () => {
    // Ported from Core tests/trust/cisco-shards.test.ts:202.
    const plan = fakePlan();
    const shard = plan.shards[0];
    if (shard === undefined) throw new Error("fixture shard missing");

    for (const concurrency of [0, 65, 1.5]) {
      await expect(
        runCiscoShardJobsV1(plan, shard.id, async () => ({}), concurrency),
      ).rejects.toThrow("Cisco shard worker concurrency must be an integer from 1 through 64");
    }
  });

  it("propagates worker failures and reports the lowest-index one", async () => {
    // Core tests/trust/cisco-shards.test.ts:205, extended to pin the
    // lowest-index selection the drain rule promises.
    const plan = fakePlan();
    const shard = plan.shards[0];
    if (shard === undefined) throw new Error("fixture shard missing");

    await expect(
      runCiscoShardJobsV1(plan, shard.id, async () => {
        throw new Error("worker failed");
      }),
    ).rejects.toThrow(/worker failed/);

    await expect(
      runCiscoShardJobsV1(
        plan,
        shard.id,
        async (job) => {
          if (job.path === "skills/skill-1") {
            await new Promise((resolvePromise) => setTimeout(resolvePromise, 5));
            throw new Error("failure-1");
          }
          if (job.path === "skills/skill-0") {
            await new Promise((resolvePromise) => setTimeout(resolvePromise, 30));
            throw new Error("failure-0");
          }
          await new Promise((resolvePromise) => setTimeout(resolvePromise, 40));
          return {};
        },
        3,
      ),
    ).rejects.toThrow(/^failure-0$/);
  });

  it("rejects evidence values Core's canonicalization cannot digest", async () => {
    // Ported from Core tests/trust/cisco-shards.test.ts:192 (async variant).
    const plan = fakePlan();
    const shard = plan.shards[0];
    if (shard === undefined) throw new Error("fixture shard missing");

    await expect(runCiscoShardJobsV1(plan, shard.id, async () => 1n)).rejects.toThrow(
      /unsupported bigint/,
    );
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    await expect(runCiscoShardJobsV1(plan, shard.id, async () => cyclic)).rejects.toThrow(
      /must not contain cycles/,
    );
  });

  it("digests evidence with Core's localeCompare key order, skipping undefined", () => {
    expect(ciscoShardSha256V1({ b: 1, a: 2, omitted: undefined })).toBe(
      ciscoShardSha256V1({ a: 2, b: 1 }),
    );
  });
});

describe("verifyCiscoShardSourceV1", () => {
  it("reports the first job whose input identity drifted", () => {
    const root = fixtureRoot("aih-cisco-shards-verify-");
    skill(root, join("skills", "alpha"), "# alpha\n");
    const safeRoot = realpathSync(root);
    const plan = buildManifest({
      source: {
        id: "ecc",
        pinnedSha: SOURCE_SHA,
        treeSha256: hashComponentTreeV1(safeRoot, ["skills/alpha"]).treeSha256,
      },
      analyzer: { version: "2.0.14", lockSha256: "c".repeat(64) },
      policy: { version: "native.test", profile: "ecc-full" },
      jobs: [{ path: "skills/alpha", inputSha256: "f".repeat(64) }],
      shardCount: 1,
    });

    expect(() => verifyCiscoShardSourceV1(safeRoot, plan)).toThrow(
      "Cisco shard input identity changed: skills/alpha",
    );
  });

  it("hashes shard inputs exactly as Core's component tree hash", () => {
    // Known-answer pin of Core's hashComponentTree serialization for the
    // fixture tree skills/alpha/SKILL.md = "# alpha\n": the tree digest is the
    // sha256 of the JSON entry list Core's algorithm produces. A drift between
    // Scan's hashComponentTreeV1 and Core's hashComponentTree breaks here.
    const root = fixtureRoot("aih-cisco-shards-hash-");
    skill(root, join("skills", "alpha"), "# alpha\n");

    const hashed = hashComponentTreeV1(realpathSync(root), ["skills/alpha"]);

    expect(hashed.files).toEqual([
      {
        path: "skills/alpha/SKILL.md",
        bytes: 8,
        sha256: "a6098732ccd311fb1f4cf46a2e05389ac24f7207f9be513a0d1d423d8109b2c7",
      },
    ]);
    expect(hashed.treeSha256).toBe(
      "ec2f5f48219eb13c264eb2698ab4e51a8a3639a293a7c768e9267a467d6b5e06",
    );
  });
});

describe("parseCiscoShardManifestV1", () => {
  it("round-trips a Core-shaped manifest", () => {
    const plan = buildManifest({
      source: { id: "ecc", pinnedSha: SOURCE_SHA, treeSha256: "b".repeat(64) },
      analyzer: { version: "2.0.14", lockSha256: "c".repeat(64) },
      policy: { version: "native.test", profile: "ecc-full" },
      jobs: [{ path: "skills/alpha", inputSha256: INPUT_HASHES[0] ?? "0".repeat(64) }],
      shardCount: 1,
    });

    expect(parseCiscoShardManifestV1(JSON.parse(JSON.stringify(plan)))).toEqual(plan);
  });

  it.each([
    [{ schemaVersion: 2 }, /invalid Cisco shard manifest V1/],
    [{ extra: true }, /invalid Cisco shard manifest V1/],
  ])("rejects malformed manifests %j", (patch, pattern) => {
    const plan = buildManifest({
      source: { id: "ecc", pinnedSha: SOURCE_SHA, treeSha256: "b".repeat(64) },
      analyzer: { version: "2.0.14", lockSha256: "c".repeat(64) },
      policy: { version: "native.test", profile: "ecc-full" },
      jobs: [{ path: "skills/alpha", inputSha256: INPUT_HASHES[0] ?? "0".repeat(64) }],
      shardCount: 1,
    });
    expect(() => parseCiscoShardManifestV1({ ...plan, ...patch })).toThrow(pattern);
  });

  it("rejects unsafe job paths with Core's rule", () => {
    const plan = buildManifest({
      source: { id: "ecc", pinnedSha: SOURCE_SHA, treeSha256: "b".repeat(64) },
      analyzer: { version: "2.0.14", lockSha256: "c".repeat(64) },
      policy: { version: "native.test", profile: "ecc-full" },
      jobs: [{ path: "skills/alpha", inputSha256: INPUT_HASHES[0] ?? "0".repeat(64) }],
      shardCount: 1,
    });
    const job = plan.jobs[0];
    if (job === undefined) throw new Error("fixture job missing");

    expect(() =>
      parseCiscoShardManifestV1({ ...plan, jobs: [{ ...job, path: "../escape" }] }),
    ).toThrow(/invalid Cisco shard manifest V1:.*safe POSIX/s);
  });
});
