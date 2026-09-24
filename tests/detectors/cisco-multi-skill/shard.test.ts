import { createHash } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  CISCO_MULTI_SKILL_SCANNER_PROJECT_V1,
  type CiscoMultiSkillRunnerV1,
} from "../../../src/detectors/cisco-multi-skill/plan-v1.js";
import {
  type CiscoShardJobV1,
  ciscoSkillScannerLockSha256V1,
  runCiscoShardV1,
} from "../../../src/detectors/cisco-multi-skill/shard-v1.js";
import { hashComponentTreeV1 } from "../../../src/observation/source-hash-v1.js";
import {
  completionOfLogV1,
  diskFilesV1,
  diskSubjectV1,
} from "../../runner/completion-evidence-support.js";

// Parity tests for the shard EXECUTION side of Core's `detector.cisco`
// (`src/trust/detectors.ts` `runCiscoSourceShard`), ported from Core's
// `tests/trust/cisco-shards.test.ts` execution-side cases onto the C2a §3.7
// engine function. Shard manifest build, evidence digests and the join stay
// in Core; jobs here are what Core's manifest would list for the fixture.

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

/** Fixture scanner: writes one SARIF result whose message is the SKILL.md heading. */
function scanningRunner(hooks?: {
  beforeOutput?: (target: string) => void;
  invocations?: (scanCount: number) => Record<string, unknown>[];
  /** S2g: the job's result locations (default: one `SKILL.md` location). */
  locations?: (target: string) => unknown[] | undefined;
  /** S2g: extra run properties, such as `originalUriBaseIds`. */
  run?: (target: string) => Record<string, unknown>;
  /** S2h: extra result properties, such as `relatedLocations` or `codeFlows`. */
  result?: (target: string) => Record<string, unknown>;
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
            tool: { driver: { name: "skill-scanner", version: "1.0.0" } },
            // Real skill-scanner reports its invocation; a job's SARIF must prove completion (S2e).
            invocations: hooks?.invocations?.(scanCount) ?? [{ executionSuccessful: true }],
            results: [
              {
                ruleId: "fixture",
                message: { text: heading },
                ...fixtureLocations(hooks?.locations, target),
                ...(hooks?.result?.(target) ?? {}),
              },
            ],
            ...(hooks?.run?.(target) ?? {}),
          },
        ],
      }),
      "utf8",
    );
    return { code: 0, stdout: "", stderr: "" };
  };
}

/** A fixture result's `locations` property: the hook's list, none, or one `SKILL.md`. */
function fixtureLocations(
  hook: ((target: string) => unknown[] | undefined) | undefined,
  target: string,
): Record<string, unknown> {
  if (hook === undefined)
    return {
      locations: [
        { physicalLocation: { artifactLocation: { uri: "SKILL.md" }, region: { startLine: 1 } } },
      ],
    };
  const locations = hook(target);
  return locations === undefined ? {} : { locations };
}

/** Source-relative directories holding a SKILL.md, sorted (the fixture manifest's jobs). */
function skillPaths(root: string, prefix = ""): string[] {
  const entries = readdirSync(join(root, prefix), { withFileTypes: true });
  const own = entries.some((entry) => entry.isFile() && entry.name === "SKILL.md") ? [prefix] : [];
  return [
    ...own,
    ...entries
      .filter((entry) => entry.isDirectory())
      .flatMap((entry) =>
        skillPaths(root, prefix.length === 0 ? entry.name : `${prefix}/${entry.name}`),
      ),
  ]
    .filter((path) => path.length > 0)
    .sort((left, right) => left.localeCompare(right));
}

describe("hashComponentTreeV1 (Core hashComponentTree parity)", () => {
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

describe("runCiscoShardV1", () => {
  // C2a §3.7: the shard execution engine function behind Core's future
  // `runCiscoShardV1` export. Boundary validation is a typed refusal, source
  // drift is a typed coverage failure, and outputs carry per-job SARIF bytes
  // with their plain sha256.
  function shardRequestJobs(root: string): CiscoShardJobV1[] {
    const safeRoot = realpathSync(root);
    return skillPaths(safeRoot).map((path) => ({
      id: createHash("sha256").update(path).digest("hex"),
      path,
      inputSha256: hashComponentTreeV1(safeRoot, [path]).treeSha256,
    }));
  }

  function shardRequest(
    root: string,
    overrides?: {
      jobs?: CiscoShardJobV1[];
      expected?: { analyzerVersion: string; lockSha256: string };
      concurrency?: number;
      run?: CiscoMultiSkillRunnerV1;
    },
  ) {
    return {
      run: overrides?.run ?? scanningRunner(),
      platform: "linux" as const,
      env: {},
      sourceRoot: root,
      jobs: overrides?.jobs ?? shardRequestJobs(root),
      expected: overrides?.expected ?? {
        analyzerVersion: "2.0.14",
        lockSha256: bundledLockSha256(),
      },
      concurrency: overrides?.concurrency ?? 2,
    };
  }

  it("runs the shard's jobs and returns per-job SARIF bytes with their sha256", async () => {
    const root = fixtureRoot("aih-cisco-shard-v1-");
    skill(root, join("skills", "alpha"), "# alpha\n");
    skill(root, join("skills", "beta"), "# beta\n");
    const run = scanningRunner({
      invocations: () => [
        {
          executionSuccessful: true,
          startTimeUtc: "2026-07-30T00:00:00Z",
          endTimeUtc: "2026-07-30T00:00:10Z",
        },
      ],
    });
    const jobs = shardRequestJobs(root);

    const outcome = await runCiscoShardV1(shardRequest(root, { jobs, run }));

    expect(outcome.kind).toBe("completed");
    if (outcome.kind !== "completed") return;
    expect(outcome.analyzer).toEqual({ version: "2.0.14", lockSha256: bundledLockSha256() });
    expect(outcome.sourceSeal.before).toBe(outcome.sourceSeal.after);
    expect(outcome.sourceSeal.before).toMatch(/^[0-9a-f]{64}$/);
    expect(outcome.outputs.map((output) => output.path)).toEqual(["skills/alpha", "skills/beta"]);
    for (const [index, output] of outcome.outputs.entries()) {
      expect(output.jobId).toBe(jobs[index]?.id);
      expect(output.inputSha256).toBe(jobs[index]?.inputSha256);
      expect(output.sarif).toBeInstanceOf(Uint8Array);
      expect(output.sha256).toBe(
        createHash("sha256").update(Buffer.from(output.sarif)).digest("hex"),
      );
      const sarif = JSON.parse(Buffer.from(output.sarif).toString("utf8")) as {
        runs: Array<{
          invocations?: Array<Record<string, unknown>>;
          results: Array<{
            message: { text: string };
            locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }>;
          }>;
        }>;
      };
      // §3.4 applied per job: URIs prefixed, invocation timestamps removed; §1.6 (S2g): the
      // invocation gains Scan's completion evidence for the job.
      expect(sarif.runs[0]?.invocations).toEqual([
        {
          executionSuccessful: true,
          properties: {
            aihScanCompletionV1: expect.objectContaining({
              detectorId: "detector.cisco",
              analyzedFileCount: 1,
            }),
          },
        },
      ]);
      expect(sarif.runs[0]?.results[0]?.message.text).toBe(`# ${output.path.split("/")[1] ?? ""}`);
      expect(sarif.runs[0]?.results[0]?.locations[0]?.physicalLocation.artifactLocation.uri).toBe(
        `${output.path}/SKILL.md`,
      );
    }
  });

  it("checks the expected analyzer version before any `+` suffix against the gate", async () => {
    const root = fixtureRoot("aih-cisco-shard-v1-version-");
    skill(root, join("skills", "alpha"), "# alpha\n");

    const accepted = await runCiscoShardV1(
      shardRequest(root, {
        expected: { analyzerVersion: "2.0.14+uvlock.deadbeef", lockSha256: bundledLockSha256() },
      }),
    );
    expect(accepted.kind).toBe("completed");
    if (accepted.kind === "completed") expect(accepted.analyzer.version).toBe("2.0.14");

    const seenArgv: string[][] = [];
    const mismatchedRun: CiscoMultiSkillRunnerV1 = async (argv) => {
      seenArgv.push([...argv]);
      return { code: 0, stdout: "skill-scanner 2.0.14\n", stderr: "" };
    };
    const rejected = await runCiscoShardV1(
      shardRequest(root, {
        run: mismatchedRun,
        expected: { analyzerVersion: "9.9.9", lockSha256: bundledLockSha256() },
      }),
    );
    expect(rejected).toEqual({
      kind: "failed",
      stage: "availability",
      detail: 'skill-scanner version "skill-scanner 2.0.14" does not match 9.9.9',
    });
    expect(seenArgv.length).toBeGreaterThan(0);
    expect(seenArgv.every((argv) => argv.includes("--version"))).toBe(true);
  });

  it("refuses a lock mismatch before anything runs", async () => {
    const root = fixtureRoot("aih-cisco-shard-v1-lock-");
    skill(root, join("skills", "alpha"), "# alpha\n");
    let invoked = false;
    const run: CiscoMultiSkillRunnerV1 = async () => {
      invoked = true;
      return { code: 0, stdout: "", stderr: "" };
    };

    const outcome = await runCiscoShardV1(
      shardRequest(root, {
        run,
        expected: { analyzerVersion: "2.0.14", lockSha256: "0".repeat(64) },
      }),
    );

    expect(outcome).toEqual({
      kind: "refused",
      reason: "analyzer-lock-mismatch",
      detail: `Cisco shard analyzer lock does not match the expected identity: ${bundledLockSha256()}`,
    });
    expect(invoked).toBe(false);
  });

  it.each([
    ["../escape"],
    ["C:/evil"],
    ["/absolute"],
    ["a//b"],
    ["a/./b"],
    [""],
  ])("refuses the unsafe job path %j before anything runs", async (path) => {
    const root = fixtureRoot("aih-cisco-shard-v1-path-");
    skill(root, join("skills", "alpha"), "# alpha\n");
    let invoked = false;
    const run: CiscoMultiSkillRunnerV1 = async () => {
      invoked = true;
      return { code: 0, stdout: "", stderr: "" };
    };
    const job: CiscoShardJobV1 = {
      id: "e".repeat(64),
      path,
      inputSha256: "f".repeat(64),
    };

    const outcome = await runCiscoShardV1(shardRequest(root, { run, jobs: [job] }));

    expect(outcome.kind).toBe("refused");
    if (outcome.kind !== "refused") return;
    expect(outcome.reason).toBe("shard-request-invalid");
    expect(invoked).toBe(false);
  });

  it("refuses duplicate job ids", async () => {
    const root = fixtureRoot("aih-cisco-shard-v1-dup-");
    skill(root, join("skills", "alpha"), "# alpha\n");
    skill(root, join("skills", "beta"), "# beta\n");
    const jobs = shardRequestJobs(root).map((job) => ({ ...job, id: "e".repeat(64) }));

    const outcome = await runCiscoShardV1(shardRequest(root, { jobs }));

    expect(outcome).toMatchObject({
      kind: "refused",
      reason: "shard-request-invalid",
      detail: `duplicate shard job id: ${"e".repeat(64)}`,
    });
  });

  it("refuses a job path that holds no SKILL.md", async () => {
    const root = fixtureRoot("aih-cisco-shard-v1-noskill-");
    skill(root, join("skills", "alpha"), "# alpha\n");
    mkdirSync(join(root, "docs"), { recursive: true });
    writeFileSync(join(root, "docs", "readme.md"), "# Docs\n", "utf8");
    const jobs: CiscoShardJobV1[] = [
      { id: "e".repeat(64), path: "docs", inputSha256: "f".repeat(64) },
    ];

    const outcome = await runCiscoShardV1(shardRequest(root, { jobs }));

    expect(outcome).toEqual({
      kind: "refused",
      reason: "shard-request-invalid",
      detail: "Cisco shard job path holds no SKILL.md: docs",
    });
  });

  describe("job directory containment", () => {
    // A job path must be a real directory chain inside sourceRoot. The
    // component hash only inspects the job directory and its descendants, so
    // a symlinked (or, on Windows, junction) ANCESTOR used to pass the
    // identity check and send the analyzer outside the declared root.
    function outsideSkill(): string {
      const outside = fixtureRoot("aih-cisco-shard-v1-outside-");
      skill(outside, "skill", "# outside\n");
      return outside;
    }

    /** Creates a directory link, or returns false where the OS refuses it. */
    function directoryLink(target: string, path: string): boolean {
      try {
        symlinkSync(target, path, process.platform === "win32" ? "junction" : "dir");
        return true;
      } catch {
        return false;
      }
    }

    function probeOnlyRunner(calls: string[][]): CiscoMultiSkillRunnerV1 {
      const inner = scanningRunner();
      return async (argv, options) => {
        calls.push([...argv]);
        return inner(argv, options);
      };
    }

    it.for<[string, string, string]>([
      ["a parent component", "link", "link/skill"],
      ["the job directory itself", "link", "link"],
      ["a nested parent component", "skills/link", "skills/link/skill"],
    ])("refuses a job path whose chain crosses a directory link at %s", async ([
      _label,
      linkPath,
      jobPath,
    ], ctx) => {
      const root = fixtureRoot("aih-cisco-shard-v1-link-");
      skill(root, join("skills", "alpha"), "# alpha\n");
      const outside = outsideSkill();
      const target = jobPath === linkPath ? join(outside, "skill") : outside;
      if (!directoryLink(target, join(root, ...linkPath.split("/")))) {
        // This OS/account cannot create a directory link; nothing to prove here.
        ctx.skip();
        return;
      }
      const safeRoot = realpathSync(root);
      // Before the repair this identity matched, because the walker never
      // inspected the linked ancestor.
      const inputSha256 =
        jobPath === linkPath ? "a".repeat(64) : hashComponentTreeV1(safeRoot, [jobPath]).treeSha256;
      const calls: string[][] = [];

      const outcome = await runCiscoShardV1(
        shardRequest(root, {
          jobs: [{ id: "link-job", path: jobPath, inputSha256 }],
          run: probeOnlyRunner(calls),
        }),
      );

      expect(outcome).toEqual({
        kind: "refused",
        reason: "shard-request-invalid",
        detail: `Cisco shard job path crosses a symbolic link or junction: ${jobPath}`,
      });
      expect(calls).toEqual([]);
    });

    it("refuses a job path whose component is a file, not a directory", async () => {
      const root = fixtureRoot("aih-cisco-shard-v1-filecomp-");
      writeFileSync(join(root, "plain"), "not a directory\n", "utf8");

      const outcome = await runCiscoShardV1(
        shardRequest(root, {
          jobs: [{ id: "file-job", path: "plain/skill", inputSha256: "a".repeat(64) }],
        }),
      );

      expect(outcome.kind).toBe("refused");
      if (outcome.kind !== "refused") return;
      expect(outcome.reason).toBe("shard-request-invalid");
      expect(outcome.detail).toContain("plain/skill");
    });
  });

  it.each([
    [0],
    [65],
    [1.5],
    [Number.NaN],
  ])("refuses worker concurrency %j outside 1..64", async (concurrency) => {
    const root = fixtureRoot("aih-cisco-shard-v1-conc-");
    skill(root, join("skills", "alpha"), "# alpha\n");

    const outcome = await runCiscoShardV1(shardRequest(root, { concurrency }));

    expect(outcome).toEqual({
      kind: "refused",
      reason: "shard-request-invalid",
      detail: "shard worker concurrency must be an integer from 1 through 64",
    });
  });

  it("refuses malformed digests and an empty job list", async () => {
    const root = fixtureRoot("aih-cisco-shard-v1-shape-");
    skill(root, join("skills", "alpha"), "# alpha\n");

    const noJobs = await runCiscoShardV1(shardRequest(root, { jobs: [] }));
    expect(noJobs).toMatchObject({ kind: "refused", reason: "shard-request-invalid" });

    const badInput = await runCiscoShardV1(
      shardRequest(root, {
        jobs: [{ id: "e".repeat(64), path: "skills/alpha", inputSha256: "not-a-digest" }],
      }),
    );
    expect(badInput).toMatchObject({ kind: "refused", reason: "shard-request-invalid" });

    const badLock = await runCiscoShardV1(
      shardRequest(root, {
        expected: { analyzerVersion: "2.0.14", lockSha256: "ZZZ" },
      }),
    );
    expect(badLock).toMatchObject({ kind: "refused", reason: "shard-request-invalid" });
  });

  it("fails with stage coverage when a job's input drifts before its scan", async () => {
    const root = fixtureRoot("aih-cisco-shard-v1-drift-before-");
    skill(root, join("skills", "alpha"), "# alpha\n");
    skill(root, join("skills", "beta"), "# beta\n");
    const run = scanningRunner({
      beforeOutput: (target) => {
        if (target.endsWith("alpha")) {
          writeFileSync(join(root, "skills", "beta", "SKILL.md"), "# mutated early\n", "utf8");
        }
      },
    });

    const outcome = await runCiscoShardV1(shardRequest(root, { run, concurrency: 1 }));

    expect(outcome).toEqual({
      kind: "failed",
      stage: "coverage",
      detail: "source changed before scan: skills/beta",
    });
  });

  it("fails with stage coverage when a job's input drifts during its scan", async () => {
    const root = fixtureRoot("aih-cisco-shard-v1-drift-during-");
    skill(root, join("skills", "alpha"), "# alpha\n");
    const run = scanningRunner({
      beforeOutput: (target) => {
        writeFileSync(join(target, "SKILL.md"), "# mutated during scan\n", "utf8");
      },
    });

    const outcome = await runCiscoShardV1(shardRequest(root, { run }));

    expect(outcome).toEqual({
      kind: "failed",
      stage: "coverage",
      detail: "source changed during scan: skills/alpha",
    });
  });

  it("fails with stage coverage when the source drifts behind the last job's back", async () => {
    // Job alpha drifts while job beta scans: beta's own seals pass, and the
    // end-of-shard seal catches the drift.
    const root = fixtureRoot("aih-cisco-shard-v1-drift-after-");
    skill(root, join("skills", "alpha"), "# alpha\n");
    skill(root, join("skills", "beta"), "# beta\n");
    const run = scanningRunner({
      beforeOutput: (target) => {
        if (target.endsWith("beta")) {
          writeFileSync(join(root, "skills", "alpha", "SKILL.md"), "# mutated late\n", "utf8");
        }
      },
    });

    const outcome = await runCiscoShardV1(shardRequest(root, { run, concurrency: 1 }));

    expect(outcome).toEqual({
      kind: "failed",
      stage: "coverage",
      detail:
        "source changed after the shard: skills/alpha no longer matches its declared input identity",
    });
  });

  it("fails with stage coverage when the declared input identity never matched", async () => {
    const root = fixtureRoot("aih-cisco-shard-v1-drift-start-");
    skill(root, join("skills", "alpha"), "# alpha\n");
    const jobs = shardRequestJobs(root).map((job) => ({ ...job, inputSha256: "f".repeat(64) }));
    let scanned = false;
    const base = scanningRunner();
    const run: CiscoMultiSkillRunnerV1 = async (argv, opts) => {
      if (argv.includes("scan")) scanned = true;
      return base(argv, opts);
    };

    const outcome = await runCiscoShardV1(shardRequest(root, { jobs, run }));

    expect(outcome).toEqual({
      kind: "failed",
      stage: "coverage",
      detail:
        "source changed before the shard: skills/alpha no longer matches its declared input identity",
    });
    expect(scanned).toBe(false);
  });

  it("reports a failing job at the execution stage with no partial outputs", async () => {
    const root = fixtureRoot("aih-cisco-shard-v1-fail-");
    skill(root, join("skills", "alpha"), "# alpha\n");
    skill(root, join("skills", "beta"), "# beta\n");
    const run: CiscoMultiSkillRunnerV1 = async (argv) => {
      if (argv.includes("--version")) {
        return { code: 0, stdout: "skill-scanner 2.0.14\n", stderr: "" };
      }
      const target = (argv[argv.indexOf("scan") + 1] ?? "").replaceAll("\\", "/");
      const output = argv[argv.indexOf("--output-sarif") + 1];
      if (output === undefined) return { code: 1, stdout: "", stderr: "missing SARIF path" };
      if (target.endsWith("alpha")) {
        await new Promise((resolvePromise) => setTimeout(resolvePromise, 5));
        return { code: 2, stdout: "", stderr: "fixture shard failure" };
      }
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 30));
      writeFileSync(output, JSON.stringify({ runs: [] }), "utf8");
      return { code: 0, stdout: "", stderr: "" };
    };

    const outcome = await runCiscoShardV1(shardRequest(root, { run, concurrency: 2 }));

    // The union carries no `outputs` on failure: no partial SARIF exists.
    expect(outcome).toEqual({
      kind: "failed",
      stage: "execution",
      detail: "fixture shard failure",
    });
  });

  // S2g (review of U1d): the tree hashes prove the inputs did not change, not that a result
  // names a file the job analyzed. Every result location must name a sealed file of that
  // job's own inventory, or the shard fails at `output` (lowest index, no partial outputs).
  describe("results are bound to their job's sealed files", () => {
    const at = (uri: unknown) => [{ physicalLocation: { artifactLocation: { uri } } }];
    const failsAtOutput = async (
      root: string,
      hooks: Parameters<typeof scanningRunner>[0],
      detail: RegExp,
    ) => {
      const outcome = await runCiscoShardV1(shardRequest(root, { run: scanningRunner(hooks) }));
      expect(outcome).toMatchObject({ kind: "failed", stage: "output" });
      expect(outcome).not.toHaveProperty("outputs");
      if (outcome.kind === "failed") expect(outcome.detail).toMatch(detail);
    };

    it("fails a result naming a file the job does not hold (reviewer: missing.md)", async () => {
      const root = fixtureRoot("aih-cisco-shard-v1-bind-");
      skill(root, join("skills", "alpha"), "# alpha\n");
      await failsAtOutput(
        root,
        { locations: () => at("missing.md") },
        /skills\/alpha\/missing\.md/,
      );
    });

    it("fails a case-folded name the file system might resolve (reviewer: skill.md)", async () => {
      const root = fixtureRoot("aih-cisco-shard-v1-bind-");
      skill(root, join("skills", "alpha"), "# alpha\n");
      await failsAtOutput(root, { locations: () => at("skill.md") }, /skills\/alpha\/skill\.md/);
    });

    it("fails a result without a location or URI, and an unbound further location", async () => {
      const root = fixtureRoot("aih-cisco-shard-v1-bind-");
      skill(root, join("skills", "alpha"), "# alpha\n");
      await failsAtOutput(root, { locations: () => undefined }, /names no sealed file/);
      await failsAtOutput(root, { locations: () => [] }, /names no sealed file/);
      await failsAtOutput(
        root,
        { locations: () => [{ physicalLocation: {} }] },
        /names no sealed file/,
      );
      await failsAtOutput(
        root,
        { locations: () => [...at("SKILL.md"), ...at("ghost.md")] },
        /ghost\.md/,
      );
    });

    it("fails a result naming a sealed file of another job in the same shard", async () => {
      const root = fixtureRoot("aih-cisco-shard-v1-bind-");
      skill(root, join("skills", "alpha"), "# alpha\n");
      skill(root, join("skills", "beta"), "# beta\n");
      const safeRoot = realpathSync(root).replaceAll("\\", "/");
      const rootUri = `file://${safeRoot.startsWith("/") ? "" : "/"}${safeRoot}/`;
      await failsAtOutput(
        root,
        {
          locations: () => [
            {
              physicalLocation: {
                artifactLocation: { uri: "skills/beta/SKILL.md", uriBaseId: "ROOT" },
              },
            },
          ],
          run: () => ({ originalUriBaseIds: { ROOT: { uri: rootUri } } }),
        },
        /skills\/alpha: .*skills\/beta\/SKILL\.md/,
      );
    });

    it("reports the lowest-index unbound job", async () => {
      const root = fixtureRoot("aih-cisco-shard-v1-bind-");
      skill(root, join("skills", "alpha"), "# alpha\n");
      skill(root, join("skills", "beta"), "# beta\n");
      await failsAtOutput(
        root,
        {
          locations: (target) =>
            at(target.replaceAll("\\", "/").endsWith("beta") ? "gone.md" : "SKILL.md"),
        },
        /skills\/beta\/gone\.md/,
      );
      await failsAtOutput(root, { locations: () => at("gone.md") }, /skills\/alpha\/gone\.md/);
    });

    // S2h (review of S2g): a location may name its file by `artifactLocation.index` into
    // run.artifacts instead of by `uri`; every index is resolved and bound like a URI.
    describe("artifact indices", () => {
      const byIndex = (index: unknown, uri?: string) => [
        {
          physicalLocation: { artifactLocation: { ...(uri === undefined ? {} : { uri }), index } },
        },
      ];
      const twoJobs = () => {
        const root = fixtureRoot("aih-cisco-shard-v1-index-");
        skill(root, join("skills", "alpha"), "# alpha\n");
        skill(root, join("skills", "beta"), "# beta\n");
        mkdirSync(join(root, "skills", "alpha", "scripts"));
        writeFileSync(join(root, "skills", "alpha", "scripts", "run.sh"), "echo\n", "utf8");
        return root;
      };
      /** Run properties whose artifact 0 is job beta's SKILL.md, through a root base. */
      const otherJobArtifact = (root: string) => () => {
        const safeRoot = realpathSync(root).replaceAll("\\", "/");
        return {
          originalUriBaseIds: {
            ROOT: { uri: `file://${safeRoot.startsWith("/") ? "" : "/"}${safeRoot}/` },
          },
          artifacts: [{ location: { uri: "skills/beta/SKILL.md", uriBaseId: "ROOT" } }],
        };
      };

      it("fails a related location whose index names another job's file (reviewer reproduction)", async () => {
        const root = twoJobs();
        await failsAtOutput(
          root,
          { run: otherJobArtifact(root), result: () => ({ relatedLocations: byIndex(0) }) },
          /skills\/alpha: .*related .*skills\/beta\/SKILL\.md/,
        );
      });

      it("fails an index anywhere in a result: primary, code flow, stack, analysis target", async () => {
        const root = twoJobs();
        const run = otherJobArtifact(root);
        const other = /skills\/beta\/SKILL\.md/;
        await failsAtOutput(
          root,
          { run, locations: () => [...at("SKILL.md"), ...byIndex(0)] },
          /a location has no URI/,
        );
        await failsAtOutput(
          root,
          { run, locations: () => [...at("SKILL.md"), ...byIndex(0, "SKILL.md")] },
          /disagree/,
        );
        await failsAtOutput(
          root,
          {
            run,
            result: () => ({
              codeFlows: [{ threadFlows: [{ locations: [{ location: byIndex(0)[0] }] }] }],
            }),
          },
          other,
        );
        await failsAtOutput(
          root,
          { run, result: () => ({ stacks: [{ frames: [{ location: byIndex(0)[0] }] }] }) },
          other,
        );
        await failsAtOutput(root, { run, result: () => ({ analysisTarget: { index: 0 } }) }, other);
        await failsAtOutput(
          root,
          { run: () => ({ ...run(), threadFlowLocations: [{ location: byIndex(0)[0] }] }) },
          other,
        );
      });

      it("fails a malformed or unresolved index", async () => {
        const root = twoJobs();
        const own = () => ({ artifacts: [{ location: { uri: "SKILL.md" } }] });
        for (const index of [1, -1, 0.5, "0", null, true, {}])
          await failsAtOutput(
            root,
            { run: own, result: () => ({ relatedLocations: byIndex(index) }) },
            /artifact index/,
          );
        await failsAtOutput(
          root,
          { result: () => ({ relatedLocations: byIndex(0) }) },
          /artifact index 0/,
        );
        for (const artifacts of [[{}], [{ location: {} }], [{ location: { uri: 3 } }], ["x"]])
          await failsAtOutput(
            root,
            { run: () => ({ artifacts }), result: () => ({ relatedLocations: byIndex(0) }) },
            /artifact index 0|artifact URI|not a string/,
          );
        await failsAtOutput(
          root,
          {
            run: () => ({ artifacts: [{ location: { uri: "SKILL.md", index: 1 } }] }),
            result: () => ({ relatedLocations: byIndex(0) }),
          },
          /artifact index 0/,
        );
        await failsAtOutput(
          root,
          {
            result: () => ({ relatedLocations: [{ physicalLocation: { artifactLocation: {} } }] }),
          },
          /names no file/,
        );
      });

      it("fails an index whose artifact disagrees with the URI given beside it", async () => {
        const root = twoJobs();
        const scripts = () => ({ artifacts: [{ location: { uri: "scripts/run.sh" } }] });
        await failsAtOutput(
          root,
          { run: scripts, locations: () => byIndex(0, "SKILL.md") },
          /disagree/,
        );
        await failsAtOutput(
          root,
          { run: scripts, result: () => ({ relatedLocations: byIndex(0, "SKILL.md") }) },
          /disagree/,
        );
      });

      it("fails an index naming a directory artifact, which is no sealed file", async () => {
        const root = twoJobs();
        await failsAtOutput(
          root,
          {
            run: () => ({ artifacts: [{ location: { uri: "scripts/" } }] }),
            result: () => ({ relatedLocations: byIndex(0) }),
          },
          /skills\/alpha\/scripts\//,
        );
      });

      it("completes when every index resolves to a sealed file of the job and agrees", async () => {
        const root = fixtureRoot("aih-cisco-shard-v1-index-");
        skill(root, join("skills", "alpha"), "# alpha\n");
        mkdirSync(join(root, "skills", "alpha", "scripts"));
        writeFileSync(join(root, "skills", "alpha", "scripts", "run.sh"), "echo\n", "utf8");
        const outcome = await runCiscoShardV1(
          shardRequest(root, {
            run: scanningRunner({
              run: () => ({
                artifacts: [
                  { location: { uri: "SKILL.md" } },
                  { location: { uri: "scripts/run.sh", index: 1 } },
                  { location: { uri: "scripts/" } },
                ],
              }),
              locations: () => byIndex(0, "SKILL.md"),
              result: () => ({
                relatedLocations: [...byIndex(1), { message: { text: "no file" } }],
                codeFlows: [{ threadFlows: [{ locations: [{ location: byIndex(0)[0] }] }] }],
                // A property bag is the analyzer's own data, never a location.
                properties: { artifactLocation: { index: 99 } },
              }),
            }),
          }),
        );
        expect(outcome.kind === "failed" ? outcome.detail : outcome.kind).toBe("completed");
      });
    });

    // S2i (review of S2h): the analysis target is normalized like every other location
    // before it is bound, so it names a job-relative file exactly as a location does.
    describe("analysis target", () => {
      const rootBase = (root: string) => {
        const safeRoot = realpathSync(root).replaceAll("\\", "/");
        return { ROOT: { uri: `file://${safeRoot.startsWith("/") ? "" : "/"}${safeRoot}/` } };
      };
      const completes = async (root: string, hooks: Parameters<typeof scanningRunner>[0]) => {
        const outcome = await runCiscoShardV1(shardRequest(root, { run: scanningRunner(hooks) }));
        expect(outcome.kind === "failed" ? outcome.detail : outcome.kind).toBe("completed");
      };

      it("binds a job-relative analysis target (reviewer case: SKILL.md)", async () => {
        const root = fixtureRoot("aih-cisco-shard-v1-target-");
        skill(root, join("skills", "alpha"), "# alpha\n");
        await completes(root, { result: () => ({ analysisTarget: { uri: "SKILL.md" } }) });
        await completes(root, {
          run: () => ({ artifacts: [{ location: { uri: "SKILL.md" } }] }),
          result: () => ({ analysisTarget: { index: 0 } }),
        });
      });

      it("fails a root-relative spelling, which names another job-relative path (reviewer case)", async () => {
        const root = fixtureRoot("aih-cisco-shard-v1-target-");
        skill(root, join("skills", "alpha"), "# alpha\n");
        await failsAtOutput(
          root,
          { result: () => ({ analysisTarget: { uri: "skills/alpha/SKILL.md" } }) },
          /analysis target names .*skills\/alpha\/skills\/alpha\/SKILL\.md.*not a sealed file/,
        );
      });

      it("binds a base-resolved analysis target, and fails one resolving to another job", async () => {
        const root = fixtureRoot("aih-cisco-shard-v1-target-");
        skill(root, join("skills", "alpha"), "# alpha\n");
        skill(root, join("skills", "beta"), "# beta\n");
        await completes(root, {
          run: () => ({ originalUriBaseIds: rootBase(root) }),
          result: (target) => ({
            analysisTarget: {
              uri: `skills/${target.replaceAll("\\", "/").split("/").at(-1) ?? ""}/SKILL.md`,
              uriBaseId: "ROOT",
            },
          }),
        });
        await failsAtOutput(
          root,
          {
            run: () => ({ originalUriBaseIds: rootBase(root) }),
            result: () => ({ analysisTarget: { uri: "skills/beta/SKILL.md", uriBaseId: "ROOT" } }),
          },
          /skills\/alpha: .*skills\/beta\/SKILL\.md/,
        );
      });
    });

    it("completes when every result names a sealed file of its own job", async () => {
      const root = fixtureRoot("aih-cisco-shard-v1-bind-");
      skill(root, join("skills", "alpha"), "# alpha\n");
      mkdirSync(join(root, "skills", "alpha", "scripts"));
      writeFileSync(join(root, "skills", "alpha", "scripts", "run.sh"), "echo\n", "utf8");
      const outcome = await runCiscoShardV1(
        shardRequest(root, {
          run: scanningRunner({ locations: () => [...at("SKILL.md"), ...at("scripts/run.sh")] }),
        }),
      );
      expect(outcome.kind).toBe("completed");
    });
  });

  it("exposes the bundled analyzer lock digest", () => {
    expect(ciscoSkillScannerLockSha256V1()).toBe(bundledLockSha256());
    expect(ciscoSkillScannerLockSha256V1()).toMatch(/^[0-9a-f]{64}$/);
  });

  it("removes volatile Cisco invocation timestamps so per-job SARIF is time-independent", async () => {
    // Ported from Core tests/trust/cisco-shards.test.ts:324 (execution side).
    const root = fixtureRoot("aih-cisco-shards-time-");
    skill(root, join("skills", "alpha"), "# alpha\n");
    const run = scanningRunner({
      invocations: (scanCount) => [
        {
          executionSuccessful: true,
          startTimeUtc: `2026-07-30T00:00:0${scanCount}Z`,
          endTimeUtc: `2026-07-30T00:00:1${scanCount}Z`,
        },
      ],
    });

    const first = await runCiscoShardV1(shardRequest(root, { run }));
    const second = await runCiscoShardV1(shardRequest(root, { run }));

    if (first.kind !== "completed" || second.kind !== "completed")
      throw new Error("expected completed shard runs");
    expect(second.outputs[0]?.sha256).toBe(first.outputs[0]?.sha256);
    const sarif = JSON.parse(Buffer.from(second.outputs[0]?.sarif ?? []).toString("utf8")) as {
      runs: Array<{ invocations?: Array<Record<string, unknown>> }>;
    };
    // S2g: the only invocation property left is Scan's completion evidence.
    expect(sarif.runs[0]?.invocations).toEqual([
      { executionSuccessful: true, properties: { aihScanCompletionV1: expect.any(Object) } },
    ]);
  });

  // S2g (C2a §1.6): each job output names the files its job sealed, and Scan alone writes it.
  describe("completion evidence v1", () => {
    it("names, in every job's SARIF, exactly the job's own files", async () => {
      const root = fixtureRoot("aih-cisco-shard-v1-evidence-");
      skill(root, join("skills", "alpha"), "# alpha\n");
      mkdirSync(join(root, "skills", "alpha", "scripts"));
      writeFileSync(join(root, "skills", "alpha", "scripts", "run.sh"), "echo\n", "utf8");
      skill(root, join("skills", "beta"), "# beta\n");
      writeFileSync(join(root, "README.md"), "# outside every job\n", "utf8");

      const outcome = await runCiscoShardV1(shardRequest(root));

      expect(outcome.kind).toBe("completed");
      if (outcome.kind !== "completed") return;
      expect(outcome.outputs.map((output) => output.path)).toEqual(["skills/alpha", "skills/beta"]);
      for (const output of outcome.outputs) {
        const files = diskFilesV1(root).filter((path) => path.startsWith(`${output.path}/`));
        const log = JSON.parse(Buffer.from(output.sarif).toString("utf8"));
        expect(completionOfLogV1(log)).toEqual({
          detectorId: "detector.cisco",
          ...diskSubjectV1(root, files),
          analyzer: { version: outcome.analyzer.version, lockSha256: outcome.analyzer.lockSha256 },
        });
        expect(output.sha256).toBe(createHash("sha256").update(output.sarif).digest("hex"));
      }
    });

    it("fails a job whose analyzer already wrote the completion key, with no partial outputs", async () => {
      const root = fixtureRoot("aih-cisco-shard-v1-evidence-");
      skill(root, join("skills", "alpha"), "# alpha\n");
      const outcome = await runCiscoShardV1(
        shardRequest(root, {
          run: scanningRunner({
            invocations: () => [
              { executionSuccessful: true, properties: { aihScanCompletionV1: { forged: true } } },
            ],
          }),
        }),
      );

      expect(outcome).toMatchObject({ kind: "failed", stage: "output" });
      expect(outcome).not.toHaveProperty("outputs");
      if (outcome.kind === "failed") expect(outcome.detail).toMatch(/skills\/alpha: .*forged/);
    });
  });
});
