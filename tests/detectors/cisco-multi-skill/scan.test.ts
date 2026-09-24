import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  CISCO_MULTI_SKILL_SCAN_TIMEOUT_MS_V1,
  type CiscoMultiSkillRunnerV1,
  type CiscoMultiSkillRunOptionsV1,
  type CiscoMultiSkillRunResultV1,
  resolveCiscoScanConcurrencyV1,
} from "../../../src/detectors/cisco-multi-skill/plan-v1.js";
import {
  ciscoScanFailureReasonV1,
  probeCiscoSkillScannerV1,
  runCiscoSourceTreeScanV1,
} from "../../../src/detectors/cisco-multi-skill/scan-v1.js";

// Parity tests for the execution/merge half of Core's `detector.cisco`
// multi-skill scan (`src/trust/detectors.ts` `runCiscoSkillScan`,
// `scanCiscoSkillDirectory`, `mapConcurrentStable`, `checkCiscoAvailable`,
// `prefixCiscoSarifUris`). Ported from Core's `tests/trust/scan.test.ts`
// (~3052-3412, 4462-4851, 5297-5311), reduced to the engine boundary: Core's
// grading, posture gating and rule mapping are not part of these assertions.

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "aih-scan-cisco-multi-skill-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function skill(rel: string, body: string): void {
  const root = join(dir, rel);
  mkdirSync(root, { recursive: true });
  writeFileSync(join(root, "SKILL.md"), body, "utf8");
}

type SarifFixture = { runs: Array<Record<string, unknown>> };

const EMPTY_SARIF: SarifFixture = { runs: [{ results: [] }] };

/**
 * A fixture completed to real skill-scanner 2.0.14's shape (S2e): SARIF 2.1.0 whose runs
 * name the tool driver and report a successful invocation, which a job's SARIF must prove.
 */
function complete(sarif: SarifFixture) {
  return {
    version: "2.1.0",
    runs: sarif.runs.map((run) => ({
      tool: { driver: { name: "skill-scanner", version: "1.0.0" } },
      invocations: [{ executionSuccessful: true }],
      ...run,
    })),
  };
}

const CLEAN_RUN = complete(EMPTY_SARIF).runs[0];

type FakeHandler = (
  argv: readonly string[],
  opts?: CiscoMultiSkillRunOptionsV1,
) => Partial<CiscoMultiSkillRunResultV1> | undefined;

function fakeRunner(handler: FakeHandler): CiscoMultiSkillRunnerV1 {
  return async (argv, opts) => ({
    code: 0,
    stdout: "",
    stderr: "",
    ...(handler(argv, opts) ?? {}),
  });
}

function isCiscoSkillScannerArgv(argv: readonly string[]): boolean {
  return argv[0] === "uv" && argv[1] === "run" && argv.includes("skill-scanner");
}

function ciscoRunner(sarif: SarifFixture, onScan?: FakeHandler): CiscoMultiSkillRunnerV1 {
  return fakeRunner((argv, opts) => {
    if (!isCiscoSkillScannerArgv(argv)) return { code: 127, stderr: "not found", spawnError: true };
    if (argv.includes("--version")) return { code: 0, stdout: "skill-scanner 2.0.14\n" };
    if (argv.includes("scan")) {
      onScan?.(argv, opts);
      const out = argv[argv.indexOf("--output-sarif") + 1];
      if (out === undefined) return { code: 1, stderr: "missing --output-sarif" };
      writeFileSync(out, JSON.stringify(complete(sarif)), "utf8");
      return { code: 0, stdout: `Report saved to: ${out}\n` };
    }
    return undefined;
  });
}

const SKIP_DIRS = new Set([
  ".git",
  ".hg",
  ".svn",
  ".aih",
  "coverage",
  "dist",
  "node_modules",
  "vendor",
]);

/** Test stand-in for Core's trust inventory: every regular file, skip dirs excluded. */
function inventory(root: string, prefix = ""): string[] {
  return readdirSync(join(root, prefix), { withFileTypes: true }).flatMap((entry) => {
    const rel = prefix.length === 0 ? entry.name : `${prefix}/${entry.name}`;
    if (entry.isDirectory()) return SKIP_DIRS.has(entry.name) ? [] : inventory(root, rel);
    return entry.isFile() ? [rel] : [];
  });
}

/**
 * Core's side of the seam for the ported `runCiscoSkillScan` cases: Core
 * declares its inventory as the selection and sends its resolved
 * `AIH_CISCO_SCAN_CONCURRENCY` as `detectorOptions.concurrency` (C2a §3.3);
 * a non-completed outcome surfaces as its detail, as Core's legacy throw did.
 * Core checked availability before `runCiscoSkillScan`, so the version gate
 * is answered here and each case's runner sees only its scans.
 */
async function runTree(request: {
  run: CiscoMultiSkillRunnerV1;
  platform: "linux";
  env: NodeJS.ProcessEnv;
  tree: string;
}): Promise<string> {
  const outcome = await runCiscoSourceTreeScanV1({
    run: async (argv, opts) =>
      argv.includes("--version")
        ? { code: 0, stdout: "skill-scanner 2.0.14\n", stderr: "" }
        : request.run(argv, opts),
    platform: request.platform,
    env: request.env,
    sourceRoot: request.tree,
    selectedClosurePaths: inventory(request.tree),
    detectorOptions: { concurrency: resolveCiscoScanConcurrencyV1(request.env) },
  });
  if (outcome.kind === "completed") return outcome.sarifText;
  throw new Error(outcome.detail);
}

function mergedRuns(text: string): Array<Record<string, unknown>> {
  return (JSON.parse(text) as { runs: Array<Record<string, unknown>> }).runs;
}

describe("runCiscoSourceTreeScanV1 (ported Core runCiscoSkillScan cases)", () => {
  it("runs one locked offline skill-scanner scan per skill directory", async () => {
    // Ported from Core tests/trust/scan.test.ts:3052.
    skill("skills/clean", "# Clean\n");
    const scanTargets: string[] = [];
    const observed: Array<{ cwd?: string; timeoutMs?: number }> = [];

    const text = await runTree({
      run: ciscoRunner(EMPTY_SARIF, (argv, opts) => {
        scanTargets.push(argv[argv.indexOf("scan") + 1] ?? "");
        observed.push({ cwd: opts?.cwd, timeoutMs: opts?.timeoutMs });
      }),
      platform: "linux",
      env: {},
      tree: realpathSync(dir),
    });

    const skillDir = realpathSync(join(dir, "skills", "clean"));
    expect(scanTargets).toEqual([skillDir]);
    expect(observed).toEqual([{ cwd: skillDir, timeoutMs: CISCO_MULTI_SKILL_SCAN_TIMEOUT_MS_V1 }]);
    expect(JSON.parse(text)).toEqual({ version: "2.1.0", runs: [CLEAN_RUN] });
  });

  it("scrubs the environment each skill scan sees", async () => {
    // The scan-call half of Core's env-scrub assertions (tests/trust/scan.test.ts:4400).
    skill("skills/clean", "# Clean\n");
    const seenEnvs: Array<NodeJS.ProcessEnv | undefined> = [];

    await runTree({
      run: ciscoRunner(EMPTY_SARIF, (_argv, opts) => {
        seenEnvs.push(opts?.env);
      }),
      platform: "linux",
      env: {
        PATH: "bin",
        HOME: "/home/fixture",
        GITHUB_TOKEN: "ghp_fixture_should_not_escape",
        OPENAI_API_KEY: "sk-fixture-should-not-escape",
      },
      tree: realpathSync(dir),
    });

    expect(seenEnvs).toHaveLength(1);
    expect(seenEnvs[0]).toMatchObject({ PATH: "bin", HOME: "/home/fixture" });
    expect(seenEnvs[0]).not.toHaveProperty("GITHUB_TOKEN");
    expect(seenEnvs[0]).not.toHaveProperty("OPENAI_API_KEY");
  });

  it("anchors Cisco scans to each skill directory so evidence is projection-independent", async () => {
    // Ported from Core tests/trust/scan.test.ts:3114, asserted at the engine
    // boundary: identical relative layout under two roots must merge to
    // identical SARIF text, timestamps included in the fixture to prove they
    // are stripped.
    const projections = [
      mkdtempSync(join(tmpdir(), "aih-cisco-projection-alpha-")),
      mkdtempSync(join(tmpdir(), "aih-cisco-projection-beta-")),
    ];
    try {
      const scanProjection = async (projectionRoot: string, tag: string): Promise<string> => {
        const skillRoot = join(projectionRoot, "skills", "clean");
        mkdirSync(skillRoot, { recursive: true });
        writeFileSync(join(skillRoot, "SKILL.md"), "# Clean\n", "utf8");
        const observedCwds: Array<string | undefined> = [];
        const run: CiscoMultiSkillRunnerV1 = async (argv, opts) => {
          if (!isCiscoSkillScannerArgv(argv) || !argv.includes("scan")) {
            return { code: 127, stdout: "", stderr: "not found", spawnError: true };
          }
          observedCwds.push(opts?.cwd);
          const target = argv[argv.indexOf("scan") + 1];
          const out = argv[argv.indexOf("--output-sarif") + 1];
          if (target === undefined || out === undefined) {
            return { code: 1, stdout: "", stderr: "missing Cisco scan path" };
          }
          writeFileSync(
            out,
            JSON.stringify(
              complete({
                runs: [
                  {
                    invocations: [
                      {
                        executionSuccessful: true,
                        startTimeUtc: `2026-07-30T00:00:0${tag}Z`,
                        endTimeUtc: `2026-07-30T00:00:1${tag}Z`,
                      },
                    ],
                    results: [
                      {
                        ruleId: "CISCO_FIXTURE",
                        message: { text: "stable finding" },
                        locations: [
                          {
                            physicalLocation: {
                              artifactLocation: {
                                uri: relative(opts?.cwd ?? process.cwd(), join(target, "SKILL.md")),
                              },
                              region: { startLine: 1 },
                            },
                          },
                        ],
                      },
                    ],
                  },
                ],
              }),
            ),
            "utf8",
          );
          return { code: 0, stdout: `Report saved to: ${out}\n`, stderr: "" };
        };

        const text = await runTree({
          run,
          platform: "linux",
          env: {},
          tree: realpathSync(projectionRoot),
        });
        expect(observedCwds).toEqual([realpathSync(skillRoot)]);
        return text;
      };

      const [first, second] = await Promise.all([
        scanProjection(projections[0] ?? "", "1"),
        scanProjection(projections[1] ?? "", "2"),
      ]);
      expect(second).toBe(first);
      const run = mergedRuns(first)[0] as {
        invocations: Array<Record<string, unknown>>;
        results: Array<{
          locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }>;
        }>;
      };
      expect(run.invocations).toEqual([{ executionSuccessful: true }]);
      expect(run.results[0]?.locations[0]?.physicalLocation.artifactLocation.uri).toBe(
        "skills/clean/SKILL.md",
      );
    } finally {
      for (const projection of projections) rmSync(projection, { recursive: true, force: true });
    }
  });

  it("bounds independent Cisco skill scans at four while preserving every target", async () => {
    // Ported from Core tests/trust/scan.test.ts:3186.
    const expectedTargets = Array.from({ length: 7 }, (_, index) => {
      const rel = `skills/skill-${index}`;
      skill(rel, `# Skill ${index}\n`);
      return realpathSync(join(dir, rel));
    });
    let active = 0;
    let maxActive = 0;
    const seenTargets: string[] = [];
    const run: CiscoMultiSkillRunnerV1 = async (argv) => {
      if (!isCiscoSkillScannerArgv(argv) || !argv.includes("scan")) {
        return { code: 127, stdout: "", stderr: "not found", spawnError: true };
      }
      const target = argv[argv.indexOf("scan") + 1] ?? "";
      const output = argv[argv.indexOf("--output-sarif") + 1];
      if (output === undefined) return { code: 1, stdout: "", stderr: "missing SARIF path" };
      active++;
      maxActive = Math.max(maxActive, active);
      seenTargets.push(target);
      try {
        await new Promise((resolvePromise) => setTimeout(resolvePromise, 15));
        writeFileSync(output, JSON.stringify(complete(EMPTY_SARIF)), "utf8");
        return { code: 0, stdout: `Report saved to: ${output}\n`, stderr: "" };
      } finally {
        active--;
      }
    };

    const text = await runTree({
      run,
      platform: "linux",
      env: {},
      tree: realpathSync(dir),
    });

    expect(JSON.parse(text)).toEqual({ version: "2.1.0", runs: Array(7).fill(CLEAN_RUN) });
    expect(maxActive).toBeGreaterThan(1);
    expect(maxActive).toBeLessThanOrEqual(4);
    expect([...seenTargets].sort()).toEqual(expectedTargets.sort());
  });

  it("uses an explicit Cisco worker limit for a right-sized vet host", async () => {
    // Ported from Core tests/trust/scan.test.ts:3240.
    for (let index = 0; index < 8; index++) skill(`skills/skill-${index}`, `# Skill ${index}\n`);
    let active = 0;
    let maxActive = 0;
    const run: CiscoMultiSkillRunnerV1 = async (argv) => {
      if (!isCiscoSkillScannerArgv(argv) || !argv.includes("scan")) {
        return { code: 127, stdout: "", stderr: "not found", spawnError: true };
      }
      const output = argv[argv.indexOf("--output-sarif") + 1];
      if (output === undefined) return { code: 1, stdout: "", stderr: "missing SARIF path" };
      active++;
      maxActive = Math.max(maxActive, active);
      try {
        await new Promise((resolvePromise) => setTimeout(resolvePromise, 15));
        writeFileSync(output, JSON.stringify(complete(EMPTY_SARIF)), "utf8");
        return { code: 0, stdout: `Report saved to: ${output}\n`, stderr: "" };
      } finally {
        active--;
      }
    };

    await runTree({
      run,
      platform: "linux",
      env: { AIH_CISCO_SCAN_CONCURRENCY: "6" },
      tree: realpathSync(dir),
    });

    expect(maxActive).toBe(6);
  });

  it("drains in-flight Cisco scans before reporting a concurrent failure", async () => {
    // Ported from Core tests/trust/scan.test.ts:3285.
    for (let index = 0; index < 7; index++) skill(`skills/skill-${index}`, `# Skill ${index}\n`);
    let active = 0;
    let maxActive = 0;
    const run: CiscoMultiSkillRunnerV1 = async (argv) => {
      if (!isCiscoSkillScannerArgv(argv) || !argv.includes("scan")) {
        return { code: 127, stdout: "", stderr: "not found", spawnError: true };
      }
      const target = argv[argv.indexOf("scan") + 1] ?? "";
      const output = argv[argv.indexOf("--output-sarif") + 1];
      if (output === undefined) return { code: 1, stdout: "", stderr: "missing SARIF path" };
      active++;
      maxActive = Math.max(maxActive, active);
      try {
        if (target.endsWith("skill-0")) {
          await new Promise((resolvePromise) => setTimeout(resolvePromise, 5));
          return { code: 2, stdout: "", stderr: "fixture Cisco failure" };
        }
        await new Promise((resolvePromise) => setTimeout(resolvePromise, 40));
        writeFileSync(output, JSON.stringify(complete(EMPTY_SARIF)), "utf8");
        return { code: 0, stdout: `Report saved to: ${output}\n`, stderr: "" };
      } finally {
        active--;
      }
    };

    await expect(
      runTree({ run, platform: "linux", env: {}, tree: realpathSync(dir) }),
    ).rejects.toThrow("fixture Cisco failure");
    expect(maxActive).toBeGreaterThan(1);
    expect(maxActive).toBeLessThanOrEqual(4);
    expect(active).toBe(0);
  });

  it("reports the lowest-index failure when several skills fail", async () => {
    // Core's mapConcurrentStable sorts failures by input index; the first
    // failure observed is not necessarily the one reported.
    skill("skills/a", "# A\n");
    skill("skills/b", "# B\n");
    skill("skills/c", "# C\n");
    const run: CiscoMultiSkillRunnerV1 = async (argv) => {
      if (!isCiscoSkillScannerArgv(argv) || !argv.includes("scan")) {
        return { code: 127, stdout: "", stderr: "not found", spawnError: true };
      }
      const target = (argv[argv.indexOf("scan") + 1] ?? "").replaceAll("\\", "/");
      const output = argv[argv.indexOf("--output-sarif") + 1];
      if (output === undefined) return { code: 1, stdout: "", stderr: "missing SARIF path" };
      if (target.endsWith("skills/b")) {
        await new Promise((resolvePromise) => setTimeout(resolvePromise, 5));
        return { code: 2, stdout: "", stderr: "failure-b" };
      }
      if (target.endsWith("skills/a")) {
        await new Promise((resolvePromise) => setTimeout(resolvePromise, 30));
        return { code: 2, stdout: "", stderr: "failure-a" };
      }
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 40));
      writeFileSync(output, JSON.stringify(complete(EMPTY_SARIF)), "utf8");
      return { code: 0, stdout: "", stderr: "" };
    };

    await expect(
      runTree({ run, platform: "linux", env: {}, tree: realpathSync(dir) }),
    ).rejects.toThrow(/^failure-a$/);
  });

  it("prefixes result artifact URIs with the source-relative skill directory", async () => {
    // The merge half of Core tests/trust/scan.test.ts:4492 — rule mapping and
    // grading stay in Core; the merged SARIF keeps rule ids and prefixed URIs.
    skill("skills/clean", "# Clean\n");
    const sarif = {
      runs: [
        {
          results: [
            {
              ruleId: "PROMPT_INJECTION_IGNORE_INSTRUCTIONS",
              message: { text: "Pattern detected: Ignore previous instructions" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: "SKILL.md" },
                    region: { startLine: 7 },
                  },
                },
              ],
            },
            {
              ruleId: "YARA_command_injection_generic",
              message: { text: "bash -i >& /dev/tcp/" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: "install.sh" },
                    region: { startLine: 1 },
                  },
                },
              ],
            },
            {
              ruleId: "CISCO_UNKNOWN_RULE",
              message: { text: "future Cisco finding" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: "notes.txt" },
                    region: { startLine: 2 },
                  },
                },
              ],
            },
          ],
        },
      ],
    };

    const text = await runTree({
      run: ciscoRunner(sarif),
      platform: "linux",
      env: {},
      tree: realpathSync(dir),
    });

    const results = (
      mergedRuns(text)[0] as {
        results: Array<{
          ruleId: string;
          locations: Array<{
            physicalLocation: { artifactLocation: { uri: string }; region: { startLine: number } };
          }>;
        }>;
      }
    ).results;
    expect(
      results.map((result) => [
        result.ruleId,
        result.locations[0]?.physicalLocation.artifactLocation.uri,
        result.locations[0]?.physicalLocation.region.startLine,
      ]),
    ).toEqual([
      ["PROMPT_INJECTION_IGNORE_INSTRUCTIONS", "skills/clean/SKILL.md", 7],
      ["YARA_command_injection_generic", "skills/clean/install.sh", 1],
      ["CISCO_UNKNOWN_RULE", "skills/clean/notes.txt", 2],
    ]);
  });

  it("fails unsafe Cisco SARIF artifact URIs at output, never naming cisco.sarif (S2g)", async () => {
    // S2g (review of U1d): the legacy fallback name could bind a finding to an unrelated
    // sealed root-level cisco.sarif, so an unsafe URI fails the job instead.
    skill("skills/clean", "# Clean\n");
    const sarif = {
      runs: [
        {
          results: [
            {
              ruleId: "CISCO_UNKNOWN_RULE",
              message: { text: "unsafe SARIF uri" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: "../../../../etc/passwd" },
                    region: { startLine: 9 },
                  },
                },
              ],
            },
            {
              ruleId: "CISCO_DRIVE_RULE",
              message: { text: "drive-relative SARIF uri" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: "C:evil" },
                    region: { startLine: 4 },
                  },
                },
              ],
            },
          ],
        },
      ],
    };

    await expect(
      runTree({ run: ciscoRunner(sarif), platform: "linux", env: {}, tree: realpathSync(dir) }),
    ).rejects.toThrow(/detector SARIF location: .*not a safe source-relative/);
  });

  it("fails the reviewer's ../outside.md beside a sealed root-level cisco.sarif (S2g)", async () => {
    skill("skills/clean", "# Clean\n");
    writeFileSync(join(dir, "cisco.sarif"), "{}\n");
    const escaping = {
      runs: [
        {
          results: [
            {
              ruleId: "CISCO_UNKNOWN_RULE",
              message: { text: "escape" },
              locations: [{ physicalLocation: { artifactLocation: { uri: "../outside.md" } } }],
            },
          ],
        },
      ],
    };
    const tree = realpathSync(dir);
    const scanner = ciscoRunner(escaping);
    const outcome = await runCiscoSourceTreeScanV1({
      run: async (argv, opts) =>
        argv.includes("--version")
          ? { code: 0, stdout: "skill-scanner 2.0.14\n", stderr: "" }
          : scanner(argv, opts),
      platform: "linux",
      env: {},
      sourceRoot: tree,
      selectedClosurePaths: inventory(tree),
      detectorOptions: { concurrency: 1 },
    });
    expect(outcome).toMatchObject({ kind: "failed", stage: "output" });
    if (outcome.kind === "failed") expect(outcome.detail).toMatch(/not a safe source-relative/);
  });

  it("strips authority-free file:// prefixes and fails absolute file URIs", async () => {
    skill("skills/clean", "# Clean\n");
    const sarif = {
      runs: [
        {
          results: [
            {
              ruleId: "FIXTURE",
              message: { text: "file url" },
              locations: [{ physicalLocation: { artifactLocation: { uri: "file://SKILL.md" } } }],
            },
            {
              ruleId: "FIXTURE",
              message: { text: "absolute file url" },
              locations: [
                { physicalLocation: { artifactLocation: { uri: "file:///etc/passwd" } } },
              ],
            },
          ],
        },
      ],
    };

    await expect(
      runTree({ run: ciscoRunner(sarif), platform: "linux", env: {}, tree: realpathSync(dir) }),
    ).rejects.toThrow(/detector SARIF location: .*not a safe source-relative/);

    const safe = { runs: [{ results: sarif.runs[0]?.results.slice(0, 1) ?? [] }] };
    const text = await runTree({
      run: ciscoRunner(safe),
      platform: "linux",
      env: {},
      tree: realpathSync(dir),
    });
    const results = (
      mergedRuns(text)[0] as {
        results: Array<{
          locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }>;
        }>;
      }
    ).results;
    expect(
      results.map((result) => result.locations[0]?.physicalLocation.artifactLocation.uri),
    ).toEqual(["skills/clean/SKILL.md"]);
  });

  it("fails when a skill scan emits no valid SARIF", async () => {
    skill("skills/clean", "# Clean\n");
    const run = fakeRunner((argv) => {
      if (!isCiscoSkillScannerArgv(argv)) return undefined;
      if (argv.includes("scan")) {
        const out = argv[argv.indexOf("--output-sarif") + 1];
        if (out === undefined) return { code: 1, stderr: "missing --output-sarif" };
        writeFileSync(out, "not SARIF", "utf8");
        return { code: 0, stdout: "done\n" };
      }
      return undefined;
    });

    await expect(
      runTree({ run, platform: "linux", env: {}, tree: realpathSync(dir) }),
    ).rejects.toThrow("detector did not emit valid SARIF");
  });

  it("fails when the tree holds no SKILL.md directory", async () => {
    await expect(
      runTree({
        run: fakeRunner(() => undefined),
        platform: "linux",
        env: {},
        tree: realpathSync(dir),
      }),
    ).rejects.toThrow("no SKILL.md directories found for Cisco scan");
  });

  it("reports the process failure reason for a failed scan", async () => {
    skill("skills/clean", "# Clean\n");
    const run = fakeRunner((argv) => {
      if (!isCiscoSkillScannerArgv(argv)) return undefined;
      if (argv.includes("scan")) return { code: 2, stdout: "", stderr: "" };
      return undefined;
    });

    await expect(
      runTree({ run, platform: "linux", env: {}, tree: realpathSync(dir) }),
    ).rejects.toThrow("detector exit 2");
  });
});

describe("ciscoScanFailureReasonV1", () => {
  it("classifies process results exactly as Core's runFailureReason", () => {
    expect(
      ciscoScanFailureReasonV1({ code: 0, stdout: "", stderr: "" }, "fallback"),
    ).toBeUndefined();
    expect(ciscoScanFailureReasonV1({ code: 2, stdout: "out", stderr: "boom" }, "fallback")).toBe(
      "boom",
    );
    expect(ciscoScanFailureReasonV1({ code: 2, stdout: "out", stderr: "" }, "fallback")).toBe(
      "out",
    );
    expect(
      ciscoScanFailureReasonV1(
        { code: null, stdout: "", stderr: "", spawnError: true },
        "detector exit signal",
      ),
    ).toBe("detector exit signal");
  });
});

describe("probeCiscoSkillScannerV1", () => {
  it("accepts the pinned version", async () => {
    const run = fakeRunner((argv) =>
      argv.includes("--version") ? { code: 0, stdout: "skill-scanner 2.0.14\n" } : undefined,
    );

    await expect(probeCiscoSkillScannerV1({ run, platform: "linux", env: {} })).resolves.toEqual({
      kind: "available",
    });
  });

  it("classifies a probe that cannot run as an acquisition failure", async () => {
    const spawnFailed = fakeRunner(() => ({
      code: 127,
      stdout: "",
      stderr: "uv not found",
      spawnError: true,
    }));
    const exited = fakeRunner(() => ({ code: 1, stdout: "", stderr: "lock unsatisfiable" }));
    const throwing: CiscoMultiSkillRunnerV1 = async () => {
      throw new Error("spawn blew up");
    };

    await expect(
      probeCiscoSkillScannerV1({ run: spawnFailed, platform: "linux", env: {} }),
    ).resolves.toEqual({ kind: "unavailable", stage: "acquisition", detail: "uv not found" });
    await expect(
      probeCiscoSkillScannerV1({ run: exited, platform: "linux", env: {} }),
    ).resolves.toEqual({
      kind: "unavailable",
      stage: "acquisition",
      detail: "lock unsatisfiable",
    });
    await expect(
      probeCiscoSkillScannerV1({ run: throwing, platform: "linux", env: {} }),
    ).resolves.toEqual({ kind: "unavailable", stage: "acquisition", detail: "spawn blew up" });
  });

  it("classifies a wrong answer from the probe as an availability failure", async () => {
    const empty = fakeRunner(() => ({ code: 0, stdout: "  \n" }));
    const mismatched = fakeRunner(() => ({ code: 0, stdout: "skill-scanner 9.9.9\n" }));

    await expect(
      probeCiscoSkillScannerV1({ run: empty, platform: "linux", env: {} }),
    ).resolves.toEqual({
      kind: "unavailable",
      stage: "availability",
      detail: "skill-scanner version check emitted no output",
    });
    await expect(
      probeCiscoSkillScannerV1({ run: mismatched, platform: "linux", env: {} }),
    ).resolves.toEqual({
      kind: "unavailable",
      stage: "availability",
      detail: 'skill-scanner version "skill-scanner 9.9.9" does not match 2.0.14',
    });
  });
});

describe("runCiscoSourceTreeScanV1", () => {
  // C2a §3 engine-function behaviour: boundary validation and failure
  // classification are typed outcomes, never thrown errors.
  function selectionOf(...skillDirs: readonly string[]): string[] {
    return skillDirs.map((rel) => (rel.length === 0 ? "SKILL.md" : `${rel}/SKILL.md`));
  }

  it("refuses invalid detector options before any runner call", async () => {
    skill("skills/clean", "# Clean\n");
    let invoked = false;
    const run: CiscoMultiSkillRunnerV1 = async () => {
      invoked = true;
      return { code: 0, stdout: "", stderr: "" };
    };

    const outcome = await runCiscoSourceTreeScanV1({
      run,
      platform: "linux",
      env: {},
      sourceRoot: realpathSync(dir),
      selectedClosurePaths: selectionOf("skills/clean"),
      detectorOptions: { concurrency: 0 },
    });

    expect(outcome).toEqual({
      kind: "refused",
      reason: "detector-options-invalid",
      detail: "concurrency must be an integer from 1 through 64",
    });
    expect(invoked).toBe(false);
  });

  it("refuses unknown detector option keys", async () => {
    skill("skills/clean", "# Clean\n");
    const outcome = await runCiscoSourceTreeScanV1({
      run: fakeRunner(() => undefined),
      platform: "linux",
      env: {},
      sourceRoot: realpathSync(dir),
      selectedClosurePaths: selectionOf("skills/clean"),
      detectorOptions: { concurrency: 2, extra: true },
    });

    expect(outcome).toMatchObject({
      kind: "refused",
      reason: "detector-options-invalid",
      detail: 'detectorOptions holds unknown key: "extra"',
    });
  });

  it("refuses a selection with no SKILL.md directory before any runner call", async () => {
    // C2a §3.5: B2 maps this refusal to Core's `subject-requirement-unmet`.
    let invoked = false;
    const run: CiscoMultiSkillRunnerV1 = async () => {
      invoked = true;
      return { code: 0, stdout: "", stderr: "" };
    };

    const outcome = await runCiscoSourceTreeScanV1({
      run,
      platform: "linux",
      env: {},
      sourceRoot: realpathSync(dir),
      selectedClosurePaths: ["docs/readme.md"],
    });

    expect(outcome).toEqual({
      kind: "refused",
      reason: "subject-requirement-unmet",
      detail: "no SKILL.md directories found for Cisco scan",
    });
    expect(invoked).toBe(false);
  });

  it("refuses a selected skill directory reached through a directory link, before any runner call", async (ctx) => {
    // The selection names paths; a linked (or junction) ancestor would send
    // the analyzer outside the declared root. Every job directory must be a
    // real directory chain inside sourceRoot.
    skill("skills/clean", "# Clean\n");
    const outside = mkdtempSync(join(tmpdir(), "aih-scan-cisco-outside-"));
    try {
      mkdirSync(join(outside, "skill"), { recursive: true });
      writeFileSync(join(outside, "skill", "SKILL.md"), "# Outside\n", "utf8");
      try {
        symlinkSync(outside, join(dir, "link"), process.platform === "win32" ? "junction" : "dir");
      } catch {
        // This OS/account cannot create a directory link; nothing to prove here.
        ctx.skip();
        return;
      }
      let invoked = false;
      const run: CiscoMultiSkillRunnerV1 = async () => {
        invoked = true;
        return { code: 0, stdout: "", stderr: "" };
      };

      const outcome = await runCiscoSourceTreeScanV1({
        run,
        platform: "linux",
        env: {},
        sourceRoot: realpathSync(dir),
        selectedClosurePaths: selectionOf("skills/clean", "link/skill"),
      });

      expect(outcome).toEqual({
        kind: "refused",
        reason: "subject-requirement-unmet",
        detail: "Cisco job path crosses a symbolic link or junction: link/skill",
      });
      expect(invoked).toBe(false);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it.each([
    ["../escape/SKILL.md", "../escape"],
    ["a//b/SKILL.md", "a//b"],
  ])("refuses the unsafe selected path %j before any runner call", async (entry, jobPath) => {
    skill("skills/clean", "# Clean\n");
    let invoked = false;
    const run: CiscoMultiSkillRunnerV1 = async () => {
      invoked = true;
      return { code: 0, stdout: "", stderr: "" };
    };

    const outcome = await runCiscoSourceTreeScanV1({
      run,
      platform: "linux",
      env: {},
      sourceRoot: realpathSync(dir),
      selectedClosurePaths: [entry],
    });

    expect(outcome).toEqual({
      kind: "refused",
      reason: "subject-requirement-unmet",
      detail: `Cisco job path is not a safe POSIX source-relative path: ${jobPath}`,
    });
    expect(invoked).toBe(false);
  });

  it("fails at the availability stage when the version gate mismatches, before any job", async () => {
    skill("skills/clean", "# Clean\n");
    const seenArgv: string[][] = [];
    const run = fakeRunner((argv) => {
      seenArgv.push([...argv]);
      if (argv.includes("--version")) return { code: 0, stdout: "skill-scanner 9.9.9\n" };
      return { code: 0, stdout: "" };
    });

    const outcome = await runCiscoSourceTreeScanV1({
      run,
      platform: "linux",
      env: {},
      sourceRoot: realpathSync(dir),
      selectedClosurePaths: selectionOf("skills/clean"),
    });

    expect(outcome).toEqual({
      kind: "failed",
      stage: "availability",
      detail: 'skill-scanner version "skill-scanner 9.9.9" does not match 2.0.14',
    });
    expect(seenArgv.length).toBeGreaterThan(0);
    expect(seenArgv.every((argv) => argv.includes("--version"))).toBe(true);
  });

  it("fails at the acquisition stage when the analyzer environment cannot run", async () => {
    skill("skills/clean", "# Clean\n");
    const run = fakeRunner((argv) =>
      argv.includes("--version")
        ? { code: 127, stdout: "", stderr: "uv not found", spawnError: true }
        : undefined,
    );

    const outcome = await runCiscoSourceTreeScanV1({
      run,
      platform: "linux",
      env: {},
      sourceRoot: realpathSync(dir),
      selectedClosurePaths: selectionOf("skills/clean"),
    });

    expect(outcome).toEqual({ kind: "failed", stage: "acquisition", detail: "uv not found" });
  });

  it("merges job runs in stable job order, not completion order", async () => {
    // C2a §3.3: results are stable in job order; job order is the
    // localeCompare-sorted selection order of §3.1.
    for (let index = 0; index < 3; index++) skill(`skills/skill-${index}`, `# Skill ${index}\n`);
    const delays = new Map([
      ["skill-0", 40],
      ["skill-1", 20],
      ["skill-2", 5],
    ]);
    const run: CiscoMultiSkillRunnerV1 = async (argv) => {
      if (argv.includes("--version")) {
        return { code: 0, stdout: "skill-scanner 2.0.14\n", stderr: "" };
      }
      const target = argv[argv.indexOf("scan") + 1] ?? "";
      const output = argv[argv.indexOf("--output-sarif") + 1];
      if (output === undefined) return { code: 1, stdout: "", stderr: "missing SARIF path" };
      const name = target.replaceAll("\\", "/").split("/").pop() ?? "";
      await new Promise((resolvePromise) => setTimeout(resolvePromise, delays.get(name) ?? 0));
      writeFileSync(
        output,
        JSON.stringify(
          complete({
            runs: [{ results: [{ ruleId: "fixture", message: { text: name } }] }],
          }),
        ),
        "utf8",
      );
      return { code: 0, stdout: "", stderr: "" };
    };

    const outcome = await runCiscoSourceTreeScanV1({
      run,
      platform: "linux",
      env: {},
      sourceRoot: realpathSync(dir),
      selectedClosurePaths: selectionOf("skills/skill-0", "skills/skill-1", "skills/skill-2"),
    });

    expect(outcome.kind).toBe("completed");
    if (outcome.kind !== "completed") return;
    expect(outcome.skillDirectories).toEqual([
      "skills/skill-0",
      "skills/skill-1",
      "skills/skill-2",
    ]);
    expect(
      mergedRuns(outcome.sarifText).map(
        (jobRun) =>
          (jobRun as { results: Array<{ message: { text: string } }> }).results[0]?.message.text,
      ),
    ).toEqual(["skill-0", "skill-1", "skill-2"]);
  });

  it("runs at the validated detectorOptions concurrency", async () => {
    for (let index = 0; index < 5; index++) skill(`skills/skill-${index}`, `# Skill ${index}\n`);
    let active = 0;
    let maxActive = 0;
    const run: CiscoMultiSkillRunnerV1 = async (argv) => {
      if (argv.includes("--version")) {
        return { code: 0, stdout: "skill-scanner 2.0.14\n", stderr: "" };
      }
      const output = argv[argv.indexOf("--output-sarif") + 1];
      if (output === undefined) return { code: 1, stdout: "", stderr: "missing SARIF path" };
      active++;
      maxActive = Math.max(maxActive, active);
      try {
        await new Promise((resolvePromise) => setTimeout(resolvePromise, 15));
        writeFileSync(output, JSON.stringify(complete(EMPTY_SARIF)), "utf8");
        return { code: 0, stdout: "", stderr: "" };
      } finally {
        active--;
      }
    };

    const outcome = await runCiscoSourceTreeScanV1({
      run,
      platform: "linux",
      env: {},
      sourceRoot: realpathSync(dir),
      selectedClosurePaths: selectionOf(
        "skills/skill-0",
        "skills/skill-1",
        "skills/skill-2",
        "skills/skill-3",
        "skills/skill-4",
      ),
      detectorOptions: { concurrency: 2 },
    });

    expect(outcome.kind).toBe("completed");
    expect(maxActive).toBe(2);
  });

  it("drains in-flight jobs and reports the lowest-index failure at the execution stage", async () => {
    // C2a §3.5: no new jobs start, in-flight jobs finish, the lowest-index
    // failing job's error is reported, and there is no partial SARIF.
    for (let index = 0; index < 5; index++) skill(`skills/skill-${index}`, `# Skill ${index}\n`);
    let active = 0;
    const run: CiscoMultiSkillRunnerV1 = async (argv) => {
      if (argv.includes("--version")) {
        return { code: 0, stdout: "skill-scanner 2.0.14\n", stderr: "" };
      }
      const target = (argv[argv.indexOf("scan") + 1] ?? "").replaceAll("\\", "/");
      const output = argv[argv.indexOf("--output-sarif") + 1];
      if (output === undefined) return { code: 1, stdout: "", stderr: "missing SARIF path" };
      active++;
      try {
        if (target.endsWith("skill-2")) {
          await new Promise((resolvePromise) => setTimeout(resolvePromise, 5));
          return { code: 2, stdout: "", stderr: "failure-2" };
        }
        if (target.endsWith("skill-0")) {
          await new Promise((resolvePromise) => setTimeout(resolvePromise, 30));
          return { code: 2, stdout: "", stderr: "failure-0" };
        }
        await new Promise((resolvePromise) => setTimeout(resolvePromise, 40));
        writeFileSync(output, JSON.stringify(complete(EMPTY_SARIF)), "utf8");
        return { code: 0, stdout: "", stderr: "" };
      } finally {
        active--;
      }
    };

    const outcome = await runCiscoSourceTreeScanV1({
      run,
      platform: "linux",
      env: {},
      sourceRoot: realpathSync(dir),
      selectedClosurePaths: selectionOf(
        "skills/skill-0",
        "skills/skill-1",
        "skills/skill-2",
        "skills/skill-3",
        "skills/skill-4",
      ),
    });

    expect(outcome).toEqual({ kind: "failed", stage: "execution", detail: "failure-0" });
    expect(active).toBe(0);
  });

  it("fails at the output stage when a job emits no parseable SARIF", async () => {
    skill("skills/clean", "# Clean\n");
    const run = fakeRunner((argv) => {
      if (argv.includes("--version")) return { code: 0, stdout: "skill-scanner 2.0.14\n" };
      if (argv.includes("scan")) {
        const out = argv[argv.indexOf("--output-sarif") + 1];
        if (out === undefined) return { code: 1, stderr: "missing --output-sarif" };
        writeFileSync(out, "not SARIF", "utf8");
        return { code: 0, stdout: "done\n" };
      }
      return undefined;
    });

    const outcome = await runCiscoSourceTreeScanV1({
      run,
      platform: "linux",
      env: {},
      sourceRoot: realpathSync(dir),
      selectedClosurePaths: selectionOf("skills/clean"),
    });

    expect(outcome).toEqual({
      kind: "failed",
      stage: "output",
      detail: "detector did not emit valid SARIF",
    });
  });

  it("fails at the output stage when a job writes no SARIF file", async () => {
    skill("skills/clean", "# Clean\n");
    const run = fakeRunner((argv) =>
      argv.includes("--version")
        ? { code: 0, stdout: "skill-scanner 2.0.14\n" }
        : { code: 0, stdout: "done\n" },
    );

    const outcome = await runCiscoSourceTreeScanV1({
      run,
      platform: "linux",
      env: {},
      sourceRoot: realpathSync(dir),
      selectedClosurePaths: selectionOf("skills/clean"),
    });

    expect(outcome).toEqual({
      kind: "failed",
      stage: "output",
      detail: "detector did not emit valid SARIF",
    });
  });

  it("scans a root-level SKILL.md as the root job with bare URIs", async () => {
    // C2a §3.1: a root-level SKILL.md makes the root one of the jobs, with
    // the empty prefix (§3.4: just `<uri>` for the root job).
    writeFileSync(join(dir, "SKILL.md"), "# Root\n", "utf8");
    const sarif = {
      runs: [
        {
          results: [
            {
              ruleId: "FIXTURE",
              message: { text: "root finding" },
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
    };

    const outcome = await runCiscoSourceTreeScanV1({
      run: ciscoRunner(sarif),
      platform: "linux",
      env: {},
      sourceRoot: realpathSync(dir),
      selectedClosurePaths: ["SKILL.md"],
    });

    expect(outcome.kind).toBe("completed");
    if (outcome.kind !== "completed") return;
    expect(outcome.skillDirectories).toEqual([""]);
    const run0 = mergedRuns(outcome.sarifText)[0] as {
      results: Array<{
        locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }>;
      }>;
    };
    expect(run0.results[0]?.locations[0]?.physicalLocation.artifactLocation.uri).toBe("SKILL.md");
  });

  it("bounds and control-character-encodes untrusted analyzer output in details", async () => {
    skill("skills/clean", "# Clean\n");
    const noisy = `boom\n${"x".repeat(4000)}`;
    const run = fakeRunner((argv) =>
      argv.includes("--version")
        ? { code: 0, stdout: "skill-scanner 2.0.14\n" }
        : { code: 2, stdout: "", stderr: noisy },
    );

    const outcome = await runCiscoSourceTreeScanV1({
      run,
      platform: "linux",
      env: {},
      sourceRoot: realpathSync(dir),
      selectedClosurePaths: selectionOf("skills/clean"),
    });

    expect(outcome.kind).toBe("failed");
    if (outcome.kind !== "failed") return;
    expect(outcome.stage).toBe("execution");
    expect(outcome.detail.length).toBeLessThanOrEqual(1024);
    expect(outcome.detail).not.toContain("\n");
  });
});
