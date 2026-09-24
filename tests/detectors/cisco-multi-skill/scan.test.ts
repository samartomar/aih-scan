import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  CISCO_MULTI_SKILL_SCAN_TIMEOUT_MS_V1,
  type CiscoMultiSkillRunnerV1,
  type CiscoMultiSkillRunOptionsV1,
  type CiscoMultiSkillRunResultV1,
  ciscoSkillScannerVersionArgvV1,
} from "../../../src/detectors/cisco-multi-skill/plan-v1.js";
import {
  checkCiscoSkillScannerAvailableV1,
  ciscoScanFailureReasonV1,
  runCiscoSkillScanV1,
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

const EMPTY_SARIF = { runs: [] };

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

function ciscoRunner(sarif: unknown, onScan?: FakeHandler): CiscoMultiSkillRunnerV1 {
  return fakeRunner((argv, opts) => {
    if (!isCiscoSkillScannerArgv(argv)) return { code: 127, stderr: "not found", spawnError: true };
    if (argv.includes("--version")) return { code: 0, stdout: "skill-scanner 2.0.14\n" };
    if (argv.includes("scan")) {
      onScan?.(argv, opts);
      const out = argv[argv.indexOf("--output-sarif") + 1];
      if (out === undefined) return { code: 1, stderr: "missing --output-sarif" };
      writeFileSync(out, JSON.stringify(sarif), "utf8");
      return { code: 0, stdout: `Report saved to: ${out}\n` };
    }
    return undefined;
  });
}

function mergedRuns(text: string): Array<Record<string, unknown>> {
  return (JSON.parse(text) as { runs: Array<Record<string, unknown>> }).runs;
}

describe("runCiscoSkillScanV1", () => {
  it("runs one locked offline skill-scanner scan per skill directory", async () => {
    // Ported from Core tests/trust/scan.test.ts:3052.
    skill("skills/clean", "# Clean\n");
    const scanTargets: string[] = [];
    const observed: Array<{ cwd?: string; timeoutMs?: number }> = [];

    const text = await runCiscoSkillScanV1({
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
    expect(JSON.parse(text)).toEqual({ version: "2.1.0", runs: [] });
  });

  it("scrubs the environment each skill scan sees", async () => {
    // The scan-call half of Core's env-scrub assertions (tests/trust/scan.test.ts:4400).
    skill("skills/clean", "# Clean\n");
    const seenEnvs: Array<NodeJS.ProcessEnv | undefined> = [];

    await runCiscoSkillScanV1({
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
            JSON.stringify({
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
            "utf8",
          );
          return { code: 0, stdout: `Report saved to: ${out}\n`, stderr: "" };
        };

        const text = await runCiscoSkillScanV1({
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
        writeFileSync(output, JSON.stringify(EMPTY_SARIF), "utf8");
        return { code: 0, stdout: `Report saved to: ${output}\n`, stderr: "" };
      } finally {
        active--;
      }
    };

    const text = await runCiscoSkillScanV1({
      run,
      platform: "linux",
      env: {},
      tree: realpathSync(dir),
    });

    expect(JSON.parse(text)).toEqual({ version: "2.1.0", runs: [] });
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
        writeFileSync(output, JSON.stringify(EMPTY_SARIF), "utf8");
        return { code: 0, stdout: `Report saved to: ${output}\n`, stderr: "" };
      } finally {
        active--;
      }
    };

    await runCiscoSkillScanV1({
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
        writeFileSync(output, JSON.stringify(EMPTY_SARIF), "utf8");
        return { code: 0, stdout: `Report saved to: ${output}\n`, stderr: "" };
      } finally {
        active--;
      }
    };

    await expect(
      runCiscoSkillScanV1({ run, platform: "linux", env: {}, tree: realpathSync(dir) }),
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
      writeFileSync(output, JSON.stringify(EMPTY_SARIF), "utf8");
      return { code: 0, stdout: "", stderr: "" };
    };

    await expect(
      runCiscoSkillScanV1({ run, platform: "linux", env: {}, tree: realpathSync(dir) }),
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

    const text = await runCiscoSkillScanV1({
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

  it("leaves unsafe Cisco SARIF artifact URIs unprefixed", async () => {
    // The merge half of Core tests/trust/scan.test.ts:4851 — unsafe URIs pass
    // through unchanged; Core's downstream sanitizer owns the fallback.
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

    const text = await runCiscoSkillScanV1({
      run: ciscoRunner(sarif),
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
    ).toEqual(["../../../../etc/passwd", "C:evil"]);
  });

  it("strips authority-free file:// prefixes but leaves absolute file URIs untouched", async () => {
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

    const text = await runCiscoSkillScanV1({
      run: ciscoRunner(sarif),
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
    ).toEqual(["skills/clean/SKILL.md", "file:///etc/passwd"]);
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
      runCiscoSkillScanV1({ run, platform: "linux", env: {}, tree: realpathSync(dir) }),
    ).rejects.toThrow("detector did not emit valid SARIF");
  });

  it("fails when the tree holds no SKILL.md directory", async () => {
    await expect(
      runCiscoSkillScanV1({
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
      runCiscoSkillScanV1({ run, platform: "linux", env: {}, tree: realpathSync(dir) }),
    ).rejects.toThrow("detector exit 2");
  });
});

describe("checkCiscoSkillScannerAvailableV1", () => {
  it("accepts the pinned version under the startup timeout", async () => {
    // The Cisco half of Core tests/trust/scan.test.ts:5297.
    let timeoutMs: number | undefined;
    let seenArgv: readonly string[] = [];
    const run = fakeRunner((argv, opts) => {
      if (argv.includes("skill-scanner") && argv.includes("--version")) {
        timeoutMs = opts?.timeoutMs;
        seenArgv = argv;
        return { code: 0, stdout: "skill-scanner 2.0.14\n" };
      }
      return undefined;
    });

    await expect(
      checkCiscoSkillScannerAvailableV1({ run, platform: "linux", env: {} }),
    ).resolves.toBeUndefined();
    expect(timeoutMs).toBe(120_000);
    expect(seenArgv).toEqual(ciscoSkillScannerVersionArgvV1("linux"));
  });

  it("reports the process's own words when uv cannot run the scanner", async () => {
    // The availability half of Core tests/trust/scan.test.ts:3346 and :4462.
    const run = fakeRunner((argv) =>
      isCiscoSkillScannerArgv(argv)
        ? { code: 127, stdout: "", stderr: "uv not found", spawnError: true }
        : undefined,
    );

    await expect(
      checkCiscoSkillScannerAvailableV1({ run, platform: "linux", env: {} }),
    ).resolves.toBe("uv not found");
  });

  it("reports an empty version probe", async () => {
    const run = fakeRunner(() => ({ code: 0, stdout: "  \n" }));

    await expect(
      checkCiscoSkillScannerAvailableV1({ run, platform: "linux", env: {} }),
    ).resolves.toBe("skill-scanner version check emitted no output");
  });

  it("reports a version mismatch against the expected version", async () => {
    const run = fakeRunner(() => ({ code: 0, stdout: "skill-scanner 9.9.9\n" }));

    await expect(
      checkCiscoSkillScannerAvailableV1({ run, platform: "linux", env: {} }),
    ).resolves.toBe('skill-scanner version "skill-scanner 9.9.9" does not match 2.0.14');
    await expect(
      checkCiscoSkillScannerAvailableV1({
        run,
        platform: "linux",
        env: {},
        expectedVersion: "9.9.9",
      }),
    ).resolves.toBeUndefined();
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
