import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { BaselineProcessRunnerV1 } from "../../src/baseline/runtime-v1.js";
import { resolveDetectorCapabilityV1 } from "../../src/capability/detector-capability-v1.js";
import { runDetectorV1 } from "../../src/runner/run-detector-v1.js";

/**
 * C2a §3.1–§3.6 through the public runner: a detector.cisco source-tree subject under
 * host-process-uv-v1 runs one skill-scanner job per directory holding a selected SKILL.md,
 * at most detectorOptions.concurrency at a time, merged in job order; the option is refused
 * wherever it would have no effect.
 */

const HOST = "host-process-uv-v1";
const windows = process.platform === "win32";
const SKILLS = ["a", "b", "c", "d", "e"];
const roots: string[] = [];

afterEach(() => {
  vi.restoreAllMocks();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function temporary(label: string): string {
  const root = mkdtempSync(join(tmpdir(), `aih-scan-cst-${label}-`));
  roots.push(root);
  return root;
}

function skillsTree(): string {
  const root = temporary("source");
  writeFileSync(join(root, "README.md"), "# Readme\n");
  for (const skill of SKILLS) {
    mkdirSync(join(root, "skills", skill), { recursive: true });
    writeFileSync(join(root, "skills", skill, "SKILL.md"), `# Skill ${skill}\n`);
  }
  return root;
}

const selection = ["README.md", ...SKILLS.map((skill) => `skills/${skill}/SKILL.md`)];

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
  return { env, python, uv: realpathSync.native(uvFile) };
}

const ok = (stdout: string) => ({ code: 0, stdout, stderr: "", truncated: false });
const jobSarif = (skill: string) =>
  JSON.stringify({
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "skill-scanner" } },
        results: [
          {
            ruleId: `cisco.rule-${skill}`,
            level: "warning",
            message: { text: `finding in ${skill}` },
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
  });

type Scan = { argv: readonly string[]; cwd: string | undefined };

/** A fake analyzer that records how many scans overlap. */
function ciscoHost(
  python: string,
  scans: Scan[],
  observed: { inFlight: number; peak: number },
  fail: (skill: string) => string | undefined = () => undefined,
): BaselineProcessRunnerV1 {
  return async (argv, options) => {
    if (argv[1] === "--version") return ok("uv 0.12.13 (0123456 2026-09-01 x86_64)");
    if (argv[1] === "python" && argv[2] === "find")
      return ok(argv.includes("--show-version") ? "3.12.13\n" : `${python}\n`);
    if (argv[1] === "sync") return ok("");
    if (argv.at(-1) === "--version") return ok("skill-scanner 2.0.14\n");
    scans.push({ argv: [...argv], cwd: options.cwd });
    const skillDir = argv[argv.indexOf("scan") + 1] ?? "";
    const skill = skillDir.split(/[\\/]/).at(-1) ?? "";
    observed.inFlight += 1;
    observed.peak = Math.max(observed.peak, observed.inFlight);
    await new Promise((settle) => setTimeout(settle, 30));
    observed.inFlight -= 1;
    const reason = fail(skill);
    if (reason !== undefined) return { code: 1, stdout: "", stderr: reason, truncated: false };
    writeFileSync(argv[argv.indexOf("--output-sarif") + 1] ?? "", jobSarif(skill));
    return ok("");
  };
}

function request(sourceRoot: string, env: Record<string, string>, extra = {}) {
  return {
    detectorId: "detector.cisco",
    executionProfileId: HOST,
    subject: { kind: "source-tree" as const, sourceRoot, selectedClosurePaths: selection },
    env,
    ...extra,
  };
}

function forbiddenRunner(record: { calls: number }): BaselineProcessRunnerV1 {
  return async (argv) => {
    record.calls += 1;
    throw new Error(`no process may be spawned here: ${argv.join(" ")}`);
  };
}

describe("detector.cisco source-tree under host-process-uv-v1", () => {
  it.each([
    [1, 1],
    [2, 2],
    [4, 4],
    [64, 5],
    [undefined, 4],
  ] as const)("applies concurrency %s: at most %s jobs overlap", async (concurrency, peak) => {
    const host = hostEnv();
    const scans: Scan[] = [];
    const observed = { inFlight: 0, peak: 0 };

    const outcome = await runDetectorV1(
      request(skillsTree(), host.env, {
        runner: ciscoHost(host.python, scans, observed),
        ...(concurrency === undefined ? {} : { detectorOptions: { concurrency } }),
      }),
    );

    expect(outcome.outcome).toBe("succeeded");
    expect(scans).toHaveLength(SKILLS.length);
    expect(observed.peak).toBe(peak);
  });

  it("merges one job per selected SKILL.md directory in job order, bound to the sealed files", async () => {
    const host = hostEnv();
    const scans: Scan[] = [];

    const outcome = await runDetectorV1(
      request(skillsTree(), host.env, {
        runner: ciscoHost(host.python, scans, { inFlight: 0, peak: 0 }),
        detectorOptions: { concurrency: 3 },
      }),
    );

    expect(outcome.outcome).toBe("succeeded");
    if (outcome.outcome !== "succeeded") return;
    if (outcome.evidence.kind !== "baseline-analyzer-observation-v1") return;
    const lock = resolveDetectorCapabilityV1("detector.cisco")?.executionProfiles.find(
      (entry) => entry.id === HOST,
    )?.analyzerLock;
    expect(outcome.evidence.observation.analyzer).toBe("cisco");
    expect(outcome.evidence.observation.analyzerVersion).toBe(
      `2.0.14+uvlock.${lock?.sha256.slice(0, 12)}`,
    );
    expect(
      outcome.findings.findings.map((finding) =>
        finding.location.state === "present" ? finding.location.value.path : null,
      ),
    ).toEqual(SKILLS.map((skill) => `skills/${skill}/SKILL.md`));
    expect(outcome.findings.findings.map((finding) => finding.rule)).toEqual(
      SKILLS.map((skill) => ({ state: "present", value: { nativeRuleId: `cisco.rule-${skill}` } })),
    );
    // Each job scans its own directory of the private snapshot, from inside it.
    const snapshot = dirname(dirname(scans[0]?.cwd ?? ""));
    for (const scan of scans) {
      const dir = scan.argv[scan.argv.indexOf("scan") + 1];
      expect(scan.cwd).toBe(dir);
      expect(dirname(dirname(dir ?? ""))).toBe(snapshot);
    }
    expect(existsSync(snapshot)).toBe(false);
    // The host lock, not the namespace lock, is the one installed.
    const bytes = readFileSync(
      join(import.meta.dirname, "..", "..", ...(lock?.path.split("/") ?? [])),
    );
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(lock?.sha256);
  });

  it("reports the lowest-index failing job and no partial SARIF", async () => {
    const host = hostEnv();
    const outcome = await runDetectorV1(
      request(skillsTree(), host.env, {
        runner: ciscoHost(host.python, [], { inFlight: 0, peak: 0 }, (skill) =>
          skill === "b" || skill === "d" ? `job-${skill}-broke` : undefined,
        ),
        detectorOptions: { concurrency: 4 },
      }),
    );

    expect(outcome).toMatchObject({ outcome: "failed", failure: { stage: "execution" } });
    if (outcome.outcome !== "failed") return;
    expect(outcome.failure.detail).toContain("job-b-broke");
    expect(outcome.failure.detail).not.toContain("job-d-broke");
    expect("findings" in outcome).toBe(false);
  });

  it("refuses a selection holding no SKILL.md before anything spawns", async () => {
    const host = hostEnv();
    const record = { calls: 0 };
    const root = skillsTree();

    const outcome = await runDetectorV1({
      ...request(root, host.env, { runner: forbiddenRunner(record) }),
      subject: { kind: "source-tree", sourceRoot: root, selectedClosurePaths: ["README.md"] },
    });

    expect(outcome).toMatchObject({ outcome: "refused", reason: "subject-requirement-unmet" });
    expect(outcome.outcome === "refused" && outcome.detail).toMatch(
      /no SKILL\.md directories found for Cisco scan/,
    );
    expect(record.calls).toBe(0);
  });
});

describe("detectorOptions.concurrency is accepted only where it is applied", () => {
  it.each([0, 65, 1.5, "2", null])("refuses concurrency %s", async (concurrency) => {
    const outcome = await runDetectorV1(
      request(skillsTree(), hostEnv().env, { detectorOptions: { concurrency } }),
    );
    expect(outcome).toMatchObject({ outcome: "refused", reason: "detector-options-invalid" });
  });

  it("refuses concurrency for a skill-directory subject, where it would change nothing", async () => {
    const root = temporary("skill");
    writeFileSync(join(root, "SKILL.md"), "# Skill\n");
    const record = { calls: 0 };

    const outcome = await runDetectorV1({
      detectorId: "detector.cisco",
      executionProfileId: HOST,
      subject: { kind: "skill-directory", sourceRoot: root, selectedClosurePaths: ["SKILL.md"] },
      detectorOptions: { concurrency: 2 },
      runner: forbiddenRunner(record),
    });

    expect(outcome).toMatchObject({ outcome: "refused", reason: "detector-options-invalid" });
    expect(outcome.outcome === "refused" && outcome.detail).toMatch(
      /applied only to a detector\.cisco source-tree subject under host-process-uv-v1/,
    );
    expect(record.calls).toBe(0);
  });
});
