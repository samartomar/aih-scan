import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  CISCO_MULTI_SKILL_SCANNER_PROJECT_V1,
  ciscoSkillScannerRunArgvV1,
  ciscoSkillScannerVersionArgvV1,
  planCiscoSourceTreeJobsV1,
  resolveCiscoScanConcurrencyV1,
  scrubCiscoScanEnvV1,
  validateCiscoDetectorOptionsV1,
} from "../../../src/detectors/cisco-multi-skill/plan-v1.js";

// Parity tests for the planning half of Core's `detector.cisco` multi-skill
// scan (`src/trust/detectors.ts` argv builders, `resolveCiscoScanConcurrency`,
// `collectCiscoSkillDirs`; `src/trust/fetch.ts` `scrubFetchEnv`). Ported from
// Core's `tests/trust/scan.test.ts` (~3052-3412, 5187-5213) and driven through
// fixture roots and fake inventories only.

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "aih-scan-cisco-plan-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function skill(rel: string, body: string): void {
  const root = join(dir, rel);
  mkdirSync(root, { recursive: true });
  writeFileSync(join(root, "SKILL.md"), body, "utf8");
}

describe("cisco multi-skill argv planning", () => {
  it("invokes Cisco skill-scanner from the committed uv lock without network-enabling options", () => {
    // Ported from Core tests/trust/scan.test.ts:5187.
    const argv = ciscoSkillScannerRunArgvV1("linux", "/scan-root", "/tmp/cisco.sarif");

    expect(argv).toEqual([
      "uv",
      "run",
      "--project",
      CISCO_MULTI_SKILL_SCANNER_PROJECT_V1,
      "--locked",
      "--isolated",
      "--python",
      "3.12",
      "--offline",
      "--no-python-downloads",
      "--no-env-file",
      "skill-scanner",
      "scan",
      "/scan-root",
      "--format",
      "sarif",
      "--output-sarif",
      "/tmp/cisco.sarif",
    ]);
    expect(argv).not.toEqual(expect.arrayContaining(["--use-llm"]));
    expect(argv).not.toEqual(expect.arrayContaining(["--use-virustotal"]));
    expect(argv).not.toEqual(expect.arrayContaining(["--use-aidefense"]));
  });

  it("builds the version probe argv from the same locked project", () => {
    expect(ciscoSkillScannerVersionArgvV1("linux")).toEqual([
      "uv",
      "run",
      "--project",
      CISCO_MULTI_SKILL_SCANNER_PROJECT_V1,
      "--locked",
      "--isolated",
      "--python",
      "3.12",
      "--offline",
      "--no-python-downloads",
      "--no-env-file",
      "skill-scanner",
      "--version",
    ]);
  });

  it("passes uv argv through unchanged on Windows because uv is no cmd shim", () => {
    // Core's execArgv wraps only WIN_CMD_SHIMS (claude/npm/npx/pnpm/scoop/yarn).
    expect(ciscoSkillScannerRunArgvV1("windows", "C:/scan-root", "C:/tmp/cisco.sarif")).toEqual(
      ciscoSkillScannerRunArgvV1("linux", "C:/scan-root", "C:/tmp/cisco.sarif"),
    );
  });
});

describe("resolveCiscoScanConcurrencyV1", () => {
  it.each([
    [undefined, 4],
    ["", 4],
    ["   ", 4],
    ["6", 6],
    [" 6 ", 6],
    ["0", 4],
    ["06", 4],
    ["abc", 4],
    ["4.5", 4],
    ["-3", 4],
    ["64", 64],
    ["65", 4],
    ["99999999999999999999", 4],
  ])("resolves AIH_CISCO_SCAN_CONCURRENCY=%j to %i", (raw, expected) => {
    const env: NodeJS.ProcessEnv = raw === undefined ? {} : { AIH_CISCO_SCAN_CONCURRENCY: raw };
    expect(resolveCiscoScanConcurrencyV1(env)).toBe(expected);
  });
});

describe("scrubCiscoScanEnvV1", () => {
  it("keeps the allow-list and drops secret-shaped and unknown keys", () => {
    const scrubbed = scrubCiscoScanEnvV1({
      PATH: "bin",
      HOME: "/home/fixture",
      UV_CACHE_DIR: "/cache",
      XDG_CACHE_HOME: "/xdg",
      GITHUB_TOKEN: "ghp_fixture_not_a_secret",
      OPENAI_API_KEY: "sk-fixture-not-a-secret",
      AWS_ACCESS_KEY_ID: "fixture",
      MY_SECRET: "fixture",
      MY_PASSWORD: "fixture",
      APP_CREDENTIALS: "fixture",
      UNRELATED: "fixture",
      EMPTY_ALLOWED: undefined,
    });

    expect(scrubbed).toEqual({
      PATH: "bin",
      HOME: "/home/fixture",
      UV_CACHE_DIR: "/cache",
      XDG_CACHE_HOME: "/xdg",
    });
  });
});

describe("planCiscoSourceTreeJobsV1", () => {
  // C2a §3.1: jobs are the dirname of every SELECTED SKILL.md, deduplicated
  // and sorted with Core's localeCompare collation (decision 7); the tree is
  // never walked.
  it("plans one job per selected SKILL.md directory, deduplicated and localeCompare-sorted", () => {
    const jobs = planCiscoSourceTreeJobsV1(dir, [
      "skills/b/SKILL.md",
      "docs/readme.md",
      "skills/b/nested/SKILL.md",
      "SKILL.md",
      "skills/a/SKILL.md",
      "skills/b/notes.txt",
    ]);

    expect(jobs.map((job) => job.path)).toEqual(
      ["", "skills/a", "skills/b", "skills/b/nested"].sort((left, right) =>
        left.localeCompare(right),
      ),
    );
  });

  it("treats nested skill directories as separate jobs", () => {
    const jobs = planCiscoSourceTreeJobsV1(dir, [
      "skills/beta/SKILL.md",
      "skills/beta/nested/gamma/SKILL.md",
    ]);

    expect(jobs.map((job) => job.path)).toEqual(["skills/beta", "skills/beta/nested/gamma"]);
  });

  it("gives a root-level SKILL.md the empty prefix and the root as its directory", () => {
    const jobs = planCiscoSourceTreeJobsV1(dir, ["SKILL.md"]);

    expect(jobs).toHaveLength(1);
    expect(jobs[0]?.path).toBe("");
    expect(jobs[0]?.skillDir).toBe(dir);
  });

  it("resolves job directories under the source root", () => {
    const jobs = planCiscoSourceTreeJobsV1(dir, ["skills/a/SKILL.md"]);

    expect(jobs[0]?.skillDir).toBe(join(dir, "skills", "a"));
  });

  it("plans jobs from the selection alone, never from walking the tree", () => {
    // Skills exist on disk but are not selected: no jobs. A selected path
    // under a skip directory IS a job, because the selection is Core's
    // declaration of the subject (C2a §3.6).
    skill("skills/on-disk", "# On disk\n");
    skill("node_modules/pkg", "# Pkg\n");

    expect(planCiscoSourceTreeJobsV1(dir, [])).toEqual([]);
    expect(
      planCiscoSourceTreeJobsV1(dir, ["node_modules/pkg/SKILL.md"]).map((job) => job.path),
    ).toEqual(["node_modules/pkg"]);
  });
});

describe("validateCiscoDetectorOptionsV1", () => {
  // C2a §3.3: Core clamps AIH_CISCO_SCAN_CONCURRENCY before sending; Scan
  // validates the received integer 1..64 and refuses unknown keys, never
  // throwing on bad input.
  it.each([
    [undefined, 4],
    [{}, 4],
    [{ concurrency: 1 }, 1],
    [{ concurrency: 6 }, 6],
    [{ concurrency: 64 }, 64],
  ])("accepts %j with concurrency %i", (value, expected) => {
    const validated = validateCiscoDetectorOptionsV1(value);

    expect(validated).toEqual({ ok: true, concurrency: expected });
  });

  it.each([
    [null],
    [["concurrency"]],
    ["concurrency"],
    [4],
    [{ concurrency: 0 }],
    [{ concurrency: 65 }],
    [{ concurrency: 1.5 }],
    [{ concurrency: "4" }],
    [{ concurrency: Number.MAX_SAFE_INTEGER }],
    [{ concurrency: 4, extra: true }],
    [{ unknown: 1 }],
  ])("refuses %j with a typed detector-options-invalid result", (value) => {
    const validated = validateCiscoDetectorOptionsV1(value);

    expect(validated.ok).toBe(false);
    if (!validated.ok) {
      expect(validated.reason).toBe("detector-options-invalid");
      expect(validated.detail.length).toBeGreaterThan(0);
    }
  });

  it("refuses objects with a custom prototype", () => {
    const validated = validateCiscoDetectorOptionsV1(
      Object.assign(Object.create({ infected: true }), { concurrency: 4 }),
    );

    expect(validated).toMatchObject({ ok: false, reason: "detector-options-invalid" });
  });
});
