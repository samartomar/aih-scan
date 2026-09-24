import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  CISCO_MULTI_SKILL_SCANNER_PROJECT_V1,
  type CiscoSkillInventoryEntryV1,
  ciscoSkillScannerRunArgvV1,
  ciscoSkillScannerVersionArgvV1,
  collectCiscoSkillDirsV1,
  resolveCiscoScanConcurrencyV1,
  scrubCiscoScanEnvV1,
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

function toPosix(path: string): string {
  return path.replace(/\\/g, "/");
}

function inventoryOf(absolutePaths: readonly string[]): {
  matching(
    predicate: (entry: CiscoSkillInventoryEntryV1) => boolean,
  ): Iterable<CiscoSkillInventoryEntryV1>;
} {
  const entries = absolutePaths.map((absolutePath) => ({
    absolutePath,
    relativePath: toPosix(relative(dir, absolutePath)),
    size: 1,
  }));
  return {
    *matching(predicate: (entry: CiscoSkillInventoryEntryV1) => boolean) {
      for (const entry of entries) if (predicate(entry)) yield entry;
    },
  };
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

describe("collectCiscoSkillDirsV1", () => {
  it("lists every SKILL.md directory, nested ones included, skip dirs excluded", () => {
    skill("skills/a", "# A\n");
    skill("skills/b", "# B\n");
    skill("deep/nested/c", "# C\n");
    for (const skipped of [
      "node_modules/pkg",
      "dist/built",
      "coverage/report",
      "vendor/lib",
      ".git/hooks",
      ".hg/store",
      ".svn/entries",
      ".aih/cache",
    ]) {
      skill(skipped, "# Skipped\n");
    }

    const dirs = collectCiscoSkillDirsV1(dir).map((entry) => toPosix(relative(dir, entry)));

    expect(dirs).toEqual(["deep/nested/c", "skills/a", "skills/b"]);
  });

  it("includes the root itself when the root holds a SKILL.md, sorted first", () => {
    skill("skills/a", "# A\n");
    writeFileSync(join(dir, "SKILL.md"), "# Root\n", "utf8");

    const dirs = collectCiscoSkillDirsV1(dir);

    expect(dirs[0]).toBe(resolve(dir));
    expect(dirs.map((entry) => toPosix(relative(dir, entry)))).toEqual(["", "skills/a"]);
  });

  it("takes candidates only from a supplied inventory, skip-dir names included", () => {
    // The inventory is authoritative: Core applies the walk's skip dirs only in
    // the filesystem fallback, so an inventory entry under node_modules counts.
    skill("skills/a", "# A\n");
    skill("node_modules/pkg", "# Pkg\n");
    const inventory = inventoryOf([join(dir, "node_modules", "pkg", "SKILL.md")]);

    const dirs = collectCiscoSkillDirsV1(dir, inventory);

    expect(dirs.map((entry) => toPosix(relative(dir, entry)))).toEqual(["node_modules/pkg"]);
  });

  it("ignores inventory entries whose basename is not SKILL.md", () => {
    skill("skills/a", "# A\n");
    const inventory = inventoryOf([
      join(dir, "skills", "a", "SKILL.md"),
      join(dir, "skills", "a", "notes.txt"),
    ]);

    const dirs = collectCiscoSkillDirsV1(dir, inventory);

    expect(dirs.map((entry) => toPosix(relative(dir, entry)))).toEqual(["skills/a"]);
  });

  it("sorts by source-relative POSIX path with Core's localeCompare order", () => {
    skill("skills/skill-2", "# 2\n");
    skill("skills/skill-10", "# 10\n");
    skill("alpha", "# A\n");

    const dirs = collectCiscoSkillDirsV1(dir).map((entry) => toPosix(relative(dir, entry)));

    expect(dirs).toEqual(
      ["alpha", "skills/skill-2", "skills/skill-10"].sort((left, right) =>
        left.localeCompare(right),
      ),
    );
  });
});
