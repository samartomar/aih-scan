import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, posix } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  type BaselineProcessRunnerV1,
  CISCO_SKILL_SCANNER_VERSION_V1,
  createBaselineAnalyzerExecutionV1,
} from "../../src/baseline/runtime-v1.js";
import { ciscoSourceRelativeSarifV1 } from "../../src/baseline/sarif-source-relative-v1.js";
import { BASELINE_BWRAP_EXECUTABLE_V1 } from "../../src/cli/process-runner.js";
import { canonicalStrictJsonBytesV1 } from "../../src/contract/strict-json-v1.js";

// Coordinator decision D40 (U1m): Cisco 2.1.0's SARIF reporter makes every artifact URI
// relative to its process working directory, the undeclared `%SRCROOT%`
// (`SARIFReporter._artifact_uri`: `relpath(skill_dir, os.getcwd()) / file_path` when the skill
// lies under the cwd, else `file_path`). Scan's shared normalizer reads an undeclared
// `%SRCROOT%` as the reporting skill's directory, so every Scan Cisco path must run Cisco from a
// working directory from which every skill is reached through "..". linux-namespace-uv-v1 ran
// it from `/aih/source` (the scan root), and every nested skill's location came out doubled
// (hosted CI run 36080143247).

const source = {
  id: "d40",
  owner: "aih",
  repository: "d40",
  pinnedCommit: "a".repeat(40),
  treeSha256: "b".repeat(64),
};
const temporaryDirectories: string[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  for (const directory of temporaryDirectories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});
beforeEach(() => {
  vi.spyOn(process, "platform", "get").mockReturnValue("linux");
});

const ok = (stdout = "") => ({ code: 0, stdout, stderr: "", truncated: false });
const emptySarif = canonicalStrictJsonBytesV1({
  version: "2.1.0",
  runs: [
    {
      tool: { driver: { name: "cisco" } },
      results: [],
      invocations: [{ executionSuccessful: true }],
    },
  ],
}).toString("utf8");

/** Runs detector.cisco under linux-namespace-uv-v1 with a fake runner; returns every argv. */
async function ciscoCalls(): Promise<{ calls: string[][]; sourceRoot: string }> {
  const sourceRoot = mkdtempSync(join(tmpdir(), "aih-scan-d40-"));
  temporaryDirectories.push(sourceRoot);
  mkdirSync(join(sourceRoot, "skills", "demo"), { recursive: true });
  writeFileSync(join(sourceRoot, "skills", "demo", "SKILL.md"), "# Demo\n", "utf8");
  const calls: string[][] = [];
  const runner: BaselineProcessRunnerV1 = async (argv) => {
    calls.push([...argv]);
    if (argv.includes("sync")) return ok();
    if (argv.at(-1) === "--version") return ok(`skill-scanner ${CISCO_SKILL_SCANNER_VERSION_V1}`);
    if (argv.includes("scan-all")) {
      const at = argv.findIndex(
        (value, index) => value === "--bind" && argv[index + 2] === "/aih/work",
      );
      const work = argv[at + 1] as string;
      writeFileSync(join(work, "results.sarif"), emptySarif, "utf8");
      writeFileSync(
        join(work, "results.json"),
        canonicalStrictJsonBytesV1({
          summary: { total_skills_scanned: 1 },
          results: [{ skill_path: "/aih/source/skills/demo", findings: [] }],
        }),
      );
      return ok();
    }
    throw new Error(`unexpected argv: ${argv.join(" ")}`);
  };
  await createBaselineAnalyzerExecutionV1({ runner })({ analyzer: "cisco", sourceRoot, source });
  return { calls, sourceRoot };
}

/** The value of `--chdir` in a bwrap argv (its namespace part, before `--`). */
const chdirOf = (argv: readonly string[]) => {
  const namespace = argv.slice(0, argv.indexOf("--"));
  expect(namespace.filter((value) => value === "--chdir")).toHaveLength(1);
  return namespace[namespace.indexOf("--chdir") + 1] as string;
};
/** Every mount a bwrap argv names, as `flag source destination` or `flag destination`. */
const mounts = (argv: readonly string[]) => {
  const namespace = argv.slice(0, argv.indexOf("--"));
  const out: string[] = [];
  namespace.forEach((value, index) => {
    if (["--bind", "--ro-bind", "--ro-bind-try"].includes(value))
      out.push(`${value} ${namespace[index + 1]} ${namespace[index + 2]}`);
    else if (["--dir", "--tmpfs", "--proc", "--dev"].includes(value))
      out.push(`${value} ${namespace[index + 1]}`);
  });
  return out;
};

describe("D40: linux-namespace Cisco runs from an empty directory outside the scan root", () => {
  it("runs every skill-scanner call from a cwd that reaches /aih/source and each skill through '..'", async () => {
    const { calls } = await ciscoCalls();
    const scanner = calls.filter(
      (argv) =>
        argv[0] === BASELINE_BWRAP_EXECUTABLE_V1 && argv.includes("/aih/venv/bin/skill-scanner"),
    );
    expect(scanner).toHaveLength(2);
    expect(scanner.some((argv) => argv.includes("scan-all"))).toBe(true);
    for (const argv of scanner) {
      const cwd = chdirOf(argv);
      expect(posix.isAbsolute(cwd)).toBe(true);
      expect(posix.normalize(cwd)).toBe(cwd);
      // Neither the scan root, nor below it, nor above it (so neither `/` nor `/aih`).
      for (const target of ["/aih/source", "/aih/source/skills/demo"]) {
        const relative = posix.relative(cwd, target);
        expect(relative.startsWith("../")).toBe(true);
      }
      expect(posix.relative("/aih/source", cwd).startsWith("../")).toBe(true);
      // A dedicated empty directory: created by bwrap, read-only, and not the output directory
      // or any other mount.
      expect(cwd).not.toBe("/aih/work");
      const namespace = argv.slice(0, argv.indexOf("--"));
      const created = namespace.indexOf(cwd);
      expect(namespace.slice(created - 3, created + 1)).toEqual(["--perms", "0555", "--dir", cwd]);
      expect(namespace.filter((value) => value === cwd)).toHaveLength(2);
    }
  });

  it("changes no other mount: the source stays a read-only bind and the cwd is the only addition", async () => {
    const { calls, sourceRoot } = await ciscoCalls();
    const scan = calls.find((argv) => argv.includes("scan-all")) as string[];
    const cwd = chdirOf(scan);
    const scanMounts = mounts(scan);
    expect(scanMounts).toContain(`--ro-bind ${sourceRoot} /aih/source`);
    expect(scanMounts.filter((mount) => mount.endsWith(" /aih/source"))).toHaveLength(1);
    const sync = calls.find((argv) => argv.includes("sync")) as string[];
    // The environment sync binds no source and runs from /aih/project, unchanged.
    expect(chdirOf(sync)).toBe("/aih/project");
    expect(mounts(sync)).not.toContain(`--dir ${cwd}`);
    expect(
      scanMounts.filter((mount) => !mount.includes("/aih/source") && mount !== `--dir ${cwd}`),
    ).toEqual(mounts(sync));
  });
});

describe("D40: Scan refuses, rather than guesses, a Cisco location made relative to the scan root", () => {
  // Real skill-scanner 2.1.0 output, byte for byte, captured in U1l under linux-namespace-uv-v1
  // at 42f5754 on the ci.yml probe tree (`skills/probe/SKILL.md`), when Cisco still ran from
  // `/aih/source`: the JSON `file_path` is skill-relative (`SKILL.md`), every SARIF URI is
  // relative to the cwd (`skills/probe/SKILL.md`).
  const report = JSON.parse(
    readFileSync(
      new URL(
        "../fixtures/cisco/real-2.1.0-linux-namespace-source-cwd-probe.report.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  const sarif = JSON.parse(
    readFileSync(
      new URL(
        "../fixtures/cisco/real-2.1.0-linux-namespace-source-cwd-probe.sarif",
        import.meta.url,
      ),
      "utf8",
    ),
  );

  it("holds the capture's shape: skill-relative JSON paths, cwd-relative SARIF URIs", () => {
    const paths = report.results.flatMap((skill: { findings: { file_path: string }[] }) =>
      skill.findings.map((finding) => finding.file_path),
    );
    expect(paths).toEqual(["SKILL.md", "SKILL.md", "SKILL.md"]);
    const uris = sarif.runs[0].results.map(
      (result: { locations: { physicalLocation: { artifactLocation: { uri: string } } }[] }) =>
        result.locations[0]?.physicalLocation.artifactLocation.uri,
    );
    expect(uris).toEqual([
      "skills/probe/SKILL.md",
      "skills/probe/SKILL.md",
      "skills/probe/SKILL.md",
    ]);
  });

  it("fails closed with the doubled-path refusal through the shared normalizer", () => {
    expect(() => ciscoSourceRelativeSarifV1(sarif, report, ["/aih/source"])).toThrow(
      "SARIF result 0 (FILE_MAGIC_MISMATCH skills/probe/skills/probe/SKILL.md:null) does not match JSON finding 0 (FILE_MAGIC_MISMATCH skills/probe/SKILL.md:null)",
    );
  });
});
