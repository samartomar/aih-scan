import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  BASELINE_PYTHON_EXECUTABLE_V1,
  type BaselineProcessRunnerV1,
  SEMGREP_VERSION_V1,
} from "../../src/baseline/runtime-v1.js";
import {
  type DetectorPrerequisiteV1,
  resolveDetectorExecutionProfileDocumentV1,
} from "../../src/capability/detector-capability-v1.js";
import {
  BASELINE_BWRAP_EXECUTABLE_V1,
  BASELINE_UV_EXECUTABLE_V1,
} from "../../src/cli/process-runner.js";
import {
  canonicalStrictJsonBytesV1,
  canonicalStrictJsonSha256V1,
} from "../../src/contract/strict-json-v1.js";
import { runDetectorV1 } from "../../src/runner/run-detector-v1.js";

const HOST_PROFILE = "host-process-uv-v1";
const temporaryDirectories: string[] = [];

afterEach(() => {
  vi.restoreAllMocks();
  for (const directory of temporaryDirectories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

function sourceFixture(): string {
  const root = mkdtempSync(join(tmpdir(), "aih-scan-host-process-"));
  temporaryDirectories.push(root);
  writeFileSync(join(root, "README.md"), "# Readme\n", "utf8");
  return root;
}

function mockHost(os: NodeJS.Platform, architecture: string): void {
  vi.spyOn(process, "platform", "get").mockReturnValue(os);
  vi.spyOn(process, "arch", "get").mockReturnValue(architecture as NodeJS.Architecture);
}

/** A runner that fails the test if a refusal ever reaches a spawn. */
function forbiddenRunner(record: { calls: number }): BaselineProcessRunnerV1 {
  return async (argv) => {
    record.calls += 1;
    throw new Error(`no process may be spawned for a refusal: ${argv.join(" ")}`);
  };
}

function semgrepRequest(extra: Record<string, unknown>) {
  return {
    detectorId: "detector.semgrep",
    subject: {
      kind: "source-tree" as const,
      sourceRoot: sourceFixture(),
      selectedClosurePaths: ["README.md"],
    },
    ...extra,
  };
}

const sarif = canonicalStrictJsonBytesV1({
  version: "2.1.0",
  runs: [{ tool: { driver: { name: "semgrep" } }, results: [] }],
}).toString("utf8");

describe("runDetectorV1 host-process-uv-v1", () => {
  it("keeps linux-namespace-uv-v1 the default and never downgrades when bubblewrap is missing", async () => {
    mockHost("linux", "x64");
    const record = { calls: 0 };

    const result = await runDetectorV1(
      semgrepRequest({
        prerequisiteProbe: (prerequisite: DetectorPrerequisiteV1) =>
          prerequisite.id === BASELINE_BWRAP_EXECUTABLE_V1 ? "missing" : "present",
        runner: forbiddenRunner(record),
      }),
    );

    expect(result.outcome).toBe("refused");
    if (result.outcome !== "refused") return;
    expect(result.reason).toBe("prerequisite-missing");
    expect(result.detail).toContain(BASELINE_BWRAP_EXECUTABLE_V1);
    expect(record.calls).toBe(0);
  });

  it("runs only when named, reporting isolation none and network unenforced", async () => {
    mockHost("linux", "x64");
    const probed: string[] = [];
    const calls: { argv: readonly string[]; options: Parameters<BaselineProcessRunnerV1>[1] }[] =
      [];
    const okay = (stdout: string) => ({ code: 0, stdout, stderr: "", truncated: false });
    const runner: BaselineProcessRunnerV1 = async (argv, options) => {
      calls.push({ argv: [...argv], options: { ...options, env: { ...options.env } } });
      if (argv.includes("sync")) return okay("");
      if (argv.at(-1) === "--version") return okay(SEMGREP_VERSION_V1);
      if (argv.includes("--sarif")) return okay(sarif);
      throw new Error(`unexpected argv: ${argv.join(" ")}`);
    };

    const result = await runDetectorV1(
      semgrepRequest({
        executionProfileId: HOST_PROFILE,
        env: { PATH: "/usr/bin", API_TOKEN: "secret" },
        // bubblewrap is absent, and this profile must neither need nor probe it.
        prerequisiteProbe: (prerequisite: DetectorPrerequisiteV1) => {
          probed.push(prerequisite.id);
          return prerequisite.id === BASELINE_BWRAP_EXECUTABLE_V1 ? "missing" : "present";
        },
        runner,
      }),
    );

    expect(result.outcome).toBe("succeeded");
    if (result.outcome !== "succeeded") return;
    const document = resolveDetectorExecutionProfileDocumentV1(HOST_PROFILE);
    expect(result.executionProfile).toMatchObject({
      id: HOST_PROFILE,
      isolation: "none",
      network: "unenforced",
    });
    expect(result.executionProfile.sha256).toBe(canonicalStrictJsonSha256V1(document));
    expect(result.evidence.kind).toBe("baseline-analyzer-observation-v1");
    expect(probed).toContain(BASELINE_UV_EXECUTABLE_V1);
    expect(probed).not.toContain(BASELINE_BWRAP_EXECUTABLE_V1);
    expect(result.prerequisites.map((entry) => entry.id)).not.toContain(
      BASELINE_BWRAP_EXECUTABLE_V1,
    );
    expect(calls.length).toBeGreaterThan(0);
    for (const call of calls) {
      expect(call.argv[0]).toBe(BASELINE_UV_EXECUTABLE_V1);
      expect(call.argv).not.toContain(BASELINE_BWRAP_EXECUTABLE_V1);
      expect(call.argv).not.toContain("--unshare-all");
      // The host profile still owns and kills the analyzer's whole process group.
      expect(call.options.killProcessGroup).toBe(true);
      expect(call.options.env.API_TOKEN).toBeUndefined();
    }
    const acquisition = calls.find((call) => call.argv.includes("sync"))?.argv ?? [];
    for (const flag of document?.acquisition ?? []) expect(acquisition, flag).toContain(flag);
  });

  it("gates on its own prerequisites and refuses a missing uv before spawning", async () => {
    mockHost("linux", "x64");
    const record = { calls: 0 };

    const result = await runDetectorV1(
      semgrepRequest({
        executionProfileId: HOST_PROFILE,
        prerequisiteProbe: (prerequisite: DetectorPrerequisiteV1) =>
          prerequisite.id === BASELINE_UV_EXECUTABLE_V1 ? "missing" : "present",
        runner: forbiddenRunner(record),
      }),
    );

    expect(result.outcome).toBe("refused");
    if (result.outcome !== "refused") return;
    expect(result.reason).toBe("prerequisite-missing");
    expect(result.detail).toContain(BASELINE_UV_EXECUTABLE_V1);
    expect(record.calls).toBe(0);
  });

  it("refuses Windows until process-tree containment exists, even with a caller runner", async () => {
    mockHost("win32", "x64");
    const record = { calls: 0 };
    let probes = 0;

    const result = await runDetectorV1(
      semgrepRequest({
        executionProfileId: HOST_PROFILE,
        prerequisiteProbe: () => {
          probes += 1;
          return "present";
        },
        runner: forbiddenRunner(record),
      }),
    );

    expect(result.outcome).toBe("refused");
    if (result.outcome !== "refused") return;
    expect(result.reason).toBe("unsupported-platform");
    expect(result.detail).toContain("win32/x64");
    expect(result.detail).toContain(HOST_PROFILE);
    expect(result.detail).toMatch(/process-tree containment/i);
    expect(probes).toBe(0);
    expect(record.calls).toBe(0);
  });

  it("refuses macOS, where no hosted proof supports it", async () => {
    mockHost("darwin", "arm64");
    const record = { calls: 0 };

    const result = await runDetectorV1(
      semgrepRequest({
        executionProfileId: HOST_PROFILE,
        prerequisiteProbe: () => "present",
        runner: forbiddenRunner(record),
      }),
    );

    expect(result.outcome).toBe("refused");
    if (result.outcome !== "refused") return;
    expect(result.reason).toBe("unsupported-platform");
    expect(result.detail).toContain("darwin/arm64");
    expect(result.detail).toContain(HOST_PROFILE);
    expect(record.calls).toBe(0);
  });

  it("refuses a missing pinned Python before spawning, since uv may not download one", async () => {
    mockHost("linux", "x64");
    const record = { calls: 0 };

    const result = await runDetectorV1(
      semgrepRequest({
        executionProfileId: HOST_PROFILE,
        prerequisiteProbe: (prerequisite: DetectorPrerequisiteV1) =>
          prerequisite.id === BASELINE_PYTHON_EXECUTABLE_V1 ? "missing" : "present",
        runner: forbiddenRunner(record),
      }),
    );

    expect(result.outcome).toBe("refused");
    if (result.outcome !== "refused") return;
    expect(result.reason).toBe("prerequisite-missing");
    expect(result.detail).toContain(BASELINE_PYTHON_EXECUTABLE_V1);
    expect(record.calls).toBe(0);
  });

  it("gives every host spawn exactly the fixed environment its document declares", async () => {
    mockHost("linux", "x64");
    const environments: Record<string, string>[] = [];
    const okay = (stdout: string) => ({ code: 0, stdout, stderr: "", truncated: false });
    const runner: BaselineProcessRunnerV1 = async (argv, options) => {
      environments.push({ ...options.env });
      if (argv.includes("sync")) return okay("");
      if (argv.at(-1) === "--version") return okay(SEMGREP_VERSION_V1);
      if (argv.includes("--sarif")) return okay(sarif);
      throw new Error(`unexpected argv: ${argv.join(" ")}`);
    };

    const result = await runDetectorV1(
      semgrepRequest({
        executionProfileId: HOST_PROFILE,
        // Even allow-listed caller keys must not reach a host spawn.
        env: {
          PATH: "/attacker/bin",
          HOME: "/attacker",
          XDG_CACHE_HOME: "/attacker/cache",
          API_TOKEN: "secret",
        },
        prerequisiteProbe: () => "present",
        runner,
      }),
    );

    expect(result.outcome).toBe("succeeded");
    const environment = resolveDetectorExecutionProfileDocumentV1(HOST_PROFILE)?.environment;
    expect(environment?.policy).toBe("fixed-values");
    if (environment?.policy !== "fixed-values") return;
    const declared: Readonly<Record<string, string>> = environment.values;
    expect(Object.keys(declared).sort()).toEqual([
      "HOME",
      "LANG",
      "PATH",
      "PYTHONPATH",
      "PYTHONSAFEPATH",
      "TMPDIR",
      "UV_CACHE_DIR",
      "UV_NO_ENV_FILE",
      "UV_PROJECT_ENVIRONMENT",
    ]);
    expect(declared).toMatchObject({
      PATH: "/usr/local/bin:/usr/bin:/bin",
      LANG: "C.UTF-8",
      UV_NO_ENV_FILE: "1",
      PYTHONSAFEPATH: "1",
    });
    expect(declared.PYTHONPATH).not.toMatch(/^</);
    // Run-private paths are elided in the document, as the namespace profile's mounts are.
    for (const key of ["HOME", "TMPDIR", "UV_CACHE_DIR", "UV_PROJECT_ENVIRONMENT"])
      expect(declared[key], key).toMatch(/^<.+>$/);

    expect(environments.length).toBeGreaterThan(0);
    for (const env of environments) {
      expect(Object.keys(env).sort()).toEqual(Object.keys(declared).sort());
      for (const [key, value] of Object.entries(declared)) {
        if (value.startsWith("<")) {
          expect(env[key]?.length, key).toBeGreaterThan(0);
          expect(env[key], key).not.toMatch(/attacker/);
        } else expect(env[key], key).toBe(value);
      }
    }
  });
});
