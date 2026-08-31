import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  BASELINE_PYTHON_EXECUTABLE_V1,
  type BaselineProcessRunnerV1,
  CISCO_SKILL_SCANNER_VERSION_V1,
  createBaselineAnalyzerExecutionV1,
  SEMGREP_VERSION_V1,
  SKILLSPECTOR_IMAGE_DIGEST_V1,
  SKILLSPECTOR_IMAGE_V1,
} from "../../src/baseline/runtime-v1.js";
import {
  BASELINE_BWRAP_EXECUTABLE_V1,
  BASELINE_DOCKER_EXECUTABLE_V1,
  BASELINE_UV_EXECUTABLE_V1,
} from "../../src/cli/process-runner.js";
import { canonicalStrictJsonBytesV1 } from "../../src/contract/strict-json-v1.js";

const source = {
  id: "ecc",
  owner: "affaan-m",
  repository: "everything-claude-code",
  pinnedCommit: "a".repeat(40),
  treeSha256: "b".repeat(64),
};
const temporaryDirectories: string[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  for (const directory of temporaryDirectories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});
function sourceFixture(): string {
  const root = mkdtempSync(join(tmpdir(), "aih-scan-runtime-"));
  temporaryDirectories.push(root);
  mkdirSync(join(root, "skills", "demo"), { recursive: true });
  writeFileSync(join(root, "skills", "demo", "SKILL.md"), "# Demo\n", "utf8");
  return root;
}
const sarif = (name: string) =>
  canonicalStrictJsonBytesV1({
    version: "2.1.0",
    runs: [{ tool: { driver: { name } }, results: [] }],
  }).toString("utf8");

describe("code-owned baseline analyzer runtime", () => {
  it("uses only fixed hardened Docker and lock-backed canonical uv profiles", async () => {
    const calls: Array<{
      argv: readonly string[];
      options: Parameters<BaselineProcessRunnerV1>[1];
    }> = [];
    const runner: BaselineProcessRunnerV1 = async (argv, options) => {
      calls.push({ argv: [...argv], options });
      const command = argv;
      if (argv[0] === BASELINE_DOCKER_EXECUTABLE_V1 && argv.includes("version"))
        return { code: 0, stdout: "Docker version 28", stderr: "", truncated: false };
      if (argv[0] === BASELINE_DOCKER_EXECUTABLE_V1 && argv.includes("inspect"))
        return {
          code: 0,
          stdout: JSON.stringify({ Id: SKILLSPECTOR_IMAGE_DIGEST_V1, RepoDigests: [] }),
          stderr: "",
          truncated: false,
        };
      if (argv[0] === BASELINE_DOCKER_EXECUTABLE_V1)
        return { code: 1, stdout: sarif("skillspector"), stderr: "", truncated: false };
      if (command.includes(BASELINE_UV_EXECUTABLE_V1) && command.includes("sync"))
        return { code: 0, stdout: "", stderr: "", truncated: false };
      if (
        command.at(-1) === "--version" &&
        command.some((value) => value.endsWith("/skill-scanner"))
      )
        return {
          code: 0,
          stdout: `skill-scanner ${CISCO_SKILL_SCANNER_VERSION_V1}`,
          stderr: "",
          truncated: false,
        };
      if (command.at(-1) === "--version" && command.some((value) => value.endsWith("/semgrep")))
        return {
          code: 0,
          stdout: SEMGREP_VERSION_V1,
          stderr: "",
          truncated: false,
        };
      if (command.includes("--output-sarif")) {
        const output = command[command.indexOf("--output-sarif") + 1];
        const workBind = command.findIndex(
          (value, index) => value === "--bind" && command[index + 2] === "/aih/work",
        );
        const workDirectory = workBind < 0 ? undefined : command[workBind + 1];
        if (output !== "/aih/work/results.sarif" || workDirectory === undefined)
          throw new Error("missing Cisco output custody");
        writeFileSync(join(workDirectory, "results.sarif"), sarif("cisco"), "utf8");
        return { code: 0, stdout: "", stderr: "", truncated: false };
      }
      if (command.includes("--sarif"))
        return { code: 0, stdout: sarif("semgrep"), stderr: "", truncated: false };
      throw new Error(`unexpected argv: ${argv.join(" ")}`);
    };
    const execute = createBaselineAnalyzerExecutionV1({
      runner,
      env: {
        HOME: "C:\\attacker-home",
        PATH: "C:\\attacker-tools",
        TEMP: "C:\\temp",
        UV_PYTHON: "C:\\attacker-tools\\python3.12.exe",
        API_TOKEN: "secret",
      },
    });
    const sourceRoot = sourceFixture();

    for (const analyzer of ["aih-native", "skillspector", "semgrep", "cisco"] as const) {
      const result = await execute({ analyzer, sourceRoot, source });
      expect(result.bytes.byteLength).toBeGreaterThan(0);
      expect(result.analyzerVersion).toMatch(/\S/);
    }

    expect(calls.every((call) => call.options.env.API_TOKEN === undefined)).toBe(true);
    const bubblewrapCalls = calls.filter((call) => call.argv[0] === BASELINE_BWRAP_EXECUTABLE_V1);
    expect(bubblewrapCalls.length).toBeGreaterThan(0);
    for (const call of bubblewrapCalls) {
      expect(call.argv.slice(0, 3)).toEqual([
        BASELINE_BWRAP_EXECUTABLE_V1,
        "--unshare-all",
        "--unshare-user",
      ]);
      expect(call.argv.filter((argument) => argument === "--unshare-user")).toHaveLength(1);
      const disableUserns = call.argv.indexOf("--disable-userns");
      expect(disableUserns).toBeGreaterThan(2);
      expect(call.argv[disableUserns + 1]).toBe("--assert-userns-disabled");
    }
    const dockerConfigs = calls
      .filter((call) => call.argv[0] === BASELINE_DOCKER_EXECUTABLE_V1)
      .map((call) => call.options.env.DOCKER_CONFIG);
    expect(new Set(dockerConfigs).size).toBe(1);
    expect(dockerConfigs[0]).toMatch(/aih-scan-docker-config-/);
    const docker = calls.find((call) => call.argv.includes("--network"));
    expect(docker?.argv).toEqual(
      expect.arrayContaining([
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
      ]),
    );
    expect(docker?.argv).toContain(SKILLSPECTOR_IMAGE_DIGEST_V1);
    const uvCalls = calls.filter((call) => call.argv.includes(BASELINE_UV_EXECUTABLE_V1));
    for (const call of uvCalls) {
      expect(call.argv[0]).toBe(BASELINE_BWRAP_EXECUTABLE_V1);
      expect(call.argv).toEqual(
        expect.arrayContaining([
          BASELINE_BWRAP_EXECUTABLE_V1,
          "--unshare-all",
          "--unshare-user",
          "--share-net",
          "--die-with-parent",
          "--as-pid-1",
          "--disable-userns",
          "--assert-userns-disabled",
          "--clearenv",
          "UV_NO_ENV_FILE",
          "1",
          "PYTHONSAFEPATH",
          "1",
          "PYTHONPATH",
          "/usr/local/lib/python3.13:/usr/local/lib/python3.13/lib-dynload",
          "--dir",
          "/run",
          "sync",
          "--locked",
          "--no-dev",
          "--no-install-project",
          "--no-build",
          "--link-mode",
          "copy",
          "--python",
          BASELINE_PYTHON_EXECUTABLE_V1,
          "--default-index",
          "https://pypi.org/simple",
          "--index-strategy",
          "first-index",
          "--no-python-downloads",
          "--no-config",
          "--no-sources",
        ]),
      );
      expect(call.argv).not.toContain("--no-env-file");
      const noEnvFile = call.argv.indexOf("UV_NO_ENV_FILE");
      expect(call.argv.slice(noEnvFile - 1, noEnvFile + 2)).toEqual([
        "--setenv",
        "UV_NO_ENV_FILE",
        "1",
      ]);
      expect(noEnvFile).toBeGreaterThan(call.argv.indexOf("--clearenv"));
      expect(noEnvFile).toBeLessThan(call.argv.indexOf("--"));
      const pythonPath = call.argv.indexOf("PYTHONPATH");
      expect(call.argv.slice(pythonPath - 1, pythonPath + 2)).toEqual([
        "--setenv",
        "PYTHONPATH",
        "/usr/local/lib/python3.13:/usr/local/lib/python3.13/lib-dynload",
      ]);
      expect(pythonPath).toBeGreaterThan(call.argv.indexOf("--clearenv"));
      expect(pythonPath).toBeLessThan(call.argv.indexOf("--"));
      expect(call.argv).not.toContain("--offline");
      expect(call.argv).toContain("--share-net");
      expect(call.argv).not.toContain(sourceRoot);
      expect(call.argv).not.toContain("/aih/source");
      expect(call.argv).toEqual(expect.arrayContaining(["--chdir", "/aih/project"]));
      expect(call.argv.join(" ")).not.toContain("attacker");
      expect(call.options.env.HOME).toBeUndefined();
      expect(call.options.env.PATH).toBeUndefined();
      expect(call.options.env.UV_PYTHON).toBeUndefined();
    }
    const analyzerCalls = calls.filter(
      (call) =>
        call.argv.some((value) => value === "/aih/venv/bin/semgrep") ||
        call.argv.some((value) => value === "/aih/venv/bin/skill-scanner"),
    );
    expect(analyzerCalls).toHaveLength(4);
    expect(analyzerCalls.every((call) => !call.argv.includes("--share-net"))).toBe(true);
    expect(analyzerCalls.every((call) => call.argv.includes(sourceRoot))).toBe(true);
    expect(
      analyzerCalls.every(
        (call) =>
          call.argv.includes("/aih/source") &&
          call.argv.includes("--chdir") &&
          call.argv[call.argv.indexOf("--chdir") + 1] === "/aih/source",
      ),
    ).toBe(true);
    expect(JSON.stringify(calls)).not.toContain("secret");
  });

  it("refuses host analyzer execution as Linux root", () => {
    const getuid = Object.getOwnPropertyDescriptor(process, "getuid");
    vi.spyOn(process, "platform", "get").mockReturnValue("linux");
    Object.defineProperty(process, "getuid", { configurable: true, value: () => 0 });
    try {
      expect(() => createBaselineAnalyzerExecutionV1()).toThrow(/refuses root identity/);
    } finally {
      if (getuid === undefined) delete (process as { getuid?: unknown }).getuid;
      else Object.defineProperty(process, "getuid", getuid);
    }
  });

  it("acquires only the fixed digest-addressed SkillSpector image when it is absent", async () => {
    const calls: readonly string[][] = [];
    let inspected = false;
    const runner: BaselineProcessRunnerV1 = async (argv) => {
      (calls as string[][]).push([...argv]);
      if (argv[0] === BASELINE_DOCKER_EXECUTABLE_V1 && argv.includes("version"))
        return { code: 0, stdout: "Docker version 28", stderr: "", truncated: false };
      if (argv.includes("image") && argv.includes("inspect")) {
        if (!inspected) {
          inspected = true;
          return { code: 1, stdout: "", stderr: "missing", truncated: false };
        }
        return {
          code: 0,
          stdout: JSON.stringify({ RepoDigests: [SKILLSPECTOR_IMAGE_V1] }),
          stderr: "",
          truncated: false,
        };
      }
      if (argv.includes("pull")) return { code: 0, stdout: "pulled", stderr: "", truncated: false };
      if (argv.includes("run"))
        return { code: 0, stdout: sarif("skillspector"), stderr: "", truncated: false };
      throw new Error(`unexpected argv: ${argv.join(" ")}`);
    };

    const execute = createBaselineAnalyzerExecutionV1({ runner, env: { PATH: "C:\\tools" } });
    await execute({ analyzer: "skillspector", sourceRoot: sourceFixture(), source });

    expect(calls.filter((argv) => argv.includes("pull"))).toEqual([
      [BASELINE_DOCKER_EXECUTABLE_V1, "--context", "default", "pull", SKILLSPECTOR_IMAGE_V1],
    ]);
    expect(calls.find((argv) => argv.includes("run"))).toContain(SKILLSPECTOR_IMAGE_V1);
  });

  it("preserves bounded analyzer diagnostic head and tail", async () => {
    const runner: BaselineProcessRunnerV1 = async (argv) => {
      if (argv.includes(BASELINE_UV_EXECUTABLE_V1) && argv.includes("sync"))
        return { code: 0, stdout: "", stderr: "", truncated: false };
      if (argv.at(-1) === "--version")
        return {
          code: 0,
          stdout: `skill-scanner ${CISCO_SKILL_SCANNER_VERSION_V1}`,
          stderr: "",
          truncated: false,
        };
      return {
        code: 2,
        stdout: "",
        stderr: `python prefix warning\n${"x".repeat(600)}\nfinal Cisco exception`,
        truncated: false,
      };
    };
    const execute = createBaselineAnalyzerExecutionV1({ runner, env: { PATH: "C:\\tools" } });

    const rejection = await execute({ analyzer: "cisco", sourceRoot: sourceFixture(), source }).then(
      () => undefined,
      (error: unknown) => error,
    );

    expect(rejection).toBeInstanceOf(TypeError);
    const message = (rejection as Error).message;
    expect(message).toContain("python prefix warning");
    expect(message).toContain("final Cisco exception");
    expect(message).toContain("omitted");
    expect(message.length).toBeLessThanOrEqual(520);
  });

  it.each([
    [
      "wrong image digest",
      async (argv: readonly string[]) =>
        argv[0] === BASELINE_DOCKER_EXECUTABLE_V1 && argv.includes("inspect")
          ? {
              code: 0,
              stdout: JSON.stringify({ Id: `sha256:${"f".repeat(64)}` }),
              stderr: "",
              truncated: false,
            }
          : { code: 0, stdout: "Docker version 28", stderr: "", truncated: false },
      "skillspector" as const,
    ],
    [
      "truncated output",
      async () => ({ code: 1, stdout: "{}", stderr: "", truncated: true }),
      "skillspector" as const,
    ],
    [
      "wrong Semgrep version",
      async () => ({ code: 0, stdout: "0.0.0", stderr: "", truncated: false }),
      "semgrep" as const,
    ],
  ])("fails closed on %s", async (_label, runner, analyzer) => {
    const execute = createBaselineAnalyzerExecutionV1({
      runner: runner as BaselineProcessRunnerV1,
      env: { PATH: "C:\\tools" },
    });
    await expect(execute({ analyzer, sourceRoot: sourceFixture(), source })).rejects.toThrow(
      /baseline analyzer|SkillSpector|Semgrep/i,
    );
  });
});
