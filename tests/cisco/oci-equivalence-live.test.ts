import { execFile, execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { isAbsolute, join, relative, resolve } from "node:path";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import { runCiscoOciEquivalenceLiveV1 } from "../../src/cisco/dual-run-equivalence-v1.js";

const execFileAsync = promisify(execFile);
const maxStdioBytes = 64 * 1024;
const timeoutMs = 120_000;
const liveTestTimeoutMs = 130_000;
const configDigest = process.env.AIH_SCAN_CISCO_OCI_CONFIG_DIGEST;
const liveEnabled =
  process.env.AIH_SCAN_CISCO_OCI_EQUIVALENCE === "1" &&
  process.platform === "linux" &&
  process.arch === "x64";

function requiredAbsoluteEnvironment(name: string): string {
  const value = process.env[name];
  if (typeof value !== "string" || !isAbsolute(value) || !existsSync(value))
    throw new Error(`${name} must name an existing absolute workflow path`);
  return resolve(value);
}

function descendant(root: string, candidate: string): string {
  const resolved = resolve(candidate);
  const relation = relative(root, resolved);
  if (!relation || relation === ".." || relation.startsWith("../") || !isAbsolute(resolved))
    throw new Error("workflow path must be a strict RUNNER_TEMP descendant");
  return resolved;
}

function livePrerequisites(): boolean {
  if (
    !liveEnabled ||
    typeof configDigest !== "string" ||
    !/^sha256:[a-f0-9]{64}$/.test(configDigest)
  )
    return false;
  try {
    const childPath = requiredAbsoluteEnvironment("AIH_SCAN_CISCO_CHILD_PATH");
    if (!existsSync(join(childPath, "uv"))) return false;
    execFileSync("docker", ["version", "--format", "{{.Server.Version}}"], {
      shell: false,
      stdio: "ignore",
      timeout: 10_000,
    });
    return true;
  } catch {
    return false;
  }
}

function controlledRunner(
  expectedCommand: "docker" | "uv",
  fallbackCwd: string,
  uvBase?: Readonly<Record<string, string>>,
) {
  return async (
    argv: readonly string[],
    options: {
      readonly env: Readonly<Record<string, string>>;
      readonly timeoutMs: number;
      readonly maxStdoutBytes: number;
      readonly maxStderrBytes: number;
      readonly cwd?: string;
    },
  ) => {
    expect(argv[0]).toBe(expectedCommand);
    expect(options.timeoutMs).toBe(timeoutMs);
    expect(options.maxStdoutBytes).toBe(maxStdioBytes);
    expect(options.maxStderrBytes).toBe(maxStdioBytes);
    const childEnvironment =
      expectedCommand === "uv"
        ? (() => {
            expect(options.cwd).toBe(fallbackCwd);
            expect(options.env).toEqual({ UV_OFFLINE: "1" });
            if (uvBase === undefined) throw new Error("controlled uv environment missing");
            return { ...uvBase, ...options.env };
          })()
        : (() => {
            expect(options.cwd).toBeUndefined();
            expect(Object.keys(options.env).sort()).toEqual(["DOCKER_CONFIG", "HOME", "PATH"]);
            expect(options.env.PATH).toBe("/usr/bin:/bin");
            expect(options.env.HOME).toMatch(/^.+$/);
            expect(options.env.DOCKER_CONFIG).toMatch(/^.+$/);
            return { ...options.env };
          })();
    expect(Object.keys(childEnvironment).sort()).not.toContainEqual(
      expect.stringMatching(/token|credential|auth|proxy|socket/i),
    );
    const file = argv[0];
    if (file === undefined) throw new Error("runner command missing");
    try {
      const result = await execFileAsync(file, [...argv.slice(1)], {
        cwd: options.cwd ?? fallbackCwd,
        env: childEnvironment,
        shell: false,
        timeout: timeoutMs,
        maxBuffer: maxStdioBytes,
        encoding: "utf8",
        windowsHide: true,
      });
      return { code: 0, stdout: result.stdout, stderr: result.stderr };
    } catch (error) {
      const failure = error as {
        code?: number;
        stdout?: string;
        stderr?: string;
        killed?: boolean;
      };
      return {
        code: typeof failure.code === "number" ? failure.code : 1,
        stdout: failure.stdout ?? "",
        stderr: failure.stderr ?? "",
        truncated: failure.killed === true,
      };
    }
  };
}

describe("Cisco OCI equivalence live seam", () => {
  it("is opt-in and rejects non-isolated roots or a mutable image ID", async () => {
    await expect(
      runCiscoOciEquivalenceLiveV1({
        protocol: "CiscoOciEquivalenceLiveV1",
        enabled: false,
        directRoot: "C:/tmp/direct",
        ociRoot: "C:/tmp/oci",
        configDigestSha256: `sha256:${"a".repeat(64)}`,
      }),
    ).resolves.toEqual({
      protocol: "CiscoOciEquivalenceLiveV1",
      kind: "not-run",
      reason: "opt-in-required",
    });
    for (const value of [
      {
        protocol: "CiscoOciEquivalenceLiveV1",
        enabled: true,
        directRoot: "same",
        ociRoot: "same",
        configDigestSha256: `sha256:${"a".repeat(64)}`,
      },
      {
        protocol: "CiscoOciEquivalenceLiveV1",
        enabled: true,
        directRoot: "../direct",
        ociRoot: "C:/tmp/oci",
        configDigestSha256: `sha256:${"a".repeat(64)}`,
      },
      {
        protocol: "CiscoOciEquivalenceLiveV1",
        enabled: true,
        directRoot: "C:/tmp/direct",
        ociRoot: "C:/tmp/oci",
        configDigestSha256: "latest",
      },
    ])
      await expect(runCiscoOciEquivalenceLiveV1(value)).rejects.toThrow();
  });

  it.runIf(livePrerequisites())(
    "uses the exact workflow paths and IDs through bounded shell-free injected runners",
    async () => {
      const runnerTemp = requiredAbsoluteEnvironment("RUNNER_TEMP");
      const artifactRoot = descendant(
        runnerTemp,
        requiredAbsoluteEnvironment("AIH_SCAN_CISCO_ARTIFACT_DIR"),
      );
      const directRoot = descendant(
        runnerTemp,
        requiredAbsoluteEnvironment("AIH_SCAN_CISCO_OCI_DIRECT_ROOT"),
      );
      const ociRoot = descendant(
        runnerTemp,
        requiredAbsoluteEnvironment("AIH_SCAN_CISCO_OCI_ROOT"),
      );
      const runtimeProjectRoot = requiredAbsoluteEnvironment("AIH_SCAN_CISCO_RUNTIME_PROJECT");
      const childPath = descendant(
        runnerTemp,
        requiredAbsoluteEnvironment("AIH_SCAN_CISCO_CHILD_PATH"),
      );
      const childHome = descendant(
        runnerTemp,
        requiredAbsoluteEnvironment("AIH_SCAN_CISCO_CHILD_HOME"),
      );
      const uvCache = descendant(
        runnerTemp,
        requiredAbsoluteEnvironment("AIH_SCAN_CISCO_CHILD_UV_CACHE_DIR"),
      );
      const layoutPath = requiredAbsoluteEnvironment("AIH_SCAN_CISCO_OCI_LAYOUT_PATH");
      const summaryPath = join(artifactRoot, "oci-equivalence-digest-summary.json");
      const uvConfigFile = join(runnerTemp, "aih-scan-cisco-empty-uv.toml");
      expect(existsSync(uvConfigFile)).toBe(true);
      const uvBase = {
        HOME: childHome,
        PATH: childPath,
        UV_CACHE_DIR: uvCache,
        UV_CONFIG_FILE: uvConfigFile,
      };
      const result = await runCiscoOciEquivalenceLiveV1({
        protocol: "CiscoOciEquivalenceLiveV1",
        enabled: true,
        directRoot,
        ociRoot,
        runtimeProjectRoot,
        layoutBytes: readFileSync(layoutPath),
        configDigestSha256: configDigest,
        summaryPath,
        uvRunner: controlledRunner("uv", runtimeProjectRoot, uvBase),
        dockerRunner: controlledRunner("docker", runnerTemp),
      });
      if (!("validationState" in result)) throw new Error("live producer did not run");
      expect(result.validationState).toBe("cryptographically-unverified");
      expect(readFileSync(summaryPath, "utf8")).toMatch(/digest|sha256/i);
      expect(JSON.stringify(result)).not.toMatch(
        /policy|verdict|authority|acceptance|acknowledg|qualified|trusted|signature/i,
      );
    },
    liveTestTimeoutMs,
  );
});
