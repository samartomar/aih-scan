import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  type BaselineProcessRunnerV1,
  HOST_DOCKER_ENVIRONMENT_V1,
  SKILLSPECTOR_IMAGE_DIGEST_V1,
  SKILLSPECTOR_IMAGE_V1,
} from "../../src/baseline/runtime-v1.js";
import { canonicalStrictJsonBytesV1 } from "../../src/contract/strict-json-v1.js";
import { runDetectorV1 } from "../../src/runner/run-detector-v1.js";
import {
  completionOfObservationV1,
  diskFilesV1,
  diskSubjectV1,
} from "./completion-evidence-support.js";

const PROFILE = "docker-host-local-skillspector-v1";
const LOCAL_TAG = "skillspector:aih-c7958a3268d9";
const windows = process.platform === "win32";
const hostOs = windows ? "windows" : process.platform === "darwin" ? "darwin" : "linux";
const temporaryDirectories: string[] = [];
const endpoint = windows
  ? "npipe:////./pipe/dockerDesktopLinuxEngine"
  : "unix:///var/run/docker.sock";

afterEach(() => {
  vi.restoreAllMocks();
  for (const directory of temporaryDirectories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

function temporary(label: string): string {
  const root = mkdtempSync(join(tmpdir(), `aih-scan-docker-${label}-`));
  temporaryDirectories.push(root);
  return root;
}

function hostFixture() {
  const root = temporary("tools");
  const bin = join(root, "bin");
  const home = join(root, "home");
  mkdirSync(bin, { recursive: true });
  mkdirSync(home, { recursive: true });
  const file = join(bin, windows ? "docker.exe" : "docker");
  writeFileSync(file, "fake docker\n");
  if (!windows) chmodSync(file, 0o755);
  const env: Record<string, string> = windows
    ? { PATH: bin, USERPROFILE: home, DOCKER_CONTEXT: "desktop-linux", API_TOKEN: "secret" }
    : { PATH: bin, HOME: home, DOCKER_CONTEXT: "desktop-linux", API_TOKEN: "secret" };
  return { docker: realpathSync.native(file), env };
}

function sourceFixture(): string {
  const root = temporary("source");
  writeFileSync(join(root, "README.md"), "# Readme\n");
  return root;
}

type Call = { argv: readonly string[]; options: Parameters<BaselineProcessRunnerV1>[1] };
const okay = (stdout: string) => ({ code: 0, stdout, stderr: "", truncated: false });
const context = (tls: Record<string, unknown> = {}) =>
  JSON.stringify({
    Name: "desktop-linux",
    Endpoints: { docker: { Host: endpoint, SkipTLSVerify: false } },
    TLSMaterial: tls,
  });
const sarif = canonicalStrictJsonBytesV1({
  version: "2.1.0",
  runs: [
    {
      tool: { driver: { name: "skillspector" } },
      invocations: [{ executionSuccessful: true }],
      results: [
        {
          ruleId: "skillspector.prompt-injection",
          level: "warning",
          message: { text: "prompt injection" },
          locations: [{ physicalLocation: { artifactLocation: { uri: "/scan/README.md" } } }],
        },
      ],
    },
  ],
}).toString("utf8");

function dockerRunner(
  calls: Call[],
  run: () => ReturnType<BaselineProcessRunnerV1> = async () => okay(sarif),
  contextOutput = context(),
  image: ReturnType<BaselineProcessRunnerV1> | Awaited<ReturnType<BaselineProcessRunnerV1>> = okay(
    JSON.stringify({ Id: SKILLSPECTOR_IMAGE_DIGEST_V1, RepoDigests: [] }),
  ),
): BaselineProcessRunnerV1 {
  return async (argv, options) => {
    calls.push({ argv: [...argv], options: { ...options, env: { ...options.env } } });
    if (argv[1] === "context") return okay(contextOutput);
    if (argv[1] === "version") return okay("Docker version 29");
    if (argv[1] === "image") {
      // The local profile inspects only the documented local tag, never a digest reference.
      if (argv[3] !== LOCAL_TAG) throw new Error(`unexpected image reference ${argv[3]}`);
      return image;
    }
    if (argv[1] === "pull") throw new Error("the local profile never pulls");
    if (argv[1] === "run") return run();
    if (argv[1] === "rm") return okay("");
    throw new Error(`unexpected argv: ${argv.join(" ")}`);
  };
}

function request(extra: Record<string, unknown>) {
  return {
    detectorId: "detector.skillspector",
    executionProfileId: PROFILE,
    subject: {
      kind: "source-tree" as const,
      sourceRoot: sourceFixture(),
      selectedClosurePaths: ["README.md"],
    },
    ...extra,
  };
}

describe("runDetectorV1 docker-host-local-skillspector-v1", () => {
  it("reads the current context once, then talks to its endpoint with a private client configuration", async () => {
    const host = hostFixture();
    const calls: Call[] = [];

    const outcome = await runDetectorV1(request({ env: host.env, runner: dockerRunner(calls) }));

    expect(outcome.outcome).toBe("succeeded");
    if (outcome.outcome !== "succeeded") return;
    expect(outcome.executionProfile.id).toBe(PROFILE);
    if (outcome.evidence.kind !== "baseline-analyzer-observation-v1")
      throw new Error("evidence kind");
    expect(outcome.evidence.observation.hostDocker).toEqual({
      docker: { path: host.docker, foundIn: "PATH" },
      context: { name: "desktop-linux", endpoint },
      containment: windows ? "windows-job-object" : "posix-process-group",
    });
    expect(outcome.evidence.observation.image?.acceptance).toBe("scan-pinned");
    expect(outcome.findings.findings[0]?.location).toMatchObject({
      state: "present",
      value: { path: "README.md" },
    });

    const [lookup, ...rest] = calls;
    expect(lookup?.argv).toEqual([host.docker, "context", "inspect", "--format", "{{json .}}"]);
    expect(lookup?.options.env.DOCKER_CONTEXT).toBe("desktop-linux");
    expect(lookup?.options.env.DOCKER_HOST).toBeUndefined();
    const declared = HOST_DOCKER_ENVIRONMENT_V1[hostOs];
    for (const call of calls) {
      expect(call.argv[0]).toBe(host.docker);
      expect(call.argv).not.toContain("--context");
      expect(call.options.containProcessTree).toBe(true);
      expect(call.options.cwd).toMatch(/aih-scan-docker-config-/);
      expect(JSON.stringify(call.options.env)).not.toContain("secret");
    }
    for (const call of rest) {
      expect(Object.keys(call.options.env).sort()).toEqual(Object.keys(declared).sort());
      expect(call.options.env.DOCKER_HOST).toBe(endpoint);
      expect(call.options.env.DOCKER_CONFIG).toMatch(/aih-scan-docker-config-/);
      expect(call.options.env.DOCKER_CONTEXT).toBeUndefined();
    }
    const run = calls.find((call) => call.argv[1] === "run")?.argv ?? [];
    expect(run).toEqual(
      expect.arrayContaining(["--network", "none", "--read-only", SKILLSPECTOR_IMAGE_DIGEST_V1]),
    );
  });

  it("removes the container by name when the scan is cancelled, and reports the cancellation", async () => {
    const host = hostFixture();
    const calls: Call[] = [];
    const controller = new AbortController();

    const outcome = await runDetectorV1(
      request({
        env: host.env,
        signal: controller.signal,
        runner: dockerRunner(calls, async () => ({
          code: 1,
          stdout: "",
          stderr: "",
          truncated: true,
          termination: "abort" as const,
        })),
      }),
    );

    expect(outcome.outcome).toBe("failed");
    if (outcome.outcome !== "failed") return;
    expect(outcome.failure).toMatchObject({ stage: "execution", cause: "cancelled" });
    const run = calls.find((call) => call.argv[1] === "run")?.argv ?? [];
    const name = run[run.indexOf("--name") + 1];
    expect(name).toMatch(/^aih-scan-baseline-/);
    const removal = calls.find((call) => call.argv[1] === "rm");
    expect(removal?.argv).toEqual([host.docker, "rm", "--force", "--volumes", name]);
    // The removal runs without the caller's (aborted) signal, so it is not cancelled too.
    expect(removal?.options.signal).toBeUndefined();
  });

  it("removes the container by name on a timeout too", async () => {
    const host = hostFixture();
    const calls: Call[] = [];

    const outcome = await runDetectorV1(
      request({
        env: host.env,
        timeoutMs: 60_000,
        runner: dockerRunner(calls, async () => ({
          code: 1,
          stdout: "",
          stderr: "",
          truncated: true,
          termination: "timeout" as const,
        })),
      }),
    );

    expect(outcome.outcome).toBe("failed");
    if (outcome.outcome !== "failed") return;
    expect(outcome.failure.cause).toBe("timed-out");
    expect(calls.some((call) => call.argv[1] === "rm")).toBe(true);
  });

  it("refuses a context that carries TLS material rather than carrying it into the run", async () => {
    const host = hostFixture();
    const calls: Call[] = [];

    const outcome = await runDetectorV1(
      request({
        env: host.env,
        runner: dockerRunner(calls, undefined, context({ docker: { ca: "x" } })),
      }),
    );

    expect(outcome.outcome).toBe("failed");
    if (outcome.outcome !== "failed") return;
    expect(outcome.failure.stage).toBe("availability");
    expect(outcome.failure.detail).toMatch(/TLS material/);
    expect(calls).toHaveLength(1);
  });

  it("refuses a missing docker before spawning anything", async () => {
    const empty = temporary("nothing");
    const outcome = await runDetectorV1(
      request({
        env: windows
          ? { PATH: empty, USERPROFILE: empty, ProgramFiles: empty, LOCALAPPDATA: empty }
          : { PATH: empty, HOME: empty },
        prerequisiteProbe: (prerequisite: { kind: string }) =>
          prerequisite.kind === "host-executable" ? "missing" : "not-probed",
        runner: async () => {
          throw new Error("nothing may be spawned");
        },
      }),
    );
    expect(outcome.outcome).toBe("refused");
    if (outcome.outcome !== "refused") return;
    expect(outcome.reason).toBe("prerequisite-missing");
    expect(outcome.detail).toContain("host-executable docker");
  });
});

describe("runDetectorV1 docker-hardened-skillspector-v1 container removal", () => {
  it("removes the container by name when the scan is cancelled", async () => {
    vi.spyOn(process, "platform", "get").mockReturnValue("linux");
    vi.spyOn(process, "arch", "get").mockReturnValue("x64");
    const calls: string[][] = [];
    const runner: BaselineProcessRunnerV1 = async (argv) => {
      calls.push([...argv]);
      if (argv.includes("version")) return okay("Docker version 29");
      if (argv.includes("inspect"))
        return okay(JSON.stringify({ Id: SKILLSPECTOR_IMAGE_DIGEST_V1, RepoDigests: [] }));
      if (argv.includes("run"))
        return { code: 1, stdout: "", stderr: "", truncated: true, termination: "abort" as const };
      if (argv.includes("rm")) return okay("");
      throw new Error(`unexpected argv: ${argv.join(" ")}`);
    };

    const outcome = await runDetectorV1({
      detectorId: "detector.skillspector",
      subject: {
        kind: "source-tree",
        sourceRoot: sourceFixture(),
        selectedClosurePaths: ["README.md"],
      },
      prerequisiteProbe: () => "present",
      signal: new AbortController().signal,
      runner,
    });

    expect(outcome.outcome).toBe("failed");
    if (outcome.outcome !== "failed") return;
    expect(outcome.failure.cause).toBe("cancelled");
    const run = calls.find((argv) => argv.includes("run")) ?? [];
    const name = run[run.indexOf("--name") + 1];
    expect(calls.find((argv) => argv.includes("rm"))).toEqual([
      "/usr/bin/docker",
      "--context",
      "default",
      "rm",
      "--force",
      "--volumes",
      name,
    ]);
    expect(SKILLSPECTOR_IMAGE_V1).toContain(SKILLSPECTOR_IMAGE_DIGEST_V1);
  });
});

describe("runDetectorV1 docker-host-local-skillspector-v1 image identity (never pulls)", () => {
  const accepted = `sha256:${"a".repeat(64)}`;
  const inspected = (image: Record<string, unknown>) => okay(JSON.stringify(image));

  it("runs the local tag's image by its ID with --pull never, and never pulls", async () => {
    const host = hostFixture();
    const calls: Call[] = [];
    const outcome = await runDetectorV1(request({ env: host.env, runner: dockerRunner(calls) }));
    expect(outcome.outcome).toBe("succeeded");
    const inspect = calls.find((call) => call.argv[1] === "image")?.argv;
    expect(inspect?.slice(1)).toEqual(["image", "inspect", LOCAL_TAG, "--format", "{{json .}}"]);
    expect(calls.some((call) => call.argv[1] === "pull")).toBe(false);
    const run = calls.find((call) => call.argv[1] === "run")?.argv ?? [];
    expect(run.slice(1, 4)).toEqual(["run", "--pull", "never"]);
    expect(run).toContain(SKILLSPECTOR_IMAGE_DIGEST_V1);
    if (
      outcome.outcome !== "succeeded" ||
      outcome.evidence.kind !== "baseline-analyzer-observation-v1"
    )
      return;
    expect(outcome.evidence.observation.image).toEqual({
      digest: SKILLSPECTOR_IMAGE_DIGEST_V1,
      reference: SKILLSPECTOR_IMAGE_DIGEST_V1,
      acceptance: "scan-pinned",
    });
  });

  it("runs a matching repository digest entry by that full reference", async () => {
    const host = hostFixture();
    const calls: Call[] = [];
    const entry = `ghcr.io/example/skillspector@${SKILLSPECTOR_IMAGE_DIGEST_V1}`;
    const outcome = await runDetectorV1(
      request({
        env: host.env,
        runner: dockerRunner(
          calls,
          undefined,
          undefined,
          inspected({ Id: `sha256:${"f".repeat(64)}`, RepoDigests: [entry] }),
        ),
      }),
    );
    expect(outcome.outcome).toBe("succeeded");
    const run = calls.find((call) => call.argv[1] === "run")?.argv ?? [];
    expect(run).toContain(entry);
    if (
      outcome.outcome !== "succeeded" ||
      outcome.evidence.kind !== "baseline-analyzer-observation-v1"
    )
      return;
    expect(outcome.evidence.observation.image).toMatchObject({
      digest: SKILLSPECTOR_IMAGE_DIGEST_V1,
      reference: entry,
      acceptance: "scan-pinned",
    });
  });

  it("admits a caller-accepted digest and says so", async () => {
    const host = hostFixture();
    const calls: Call[] = [];
    const outcome = await runDetectorV1(
      request({
        env: host.env,
        acceptedImageDigests: [accepted],
        runner: dockerRunner(calls, undefined, undefined, inspected({ Id: accepted })),
      }),
    );
    expect(outcome.outcome).toBe("succeeded");
    if (
      outcome.outcome !== "succeeded" ||
      outcome.evidence.kind !== "baseline-analyzer-observation-v1"
    )
      return;
    expect(outcome.evidence.observation.image).toEqual({
      digest: accepted,
      reference: accepted,
      acceptance: "caller-accepted",
    });
    expect(outcome.evidence.observation.analyzerVersion).toContain(accepted);
  });

  it("fails at availability, naming the pinned digest, when the local tag is absent or not allowed", async () => {
    for (const image of [
      { code: 1, stdout: "", stderr: "Error: No such image", truncated: false },
      inspected({ Id: `sha256:${"e".repeat(64)}`, RepoDigests: [] }),
    ]) {
      const host = hostFixture();
      const calls: Call[] = [];
      const outcome = await runDetectorV1(
        request({ env: host.env, runner: dockerRunner(calls, undefined, undefined, image) }),
      );
      expect(outcome.outcome).toBe("failed");
      if (outcome.outcome !== "failed") continue;
      expect(outcome.failure.stage).toBe("availability");
      expect(outcome.failure.detail).toContain(SKILLSPECTOR_IMAGE_DIGEST_V1);
      expect(outcome.failure.detail).toContain(LOCAL_TAG);
      expect(calls.some((call) => ["pull", "run"].includes(call.argv[1] ?? ""))).toBe(false);
    }
  });

  it("completes an empty source root with the analyzer's own empty SARIF", async () => {
    const host = hostFixture();
    const calls: Call[] = [];
    const empty = temporary("empty");
    const emptySarif = canonicalStrictJsonBytesV1({
      version: "2.1.0",
      runs: [
        {
          tool: { driver: { name: "skillspector" } },
          results: [],
          invocations: [{ executionSuccessful: true }],
        },
      ],
    }).toString("utf8");
    const outcome = await runDetectorV1({
      ...request({ env: host.env, runner: dockerRunner(calls, async () => okay(emptySarif)) }),
      subject: { kind: "source-tree", sourceRoot: empty, selectedClosurePaths: [] },
    });
    expect(outcome.outcome).toBe("succeeded");
    if (outcome.outcome !== "succeeded") return;
    expect(outcome.findings.findings).toEqual([]);
    expect(outcome.sourceSeal.before.protocol).toBe("SourceObservationSealV1");
    expect(outcome.sourceSeal.before.entries).toEqual([]);
  });
});

// S2e sweep: SkillSpector's own SARIF must prove a completed analysis (real SkillSpector
// writes one run with invocations:[{executionSuccessful:true, …warning notifications}]).
describe("runDetectorV1 docker-host-local-skillspector-v1 SARIF completion (S2e)", () => {
  const run = (document: unknown) =>
    runDetectorV1(
      request({
        env: hostFixture().env,
        runner: dockerRunner([], async () =>
          okay(canonicalStrictJsonBytesV1(document as never).toString("utf8")),
        ),
      }),
    );
  const tool = { driver: { name: "skillspector" } };

  it("fails SARIF with no runs at output", async () => {
    const outcome = await run({ version: "2.1.0", runs: [] });
    expect(outcome).toMatchObject({ outcome: "failed", failure: { stage: "output" } });
    if (outcome.outcome === "failed") expect(outcome.failure.detail).toMatch(/holds no runs/);
  });

  it("fails an invocation that did not complete at execution", async () => {
    const outcome = await run({
      version: "2.1.0",
      runs: [{ tool, results: [], invocations: [{ executionSuccessful: false }] }],
    });
    expect(outcome).toMatchObject({ outcome: "failed", failure: { stage: "execution" } });
  });
});

// S2g (C2a §1.6): SkillSpector receives the whole tree, and its profile installs no lock.
describe("runDetectorV1 docker-host-local-skillspector-v1 completion evidence v1", () => {
  it("names every file, .git and a skipped node_modules included, with no lock", async () => {
    const host = hostFixture();
    const sourceRoot = sourceFixture();
    mkdirSync(join(sourceRoot, ".git"));
    writeFileSync(join(sourceRoot, ".git", "HEAD"), "ref: refs/heads/main\n");
    mkdirSync(join(sourceRoot, "node_modules", "dep"), { recursive: true });
    writeFileSync(join(sourceRoot, "node_modules", "dep", "index.js"), "module.exports = 1;\n");
    // The pinned image's shape: a warning that names the skipped directory.
    const noted = canonicalStrictJsonBytesV1({
      version: "2.1.0",
      runs: [
        {
          tool: { driver: { name: "skillspector" } },
          results: [],
          invocations: [
            {
              executionSuccessful: true,
              toolExecutionNotifications: [
                {
                  level: "warning",
                  message: { text: "skipped a dependency directory" },
                  locations: [
                    { physicalLocation: { artifactLocation: { uri: "/scan/node_modules/" } } },
                  ],
                },
              ],
            },
          ],
        },
      ],
    }).toString("utf8");

    const outcome = await runDetectorV1({
      ...request({ env: host.env, runner: dockerRunner([], async () => okay(noted)) }),
      subject: { kind: "source-tree", sourceRoot, selectedClosurePaths: ["README.md"] },
    });

    const evidence = completionOfObservationV1(outcome);
    expect(diskFilesV1(sourceRoot)).toHaveLength(3);
    expect(evidence).toEqual({
      detectorId: "detector.skillspector",
      ...diskSubjectV1(sourceRoot, diskFilesV1(sourceRoot)),
      analyzer: {
        version:
          outcome.outcome === "succeeded" &&
          outcome.evidence.kind === "baseline-analyzer-observation-v1"
            ? outcome.evidence.observation.analyzerVersion
            : undefined,
        lockSha256: null,
      },
    });
  });

  it("gives an empty source root a zero count", async () => {
    const host = hostFixture();
    const emptySarif = canonicalStrictJsonBytesV1({
      version: "2.1.0",
      runs: [
        {
          tool: { driver: { name: "skillspector" } },
          results: [],
          invocations: [{ executionSuccessful: true }],
        },
      ],
    }).toString("utf8");
    const outcome = await runDetectorV1({
      ...request({ env: host.env, runner: dockerRunner([], async () => okay(emptySarif)) }),
      subject: { kind: "source-tree", sourceRoot: temporary("empty"), selectedClosurePaths: [] },
    });

    expect(completionOfObservationV1(outcome)).toMatchObject({ analyzedFileCount: 0 });
  });
});
