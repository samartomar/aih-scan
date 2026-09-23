import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  type BaselineProcessRunnerV1,
  CISCO_SKILL_SCANNER_VERSION_V1,
  SEMGREP_VERSION_V1,
  SKILLSPECTOR_IMAGE_DIGEST_V1,
} from "../../src/baseline/runtime-v1.js";
import {
  type DetectorPrerequisiteV1,
  resolveDetectorCapabilityV1,
  resolveDetectorExecutionProfileDocumentV1,
} from "../../src/capability/detector-capability-v1.js";
import {
  BASELINE_BWRAP_EXECUTABLE_V1,
  BASELINE_DOCKER_EXECUTABLE_V1,
} from "../../src/cli/process-runner.js";
import {
  canonicalStrictJsonBytesV1,
  canonicalStrictJsonSha256V1,
} from "../../src/contract/strict-json-v1.js";
import { type RunDetectorV1Request, runDetectorV1 } from "../../src/runner/run-detector-v1.js";

const temporaryDirectories: string[] = [];
const sha256 = (value: string | Uint8Array) => createHash("sha256").update(value).digest("hex");

afterEach(() => {
  vi.restoreAllMocks();
  for (const directory of temporaryDirectories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

function temporaryRoot(label: string): string {
  const root = mkdtempSync(join(tmpdir(), `aih-scan-run-detector-${label}-`));
  temporaryDirectories.push(root);
  return root;
}

/** A skill directory with a top-level SKILL.md, as `detector.cisco` requires. */
function skillFixture(): string {
  const root = temporaryRoot("skill");
  writeFileSync(join(root, "SKILL.md"), "# Demo skill\n", "utf8");
  writeFileSync(join(root, "profile.json"), '{"name":"demo"}\n', "utf8");
  return root;
}

/** A plain source tree with no SKILL.md anywhere. */
function sourceFixture(): string {
  const root = temporaryRoot("source");
  mkdirSync(join(root, "rules"), { recursive: true });
  writeFileSync(join(root, "rules", "base.md"), "# Rule\n", "utf8");
  writeFileSync(join(root, "README.md"), "# Readme\n", "utf8");
  return root;
}

function everyPathUnder(root: string, prefix = ""): string[] {
  return readdirSync(root, { withFileTypes: true }).flatMap((entry) => {
    const path = prefix === "" ? entry.name : `${prefix}/${entry.name}`;
    return entry.isDirectory() ? everyPathUnder(join(root, entry.name), path) : [path];
  });
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

const presentProbe = (_prerequisite: DetectorPrerequisiteV1) => "present" as const;

describe("runDetectorV1 refusals", () => {
  it.each([
    [
      "unknown-detector",
      () => ({
        detectorId: "detector.mcp-scanner",
        subject: {
          kind: "source-tree" as const,
          sourceRoot: sourceFixture(),
          selectedClosurePaths: ["README.md"],
        },
      }),
      /Scan owns no detector detector\.mcp-scanner/,
    ],
    [
      "unsupported-subject-kind",
      () => ({
        detectorId: "detector.cisco",
        subject: {
          kind: "npm-package-tree" as const,
          sourceRoot: skillFixture(),
          selectedClosurePaths: ["SKILL.md"],
        },
      }),
      /accepts skill-directory, not npm-package-tree/,
    ],
    [
      "execution-profile-unavailable",
      () => ({
        detectorId: "detector.cisco",
        executionProfileId: "host-process-uv-v1",
        subject: {
          kind: "skill-directory" as const,
          sourceRoot: skillFixture(),
          selectedClosurePaths: ["SKILL.md"],
        },
      }),
      /has no execution profile host-process-uv-v1/,
    ],
    [
      "subject-requirement-unmet",
      () => ({
        detectorId: "detector.cisco",
        subject: {
          kind: "skill-directory" as const,
          sourceRoot: sourceFixture(),
          selectedClosurePaths: ["README.md"],
        },
      }),
      /needs a top-level SKILL\.md/,
    ],
  ])("refuses with %s before anything is spawned", async (reason, build, detail) => {
    const record = { calls: 0 };

    const result = await runDetectorV1({ ...build(), runner: forbiddenRunner(record) });

    expect(result.outcome).toBe("refused");
    if (result.outcome !== "refused") return;
    expect(result.reason).toBe(reason);
    expect(result.detail).toMatch(detail);
    expect(record.calls).toBe(0);
  });

  it("refuses an OCI capture profile that was not given its capture material", async () => {
    const record = { calls: 0 };

    const result = await runDetectorV1({
      detectorId: "detector.cisco",
      executionProfileId: "oci-hardened-cisco-v1",
      subject: {
        kind: "skill-directory",
        sourceRoot: skillFixture(),
        selectedClosurePaths: ["SKILL.md"],
      },
      runner: forbiddenRunner(record),
    });

    expect(result.outcome).toBe("refused");
    if (result.outcome !== "refused") return;
    expect(result.reason).toBe("execution-profile-unavailable");
    expect(result.detail).toContain("needs a caller-supplied immutable OCI layout");
    expect(record.calls).toBe(0);
  });

  it("refuses an unsupported host platform and names both the host and the supported set", async () => {
    const record = { calls: 0 };
    mockHost("win32", "x64");

    const result = await runDetectorV1({
      detectorId: "detector.cisco",
      subject: {
        kind: "skill-directory",
        sourceRoot: skillFixture(),
        selectedClosurePaths: ["SKILL.md"],
      },
      runner: forbiddenRunner(record),
    });

    expect(result.outcome).toBe("refused");
    if (result.outcome !== "refused") return;
    expect(result.reason).toBe("unsupported-platform");
    expect(result.detail).toContain("win32/x64");
    expect(result.detail).toContain("linux/amd64");
    expect(result.detail).toContain("Linux amd64 only");
    expect(record.calls).toBe(0);
  });

  it("refuses an unsupported architecture even for the in-process analyzer", async () => {
    mockHost("linux", "mips");

    const result = await runDetectorV1({
      detectorId: "detector.aih-native",
      subject: {
        kind: "source-tree",
        sourceRoot: sourceFixture(),
        selectedClosurePaths: ["README.md"],
      },
    });

    expect(result.outcome).toBe("refused");
    if (result.outcome !== "refused") return;
    expect(result.reason).toBe("unsupported-platform");
  });

  it("refuses a missing required prerequisite and names it", async () => {
    const record = { calls: 0 };
    mockHost("linux", "x64");

    const result = await runDetectorV1({
      detectorId: "detector.skillspector",
      subject: {
        kind: "source-tree",
        sourceRoot: sourceFixture(),
        selectedClosurePaths: ["README.md"],
      },
      prerequisiteProbe: (prerequisite: DetectorPrerequisiteV1) =>
        prerequisite.id === BASELINE_DOCKER_EXECUTABLE_V1
          ? ("missing" as const)
          : ("not-probed" as const),
      runner: forbiddenRunner(record),
    });

    expect(result.outcome).toBe("refused");
    if (result.outcome !== "refused") return;
    expect(result.reason).toBe("prerequisite-missing");
    expect(result.detail).toContain(BASELINE_DOCKER_EXECUTABLE_V1);
    expect(result.detail).toContain("Install Docker");
    expect(record.calls).toBe(0);
  });

  it("never creates a SKILL.md to satisfy the skill-directory requirement", async () => {
    const sourceRoot = sourceFixture();
    const before = everyPathUnder(sourceRoot).sort();

    const result = await runDetectorV1({
      detectorId: "detector.cisco",
      subject: {
        kind: "skill-directory",
        sourceRoot,
        selectedClosurePaths: ["README.md", "rules/base.md"],
      },
    });

    expect(result.outcome).toBe("refused");
    if (result.outcome !== "refused") return;
    expect(result.reason).toBe("subject-requirement-unmet");
    expect(everyPathUnder(sourceRoot).sort()).toEqual(before);
    expect(before.some((path) => path.endsWith("SKILL.md"))).toBe(false);
    expect(existsSync(join(sourceRoot, "SKILL.md"))).toBe(false);
  });

  it("refuses a declared SKILL.md that is not part of the declared selection", async () => {
    const result = await runDetectorV1({
      detectorId: "detector.cisco",
      subject: {
        kind: "skill-directory",
        sourceRoot: skillFixture(),
        selectedClosurePaths: ["profile.json"],
      },
    });

    expect(result.outcome).toBe("refused");
    if (result.outcome !== "refused") return;
    expect(result.reason).toBe("subject-requirement-unmet");
    expect(result.detail).toContain("not one of the declared selected closure paths");
  });

  it("refuses a subject whose declared selection does not exist", async () => {
    const result = await runDetectorV1({
      detectorId: "detector.aih-native",
      subject: {
        kind: "source-tree",
        sourceRoot: sourceFixture(),
        selectedClosurePaths: ["absent.md"],
      },
    });

    expect(result.outcome).toBe("refused");
    if (result.outcome !== "refused") return;
    expect(result.reason).toBe("subject-requirement-unmet");
    expect(result.detail).toContain("could not be sealed");
  });

  it("refuses declared exclusions on a profile that analyzes the whole snapshot", async () => {
    const result = await runDetectorV1({
      detectorId: "detector.aih-native",
      subject: {
        kind: "source-tree",
        sourceRoot: sourceFixture(),
        selectedClosurePaths: ["README.md"],
        excludedPaths: ["rules/base.md"],
      },
    });

    expect(result.outcome).toBe("refused");
    if (result.outcome !== "refused") return;
    expect(result.reason).toBe("subject-requirement-unmet");
    expect(result.detail).toContain("record an exclusion that did not happen");
  });

  it("refuses a request that is not an object", async () => {
    for (const value of [undefined, null, "detector.cisco", []]) {
      const result = await runDetectorV1(value);
      expect(result.outcome).toBe("refused");
      if (result.outcome !== "refused") continue;
      expect(result.reason).toBe("unknown-detector");
    }
  });
});

describe("runDetectorV1 in-process execution", () => {
  it("really runs the in-process analyzer here and produces identical bytes twice", async () => {
    const sourceRoot = sourceFixture();
    const request: RunDetectorV1Request = {
      detectorId: "detector.aih-native",
      subject: {
        kind: "source-tree",
        sourceRoot,
        selectedClosurePaths: ["README.md", "rules/base.md"],
      },
    };

    const first = await runDetectorV1(request);
    const second = await runDetectorV1(request);

    expect(first.outcome).toBe("succeeded");
    if (first.outcome !== "succeeded" || second.outcome !== "succeeded") return;
    expect(first.executionProfile.id).toBe("in-process-native-v1");
    expect(first.executionProfile.isolation).toBe("none");
    expect(first.executionProfile.sha256).toBe(
      resolveDetectorCapabilityV1("detector.aih-native")?.executionProfile.sha256,
    );
    expect(first.seams).toEqual({
      runner: "scan-owned-default",
      prerequisiteProbe: "scan-owned-default",
    });
    if (first.evidence.kind !== "baseline-analyzer-observation-v1")
      throw new Error("evidence kind");
    if (second.evidence.kind !== "baseline-analyzer-observation-v1")
      throw new Error("evidence kind");
    const observation = first.evidence.observation;
    expect(observation.protocol).toBe("BaselineAnalyzerObservationV1");
    expect(observation.analyzer).toBe("aih-native");
    expect(observation.mediaType).toBe("application/vnd.aih.baseline-native+json");
    expect(observation.annex.sha256).toBe(sha256(observation.bytes));
    expect(observation.annex.byteLength).toBe(observation.bytes.byteLength);
    expect(observation.bytes.equals(second.evidence.observation.bytes)).toBe(true);
    expect(observation.annex.sha256).toBe(second.evidence.observation.annex.sha256);
    expect(JSON.parse(observation.bytes.toString("utf8")).protocol).toBe(
      "BaselineNativeObservationV1",
    );

    expect(first.coverage).toEqual({
      kind: "source-tree",
      sha256: first.sourceSeal.before.sourceTreeSha256,
      complete: true,
      coveredPaths: ["README.md", "rules/base.md"],
      excludedPaths: [],
      uncoveredPaths: [],
    });
    expect(first.sourceSeal.before.selectedClosurePaths).toEqual(["README.md", "rules/base.md"]);
    expect(first.sourceSeal.after.sealedSnapshotSha256).toBe(
      first.sourceSeal.before.sealedSnapshotSha256,
    );
    expect(first.findings.source).toBe("analyzer-output-digest-bound");
    expect(first.findings.findings).toEqual([]);
    expect(first.findings.gaps.map((entry) => entry.kind)).toContain("sarif-not-interpreted");
    expect(first.findings.gaps.map((entry) => entry.detail).join(" ")).toContain(
      "not a claim that nothing was found",
    );
  });

  it("preserves the caller's exact selection whatever order it is declared in", async () => {
    const sourceRoot = sourceFixture();
    const ordered = await runDetectorV1({
      detectorId: "detector.aih-native",
      subject: {
        kind: "source-tree",
        sourceRoot,
        selectedClosurePaths: ["README.md", "rules/base.md"],
      },
    });
    const reversed = await runDetectorV1({
      detectorId: "detector.aih-native",
      subject: {
        kind: "source-tree",
        sourceRoot,
        selectedClosurePaths: ["rules/base.md", "README.md"],
      },
    });

    if (ordered.outcome !== "succeeded" || reversed.outcome !== "succeeded")
      throw new Error("both runs must succeed");
    expect(reversed.coverage).toEqual(ordered.coverage);
    expect(reversed.sourceSeal.before.selectedClosureSha256).toBe(
      ordered.sourceSeal.before.selectedClosureSha256,
    );
  });

  it("returns a bounded failure instead of throwing when the analyzer rejects", async () => {
    mockHost("linux", "x64");

    const result = await runDetectorV1({
      detectorId: "detector.semgrep",
      subject: {
        kind: "source-tree",
        sourceRoot: sourceFixture(),
        selectedClosurePaths: ["README.md"],
      },
      prerequisiteProbe: presentProbe,
      env: { PATH: "/usr/bin" },
      runner: async (argv: readonly string[]) =>
        argv.includes("sync")
          ? {
              code: 1,
              stdout: "",
              stderr: `lock mismatch[31m\n${"x".repeat(900)}`,
              truncated: false,
            }
          : { code: 0, stdout: "", stderr: "", truncated: false },
    });

    expect(result.outcome).toBe("failed");
    if (result.outcome !== "failed") return;
    expect(result.failure.stage).toBe("acquisition");
    expect(result.failure.detail).toContain("lock mismatch");
    expect(result.failure.detail).not.toContain(String.fromCharCode(27));
    expect(result.failure.detail.length).toBeLessThanOrEqual(520);
    expect(result.coverage.kind).toBe("source-tree");
    expect(result.seams.prerequisiteProbe).toBe("caller-supplied");
  });

  it("names the package that executed it, beside the profile, analyzer version and annex digest", async () => {
    const manifest = JSON.parse(
      readFileSync(join(import.meta.dirname, "..", "..", "package.json"), "utf8"),
    ) as { name: string; version: string };
    const sourceRoot = sourceFixture();

    const result = await runDetectorV1({
      detectorId: "detector.aih-native",
      subject: { kind: "source-tree", sourceRoot, selectedClosurePaths: ["README.md"] },
    });

    if (result.outcome !== "succeeded") throw new Error(`expected success, got ${result.outcome}`);
    if (result.evidence.kind !== "baseline-analyzer-observation-v1")
      throw new Error("evidence kind");
    // Everything a consumer needs to state that this package, on this host, executed it:
    expect(result.producer).toEqual({ name: "@aihq/scan", version: manifest.version });
    expect(Object.isFrozen(result.producer)).toBe(true);
    expect(result.executionProfile.id).toBe("in-process-native-v1");
    expect(result.evidence.observation.analyzerVersion).toBe(
      resolveDetectorCapabilityV1("detector.aih-native")?.analyzerIdentity,
    );
    expect(result.evidence.observation.annex.sha256).toBe(
      sha256(result.evidence.observation.bytes),
    );
    expect(result.seams).toEqual({
      runner: "scan-owned-default",
      prerequisiteProbe: "scan-owned-default",
    });
  });

  it("names the package on a failure too, and on no refusal", async () => {
    mockHost("linux", "x64");
    const manifest = JSON.parse(
      readFileSync(join(import.meta.dirname, "..", "..", "package.json"), "utf8"),
    ) as { version: string };

    const failed = await runDetectorV1({
      detectorId: "detector.semgrep",
      subject: {
        kind: "source-tree",
        sourceRoot: sourceFixture(),
        selectedClosurePaths: ["README.md"],
      },
      prerequisiteProbe: presentProbe,
      runner: async () => ({ code: 1, stdout: "", stderr: "fixture failure", truncated: false }),
    });
    const refused = await runDetectorV1({ detectorId: "detector.not-owned-by-scan" });

    if (failed.outcome !== "failed") throw new Error(`expected failure, got ${failed.outcome}`);
    expect(failed.producer).toEqual({ name: "@aihq/scan", version: manifest.version });
    // A refusal executed nothing, so it carries no producer and keeps its existing shape.
    expect(Object.keys(refused).sort()).toEqual(["detail", "host", "outcome", "reason"]);
  });
});

describe("runDetectorV1 hardened analyzer profiles", () => {
  const sarif = (name: string) =>
    canonicalStrictJsonBytesV1({
      version: "2.1.0",
      runs: [{ tool: { driver: { name } }, results: [] }],
    }).toString("utf8");

  function analyzerRunner(calls: { argv: readonly string[]; env: Record<string, string> }[]) {
    const runner: BaselineProcessRunnerV1 = async (argv, options) => {
      calls.push({ argv: [...argv], env: { ...options.env } });
      const okay = (stdout: string) => ({ code: 0, stdout, stderr: "", truncated: false });
      if (argv[0] === BASELINE_DOCKER_EXECUTABLE_V1 && argv.includes("version"))
        return okay("Docker version 28");
      if (argv[0] === BASELINE_DOCKER_EXECUTABLE_V1 && argv.includes("inspect"))
        return okay(JSON.stringify({ Id: SKILLSPECTOR_IMAGE_DIGEST_V1, RepoDigests: [] }));
      if (argv[0] === BASELINE_DOCKER_EXECUTABLE_V1) return okay(sarif("skillspector"));
      if (argv.includes("sync")) return okay("");
      if (argv.at(-1) === "--version" && argv.some((value) => value.endsWith("/skill-scanner")))
        return okay(`skill-scanner ${CISCO_SKILL_SCANNER_VERSION_V1}`);
      if (argv.at(-1) === "--version") return okay(SEMGREP_VERSION_V1);
      if (argv.includes("--output-sarif")) {
        const workBind = argv.findIndex(
          (value, index) => value === "--bind" && argv[index + 2] === "/aih/work",
        );
        const workDirectory = argv[workBind + 1];
        if (workDirectory === undefined) throw new Error("missing Cisco output custody");
        writeFileSync(join(workDirectory, "results.sarif"), sarif("cisco"), "utf8");
        writeFileSync(
          join(workDirectory, "results.json"),
          canonicalStrictJsonBytesV1({ summary: { total_skills_scanned: 1 }, results: [] }),
        );
        return okay("");
      }
      if (argv.includes("--sarif")) return okay(sarif("semgrep"));
      throw new Error(`unexpected argv: ${argv.join(" ")}`);
    };
    return runner;
  }

  it.each([
    ["detector.cisco", "skill-directory", "linux-namespace-uv-v1"],
    ["detector.semgrep", "source-tree", "linux-namespace-uv-v1"],
    ["detector.skillspector", "source-tree", "docker-hardened-skillspector-v1"],
  ] as const)("runs %s under %s and records the profile that actually ran", async (detectorId, kind, profileId) => {
    mockHost("linux", "x64");
    const calls: { argv: readonly string[]; env: Record<string, string> }[] = [];
    const sourceRoot = kind === "skill-directory" ? skillFixture() : sourceFixture();

    const result = await runDetectorV1({
      detectorId,
      subject: {
        kind,
        sourceRoot,
        selectedClosurePaths: kind === "skill-directory" ? ["SKILL.md"] : ["README.md"],
      },
      prerequisiteProbe: presentProbe,
      env: { PATH: "/usr/bin", API_TOKEN: "secret", HOME: "/attacker" },
      runner: analyzerRunner(calls),
    });

    expect(result.outcome).toBe("succeeded");
    if (result.outcome !== "succeeded") return;
    expect(result.executionProfile.id).toBe(profileId);
    expect(result.executionProfile.sha256).toBe(
      canonicalStrictJsonSha256V1(resolveDetectorExecutionProfileDocumentV1(profileId)),
    );
    expect(result.seams.runner).toBe("caller-supplied");
    if (result.evidence.kind !== "baseline-analyzer-observation-v1")
      throw new Error("evidence kind");
    expect(result.evidence.observation.mediaType).toBe("application/sarif+json");
    expect(calls.length).toBeGreaterThan(0);
    // The environment reaching every spawn is scrubbed to Scan's allow-list.
    for (const call of calls) {
      expect(call.env.API_TOKEN).toBeUndefined();
      expect(call.env.HOME).toBeUndefined();
    }
    expect(JSON.stringify(calls)).not.toContain("secret");
    const document = resolveDetectorExecutionProfileDocumentV1(profileId);
    const flattened = calls.flatMap((call) => [...call.argv]);
    for (const flag of document?.containment ?? []) expect(flattened, flag).toContain(flag);
    if (profileId === "linux-namespace-uv-v1")
      expect(calls.every((call) => call.argv[0] === BASELINE_BWRAP_EXECUTABLE_V1)).toBe(true);
  });
});
