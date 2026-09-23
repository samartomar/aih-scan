import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  type BaselineProcessRunnerV1,
  SKILLSPECTOR_IMAGE_DIGEST_V1,
  SKILLSPECTOR_IMAGE_V1,
  SKILLSPECTOR_SOURCE_REVISION_V1,
} from "../../src/baseline/runtime-v1.js";
import type { DetectorPrerequisiteV1 } from "../../src/capability/detector-capability-v1.js";
import { BASELINE_DOCKER_EXECUTABLE_V1 } from "../../src/cli/process-runner.js";
import { canonicalStrictJsonBytesV1 } from "../../src/contract/strict-json-v1.js";
import { runDetectorV1 } from "../../src/runner/run-detector-v1.js";

/**
 * WO-SCAN-STEP2B: the runner resolves for every request a caller can build, a caller can
 * name extra accepted SkillSpector image digests without weakening Scan's own, and a
 * multi-skill tree is refused with the sharding it needs. No Docker, bubblewrap or uv
 * runs here: every spawn goes to a fake runner, so these tests prove the digest
 * comparison and refusal plumbing, not a real Linux run.
 */

const temporaryDirectories: string[] = [];

afterEach(() => {
  vi.restoreAllMocks();
  for (const directory of temporaryDirectories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

function temporaryRoot(label: string): string {
  const root = mkdtempSync(join(tmpdir(), `aih-scan-run-hardening-${label}-`));
  temporaryDirectories.push(root);
  return root;
}

function sourceFixture(): string {
  const root = temporaryRoot("source");
  mkdirSync(join(root, "rules"), { recursive: true });
  writeFileSync(join(root, "rules", "base.md"), "# Rule\n", "utf8");
  writeFileSync(join(root, "README.md"), "# Readme\n", "utf8");
  return root;
}

/** Two skills side by side and no SKILL.md at the top: the tree Core sends as one subject. */
function multiSkillFixture(): string {
  const root = temporaryRoot("multi-skill");
  for (const name of ["alpha", "beta"]) {
    mkdirSync(join(root, "skills", name), { recursive: true });
    writeFileSync(join(root, "skills", name, "SKILL.md"), `# ${name}\n`, "utf8");
  }
  writeFileSync(join(root, "skills", "alpha", "notes.md"), "notes\n", "utf8");
  return root;
}

function mockHost(os: NodeJS.Platform, architecture: string): void {
  vi.spyOn(process, "platform", "get").mockReturnValue(os);
  vi.spyOn(process, "arch", "get").mockReturnValue(architecture as NodeJS.Architecture);
}

function forbiddenRunner(record: { calls: number }): BaselineProcessRunnerV1 {
  return async (argv) => {
    record.calls += 1;
    throw new Error(`no process may be spawned for a refusal: ${argv.join(" ")}`);
  };
}

const presentProbe = (_prerequisite: DetectorPrerequisiteV1) => "present" as const;

function throwingGetter<T extends object>(target: T, field: string, message: string): T {
  Object.defineProperty(target, field, {
    enumerable: true,
    get() {
      throw new Error(message);
    },
  });
  return target;
}

describe("runDetectorV1 never rejects", () => {
  it("refuses a request whose detectorId accessor throws, instead of rejecting", async () => {
    const request = throwingGetter(
      {
        subject: {
          kind: "source-tree",
          sourceRoot: sourceFixture(),
          selectedClosurePaths: ["README.md"],
        },
      },
      "detectorId",
      "hostile detectorId getter",
    );

    const settled = await runDetectorV1(request).then(
      (value) => ({ resolved: true as const, value }),
      (error: unknown) => ({ resolved: false as const, error }),
    );

    expect(settled.resolved).toBe(true);
    if (!settled.resolved) return;
    const result = settled.value;
    expect(result.outcome).toBe("refused");
    if (result.outcome !== "refused") return;
    expect(result.reason).toBe("unknown-detector");
    expect(result.detail).toContain("could not be read");
    expect(result.detail).toContain("detectorId");
    expect(result.detail).toContain("hostile detectorId getter");
    expect(Object.keys(result).sort()).toEqual(["detail", "host", "outcome", "reason"]);
  });

  it.each([
    "subject",
    "executionProfileId",
    "env",
    "runner",
    "prerequisiteProbe",
    "ociCapture",
    "acceptedImageDigests",
  ])("refuses a request whose %s accessor throws", async (field) => {
    const request = throwingGetter(
      {
        detectorId: "detector.aih-native",
        subject: {
          kind: "source-tree",
          sourceRoot: sourceFixture(),
          selectedClosurePaths: ["README.md"],
        },
      },
      field,
      `hostile ${field} getter`,
    );

    const result = await runDetectorV1(request);

    expect(result.outcome).toBe("refused");
    if (result.outcome !== "refused") return;
    expect(result.reason).toBe("unknown-detector");
    expect(result.detail).toContain(field);
    expect(result.detail).toContain("could not be read");
  });

  it.each([
    "kind",
    "sourceRoot",
    "selectedClosurePaths",
    "excludedPaths",
  ])("refuses a subject whose %s accessor throws as an unmet subject requirement", async (field) => {
    const record = { calls: 0 };
    const subject = throwingGetter(
      {
        kind: "source-tree",
        sourceRoot: sourceFixture(),
        selectedClosurePaths: ["README.md"],
      } as Record<string, unknown>,
      field,
      `hostile subject.${field} getter`,
    );

    const result = await runDetectorV1({
      detectorId: "detector.aih-native",
      subject,
      runner: forbiddenRunner(record),
    });

    expect(result.outcome).toBe("refused");
    if (result.outcome !== "refused") return;
    expect(result.reason).toBe("subject-requirement-unmet");
    expect(result.detail).toContain(`subject.${field}`);
    expect(result.capability?.detectorId).toBe("detector.aih-native");
    expect(record.calls).toBe(0);
  });

  it("refuses a selected-closure array whose element accessor throws", async () => {
    const paths = ["README.md"];
    throwingGetter(paths, "0", "hostile element getter");

    const result = await runDetectorV1({
      detectorId: "detector.aih-native",
      subject: { kind: "source-tree", sourceRoot: sourceFixture(), selectedClosurePaths: paths },
    });

    expect(result.outcome).toBe("refused");
    if (result.outcome !== "refused") return;
    expect(result.reason).toBe("subject-requirement-unmet");
  });

  it("reports a throwing caller-supplied prerequisiteProbe as an availability failure", async () => {
    mockHost("linux", "x64");
    const record = { calls: 0 };

    const settled = await runDetectorV1({
      detectorId: "detector.skillspector",
      subject: {
        kind: "source-tree",
        sourceRoot: sourceFixture(),
        selectedClosurePaths: ["README.md"],
      },
      prerequisiteProbe: (prerequisite: DetectorPrerequisiteV1) => {
        if (prerequisite.kind === "container-image")
          throw new Error(`probe exploded\n${"x".repeat(900)}`);
        return "present";
      },
      runner: forbiddenRunner(record),
    }).then(
      (value) => ({ resolved: true as const, value }),
      (error: unknown) => ({ resolved: false as const, error }),
    );

    expect(settled.resolved).toBe(true);
    if (!settled.resolved) return;
    const result = settled.value;
    expect(result.outcome).toBe("failed");
    if (result.outcome !== "failed") return;
    expect(result.failure.stage).toBe("availability");
    expect(result.failure.detail).toContain("prerequisiteProbe");
    expect(result.failure.detail).toContain("probe exploded");
    expect(result.failure.detail.length).toBeLessThanOrEqual(400);
    expect(result.seams.prerequisiteProbe).toBe("caller-supplied");
    // The probe that threw and every one after it were not settled, so none is claimed.
    expect(result.prerequisites.map((entry) => [entry.kind, entry.state])).toEqual([
      ["executable", "present"],
      ["container-image", "not-probed"],
    ]);
    expect(result.producer.name).toBe("@aihq/scan");
    expect(record.calls).toBe(0);
  });

  it("reports a probe that is not a function, or returns no known state, as an availability failure", async () => {
    mockHost("linux", "x64");
    const request = (prerequisiteProbe: unknown) => ({
      detectorId: "detector.skillspector",
      subject: {
        kind: "source-tree" as const,
        sourceRoot: sourceFixture(),
        selectedClosurePaths: ["README.md"],
      },
      prerequisiteProbe,
      runner: forbiddenRunner({ calls: 0 }),
    });

    for (const probe of ["present", () => "yes", () => undefined]) {
      const result = await runDetectorV1(request(probe));
      expect(result.outcome).toBe("failed");
      if (result.outcome !== "failed") continue;
      expect(result.failure.stage).toBe("availability");
      expect(result.failure.detail).toContain("prerequisiteProbe");
    }
  });

  it("still resolves when a thrown value has a throwing message accessor", async () => {
    mockHost("linux", "x64");
    const hostile = Object.create(Error.prototype) as Error;
    Object.defineProperty(hostile, "message", {
      get() {
        throw new Error("message getter");
      },
    });

    const result = await runDetectorV1({
      detectorId: "detector.semgrep",
      subject: {
        kind: "source-tree",
        sourceRoot: sourceFixture(),
        selectedClosurePaths: ["README.md"],
      },
      prerequisiteProbe: presentProbe,
      runner: async () => {
        throw hostile;
      },
    });

    expect(result.outcome).toBe("failed");
    if (result.outcome !== "failed") return;
    expect(result.failure.detail).toBe("unknown failure");
  });
});

describe("runDetectorV1 caller-accepted SkillSpector image digests", () => {
  const acceptedA = `sha256:${"a".repeat(64)}`;
  const acceptedB = `sha256:${"b".repeat(64)}`;
  const sarif = canonicalStrictJsonBytesV1({
    version: "2.1.0",
    runs: [{ tool: { driver: { name: "skillspector" } }, results: [] }],
  }).toString("utf8");
  const okay = (stdout: string) => ({ code: 0, stdout, stderr: "", truncated: false });
  const absent = { code: 1, stdout: "", stderr: "Error: No such image", truncated: false };

  /** A fake `docker`: `images` maps an inspected reference to its `{{json .}}` output. */
  function dockerRunner(
    images: Readonly<Record<string, unknown>>,
    calls: string[][],
  ): BaselineProcessRunnerV1 {
    return async (argv) => {
      calls.push([...argv]);
      if (argv[0] !== BASELINE_DOCKER_EXECUTABLE_V1) throw new Error(`unexpected ${argv[0]}`);
      if (argv.includes("version")) return okay("Docker version 28");
      if (argv.includes("inspect")) {
        const reference = argv[argv.indexOf("inspect") + 1] ?? "";
        const image = images[reference];
        return image === undefined ? absent : okay(JSON.stringify(image));
      }
      if (argv.includes("pull")) throw new Error("no image may be pulled here");
      if (argv.includes("run")) return okay(sarif);
      throw new Error(`unexpected argv: ${argv.join(" ")}`);
    };
  }

  const skillspectorRequest = (extra: Record<string, unknown>) => ({
    detectorId: "detector.skillspector",
    subject: {
      kind: "source-tree" as const,
      sourceRoot: sourceFixture(),
      selectedClosurePaths: ["README.md"],
    },
    prerequisiteProbe: presentProbe,
    env: { PATH: "/usr/bin" },
    ...extra,
  });

  const inspectedReferences = (calls: readonly string[][]) =>
    calls
      .filter((argv) => argv.includes("inspect"))
      .map((argv) => argv[argv.indexOf("inspect") + 1]);

  it("records Scan's pinned digest when the pinned image is present, and never consults the accepted list", async () => {
    mockHost("linux", "x64");
    const calls: string[][] = [];

    const result = await runDetectorV1(
      skillspectorRequest({
        acceptedImageDigests: [acceptedA],
        runner: dockerRunner(
          { [SKILLSPECTOR_IMAGE_V1]: { Id: SKILLSPECTOR_IMAGE_DIGEST_V1, RepoDigests: [] } },
          calls,
        ),
      }),
    );

    expect(result.outcome).toBe("succeeded");
    if (result.outcome !== "succeeded") return;
    if (result.evidence.kind !== "baseline-analyzer-observation-v1")
      throw new Error("evidence kind");
    expect(result.evidence.observation.image).toEqual({
      digest: SKILLSPECTOR_IMAGE_DIGEST_V1,
      reference: SKILLSPECTOR_IMAGE_DIGEST_V1,
      acceptance: "scan-pinned",
    });
    expect(result.evidence.observation.analyzerVersion).toBe(
      `${SKILLSPECTOR_SOURCE_REVISION_V1}@${SKILLSPECTOR_IMAGE_DIGEST_V1}`,
    );
    expect(inspectedReferences(calls)).toEqual([SKILLSPECTOR_IMAGE_V1]);
  });

  it("runs the first present accepted image in the caller's order, by its local content address, and pulls nothing", async () => {
    mockHost("linux", "x64");
    const calls: string[][] = [];

    const result = await runDetectorV1(
      skillspectorRequest({
        acceptedImageDigests: [acceptedA, acceptedB],
        runner: dockerRunner({ [acceptedB]: { Id: acceptedB, RepoDigests: [] } }, calls),
      }),
    );

    expect(result.outcome).toBe("succeeded");
    if (result.outcome !== "succeeded") return;
    if (result.evidence.kind !== "baseline-analyzer-observation-v1")
      throw new Error("evidence kind");
    expect(result.evidence.observation.image).toEqual({
      digest: acceptedB,
      reference: acceptedB,
      acceptance: "caller-accepted",
    });
    expect(result.evidence.observation.analyzerVersion).toBe(
      `${SKILLSPECTOR_SOURCE_REVISION_V1}@${acceptedB}`,
    );
    // Scan's own pinned reference is always consulted first.
    expect(inspectedReferences(calls)).toEqual([SKILLSPECTOR_IMAGE_V1, acceptedA, acceptedB]);
    expect(calls.some((argv) => argv.includes("pull"))).toBe(false);
    const run = calls.find((argv) => argv.includes("run"));
    expect(run).toContain(acceptedB);
    expect(run).not.toContain(SKILLSPECTOR_IMAGE_V1);
  });

  it("matches an accepted repository digest but runs the inspected local image ID, so nothing can be pulled", async () => {
    mockHost("linux", "x64");
    const calls: string[][] = [];
    const localId = `sha256:${"c".repeat(64)}`;

    const result = await runDetectorV1(
      skillspectorRequest({
        acceptedImageDigests: [acceptedA],
        runner: dockerRunner(
          {
            [acceptedA]: {
              Id: localId,
              RepoDigests: [`registry.example/skillspector@${acceptedA}`],
            },
          },
          calls,
        ),
      }),
    );

    expect(result.outcome).toBe("succeeded");
    if (result.outcome !== "succeeded") return;
    if (result.evidence.kind !== "baseline-analyzer-observation-v1")
      throw new Error("evidence kind");
    expect(result.evidence.observation.image).toEqual({
      digest: acceptedA,
      reference: localId,
      acceptance: "caller-accepted",
    });
    expect(calls.find((argv) => argv.includes("run"))).toContain(localId);
  });

  it("fails at availability, pulling nothing, when no present image matches any accepted digest", async () => {
    mockHost("linux", "x64");
    const calls: string[][] = [];

    const result = await runDetectorV1(
      skillspectorRequest({
        acceptedImageDigests: [acceptedA, acceptedB],
        runner: dockerRunner({}, calls),
      }),
    );

    expect(result.outcome).toBe("failed");
    if (result.outcome !== "failed") return;
    expect(result.failure.stage).toBe("availability");
    expect(result.failure.detail).toContain("SkillSpector image availability");
    expect(result.failure.detail).toContain(SKILLSPECTOR_IMAGE_DIGEST_V1);
    expect(result.failure.detail).toContain("2 caller-accepted digests");
    expect(result.failure.detail).toContain("pulls nothing");
    expect(calls.some((argv) => argv.includes("pull") || argv.includes("run"))).toBe(false);
  });

  it("never lets an accepted digest excuse a pinned reference that resolves to another image", async () => {
    mockHost("linux", "x64");
    const calls: string[][] = [];
    const other = `sha256:${"f".repeat(64)}`;

    const result = await runDetectorV1(
      skillspectorRequest({
        acceptedImageDigests: [other],
        runner: dockerRunner(
          {
            [SKILLSPECTOR_IMAGE_V1]: { Id: other, RepoDigests: [] },
            [other]: { Id: other, RepoDigests: [] },
          },
          calls,
        ),
      }),
    );

    expect(result.outcome).toBe("failed");
    if (result.outcome !== "failed") return;
    expect(result.failure.detail).toContain(
      `SkillSpector image digest does not match ${SKILLSPECTOR_IMAGE_DIGEST_V1}`,
    );
    expect(calls.some((argv) => argv.includes("run"))).toBe(false);
  });

  it("fails when the image found for an accepted digest does not carry that digest", async () => {
    mockHost("linux", "x64");
    const calls: string[][] = [];

    const result = await runDetectorV1(
      skillspectorRequest({
        acceptedImageDigests: [acceptedA],
        runner: dockerRunner(
          { [acceptedA]: { Id: `sha256:${"d".repeat(64)}`, RepoDigests: [] } },
          calls,
        ),
      }),
    );

    expect(result.outcome).toBe("failed");
    if (result.outcome !== "failed") return;
    expect(result.failure.stage).toBe("availability");
    expect(result.failure.detail).toContain(`does not carry accepted digest ${acceptedA}`);
    expect(calls.some((argv) => argv.includes("run"))).toBe(false);
  });

  it.each([
    ["not an array", acceptedA],
    ["an empty list", []],
    ["an uppercase digest", [`sha256:${"A".repeat(64)}`]],
    ["a digest without its algorithm", ["a".repeat(64)]],
    ["a short digest", [`sha256:${"a".repeat(63)}`]],
    ["a repeated digest", [acceptedA, acceptedA]],
    ["a non-string entry", [7]],
    [
      "more than 32 digests",
      Array.from({ length: 33 }, (_, index) => `sha256:${index.toString(16).padStart(64, "0")}`),
    ],
  ])("refuses %s before anything is spawned", async (_label, acceptedImageDigests) => {
    mockHost("linux", "x64");
    const record = { calls: 0 };

    const result = await runDetectorV1(
      skillspectorRequest({ acceptedImageDigests, runner: forbiddenRunner(record) }),
    );

    expect(result.outcome).toBe("refused");
    if (result.outcome !== "refused") return;
    expect(result.reason).toBe("execution-profile-unavailable");
    expect(result.detail).toContain("acceptedImageDigests");
    expect(record.calls).toBe(0);
  });

  it("refuses accepted digests for a profile that runs no SkillSpector image", async () => {
    mockHost("linux", "x64");
    const record = { calls: 0 };

    const result = await runDetectorV1({
      detectorId: "detector.semgrep",
      subject: {
        kind: "source-tree",
        sourceRoot: sourceFixture(),
        selectedClosurePaths: ["README.md"],
      },
      acceptedImageDigests: [acceptedA],
      prerequisiteProbe: presentProbe,
      runner: forbiddenRunner(record),
    });

    expect(result.outcome).toBe("refused");
    if (result.outcome !== "refused") return;
    expect(result.reason).toBe("execution-profile-unavailable");
    expect(result.detail).toContain("docker-hardened-skillspector-v1");
    expect(record.calls).toBe(0);
  });
});

describe("runDetectorV1 multi-skill trees", () => {
  it("refuses a selection with several nested SKILL.md files and no top-level one, and says how to shard", async () => {
    const record = { calls: 0 };

    const result = await runDetectorV1({
      detectorId: "detector.cisco",
      subject: {
        kind: "skill-directory",
        sourceRoot: multiSkillFixture(),
        selectedClosurePaths: [
          "skills/alpha/SKILL.md",
          "skills/alpha/notes.md",
          "skills/beta/SKILL.md",
        ],
      },
      runner: forbiddenRunner(record),
    });

    expect(result.outcome).toBe("refused");
    if (result.outcome !== "refused") return;
    expect(result.reason).toBe("subject-requirement-unmet");
    expect(result.detail).toContain("one skill root per request");
    expect(result.detail).toContain("2 SKILL.md files below the declared root");
    expect(result.detail).toContain("skills/alpha, skills/beta");
    expect(result.detail).toContain("one skill-directory request per directory");
    expect(result.detail).toContain("as sourceRoot");
    expect(result.detail.length).toBeLessThanOrEqual(400);
    expect(record.calls).toBe(0);
  });

  it("names the sharding route when a whole tree is sent to a skill-directory-only detector", async () => {
    const result = await runDetectorV1({
      detectorId: "detector.cisco",
      subject: {
        kind: "source-tree",
        sourceRoot: multiSkillFixture(),
        selectedClosurePaths: ["skills/alpha/SKILL.md", "skills/beta/SKILL.md"],
      },
    });

    expect(result.outcome).toBe("refused");
    if (result.outcome !== "refused") return;
    expect(result.reason).toBe("unsupported-subject-kind");
    expect(result.detail).toContain("accepts skill-directory, not source-tree");
    expect(result.detail).toContain("one skill root per request");
  });
});
