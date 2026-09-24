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
    runs: [
      {
        tool: { driver: { name: "skillspector" } },
        results: [],
        invocations: [{ executionSuccessful: true }],
      },
    ],
  }).toString("utf8");
  const okay = (stdout: string) => ({ code: 0, stdout, stderr: "", truncated: false });
  const absent = { code: 1, stdout: "", stderr: "Error: No such image", truncated: false };

  const pullRefused = "Error response from daemon: network unreachable";

  /**
   * A fake `docker`: `images` maps an inspected reference to its `{{json .}}` output.
   * `pull` decides Scan's pinned pull: it fails, rejects as a spawn error, or succeeds and
   * makes the pinned image present.
   */
  function dockerRunner(
    images: Readonly<Record<string, unknown>>,
    calls: string[][],
    pull: "fails" | "rejects" | "succeeds" = "fails",
  ): BaselineProcessRunnerV1 {
    const store: Record<string, unknown> = { ...images };
    return async (argv) => {
      calls.push([...argv]);
      if (argv[0] !== BASELINE_DOCKER_EXECUTABLE_V1) throw new Error(`unexpected ${argv[0]}`);
      if (argv.includes("version")) return okay("Docker version 28");
      if (argv.includes("inspect")) {
        const reference = argv[argv.indexOf("inspect") + 1] ?? "";
        const image = store[reference];
        return image === undefined ? absent : okay(JSON.stringify(image));
      }
      if (argv.includes("pull")) {
        if (argv.at(-1) !== SKILLSPECTOR_IMAGE_V1)
          throw new Error(`only Scan's pinned image may be pulled: ${argv.join(" ")}`);
        if (pull === "rejects") throw new Error("spawn /usr/bin/docker EAGAIN");
        if (pull === "fails") return { code: 1, stdout: "", stderr: pullRefused, truncated: false };
        store[SKILLSPECTOR_IMAGE_V1] = { Id: SKILLSPECTOR_IMAGE_DIGEST_V1, RepoDigests: [] };
        return okay("pulled");
      }
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
  const pulls = (calls: readonly string[][]) => calls.filter((argv) => argv.includes("pull"));

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
    expect(pulls(calls)).toEqual([]);
  });

  it("still acquires Scan's pinned image first when it is absent, and runs it without consulting the list", async () => {
    mockHost("linux", "x64");
    const calls: string[][] = [];

    const result = await runDetectorV1(
      skillspectorRequest({
        acceptedImageDigests: [acceptedA],
        runner: dockerRunner(
          { [acceptedA]: { Id: acceptedA, RepoDigests: [] } },
          calls,
          "succeeds",
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
    expect(pulls(calls)).toEqual([
      [BASELINE_DOCKER_EXECUTABLE_V1, "--context", "default", "pull", SKILLSPECTOR_IMAGE_V1],
    ]);
    // The pinned reference is inspected before and after the pull; the list never is.
    expect(inspectedReferences(calls)).toEqual([SKILLSPECTOR_IMAGE_V1, SKILLSPECTOR_IMAGE_V1]);
    expect(calls.find((argv) => argv.includes("run"))).not.toContain(acceptedA);
  });

  it("runs the first present accepted local image, by its content address, only after the pinned pull failed, and records why", async () => {
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
      pinnedPullFailure: pullRefused,
    });
    expect(result.evidence.observation.analyzerVersion).toBe(
      `${SKILLSPECTOR_SOURCE_REVISION_V1}@${acceptedB}`,
    );
    // Scan's own pinned image is inspected and pulled first; only then is the list consulted.
    expect(inspectedReferences(calls)).toEqual([SKILLSPECTOR_IMAGE_V1, acceptedA, acceptedB]);
    expect(pulls(calls)).toEqual([
      [BASELINE_DOCKER_EXECUTABLE_V1, "--context", "default", "pull", SKILLSPECTOR_IMAGE_V1],
    ]);
    const pullIndex = calls.findIndex((argv) => argv.includes("pull"));
    const firstAcceptedInspect = calls.findIndex((argv) => argv.includes(acceptedA));
    expect(pullIndex).toBeLessThan(firstAcceptedInspect);
    const run = calls.find((argv) => argv.includes("run"));
    expect(run).toContain(acceptedB);
    expect(run).not.toContain(SKILLSPECTOR_IMAGE_V1);
  });

  it("treats a pinned pull that could not even be spawned as a failed acquisition too", async () => {
    mockHost("linux", "x64");
    const calls: string[][] = [];

    const result = await runDetectorV1(
      skillspectorRequest({
        acceptedImageDigests: [acceptedA],
        runner: dockerRunner({ [acceptedA]: { Id: acceptedA, RepoDigests: [] } }, calls, "rejects"),
      }),
    );

    expect(result.outcome).toBe("succeeded");
    if (result.outcome !== "succeeded") return;
    if (result.evidence.kind !== "baseline-analyzer-observation-v1")
      throw new Error("evidence kind");
    expect(result.evidence.observation.image?.acceptance).toBe("caller-accepted");
    expect(result.evidence.observation.image?.pinnedPullFailure).toContain("EAGAIN");
  });

  it("keeps a failed pinned pull an acquisition failure when no accepted digests are named", async () => {
    mockHost("linux", "x64");
    const calls: string[][] = [];

    const result = await runDetectorV1(skillspectorRequest({ runner: dockerRunner({}, calls) }));

    expect(result.outcome).toBe("failed");
    if (result.outcome !== "failed") return;
    expect(result.failure.stage).toBe("acquisition");
    expect(result.failure.detail).toContain(pullRefused);
  });

  it("matches an accepted repository digest but runs the inspected local image ID, so nothing more can be pulled", async () => {
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
      pinnedPullFailure: pullRefused,
    });
    expect(calls.find((argv) => argv.includes("run"))).toContain(localId);
  });

  it("fails at availability when the pinned pull failed and no local image matches any accepted digest", async () => {
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
    expect(result.failure.detail).toContain(pullRefused);
    expect(pulls(calls)).toHaveLength(1);
    expect(calls.some((argv) => argv.includes("run"))).toBe(false);
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

  it("names the host profile and the sharding route when a whole tree is sent to Cisco under a skill-root profile", async () => {
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
    expect(result.detail).toContain("source-tree subject only under host-process-uv-v1");
    expect(result.detail).toContain("linux-namespace-uv-v1 runs one skill root per request");
    expect(result.detail).toContain("one skill-directory request per directory");
  });
});

/**
 * Session-5 review (finding 3): JSON-representable or Proxy-shaped values a caller can
 * build must resolve to a typed refusal, never reject. Each of these reached a string
 * coercion or an `IsArray` check outside a guard before the fix.
 */
describe("runDetectorV1 never rejects on malformed field values", () => {
  type Settled =
    | { readonly resolved: true; readonly value: Awaited<ReturnType<typeof runDetectorV1>> }
    | { readonly resolved: false; readonly error: unknown };

  async function settle(request: unknown): Promise<Settled> {
    return runDetectorV1(request).then(
      (value) => ({ resolved: true as const, value }),
      (error: unknown) => ({ resolved: false as const, error }),
    );
  }

  async function refusal(request: unknown) {
    const settled = await settle(request);
    if (!settled.resolved)
      throw new Error(`runDetectorV1 rejected: ${String((settled.error as Error)?.message)}`);
    const result = settled.value;
    if (result.outcome !== "refused") throw new Error(`expected a refusal, got ${result.outcome}`);
    return result;
  }

  function nativeRequest(extra: Record<string, unknown>, record = { calls: 0 }) {
    return {
      detectorId: "detector.aih-native",
      subject: {
        kind: "source-tree",
        sourceRoot: sourceFixture(),
        selectedClosurePaths: ["README.md"],
      },
      runner: forbiddenRunner(record),
      ...extra,
    };
  }

  function revokedProxy(): object {
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();
    return proxy;
  }

  const throwingToString = () => ({
    toString() {
      throw new Error("hostile toString");
    },
  });

  it("refuses the review probe's executionProfileId (null toString and valueOf) as an unavailable profile", async () => {
    const record = { calls: 0 };
    const result = await refusal(
      nativeRequest({ executionProfileId: { toString: null, valueOf: null } }, record),
    );

    expect(result.reason).toBe("execution-profile-unavailable");
    expect(result.detail).toContain("executionProfileId");
    expect(result.detail).toContain("in-process-native-v1");
    expect(result.capability?.detectorId).toBe("detector.aih-native");
    expect(record.calls).toBe(0);
  });

  it.each([
    ["a number", 7],
    ["an array", ["in-process-native-v1"]],
    ["an object whose toString throws", throwingToString()],
    ["an empty string", ""],
    ["null", null],
    ["a boolean", true],
  ])("refuses an executionProfileId that is %s before any interpolation", async (_label, value) => {
    const record = { calls: 0 };
    const result = await refusal(nativeRequest({ executionProfileId: value }, record));

    expect(result.reason).toBe("execution-profile-unavailable");
    expect(result.detail).toContain("executionProfileId");
    expect(result.detail).not.toContain("hostile toString");
    expect(record.calls).toBe(0);
  });

  it("still refuses an unknown but well-formed executionProfileId by name", async () => {
    const result = await refusal(nativeRequest({ executionProfileId: "no-such-profile" }));

    expect(result.reason).toBe("execution-profile-unavailable");
    expect(result.detail).toContain("no execution profile no-such-profile");
  });

  it.each([
    ["a value whose toString throws", { PATH: throwingToString() }],
    ["a value with null toString and valueOf", { PATH: { toString: null, valueOf: null } }],
    ["a number value", { PATH: 5 }],
    ["a string", "PATH=/usr/bin"],
    ["an array", ["PATH=/usr/bin"]],
    ["null", null],
  ])("refuses an env that is %s rather than coerce it", async (_label, env) => {
    const record = { calls: 0 };
    const result = await refusal(nativeRequest({ env }, record));

    expect(result.reason).toBe("execution-profile-unavailable");
    expect(result.detail).toContain("env");
    expect(result.detail).not.toContain("hostile toString");
    expect(result.capability?.detectorId).toBe("detector.aih-native");
    expect(record.calls).toBe(0);
  });

  it("keeps accepting an env whose values are strings or undefined", async () => {
    const settled = await settle(nativeRequest({ env: { PATH: "/usr/bin", HOME: undefined } }));

    expect(settled.resolved).toBe(true);
    if (!settled.resolved) return;
    expect(settled.value.outcome).toBe("succeeded");
  });

  it("refuses an env Proxy whose ownKeys trap throws as an unreadable request", async () => {
    const env = new Proxy(
      {},
      {
        ownKeys() {
          throw new Error("hostile ownKeys");
        },
      },
    );
    const result = await refusal(nativeRequest({ env }));

    expect(result.reason).toBe("unknown-detector");
    expect(result.detail).toContain("env");
    expect(result.detail).toContain("hostile ownKeys");
  });

  it.each([
    ["a string", "oci"],
    ["a number", 5],
    ["an array", ["layout"]],
    ["null", null],
  ])("refuses an ociCapture that is %s, even for a detector with an OCI profile", async (_label, ociCapture) => {
    mockHost("linux", "x64");
    const root = temporaryRoot("oci-shape");
    writeFileSync(join(root, "SKILL.md"), "# Skill\n", "utf8");
    const record = { calls: 0 };
    const result = await refusal({
      detectorId: "detector.cisco",
      subject: { kind: "skill-directory", sourceRoot: root, selectedClosurePaths: ["SKILL.md"] },
      prerequisiteProbe: presentProbe,
      runner: forbiddenRunner(record),
      ociCapture,
    });

    expect(result.reason).toBe("execution-profile-unavailable");
    expect(result.detail).toContain("ociCapture");
    expect(record.calls).toBe(0);
  });

  it("resolves when every ociCapture value throws on string coercion", async () => {
    mockHost("linux", "x64");
    const root = temporaryRoot("oci-skill");
    writeFileSync(join(root, "SKILL.md"), "# Skill\n", "utf8");
    const record = { calls: 0 };
    const forbidden = forbiddenRunner(record);

    const settled = await settle({
      detectorId: "detector.cisco",
      subject: { kind: "skill-directory", sourceRoot: root, selectedClosurePaths: ["SKILL.md"] },
      prerequisiteProbe: presentProbe,
      runner: forbidden,
      ociCapture: {
        layout: throwingToString(),
        runtime: { toString: null, valueOf: null },
        broker: throwingToString(),
        annexPayloads: throwingToString(),
        runner: async (argv: readonly string[]) => forbidden(argv, {} as never),
      },
    });

    expect(settled.resolved).toBe(true);
    if (!settled.resolved) return;
    expect(["refused", "failed"]).toContain(settled.value.outcome);
    expect(record.calls).toBe(0);
  });

  it("refuses a revoked Proxy request as an unreadable request", async () => {
    const result = await refusal(revokedProxy());

    expect(result.reason).toBe("unknown-detector");
    expect(result.detail).toContain("could not be read");
    expect(Object.keys(result).sort()).toEqual(["detail", "host", "outcome", "reason"]);
  });

  it.each([
    "subject",
    "executionProfileId",
    "env",
    "ociCapture",
    "acceptedImageDigests",
  ])("refuses a request whose %s is a revoked Proxy", async (field) => {
    const result = await refusal(nativeRequest({ [field]: revokedProxy() }));

    expect(result.reason).toBe("unknown-detector");
    expect(result.detail).toContain(field);
  });

  it("refuses a Proxy request whose get trap throws", async () => {
    const request = new Proxy(nativeRequest({}), {
      get() {
        throw new Error("hostile get");
      },
    });
    const result = await refusal(request);

    expect(result.reason).toBe("unknown-detector");
    expect(result.detail).toContain("hostile get");
  });

  it("refuses a Proxy request whose every reflective trap throws", async () => {
    const hostile = () => {
      throw new Error("hostile trap");
    };
    const request = new Proxy(nativeRequest({}), {
      get: hostile,
      has: hostile,
      ownKeys: hostile,
      getOwnPropertyDescriptor: hostile,
      getPrototypeOf: hostile,
      defineProperty: hostile,
      set: hostile,
    });
    const result = await refusal(request);

    expect(result.reason).toBe("unknown-detector");
  });

  it("resolves for a Proxy request whose only throwing trap is ownKeys", async () => {
    const request = new Proxy(nativeRequest({}), {
      ownKeys() {
        throw new Error("hostile ownKeys");
      },
    });
    const settled = await settle(request);

    expect(settled.resolved).toBe(true);
  });

  it("refuses a subject that a later field accessor revokes after it was read", async () => {
    const { proxy, revoke } = Proxy.revocable(
      { kind: "source-tree", sourceRoot: sourceFixture(), selectedClosurePaths: ["README.md"] },
      {},
    );
    const request: Record<string, unknown> = { detectorId: "detector.aih-native", subject: proxy };
    Object.defineProperty(request, "env", {
      enumerable: true,
      get() {
        revoke();
        return undefined;
      },
    });

    const result = await refusal(request);

    expect(result.reason).toBe("unknown-detector");
  });
});
