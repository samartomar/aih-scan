import { describe, expect, it } from "vitest";
import {
  checkLocalSkillspectorAvailableV1,
  parseSkillspectorSarifLogV1,
  resolveLocalSkillspectorImageV1,
  runSkillspectorScanV1,
  SKILLSPECTOR_IMAGE_DIGEST_V1,
  SKILLSPECTOR_IMAGE_TAG_V1,
  type SkillspectorRunnerV1,
  type SkillspectorRunOptionsV1,
  type SkillspectorRunResultV1,
} from "../../../src/detectors/skillspector-approval/index.js";

/**
 * Ported from Core's `tests/trust/scan.test.ts` SkillSpector execution cases
 * (lines 1276-1454 and 1556-1636) plus the availability probe behaviour of
 * `resolveVerifiedSkillspectorImage`, then extended to the C2a §6 typed
 * surface: prerequisite refusals (§6.1), `acceptedImageDigests` validation
 * (§6.2), the bind-mount pre-spawn refusal and `/scan/` URI rewriting (§6.3).
 * Core asserted through its trust-scan pipeline; here the identical
 * fake-runner inputs drive the engine directly and assert identical reasons,
 * argv, timeouts and cleanup behaviour.
 */

const EMPTY_SARIF = { version: "2.1.0", runs: [{ results: [] }] };
const TREE = "/tmp/scan-root";

type Handler = (
  argv: readonly string[],
  options?: SkillspectorRunOptionsV1,
) => Partial<SkillspectorRunResultV1> | undefined;

function fakeRunner(handler: Handler): SkillspectorRunnerV1 {
  return async (argv, options) => {
    const result = handler(argv, options);
    if (result === undefined) throw new Error(`unexpected argv: ${argv.join(" ")}`);
    return { code: 0, stdout: "", stderr: "", ...result };
  };
}

function successfulSkillspector(
  argv: readonly string[],
): Partial<SkillspectorRunResultV1> | undefined {
  if (argv[0] !== "docker") return undefined;
  if (argv[1] === "--version") return { code: 0, stdout: "Docker version 27\n" };
  if (argv[1] === "image" && argv[2] === "inspect") {
    return {
      code: 0,
      stdout: JSON.stringify({
        Id: SKILLSPECTOR_IMAGE_DIGEST_V1,
        RepoDigests: [`skillspector@${SKILLSPECTOR_IMAGE_DIGEST_V1}`],
      }),
    };
  }
  if (argv[1] === "run") return { code: 0, stdout: JSON.stringify(EMPTY_SARIF) };
  return undefined;
}

describe("resolveLocalSkillspectorImageV1 (C2a §6.1 typed prerequisite refusals)", () => {
  it("scrubs the probe environment and bounds the probe timeout", async () => {
    const seen: Array<{ argv: readonly string[]; options?: SkillspectorRunOptionsV1 }> = [];
    const detector: SkillspectorRunnerV1 = async (argv, options) => {
      seen.push({ argv, options });
      const result = successfulSkillspector(argv);
      if (result === undefined) throw new Error(`unexpected argv: ${argv.join(" ")}`);
      return { code: 0, stdout: "", stderr: "", ...result };
    };

    await resolveLocalSkillspectorImageV1(
      detector,
      "linux",
      {
        PATH: "/usr/bin",
        AWS_SECRET_ACCESS_KEY: "not-a-real-secret-fixture",
        DBUS_SESSION_BUS_ADDRESS: "unix:path=/run/user/1000/bus",
        XDG_RUNTIME_DIR: "/run/user/1000",
        UNRELATED: "dropped",
      },
      30_000,
    );

    expect(seen).toHaveLength(2);
    for (const call of seen) {
      expect(call.options?.timeoutMs).toBe(30_000);
      expect(call.options?.env).toEqual({
        PATH: "/usr/bin",
        DBUS_SESSION_BUS_ADDRESS: "unix:path=/run/user/1000/bus",
        XDG_RUNTIME_DIR: "/run/user/1000",
      });
    }
  });

  it("refuses with the docker prerequisite when the client is missing", async () => {
    const missing = fakeRunner((argv) =>
      argv[0] === "docker" ? { code: 127, stderr: "not found", spawnError: true } : undefined,
    );

    const result = await resolveLocalSkillspectorImageV1(missing, "linux", {}, 30_000);

    expect(result).toEqual({
      status: "refused",
      refusal: {
        reason: "prerequisite-missing",
        prerequisite: "docker",
        detail: "Docker is unavailable (not found)",
      },
    });
    expect(await checkLocalSkillspectorAvailableV1(missing, "linux", {})).toEqual({
      reason: "prerequisite-missing",
      prerequisite: "docker",
      detail: "Docker is unavailable (not found)",
    });
  });

  it("refuses with the container-image prerequisite when the pinned tag is absent", async () => {
    const failing = fakeRunner((argv) => {
      if (argv[0] !== "docker") return undefined;
      if (argv[1] === "--version") return { code: 0, stdout: "Docker version 27\n" };
      if (argv[1] === "image" && argv[2] === "inspect") {
        return { code: 1, stderr: "Error: No such image" };
      }
      return undefined;
    });

    const result = await resolveLocalSkillspectorImageV1(failing, "linux", {}, 30_000);

    expect(result).toEqual({
      status: "refused",
      refusal: {
        reason: "prerequisite-missing",
        prerequisite: "container-image",
        detail: `sandbox image ${SKILLSPECTOR_IMAGE_TAG_V1} could not be inspected (Error: No such image)`,
      },
    });
  });

  it("refuses a digest mismatch naming the pinned digest", async () => {
    const detector = fakeRunner((argv) => {
      if (argv[0] !== "docker") return undefined;
      if (argv[1] === "--version") return { code: 0, stdout: "Docker version 27\n" };
      if (argv[1] === "image" && argv[2] === "inspect") {
        return { code: 0, stdout: JSON.stringify({ Id: `sha256:${"b".repeat(64)}` }) };
      }
      return undefined;
    });

    const result = await resolveLocalSkillspectorImageV1(detector, "linux", {}, 30_000);

    expect(result).toEqual({
      status: "refused",
      refusal: {
        reason: "prerequisite-missing",
        prerequisite: "container-image",
        detail: `sandbox image ${SKILLSPECTOR_IMAGE_TAG_V1} could not verify expected image digest ${SKILLSPECTOR_IMAGE_DIGEST_V1}`,
      },
    });
  });

  it("resolves the pinned image and records a pinned admission", async () => {
    const result = await resolveLocalSkillspectorImageV1(
      fakeRunner(successfulSkillspector),
      "linux",
      {},
      30_000,
    );

    expect(result).toEqual({
      status: "resolved",
      match: {
        reference: SKILLSPECTOR_IMAGE_DIGEST_V1,
        digest: SKILLSPECTOR_IMAGE_DIGEST_V1,
        acceptance: "pinned",
      },
    });
  });

  it("admits a caller-accepted digest and records it as caller-accepted", async () => {
    const callerDigest = `sha256:${"b".repeat(64)}`;
    const detector = fakeRunner((argv) => {
      if (argv[0] !== "docker") return undefined;
      if (argv[1] === "--version") return { code: 0, stdout: "Docker version 27\n" };
      if (argv[1] === "image" && argv[2] === "inspect") {
        return { code: 0, stdout: JSON.stringify({ Id: callerDigest }) };
      }
      return undefined;
    });

    const result = await resolveLocalSkillspectorImageV1(detector, "linux", {}, 30_000, [
      callerDigest,
    ]);

    expect(result).toEqual({
      status: "resolved",
      match: { reference: callerDigest, digest: callerDigest, acceptance: "caller-accepted" },
    });
  });
});

describe("runSkillspectorScanV1", () => {
  it("runs the verified digest, never the tag, with Core's bounded timeout", async () => {
    // Ported from Core scan.test.ts:1456-1554 (runner assertions at 1524-1528).
    const seenDockerRuns: string[][] = [];
    const seenDockerTimeouts: Array<number | undefined> = [];
    const detector = fakeRunner((argv, options) => {
      if (argv[0] !== "docker") return undefined;
      if (argv[1] === "run") {
        seenDockerRuns.push([...argv]);
        seenDockerTimeouts.push(options?.timeoutMs);
        return { code: 1, stdout: JSON.stringify(EMPTY_SARIF) };
      }
      return successfulSkillspector(argv);
    });

    const outcome = await runSkillspectorScanV1({
      run: detector,
      platform: "linux",
      env: {},
      tree: TREE,
    });

    expect(outcome).toMatchObject({
      status: "succeeded",
      sarifText: JSON.stringify(EMPTY_SARIF),
      image: {
        reference: SKILLSPECTOR_IMAGE_DIGEST_V1,
        digest: SKILLSPECTOR_IMAGE_DIGEST_V1,
        acceptance: "pinned",
      },
    });
    expect(seenDockerRuns).toHaveLength(1);
    expect(seenDockerTimeouts).toEqual([900_000]);
    expect(seenDockerRuns[0]).toContain(SKILLSPECTOR_IMAGE_DIGEST_V1);
    expect(seenDockerRuns[0]).not.toContain(SKILLSPECTOR_IMAGE_TAG_V1);
    expect(seenDockerRuns[0]).not.toContain("pull");
    // C2a §6.1: the local profile never pulls, even if the admitted image
    // disappears between inspection and execution.
    expect(seenDockerRuns[0]?.slice(0, 4)).toEqual(["docker", "run", "--pull", "never"]);
  });

  it("runs the full repo@digest reference when only RepoDigests proved the image", async () => {
    const ghcrRepoDigest = `ghcr.io/samartomar/skillspector@${SKILLSPECTOR_IMAGE_DIGEST_V1}`;
    const seenDockerRuns: string[][] = [];
    const detector = fakeRunner((argv) => {
      if (argv[0] !== "docker") return undefined;
      if (argv[1] === "--version") return { code: 0, stdout: "Docker version 27\n" };
      if (argv[1] === "image" && argv[2] === "inspect") {
        return {
          code: 0,
          stdout: JSON.stringify({
            Id: `sha256:${"b".repeat(64)}`,
            RepoDigests: [ghcrRepoDigest],
          }),
        };
      }
      if (argv[1] === "run") {
        seenDockerRuns.push([...argv]);
        return { code: 0, stdout: JSON.stringify(EMPTY_SARIF) };
      }
      return undefined;
    });

    const outcome = await runSkillspectorScanV1({
      run: detector,
      platform: "linux",
      env: {},
      tree: TREE,
    });

    expect(outcome).toMatchObject({
      status: "succeeded",
      image: {
        reference: ghcrRepoDigest,
        digest: SKILLSPECTOR_IMAGE_DIGEST_V1,
        acceptance: "pinned",
      },
    });
    expect(seenDockerRuns[0]).toContain(ghcrRepoDigest);
  });

  it("accepts a caller-accepted local digest (C2a §6.1/§6.2)", async () => {
    // Ported from Core scan.test.ts:1353-1401; C2a has Core pre-filter org policy
    // into acceptedImageDigests, so the engine consumes the digest list directly.
    const acceptedDigest = `sha256:${"b".repeat(64)}`;
    const dockerRuns: string[][] = [];
    const detector = fakeRunner((argv) => {
      if (argv[0] !== "docker") return undefined;
      if (argv[1] === "--version") return { code: 0, stdout: "Docker version 27\n" };
      if (argv[1] === "image" && argv[2] === "inspect") {
        return { code: 0, stdout: JSON.stringify({ Id: acceptedDigest }) };
      }
      if (argv[1] === "run") {
        dockerRuns.push([...argv]);
        return { code: 0, stdout: JSON.stringify(EMPTY_SARIF) };
      }
      return undefined;
    });

    const outcome = await runSkillspectorScanV1({
      run: detector,
      platform: "linux",
      env: {},
      tree: TREE,
      acceptedImageDigests: [acceptedDigest],
    });

    expect(outcome).toMatchObject({
      status: "succeeded",
      image: { reference: acceptedDigest, digest: acceptedDigest, acceptance: "caller-accepted" },
    });
    expect(dockerRuns).toHaveLength(1);
    expect(dockerRuns[0]).toContain(acceptedDigest);
  });

  it("refuses an unlisted local digest before any container runs", async () => {
    // Ported from Core scan.test.ts:1403-1454: no container ever runs.
    const dockerRuns: string[][] = [];
    const detector = fakeRunner((argv) => {
      if (argv[0] !== "docker") return undefined;
      if (argv[1] === "--version") return { code: 0, stdout: "Docker version 27\n" };
      if (argv[1] === "image" && argv[2] === "inspect") {
        return { code: 0, stdout: JSON.stringify({ Id: `sha256:${"b".repeat(64)}` }) };
      }
      if (argv[1] === "run") {
        dockerRuns.push([...argv]);
        return { code: 0, stdout: JSON.stringify(EMPTY_SARIF) };
      }
      return undefined;
    });

    const outcome = await runSkillspectorScanV1({
      run: detector,
      platform: "linux",
      env: {},
      tree: TREE,
      acceptedImageDigests: [`sha256:${"c".repeat(64)}`],
    });

    expect(outcome).toEqual({
      status: "refused",
      refusal: {
        reason: "prerequisite-missing",
        prerequisite: "container-image",
        detail: `sandbox image ${SKILLSPECTOR_IMAGE_TAG_V1} could not verify expected image digest ${SKILLSPECTOR_IMAGE_DIGEST_V1} or an org-policy approved local digest`,
      },
    });
    expect(dockerRuns).toEqual([]);
  });

  it("refuses malformed acceptedImageDigests before any probe (C2a §6.2)", async () => {
    const calls: string[][] = [];
    const detector: SkillspectorRunnerV1 = async (argv) => {
      calls.push([...argv]);
      return { code: 0, stdout: "", stderr: "" };
    };

    for (const acceptedImageDigests of [
      ["not-a-digest"],
      [SKILLSPECTOR_IMAGE_DIGEST_V1.toUpperCase()],
      [`sha256:${"b".repeat(64)}`, `sha256:${"b".repeat(64)}`],
      Array.from({ length: 17 }, (_, index) => `sha256:${String(index).padStart(64, "0")}`),
    ]) {
      const outcome = await runSkillspectorScanV1({
        run: detector,
        platform: "linux",
        env: {},
        tree: TREE,
        acceptedImageDigests,
      });
      expect(outcome.status).toBe("refused");
      if (outcome.status !== "refused") return;
      expect(outcome.refusal.reason).toBe("execution-profile-unavailable");
      expect(outcome.refusal.detail).toContain("acceptedImageDigests");
    }
    expect(calls).toEqual([]);
  });

  it("refuses a comma or control character in the bind-mount source before spawning (C2a §6.3)", async () => {
    const calls: string[][] = [];
    const detector: SkillspectorRunnerV1 = async (argv) => {
      calls.push([...argv]);
      return { code: 0, stdout: "", stderr: "" };
    };

    for (const tree of ["/tmp/with,comma", "/tmp/with\nnewline"]) {
      const outcome = await runSkillspectorScanV1({
        run: detector,
        platform: "linux",
        env: {},
        tree,
      });
      expect(outcome).toEqual({
        status: "refused",
        refusal: {
          reason: "subject-requirement-unmet",
          detail: "unsupported Docker bind mount source path: comma/control characters",
        },
      });
    }
    expect(calls).toEqual([]);
  });

  it("force-removes the bounded SkillSpector container after a scanner timeout", async () => {
    // Ported from Core scan.test.ts:1556-1599; a timeout or abort reaches the
    // engine as a spawnError from the runner seam (§6.3 cleanup rule).
    let containerName = "";
    const cleanupRuns: string[][] = [];
    const detector = fakeRunner((argv) => {
      if (argv[0] !== "docker") return undefined;
      if (argv[1] === "run") {
        containerName = argv[argv.indexOf("--name") + 1] ?? "";
        return {
          code: 1,
          stderr: "process timed out after 900000ms",
          spawnError: true,
        };
      }
      if (argv[1] === "rm") {
        cleanupRuns.push([...argv]);
        return { code: 0 };
      }
      return successfulSkillspector(argv);
    });

    const outcome = await runSkillspectorScanV1({
      run: detector,
      platform: "linux",
      env: {},
      tree: TREE,
    });

    expect(containerName).toMatch(/^aih-skillspector-[0-9a-f-]{36}$/);
    expect(cleanupRuns).toEqual([["docker", "rm", "--force", "--volumes", containerName]]);
    expect(outcome).toEqual({
      status: "failed",
      failure: { stage: "execution", detail: "process timed out after 900000ms" },
    });
  });

  it("force-removes the bounded container when captured output is truncated", async () => {
    const cleanupRuns: string[][] = [];
    const detector = fakeRunner((argv) => {
      if (argv[0] !== "docker") return undefined;
      if (argv[1] === "run") return { code: 0, stdout: '{"runs":[', truncated: true };
      if (argv[1] === "rm") {
        cleanupRuns.push([...argv]);
        return { code: 0 };
      }
      return successfulSkillspector(argv);
    });

    const outcome = await runSkillspectorScanV1({
      run: detector,
      platform: "linux",
      env: {},
      tree: TREE,
      containerName: "aih-skillspector-fixed",
    });

    expect(cleanupRuns).toEqual([
      ["docker", "rm", "--force", "--volumes", "aih-skillspector-fixed"],
    ]);
    expect(outcome).toEqual({
      status: "failed",
      failure: { stage: "execution", detail: "detector exit 0" },
    });
  });

  it("appends a failed container cleanup to the failure detail", async () => {
    const detector = fakeRunner((argv) => {
      if (argv[0] !== "docker") return undefined;
      if (argv[1] === "run") return { code: 1, stderr: "process timed out", spawnError: true };
      if (argv[1] === "rm") return { code: 1, stderr: "No such container" };
      return successfulSkillspector(argv);
    });

    const outcome = await runSkillspectorScanV1({
      run: detector,
      platform: "linux",
      env: {},
      tree: TREE,
    });

    expect(outcome).toEqual({
      status: "failed",
      failure: {
        stage: "execution",
        detail: "process timed out; container cleanup failed: No such container",
      },
    });
  });

  it.each([
    [0, "", "output", "detector exit 0 emitted no SARIF"],
    [
      2,
      JSON.stringify(EMPTY_SARIF),
      "execution",
      `detector exit 2: ${JSON.stringify(EMPTY_SARIF)}`,
    ],
    [1, "not SARIF", "output", "detector did not emit valid SARIF"],
  ] as const)("rejects SkillSpector output outside the finding-exit SARIF contract (exit %i)", async (code, stdout, stage, expectedDetail) => {
    // Ported from Core scan.test.ts:1601-1636. The C2a engine emits the final
    // observation bytes, so the SARIF shape gate Core applied downstream
    // ("detector did not emit valid SARIF") is an output-stage failure here.
    const detector = fakeRunner((argv) => {
      if (argv[0] !== "docker") return undefined;
      if (argv[1] === "run") return { code, stdout };
      return successfulSkillspector(argv);
    });

    const outcome = await runSkillspectorScanV1({
      run: detector,
      platform: "linux",
      env: {},
      tree: TREE,
    });

    expect(outcome).toEqual({ status: "failed", failure: { stage, detail: expectedDetail } });
  });

  it("completes an empty tree with zero results (C2a §6.3)", async () => {
    const outcome = await runSkillspectorScanV1({
      run: fakeRunner(successfulSkillspector),
      platform: "linux",
      env: {},
      tree: TREE,
    });

    expect(outcome.status).toBe("succeeded");
    if (outcome.status !== "succeeded") return;
    expect(outcome.sarif.runs).toHaveLength(1);
    expect(JSON.parse(outcome.sarifText)).toEqual(EMPTY_SARIF);
    expect(Object.isFrozen(outcome.sarif)).toBe(true);
  });

  it("rewrites /scan/ artifact URIs source-relative and falls back unsafe ones (C2a §6.3)", async () => {
    const containerSarif = {
      version: "2.1.0",
      runs: [
        {
          results: [
            {
              ruleId: "sc4",
              locations: [
                { physicalLocation: { artifactLocation: { uri: "/scan/dist/bundle.js" } } },
              ],
            },
            {
              ruleId: "yr4",
              locations: [{ physicalLocation: { artifactLocation: { uri: "scan/SKILL.md" } } }],
            },
            {
              ruleId: "hostile",
              locations: [
                { physicalLocation: { artifactLocation: { uri: "/scan/../escape.md" } } },
              ],
            },
            {
              ruleId: "absolute",
              locations: [{ physicalLocation: { artifactLocation: { uri: "/etc/passwd" } } }],
            },
            { ruleId: "missing", locations: [{ physicalLocation: { artifactLocation: {} } }] },
          ],
        },
      ],
    };
    const detector = fakeRunner((argv) => {
      if (argv[0] !== "docker") return undefined;
      if (argv[1] === "run") return { code: 1, stdout: JSON.stringify(containerSarif) };
      return successfulSkillspector(argv);
    });

    const outcome = await runSkillspectorScanV1({
      run: detector,
      platform: "linux",
      env: {},
      tree: TREE,
    });

    expect(outcome.status).toBe("succeeded");
    if (outcome.status !== "succeeded") return;
    const uris = (
      outcome.sarif.runs[0] as {
        results: Array<{
          locations: Array<{ physicalLocation: { artifactLocation: { uri?: string } } }>;
        }>;
      }
    ).results.map((result) => result.locations[0]?.physicalLocation.artifactLocation.uri);
    expect(uris).toEqual([
      "dist/bundle.js",
      "SKILL.md",
      "skillspector.sarif",
      "skillspector.sarif",
      "skillspector.sarif",
    ]);
    expect(JSON.parse(outcome.sarifText).runs[0].results[0].locations[0]).toEqual({
      physicalLocation: { artifactLocation: { uri: "dist/bundle.js" } },
    });
  });
});

describe("parseSkillspectorSarifLogV1", () => {
  it("accepts a SARIF log with a runs array", () => {
    const parsed = parseSkillspectorSarifLogV1(
      JSON.stringify({ version: "2.1.0", runs: [{ results: [] }] }),
    );

    expect(parsed?.version).toBe("2.1.0");
    expect(parsed?.runs).toHaveLength(1);
    expect(Object.isFrozen(parsed)).toBe(true);
  });

  it.each([
    "not SARIF",
    JSON.stringify({}),
    JSON.stringify([]),
    JSON.stringify({ runs: {} }),
  ])("rejects output Core would classify as 'detector did not emit valid SARIF': %s", (raw) => {
    expect(parseSkillspectorSarifLogV1(raw)).toBeUndefined();
  });
});
