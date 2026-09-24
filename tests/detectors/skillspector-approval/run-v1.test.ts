import { describe, expect, it } from "vitest";
import {
  checkSkillspectorAvailableV1,
  parseSkillspectorSarifLogV1,
  resolveVerifiedSkillspectorImageV1,
  runSkillspectorScanV1,
  SKILLSPECTOR_IMAGE_DIGEST_V1,
  SKILLSPECTOR_IMAGE_TAG_V1,
  SKILLSPECTOR_SOURCE_REVISION_V1,
  type SkillspectorRunnerV1,
  type SkillspectorRunOptionsV1,
  type SkillspectorRunResultV1,
} from "../../../src/detectors/skillspector-approval/index.js";

/**
 * Ported from Core's `tests/trust/scan.test.ts` SkillSpector execution cases
 * (lines 1276-1454 and 1556-1636) plus the availability probe behaviour of
 * `resolveVerifiedSkillspectorImage`. Core asserted through its trust-scan
 * pipeline; here the identical fake-runner inputs drive the engine directly and
 * assert identical reasons, argv, timeouts and cleanup behaviour.
 */

const EMPTY_SARIF = { runs: [] };
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

describe("resolveVerifiedSkillspectorImageV1", () => {
  it("reports Docker unavailable on a spawn error, as Core does", async () => {
    const missing = fakeRunner((argv) =>
      argv[0] === "docker" ? { code: 127, stderr: "not found", spawnError: true } : undefined,
    );

    const result = await resolveVerifiedSkillspectorImageV1(missing, "linux", {}, 30_000);

    expect(result).toEqual({ reason: "Docker is unavailable (not found)" });
    expect(await checkSkillspectorAvailableV1(missing, "linux", {})).toBe(
      "Docker is unavailable (not found)",
    );
  });

  it("reports a failed docker --version with its exit summary", async () => {
    const failing = fakeRunner((argv) =>
      argv[0] === "docker" && argv[1] === "--version" ? { code: 1 } : undefined,
    );

    const result = await resolveVerifiedSkillspectorImageV1(failing, "linux", {}, 30_000);

    expect(result).toEqual({ reason: "docker --version failed (exit 1)" });
  });

  it("reports an uninspectable pinned image", async () => {
    const failing = fakeRunner((argv) => {
      if (argv[0] !== "docker") return undefined;
      if (argv[1] === "--version") return { code: 0, stdout: "Docker version 27\n" };
      if (argv[1] === "image" && argv[2] === "inspect") {
        return { code: 1, stderr: "Error: No such image" };
      }
      return undefined;
    });

    const result = await resolveVerifiedSkillspectorImageV1(failing, "linux", {}, 30_000);

    expect(result).toEqual({
      reason: `sandbox image ${SKILLSPECTOR_IMAGE_TAG_V1} could not be inspected (Error: No such image)`,
    });
  });

  it("rejects a self-labeled SkillSpector image whose digest is not allowlisted", async () => {
    // Ported from Core scan.test.ts:1307-1351. OCI labels are never consulted.
    const dockerRuns: string[][] = [];
    const detector = fakeRunner((argv) => {
      if (argv[0] !== "docker") return undefined;
      if (argv[1] === "--version") return { code: 0, stdout: "Docker version 27\n" };
      if (argv[1] === "image" && argv[2] === "inspect") {
        return {
          code: 0,
          stdout: JSON.stringify({
            Id: `sha256:${"b".repeat(64)}`,
            Config: {
              Labels: {
                "org.opencontainers.image.revision": SKILLSPECTOR_SOURCE_REVISION_V1,
              },
            },
          }),
        };
      }
      if (argv[1] === "run") {
        dockerRuns.push([...argv]);
        return { code: 0, stdout: JSON.stringify(EMPTY_SARIF) };
      }
      return undefined;
    });

    const result = await resolveVerifiedSkillspectorImageV1(detector, "linux", {}, 30_000);

    expect(result).toEqual({
      reason: `sandbox image ${SKILLSPECTOR_IMAGE_TAG_V1} could not verify expected image digest ${SKILLSPECTOR_IMAGE_DIGEST_V1}`,
    });
    expect(dockerRuns).toEqual([]);
  });

  it("names the org-policy approved local digest route when approvals exist", async () => {
    const detector = fakeRunner((argv) => {
      if (argv[0] !== "docker") return undefined;
      if (argv[1] === "--version") return { code: 0, stdout: "Docker version 27\n" };
      if (argv[1] === "image" && argv[2] === "inspect") {
        return { code: 0, stdout: JSON.stringify({ Id: `sha256:${"b".repeat(64)}` }) };
      }
      return undefined;
    });

    const result = await resolveVerifiedSkillspectorImageV1(detector, "linux", {}, 30_000, [
      {
        imageTag: SKILLSPECTOR_IMAGE_TAG_V1,
        imageDigest: `sha256:${"c".repeat(64)}`,
        sourceRevision: SKILLSPECTOR_SOURCE_REVISION_V1,
      },
    ]);

    expect(result).toEqual({
      reason: `sandbox image ${SKILLSPECTOR_IMAGE_TAG_V1} could not verify expected image digest ${SKILLSPECTOR_IMAGE_DIGEST_V1} or an org-policy approved local digest`,
    });
  });

  it("scrubs the probe environment and bounds the probe timeout", async () => {
    const seen: Array<{ argv: readonly string[]; options?: SkillspectorRunOptionsV1 }> = [];
    const detector: SkillspectorRunnerV1 = async (argv, options) => {
      seen.push({ argv, options });
      const result = successfulSkillspector(argv);
      if (result === undefined) throw new Error(`unexpected argv: ${argv.join(" ")}`);
      return { code: 0, stdout: "", stderr: "", ...result };
    };

    await resolveVerifiedSkillspectorImageV1(
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

    expect(outcome).toMatchObject({ ok: true, sarif: JSON.stringify(EMPTY_SARIF) });
    expect(seenDockerRuns).toHaveLength(1);
    expect(seenDockerTimeouts).toEqual([900_000]);
    expect(seenDockerRuns[0]).toContain(SKILLSPECTOR_IMAGE_DIGEST_V1);
    expect(seenDockerRuns[0]).not.toContain(SKILLSPECTOR_IMAGE_TAG_V1);
    expect(seenDockerRuns[0]).not.toContain("pull");
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

    expect(outcome).toMatchObject({ ok: true, image: ghcrRepoDigest });
    expect(seenDockerRuns[0]).toContain(ghcrRepoDigest);
  });

  it("accepts an org-policy approved local SkillSpector digest", async () => {
    // Ported from Core scan.test.ts:1353-1401.
    const approvedLocalDigest = `sha256:${"b".repeat(64)}`;
    const dockerRuns: string[][] = [];
    const detector = fakeRunner((argv) => {
      if (argv[0] !== "docker") return undefined;
      if (argv[1] === "--version") return { code: 0, stdout: "Docker version 27\n" };
      if (argv[1] === "image" && argv[2] === "inspect") {
        return {
          code: 0,
          stdout: JSON.stringify({
            Id: approvedLocalDigest,
            Config: {
              Labels: {
                "org.opencontainers.image.revision": SKILLSPECTOR_SOURCE_REVISION_V1,
              },
            },
          }),
        };
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
      approvedImages: [
        {
          imageTag: SKILLSPECTOR_IMAGE_TAG_V1,
          imageDigest: approvedLocalDigest,
          sourceRevision: SKILLSPECTOR_SOURCE_REVISION_V1,
        },
      ],
    });

    expect(outcome).toMatchObject({ ok: true, image: approvedLocalDigest });
    expect(dockerRuns).toHaveLength(1);
    expect(dockerRuns[0]).toContain(approvedLocalDigest);
  });

  it("rejects an org-policy approved local SkillSpector digest for another source revision", async () => {
    // Ported from Core scan.test.ts:1403-1454: no container ever runs.
    const approvedLocalDigest = `sha256:${"b".repeat(64)}`;
    const dockerRuns: string[][] = [];
    const detector = fakeRunner((argv) => {
      if (argv[0] !== "docker") return undefined;
      if (argv[1] === "--version") return { code: 0, stdout: "Docker version 27\n" };
      if (argv[1] === "image" && argv[2] === "inspect") {
        return { code: 0, stdout: JSON.stringify({ Id: approvedLocalDigest }) };
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
      approvedImages: [
        {
          imageTag: SKILLSPECTOR_IMAGE_TAG_V1,
          imageDigest: approvedLocalDigest,
          sourceRevision: "a".repeat(40),
        },
      ],
    });

    expect(outcome).toEqual({
      ok: false,
      failure: {
        stage: "availability",
        detail: `sandbox image ${SKILLSPECTOR_IMAGE_TAG_V1} could not verify expected image digest ${SKILLSPECTOR_IMAGE_DIGEST_V1} or an org-policy approved local digest`,
      },
    });
    expect(dockerRuns).toEqual([]);
  });

  it("force-removes the bounded SkillSpector container after a scanner timeout", async () => {
    // Ported from Core scan.test.ts:1556-1599.
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
      ok: false,
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
      ok: false,
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
      ok: false,
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
  ] as const)("rejects SkillSpector output outside the finding-exit SARIF contract (exit %i)", async (code, stdout, stage, expectedDetail) => {
    // Ported from Core scan.test.ts:1601-1636. Core's third case
    // (exit 1, "not SARIF") fails downstream SARIF parsing; here the run
    // returns the stdout and parseSkillspectorSarifLogV1 rejects it below.
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

    expect(outcome).toEqual({ ok: false, failure: { stage, detail: expectedDetail } });
  });

  it("returns finding-exit stdout verbatim; the SARIF shape gate rejects non-SARIF", async () => {
    const detector = fakeRunner((argv) => {
      if (argv[0] !== "docker") return undefined;
      if (argv[1] === "run") return { code: 1, stdout: "not SARIF" };
      return successfulSkillspector(argv);
    });

    const outcome = await runSkillspectorScanV1({
      run: detector,
      platform: "linux",
      env: {},
      tree: TREE,
    });

    expect(outcome).toMatchObject({ ok: true, sarif: "not SARIF" });
    if (outcome.ok) expect(parseSkillspectorSarifLogV1(outcome.sarif)).toBeUndefined();
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
