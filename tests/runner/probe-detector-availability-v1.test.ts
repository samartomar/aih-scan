import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { resolveDetectorCapabilityV1 } from "../../src/capability/detector-capability-v1.js";
import { probeDetectorAvailabilityV1 } from "../../src/index.js";

/**
 * C2a §3.8, decision 4: probe a detector under a named profile without a subject and without
 * executing anything, with the same gates and refusal reasons as runDetectorV1.
 */

const directories: string[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  for (const directory of directories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});
function emptyDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "aih-scan-probe-"));
  directories.push(directory);
  return directory;
}
function mockHost(os: NodeJS.Platform, architecture: string): void {
  vi.spyOn(process, "platform", "get").mockReturnValue(os);
  vi.spyOn(process, "arch", "get").mockReturnValue(architecture as NodeJS.Architecture);
}

describe("probeDetectorAvailabilityV1", () => {
  it("reports available with the analyzer version, the named profile and every prerequisite state", async () => {
    mockHost("linux", "x64");
    const result = await probeDetectorAvailabilityV1({
      detectorId: "detector.semgrep",
      executionProfileId: "host-process-uv-v1",
      prerequisiteProbe: () => "present",
    });
    expect(result.available).toBe(true);
    if (!result.available) return;
    const capability = resolveDetectorCapabilityV1("detector.semgrep");
    expect(result.analyzerVersion).toBe(capability?.analyzerVersion);
    expect(result.executionProfile.id).toBe("host-process-uv-v1");
    expect(result.prerequisites.map((entry) => entry.state)).toEqual([
      "present",
      "present",
      "present",
      "present",
    ]);
    expect(result.seams.prerequisiteProbe).toBe("caller-supplied");
  });

  it("refuses a missing host uv with runDetectorV1's reason and detail", async () => {
    const empty = emptyDirectory();
    const result = await probeDetectorAvailabilityV1({
      detectorId: "detector.semgrep",
      executionProfileId: "host-process-uv-v1",
      env:
        process.platform === "win32"
          ? { PATH: empty, USERPROFILE: empty, LOCALAPPDATA: empty, ProgramFiles: empty }
          : { PATH: empty, HOME: empty },
    });
    expect(result).toMatchObject({ available: false, reason: "prerequisite-missing" });
    if (result.available) return;
    expect(result.detail).toContain("host-executable uv");
  });

  it("refuses an unknown detector, an absent or unknown profile and a foreign platform", async () => {
    mockHost("win32", "x64");
    expect(
      await probeDetectorAvailabilityV1({ detectorId: "detector.nope", executionProfileId: "x" }),
    ).toMatchObject({ available: false, reason: "unknown-detector" });
    expect(await probeDetectorAvailabilityV1({ detectorId: "detector.semgrep" })).toMatchObject({
      available: false,
      reason: "execution-profile-unavailable",
    });
    expect(
      await probeDetectorAvailabilityV1({
        detectorId: "detector.semgrep",
        executionProfileId: "docker-host-local-skillspector-v1",
      }),
    ).toMatchObject({ available: false, reason: "execution-profile-unavailable" });
    expect(
      await probeDetectorAvailabilityV1({
        detectorId: "detector.semgrep",
        executionProfileId: "linux-namespace-uv-v1",
        prerequisiteProbe: () => "present",
      }),
    ).toMatchObject({ available: false, reason: "unsupported-platform" });
  });

  it("validates acceptedImageDigests exactly as runDetectorV1 does", async () => {
    mockHost("linux", "x64");
    const digest = `sha256:${"a".repeat(64)}`;
    expect(
      await probeDetectorAvailabilityV1({
        detectorId: "detector.semgrep",
        executionProfileId: "host-process-uv-v1",
        acceptedImageDigests: [digest],
      }),
    ).toMatchObject({ available: false, reason: "execution-profile-unavailable" });
    expect(
      await probeDetectorAvailabilityV1({
        detectorId: "detector.skillspector",
        executionProfileId: "docker-host-local-skillspector-v1",
        acceptedImageDigests: ["sha256:nope"],
      }),
    ).toMatchObject({ available: false, reason: "execution-profile-unavailable" });
    const accepted = await probeDetectorAvailabilityV1({
      detectorId: "detector.skillspector",
      executionProfileId: "docker-host-local-skillspector-v1",
      acceptedImageDigests: [digest],
      prerequisiteProbe: (prerequisite: { kind: string }) =>
        prerequisite.kind === "container-image" ? "not-probed" : "present",
    });
    expect(accepted.available).toBe(true);
    if (!accepted.available) return;
    expect(accepted.prerequisites.map((entry) => `${entry.kind}:${entry.state}`)).toEqual([
      "host-executable:present",
      "container-image:not-probed",
    ]);
  });

  it("fails availability for an aborted signal or a probe that throws, and never rejects", async () => {
    mockHost("linux", "x64");
    const controller = new AbortController();
    controller.abort();
    expect(
      await probeDetectorAvailabilityV1({
        detectorId: "detector.semgrep",
        executionProfileId: "host-process-uv-v1",
        signal: controller.signal,
        prerequisiteProbe: () => "present",
      }),
    ).toMatchObject({ available: false, reason: "availability-failed" });
    expect(
      await probeDetectorAvailabilityV1({
        detectorId: "detector.semgrep",
        executionProfileId: "host-process-uv-v1",
        prerequisiteProbe: () => {
          throw new Error("probe broke");
        },
      }),
    ).toMatchObject({ available: false, reason: "availability-failed" });
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();
    expect(await probeDetectorAvailabilityV1(proxy)).toMatchObject({
      available: false,
      reason: "unknown-detector",
    });
    expect(await probeDetectorAvailabilityV1(null)).toMatchObject({ available: false });
  });
});
