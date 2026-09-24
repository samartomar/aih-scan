import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { listDetectorCapabilitiesV1 } from "../../src/capability/detector-capability-v1.js";
import { probeDetectorAvailabilityV1 } from "../../src/runner/run-detector-v1.js";

/**
 * C2a §3.8 for every detector and profile this build registers: the probe answers from the
 * profile, the platform and the prerequisites alone. It takes no subject and never scans,
 * pulls or executes anything: the fake uv and docker below record any execution.
 */

const windows = process.platform === "win32";
const roots: string[] = [];
const TOKEN = "probe-token-value-never-echoed";

afterEach(() => {
  vi.unstubAllEnvs();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

/** A PATH holding a uv and a docker that write a marker if anything ever runs them. */
function trapHost() {
  const root = mkdtempSync(join(tmpdir(), "aih-scan-probe-"));
  roots.push(root);
  const bin = join(root, "bin");
  mkdirSync(bin);
  const marker = join(root, "executed");
  for (const name of ["uv", "docker"]) {
    const file = join(bin, windows ? `${name}.exe` : name);
    writeFileSync(file, windows ? "not a program\n" : `#!/bin/sh\necho "$0" >> '${marker}'\n`);
    if (!windows) chmodSync(file, 0o755);
  }
  return { bin, marker };
}

const hostKey = () => {
  const os = windows ? "windows" : process.platform === "darwin" ? "darwin" : "linux";
  const architecture = process.arch === "x64" ? "amd64" : process.arch;
  return `${os}/${architecture}`;
};

const pairs = listDetectorCapabilitiesV1().flatMap((capability) =>
  capability.executionProfiles.map((profile) => ({ capability, profile })),
);

describe("probeDetectorAvailabilityV1 over every registered detector and profile", () => {
  it("registers the B2 detectors", () => {
    expect(
      pairs.map(({ capability, profile }) => `${capability.detectorId} ${profile.id}`),
    ).toEqual(
      expect.arrayContaining([
        "detector.aih-trust-lint in-process-trust-lint-v1",
        "detector.aih-binding-gate in-process-binding-gate-v1",
        "detector.cisco-mcp-scanner host-process-uv-v1",
        "detector.snyk-agent-scan host-process-uv-v1",
        "detector.cisco host-process-uv-v1",
      ]),
    );
  });

  it.each(
    pairs.map(({ capability, profile }) => [
      capability.detectorId,
      profile.id,
      capability,
      profile,
    ]),
  )("%s under %s: a typed answer, and nothing executed", async (detectorId, profileId, _c, profile) => {
    const trap = trapHost();
    vi.stubEnv("PATH", trap.bin);
    const env =
      detectorId === "detector.snyk-agent-scan" ? { SNYK_TOKEN: TOKEN } : { PATH: trap.bin };

    const answer = await probeDetectorAvailabilityV1({
      detectorId,
      executionProfileId: profileId,
      env,
    });

    const supported = profile.supportedPlatforms.some(
      (entry) => `${entry.os}/${entry.architecture}` === hostKey(),
    );
    if (!supported) {
      expect(answer).toMatchObject({ available: false, reason: "unsupported-platform" });
    } else if (profile.prerequisites.some((entry) => entry.kind === "executable")) {
      // Absolute executables (/usr/bin/bwrap, /usr/bin/docker) depend on this host.
      expect(
        answer.available || (!answer.available && answer.reason === "prerequisite-missing"),
      ).toBe(true);
    } else {
      expect(answer).toMatchObject({ available: true, executionProfile: { id: profileId } });
      if (!answer.available) return;
      // An image, a Python and an index are settled only by a run.
      for (const [index, state] of answer.prerequisites.entries()) {
        const kind = profile.prerequisites[index]?.kind;
        if (kind === "container-image" || kind === "uv-python" || kind === "network")
          expect(state.state).toBe("not-probed");
        else expect(state.state).toBe("present");
      }
    }
    expect(JSON.stringify(answer)).not.toContain(TOKEN);
    expect(existsSync(trap.marker)).toBe(false);
  });

  it.each([
    ["detector.aih-trust-lint", "in-process-trust-lint-v1"],
    ["detector.aih-binding-gate", "in-process-binding-gate-v1"],
  ])("answers %s available with no prerequisites and no environment", async (detectorId, id) => {
    const answer = await probeDetectorAvailabilityV1({
      detectorId,
      executionProfileId: id,
      env: {},
    });
    expect(answer).toMatchObject({
      available: true,
      analyzerVersion: "1.0.0",
      executionProfile: { id },
      prerequisites: [],
    });
  });

  it("answers cisco-mcp-scanner by its Linux-only lock", async () => {
    const trap = trapHost();
    const answer = await probeDetectorAvailabilityV1({
      detectorId: "detector.cisco-mcp-scanner",
      executionProfileId: "host-process-uv-v1",
      env: { PATH: trap.bin },
    });
    if (process.platform === "linux") expect(answer.available).toBe(true);
    else {
      expect(answer).toMatchObject({ available: false, reason: "unsupported-platform" });
      expect(!answer.available && answer.detail).toMatch(/litellm 1\.93\.0/);
    }
  });
});

describe("the Snyk probe reads env as runDetectorV1 does: the request env of SNYK_TOKEN alone", () => {
  const snykSupported = () =>
    listDetectorCapabilitiesV1()
      .find((capability) => capability.detectorId === "detector.snyk-agent-scan")
      ?.executionProfiles[0]?.supportedPlatforms.some(
        (entry) => `${entry.os}/${entry.architecture}` === hostKey(),
      ) ?? false;
  const probe = (env: unknown) =>
    probeDetectorAvailabilityV1({
      detectorId: "detector.snyk-agent-scan",
      executionProfileId: "host-process-uv-v1",
      env,
    });

  it("finds uv on the host environment and the token in the request env", async () => {
    if (!snykSupported()) return;
    vi.stubEnv("PATH", trapHost().bin);
    const answer = await probe({ SNYK_TOKEN: TOKEN });
    expect(answer.available).toBe(true);
    if (!answer.available) return;
    expect(answer.prerequisites).toContainEqual(
      expect.objectContaining({ kind: "environment-variable", id: "SNYK_TOKEN", state: "present" }),
    );
    expect(JSON.stringify(answer)).not.toContain(TOKEN);
  });

  it.each([
    ["no env", undefined],
    ["an empty env", {}],
    ["a blank token", { SNYK_TOKEN: "   " }],
  ])("answers prerequisite-missing for %s, naming the variable", async (_label, env) => {
    if (!snykSupported()) return;
    vi.stubEnv("PATH", trapHost().bin);
    const answer = await probe(env);
    expect(answer).toMatchObject({ available: false, reason: "prerequisite-missing" });
    expect(!answer.available && answer.detail).toMatch(/SNYK_TOKEN/);
  });

  it("refuses any other variable in env, as a run would", async () => {
    if (!snykSupported()) return;
    const answer = await probe({ SNYK_TOKEN: TOKEN, PATH: "/usr/bin" });
    expect(answer).toMatchObject({ available: false, reason: "detector-options-invalid" });
    expect(JSON.stringify(answer)).not.toContain(TOKEN);
  });
});
