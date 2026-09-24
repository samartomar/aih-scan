import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  type DetectorExecutionProfileV1,
  IN_PROCESS_BINDING_GATE_PROFILE_V1,
  IN_PROCESS_TRUST_LINT_PROFILE_V1,
  listDetectorCapabilitiesV1,
  resolveDetectorCapabilityV1,
  resolveDetectorExecutionProfileDocumentV1,
  snykAgentScanPlatformSupportV1,
} from "../../src/capability/detector-capability-v1.js";

/**
 * Phase B2 registration (C2 / C2a §1.2, §3.1, §3.7, §4, §5, §6, §8.1): the detectors Core
 * delegates are all registered, every uv-backed profile publishes its analyzer lock, and
 * each profile states isolation and network truthfully.
 */

const packageRoot = join(import.meta.dirname, "..", "..");
const lockSha256 = (path: string) =>
  createHash("sha256")
    .update(readFileSync(join(packageRoot, ...path.split("/"))))
    .digest("hex");
const platforms = (profile: DetectorExecutionProfileV1 | undefined) =>
  profile?.supportedPlatforms.map((entry) => `${entry.os}/${entry.architecture}`);
const profileOf = (detectorId: string, profileId: string) =>
  resolveDetectorCapabilityV1(detectorId)?.executionProfiles.find(
    (entry) => entry.id === profileId,
  );
const EVERY_PLATFORM = [
  "darwin/amd64",
  "darwin/arm64",
  "linux/amd64",
  "linux/arm64",
  "windows/amd64",
  "windows/arm64",
];
// snyk-agent-scan 0.6.4 guards its POSIX-only pwd imports and its lock installs build-free
// on these hosts; macOS amd64 and Windows arm64 lack a cryptography 50.0.0 wheel.
const SNYK_HOST_PLATFORMS = ["darwin/arm64", "linux/amd64", "linux/arm64", "windows/amd64"];

describe("B2 detector registration", () => {
  it("registers every detector Core delegates, in canonical order", () => {
    expect(listDetectorCapabilitiesV1().map((entry) => entry.detectorId)).toEqual([
      "detector.aih-binding-gate",
      "detector.aih-native",
      "detector.aih-trust-lint",
      "detector.cisco",
      "detector.cisco-mcp-scanner",
      "detector.semgrep",
      "detector.skillspector",
      "detector.snyk-agent-scan",
    ]);
  });

  it("registers the in-process trust lint and binding gate on every platform, spawning nothing", () => {
    for (const [detectorId, profile, driver] of [
      ["detector.aih-trust-lint", IN_PROCESS_TRUST_LINT_PROFILE_V1, "aih-trust-lint"],
      ["detector.aih-binding-gate", IN_PROCESS_BINDING_GATE_PROFILE_V1, "aih-binding-gate"],
    ] as const) {
      const capability = resolveDetectorCapabilityV1(detectorId);
      expect(capability, detectorId).toMatchObject({
        backend: "in-process",
        subjectKinds: ["source-tree"],
        emptySource: "completes",
        outputs: ["sarif-2.1.0"],
        analyzerIdentity: `${driver}@1.0.0`,
        analyzerVersion: "1.0.0",
      });
      expect(capability?.executionProfile).toEqual(profile);
      expect(capability?.executionProfiles).toEqual([profile]);
      expect(platforms(capability?.executionProfile)).toEqual(EVERY_PLATFORM);
      expect(capability?.executionProfile.analyzerLock).toBeUndefined();
      const notes = resolveDetectorExecutionProfileDocumentV1(profile.id)?.notes.join(" ") ?? "";
      // Synchronous in-process analysis cannot be preempted; the profile says what is true.
      expect(notes, detectorId).toMatch(/checked before the analysis starts and again before/);
      expect(notes, detectorId).toMatch(/source seal is taken before and after/);
    }
  });

  it("accepts a source-tree subject for detector.cisco, planned as one job per selected SKILL.md directory", () => {
    const cisco = resolveDetectorCapabilityV1("detector.cisco");
    expect(cisco?.subjectKinds).toEqual(["skill-directory", "source-tree"]);
    expect(cisco?.subjectRequirements.join(" ")).toMatch(
      /source-tree subject runs one skill-scanner job per directory holding a selected SKILL\.md/,
    );
    expect(cisco?.subjectRequirements.join(" ")).toMatch(/only under host-process-uv-v1/);
  });

  it("registers detector.cisco-mcp-scanner under host-process-uv-v1 where its lock installs build-free", () => {
    const capability = resolveDetectorCapabilityV1("detector.cisco-mcp-scanner");
    expect(capability).toMatchObject({
      backend: "host-process-uv",
      analyzerIdentity: null,
      analyzerVersion: "4.8.4",
      subjectKinds: ["source-tree"],
      emptySource: "refused",
      outputs: ["sarif-2.1.0"],
    });
    expect(capability?.executionProfiles.map((entry) => entry.id)).toEqual(["host-process-uv-v1"]);
    const host = capability?.executionProfile;
    expect(host).toMatchObject({ isolation: "none", network: "unenforced" });
    // litellm 1.93.0 publishes manylinux wheels only (C2a §4.4): Linux alone installs build-free.
    expect(platforms(host)).toEqual(["linux/amd64", "linux/arm64"]);
    expect(host?.prerequisites.map((entry) => `${entry.kind}:${entry.id}`)).toEqual([
      "host-executable:uv",
      "uv-python:3.12",
      "bundled-asset:tools/baseline-analyzers/cisco-mcp-scanner/uv.lock",
      "network:https://pypi.org/simple",
    ]);
  });

  it("derives the snyk-agent-scan platform set from the pinned analyzer version", () => {
    const capability = resolveDetectorCapabilityV1("detector.snyk-agent-scan");
    const profile = capability?.executionProfiles[0];
    expect(capability?.analyzerVersion).toBe("0.6.4");
    // 0.6.4 guards its pwd imports (agents/base.py, and utils.py only under
    // --scan-all-users on Linux or macOS); U1c ran help and a real scan on Windows.
    expect(platforms(profile)).toEqual(SNYK_HOST_PLATFORMS);
    const notes = resolveDetectorExecutionProfileDocumentV1("host-process-uv-v1")?.notes ?? [];
    expect(notes.join(" ")).not.toMatch(/pwd/);
    expect(notes).toContainEqual(
      "detector.snyk-agent-scan 0.6.4 runs on Linux amd64 and arm64, macOS arm64 and Windows amd64; macOS amd64 and Windows arm64 lack an exact-pinned cryptography 50.0.0 wheel, which Scan never builds from source.",
    );
    // The platform set belongs to the version: 0.5.17 imports pwd unconditionally on its
    // scan path, and a version without recorded evidence has no platform set at all.
    const legacy = snykAgentScanPlatformSupportV1("0.5.17");
    expect(legacy.platforms.map((entry) => `${entry.os}/${entry.architecture}`)).toEqual([
      "darwin/arm64",
      "linux/amd64",
      "linux/arm64",
    ]);
    expect(legacy.refusal).toMatch(/0\.5\.17 imports Python's POSIX-only pwd module/);
    expect(() => snykAgentScanPlatformSupportV1("0.6.5")).toThrow(
      /no recorded platform evidence for snyk-agent-scan 0\.6\.5/,
    );
  });

  it("registers detector.snyk-agent-scan with SNYK_TOKEN as a required prerequisite", () => {
    const capability = resolveDetectorCapabilityV1("detector.snyk-agent-scan");
    expect(capability).toMatchObject({
      backend: "host-process-uv",
      analyzerIdentity: null,
      analyzerVersion: "0.6.4",
      subjectKinds: ["source-tree"],
      emptySource: "completes",
      outputs: ["sarif-2.1.0"],
    });
    expect(capability?.executionProfiles.map((entry) => entry.id)).toEqual(["host-process-uv-v1"]);
    const host = capability?.executionProfile;
    expect(platforms(host)).toEqual(SNYK_HOST_PLATFORMS);
    expect(
      host?.prerequisites.map((entry) => `${entry.kind}:${entry.id}:${entry.required}`),
    ).toEqual([
      "host-executable:uv:true",
      "uv-python:3.12:true",
      "bundled-asset:tools/baseline-analyzers/snyk-agent-scan/uv.lock:true",
      "network:https://pypi.org/simple:true",
      "environment-variable:SNYK_TOKEN:true",
    ]);
    const token = host?.prerequisites.find((entry) => entry.kind === "environment-variable");
    expect(token?.detail).toMatch(/request env/);
  });

  it("publishes analyzerLock { path, sha256 } on every uv-backed profile, equal to the bundled lock", () => {
    const expected: Record<string, Record<string, string>> = {
      "detector.cisco": {
        "linux-namespace-uv-v1": "tools/baseline-analyzers/cisco-skill-scanner/uv.lock",
        "host-process-uv-v1": "tools/baseline-analyzers/cisco-skill-scanner/uv.lock",
      },
      "detector.semgrep": {
        "linux-namespace-uv-v1": "tools/baseline-analyzers/semgrep/uv.lock",
        "host-process-uv-v1": "tools/baseline-analyzers/semgrep/uv.lock",
      },
      "detector.cisco-mcp-scanner": {
        "host-process-uv-v1": "tools/baseline-analyzers/cisco-mcp-scanner/uv.lock",
      },
      "detector.snyk-agent-scan": {
        "host-process-uv-v1": "tools/baseline-analyzers/snyk-agent-scan/uv.lock",
      },
    };
    for (const capability of listDetectorCapabilitiesV1()) {
      for (const profile of capability.executionProfiles) {
        const path = expected[capability.detectorId]?.[profile.id];
        if (path === undefined) {
          expect(profile.analyzerLock, `${capability.detectorId} ${profile.id}`).toBeUndefined();
          continue;
        }
        expect(profile.analyzerLock, `${capability.detectorId} ${profile.id}`).toEqual({
          path,
          sha256: lockSha256(path),
        });
      }
    }
    // Since skill-scanner 2.1.0 the namespace and host Cisco profiles share one lock.
    expect(profileOf("detector.cisco", "linux-namespace-uv-v1")?.analyzerLock?.sha256).toBe(
      profileOf("detector.cisco", "host-process-uv-v1")?.analyzerLock?.sha256,
    );
  });

  it("states truthfully in the host profile document which detectors run under it and what reaches the network", () => {
    const notes = resolveDetectorExecutionProfileDocumentV1("host-process-uv-v1")?.notes.join(" ");
    expect(notes).toMatch(/detector\.cisco-mcp-scanner.+Linux amd64 and arm64 only/);
    expect(notes).toMatch(/litellm 1\.93\.0/);
    expect(notes).toMatch(/snyk-agent-scan contacts Snyk's service during the scan stage/);
    expect(notes).toMatch(/SNYK_TOKEN reaches only the scan invocation/);
    expect(notes).toMatch(/one skill-scanner scan job per directory/);
    expect(notes).toMatch(/at most detectorOptions\.concurrency/);
  });

  it("keeps SkillSpector's never-pull local profile beside its hardened default", () => {
    const local = profileOf("detector.skillspector", "docker-host-local-skillspector-v1");
    expect(local).toMatchObject({ isolation: "container", network: "none" });
    expect(local?.analyzerLock).toBeUndefined();
    expect(
      resolveDetectorExecutionProfileDocumentV1("docker-host-local-skillspector-v1")?.containment,
    ).toEqual(expect.arrayContaining(["--pull", "never", "--network", "none"]));
  });
});
