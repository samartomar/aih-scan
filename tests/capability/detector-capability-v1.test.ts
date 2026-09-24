import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  BASELINE_ENVIRONMENT_ALLOW_LIST_V1,
  type BaselineProcessRunnerV1,
  CISCO_SKILL_SCANNER_VERSION_V1,
  createBaselineAnalyzerRunV1,
  HOST_DOCKER_CONTEXT_VARIABLES_V1,
  HOST_DOCKER_ENVIRONMENT_V1,
  HOST_PROCESS_UV_DISCOVERY_VARIABLES_V1,
  HOST_PROCESS_UV_ENVIRONMENT_V1,
  SEMGREP_VERSION_V1,
  SKILLSPECTOR_IMAGE_DIGEST_V1,
  SKILLSPECTOR_IMAGE_V1,
  SKILLSPECTOR_LOCAL_IMAGE_TAG_V1,
} from "../../src/baseline/runtime-v1.js";
import {
  IN_PROCESS_BINDING_GATE_PROFILE_V1,
  IN_PROCESS_TRUST_LINT_PROFILE_V1,
  listDetectorCapabilitiesV1,
  listDetectorExecutionProfileDocumentsV1,
  resolveDetectorCapabilityV1,
  resolveDetectorExecutionProfileDocumentV1,
} from "../../src/capability/detector-capability-v1.js";
import {
  BASELINE_BWRAP_EXECUTABLE_V1,
  BASELINE_UV_EXECUTABLE_V1,
} from "../../src/cli/process-runner.js";
import {
  canonicalStrictJsonBytesV1,
  canonicalStrictJsonSha256V1,
} from "../../src/contract/strict-json-v1.js";

const temporaryDirectories: string[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  for (const directory of temporaryDirectories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

function sourceFixture(): string {
  const root = mkdtempSync(join(tmpdir(), "aih-scan-capability-"));
  temporaryDirectories.push(root);
  mkdirSync(join(root, "skills", "demo"), { recursive: true });
  writeFileSync(join(root, "skills", "demo", "SKILL.md"), "# Demo\n", "utf8");
  return root;
}

const sarif = (name: string) =>
  canonicalStrictJsonBytesV1({
    version: "2.1.0",
    runs: [
      { tool: { driver: { name } }, results: [], invocations: [{ executionSuccessful: true }] },
    ],
  }).toString("utf8");

describe("DetectorCapabilityV1", () => {
  it("publishes a frozen, canonical, digest-stable capability for each Scan-owned detector", () => {
    const capabilities = listDetectorCapabilitiesV1();

    expect(capabilities.map((entry) => entry.detectorId)).toEqual([
      "detector.aih-binding-gate",
      "detector.aih-native",
      "detector.aih-trust-lint",
      "detector.cisco",
      "detector.cisco-mcp-scanner",
      "detector.semgrep",
      "detector.skillspector",
      "detector.snyk-agent-scan",
    ]);
    expect(listDetectorCapabilitiesV1()).toBe(capabilities);
    for (const capability of capabilities) {
      expect(Object.isFrozen(capability)).toBe(true);
      expect(Object.isFrozen(capability.executionProfiles)).toBe(true);
      const { capabilitySha256, ...authoring } = capability;
      expect(capabilitySha256).toBe(
        canonicalStrictJsonSha256V1({
          domain: "aih.detector-capability-v1",
          capability: authoring,
        }),
      );
      expect(capability.executionProfiles[0]).toEqual(capability.executionProfile);
      expect(capability.contracts.findingsProtocol).toBe("ScanFindingsV1");
    }
  });

  it("binds every execution profile digest to a readable document this package publishes", () => {
    for (const capability of listDetectorCapabilitiesV1()) {
      for (const profile of capability.executionProfiles) {
        const document = resolveDetectorExecutionProfileDocumentV1(profile.id);
        expect(document, profile.id).toBeDefined();
        expect(canonicalStrictJsonSha256V1(document)).toBe(profile.sha256);
        expect(document?.isolation).toBe(profile.isolation);
        expect(document?.network).toBe(profile.network);
      }
    }
    expect(resolveDetectorExecutionProfileDocumentV1("no-such-profile")).toBeUndefined();
    expect(resolveDetectorCapabilityV1("detector.mcp-scanner")).toBeUndefined();
    expect(resolveDetectorCapabilityV1(42)).toBeUndefined();
  });

  it("states honestly that only in-process analyzers and host-only detectors default off Linux amd64", () => {
    for (const capability of listDetectorCapabilitiesV1()) {
      const platforms = capability.supportedPlatforms.map(
        (entry) => `${entry.os}/${entry.architecture}`,
      );
      if (capability.backend === "in-process") {
        expect(platforms).toContain("windows/amd64");
        expect(capability.executionProfile.isolation).toBe("none");
        expect(capability.prerequisites).toEqual([]);
      } else if (capability.backend === "host-process-uv") {
        // The host profile is these detectors' only profile; it still runs only when named.
        expect(capability.executionProfiles.map((entry) => entry.id)).toEqual([
          "host-process-uv-v1",
        ]);
        expect(capability.executionProfile.isolation).toBe("none");
        expect(capability.prerequisites.length).toBeGreaterThan(0);
      } else {
        expect(platforms).toEqual(["linux/amd64"]);
        expect(capability.prerequisites.length).toBeGreaterThan(0);
      }
    }
  });

  it("names the analyzer identity only where Scan mints one", () => {
    const native = resolveDetectorCapabilityV1("detector.aih-native");
    expect(native?.analyzerIdentity).toMatch(/^native\.[0-9a-f]{12}$/);
    expect(resolveDetectorCapabilityV1("detector.cisco")?.analyzerIdentity).toBeNull();
    expect(resolveDetectorCapabilityV1("detector.semgrep")?.analyzerVersion).toBe(
      SEMGREP_VERSION_V1,
    );
    expect(resolveDetectorCapabilityV1("detector.cisco")?.analyzerVersion).toBe(
      CISCO_SKILL_SCANNER_VERSION_V1,
    );
    expect(resolveDetectorCapabilityV1("detector.skillspector")?.analyzerVersion).toContain(
      SKILLSPECTOR_IMAGE_DIGEST_V1,
    );
  });

  it("documents the containment the analyzer profiles actually apply", async () => {
    // The hardened profiles run absolute Linux executables, so this declares a Linux host.
    vi.spyOn(process, "platform", "get").mockReturnValue("linux");
    const calls: string[][] = [];
    const runner: BaselineProcessRunnerV1 = async (argv) => {
      calls.push([...argv]);
      if (argv.includes("version")) return okay("Docker version 28");
      if (argv.includes("inspect"))
        return okay(JSON.stringify({ Id: SKILLSPECTOR_IMAGE_DIGEST_V1, RepoDigests: [] }));
      if (argv.includes("run")) return okay(sarif("skillspector"));
      if (argv.includes("sync")) return okay("");
      if (argv.at(-1) === "--version") return okay(SEMGREP_VERSION_V1);
      if (argv.includes("--sarif")) return okay(sarif("semgrep"));
      throw new Error(`unexpected argv: ${argv.join(" ")}`);
    };
    const okay = (stdout: string) => ({ code: 0, stdout, stderr: "", truncated: false });
    const run = createBaselineAnalyzerRunV1({ runner, env: { PATH: "C:\\tools" } });
    const sourceRoot = sourceFixture();

    await run({ analyzer: "semgrep", sourceRoot });
    const namespaceArgv = calls.filter((argv) => argv.includes("--unshare-all")).flat();
    const namespaceDocument = resolveDetectorExecutionProfileDocumentV1("linux-namespace-uv-v1");
    for (const flag of namespaceDocument?.containment ?? [])
      expect(namespaceArgv, flag).toContain(flag);
    for (const flag of namespaceDocument?.acquisition ?? [])
      expect(
        calls.find((argv) => argv.includes("sync")),
        flag,
      ).toContain(flag);
    for (const executable of namespaceDocument?.executables ?? [])
      expect(namespaceArgv, executable).toContain(executable);

    calls.length = 0;
    await run({ analyzer: "skillspector", sourceRoot });
    const dockerArgv = calls.find((argv) => argv.includes("run")) ?? [];
    const dockerDocument = resolveDetectorExecutionProfileDocumentV1(
      "docker-hardened-skillspector-v1",
    );
    for (const flag of dockerDocument?.containment ?? []) expect(dockerArgv, flag).toContain(flag);
    expect(dockerDocument?.image).toBe(SKILLSPECTOR_IMAGE_V1);
    expect(dockerArgv).toContain(SKILLSPECTOR_IMAGE_DIGEST_V1);
  });

  it("publishes no profile document that claims isolation it does not apply", () => {
    const documents = listDetectorExecutionProfileDocumentsV1();
    expect(documents.map((entry) => entry.id).sort()).toEqual([
      "docker-hardened-skillspector-v1",
      "docker-host-local-skillspector-v1",
      "host-process-uv-v1",
      "in-process-binding-gate-v1",
      "in-process-native-v1",
      "in-process-trust-lint-v1",
      "linux-namespace-uv-v1",
      "oci-hardened-cisco-v1",
    ]);
    const inProcess = resolveDetectorExecutionProfileDocumentV1("in-process-native-v1");
    expect(inProcess?.executables).toEqual([]);
    expect(inProcess?.containment).toEqual([]);
    expect(inProcess?.notes.join(" ")).toContain("spawns nothing");
    for (const id of ["in-process-trust-lint-v1", "in-process-binding-gate-v1"]) {
      const document = resolveDetectorExecutionProfileDocumentV1(id);
      expect(document, id).toMatchObject({
        isolation: "none",
        network: "none",
        backend: "in-process",
        executables: [],
        image: null,
        containment: [],
        acquisition: [],
        mounts: [],
      });
      expect(document?.notes.join(" "), id).toContain("spawns nothing");
    }
    // The host profiles fix every spawn's whole environment per OS; the others keep their
    // unchanged allow-list-scrub rule.
    for (const document of documents) {
      if (
        document.id === "host-process-uv-v1" ||
        document.id === "docker-host-local-skillspector-v1"
      ) {
        expect(document.environment.policy, document.id).toBe("fixed-values-by-os");
        continue;
      }
      expect(document.environment, document.id).toEqual({
        policy: "allow-list-scrub",
        allowed: BASELINE_ENVIRONMENT_ALLOW_LIST_V1,
      });
    }
  });

  it("publishes host-process-uv-v1 as an explicit, truthfully unisolated profile for Semgrep and Cisco", () => {
    const semgrep = resolveDetectorCapabilityV1("detector.semgrep");
    expect(semgrep?.backend).toBe("linux-namespace-uv");
    expect(semgrep?.executionProfile.id).toBe("linux-namespace-uv-v1");
    expect(semgrep?.executionProfiles.map((entry) => entry.id)).toEqual([
      "linux-namespace-uv-v1",
      "host-process-uv-v1",
    ]);
    expect(
      resolveDetectorCapabilityV1("detector.cisco")?.executionProfiles.map((entry) => entry.id),
    ).toEqual(["linux-namespace-uv-v1", "host-process-uv-v1", "oci-hardened-cisco-v1"]);
    const host = semgrep?.executionProfiles.find((entry) => entry.id === "host-process-uv-v1");
    expect(host).toMatchObject({
      isolation: "none",
      network: "unenforced",
      evidence: "BaselineAnalyzerObservationV1",
    });

    const document = resolveDetectorExecutionProfileDocumentV1("host-process-uv-v1");
    const namespace = resolveDetectorExecutionProfileDocumentV1("linux-namespace-uv-v1");
    expect(document).toMatchObject({
      backend: "host-process-uv",
      isolation: "none",
      network: "unenforced",
      image: null,
      mounts: [],
    });
    expect(document?.executables.join(" ")).toMatch(
      /uv \(uv\.exe on Windows\) on the declared PATH/,
    );
    expect(document?.executables.join(" ")).toMatch(/WindowsPowerShell.+powershell\.exe/);
    expect(document?.acquisition).toEqual(namespace?.acquisition);
    for (const flag of namespace?.containment ?? [])
      expect(document?.containment, flag).not.toContain(flag);
    const containment = document?.containment.join(" ") ?? "";
    expect(containment).toMatch(/process group/);
    expect(containment).toMatch(
      /Job Object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE and no breakaway/,
    );
    expect(containment).toMatch(/killed and the run fails closed/);
    expect(containment).toMatch(
      /membership part of process creation \(PROC_THREAD_ATTRIBUTE_JOB_LIST\)/,
    );
    expect(containment).toMatch(/command line, inherited environment or working directory/);
    const notes = document?.notes.join(" ") ?? "";
    expect(notes).toMatch(
      /Residual limit on linux and darwin: a descendant that deliberately leaves the session \(setsid\) and also clears its environment and moves its working directory/,
    );
    expect(notes).toMatch(/linux-namespace-uv-v1 is the containment option on Linux/);
    expect(notes).toMatch(/not enforced/i);
    expect(notes).toMatch(/--offline/);
    expect(notes).toMatch(/persistent, Scan-owned uv cache/);
    expect(notes).toMatch(/--no-python-downloads/);
    expect(notes).toMatch(/macOS amd64 \(cryptography 50\.0\.0\) and Windows arm64/);
    expect(notes).not.toMatch(/cisco-skill-scanner-host/);
    expect(notes).toMatch(/Cisco installs the same cisco-skill-scanner lock under both profiles/);
    expect(notes).toMatch(/empty source root completes for detector\.semgrep/);

    expect(
      listDetectorCapabilitiesV1()
        .filter((entry) =>
          entry.executionProfiles.some((profile) => profile.id === "host-process-uv-v1"),
        )
        .map((entry) => entry.detectorId),
    ).toEqual([
      "detector.cisco",
      "detector.cisco-mcp-scanner",
      "detector.semgrep",
      "detector.snyk-agent-scan",
    ]);
  });

  it("publishes the exact per-OS environment the host runtime applies, and the caller variables it reads", () => {
    const document = resolveDetectorExecutionProfileDocumentV1("host-process-uv-v1");
    if (document?.environment.policy !== "fixed-values-by-os") throw new Error("policy");
    expect(document.environment.values).toEqual(HOST_PROCESS_UV_ENVIRONMENT_V1);
    expect(document.environment.callerVariables).toEqual(HOST_PROCESS_UV_DISCOVERY_VARIABLES_V1);
    for (const os of ["linux", "darwin", "windows"] as const) {
      const values = document.environment.values[os];
      expect(values.UV_NO_ENV_FILE, os).toBe("1");
      expect(values.UV_PYTHON_DOWNLOADS, os).toBe("never");
      expect(values.SEMGREP_ENABLE_VERSION_CHECK, os).toBe("0");
      expect(values.PYTHONPATH, os).toBeUndefined();
    }
    expect(Object.keys(document.environment.values.windows)).toEqual(
      expect.arrayContaining([
        "SystemRoot",
        "PATHEXT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "LOCALAPPDATA",
      ]),
    );
  });

  it("publishes docker-host-local-skillspector-v1 for SkillSpector only: never pulls, hardened container flags", () => {
    const skillspector = resolveDetectorCapabilityV1("detector.skillspector");
    expect(skillspector?.executionProfile.id).toBe("docker-hardened-skillspector-v1");
    expect(skillspector?.executionProfiles.map((entry) => entry.id)).toEqual([
      "docker-hardened-skillspector-v1",
      "docker-host-local-skillspector-v1",
    ]);
    expect(
      resolveDetectorExecutionProfileDocumentV1("docker-host-skillspector-v1"),
    ).toBeUndefined();
    const hostDocker = resolveDetectorExecutionProfileDocumentV1(
      "docker-host-local-skillspector-v1",
    );
    const hardened = resolveDetectorExecutionProfileDocumentV1("docker-hardened-skillspector-v1");
    expect(hostDocker?.containment).toEqual(["--pull", "never", ...(hardened?.containment ?? [])]);
    expect(hostDocker?.image).toBe(SKILLSPECTOR_LOCAL_IMAGE_TAG_V1);
    expect(SKILLSPECTOR_LOCAL_IMAGE_TAG_V1).toBe("skillspector:aih-2d198ab910ad");
    expect(hostDocker?.network).toBe("none");
    expect(hostDocker?.acquisition).toEqual([]);
    expect(hostDocker?.notes.join(" ")).toMatch(/never pulls/);
    expect(hostDocker?.notes.join(" ")).toMatch(/RepoDigests/);
    expect(hostDocker?.notes.join(" ")).toMatch(/acceptedImageDigests/);
    if (hostDocker?.environment.policy !== "fixed-values-by-os") throw new Error("policy");
    expect(hostDocker.environment.values).toEqual(HOST_DOCKER_ENVIRONMENT_V1);
    expect(hostDocker.environment.callerVariables).toEqual(HOST_DOCKER_CONTEXT_VARIABLES_V1);
    expect(hostDocker.notes.join(" ")).toMatch(/removed by name with docker rm --force --volumes/);
    expect(hostDocker.notes.join(" ")).toMatch(/current Docker context/);
    const profile = skillspector?.executionProfiles.find(
      (entry) => entry.id === "docker-host-local-skillspector-v1",
    );
    expect(profile?.prerequisites.map((entry) => `${entry.kind}:${entry.id}`)).toEqual([
      "host-executable:docker",
      `container-image:${SKILLSPECTOR_LOCAL_IMAGE_TAG_V1}`,
    ]);
    expect(profile?.supportedPlatforms).toEqual([
      { os: "darwin", architecture: "amd64" },
      { os: "darwin", architecture: "arm64" },
      { os: "linux", architecture: "amd64" },
      { os: "windows", architecture: "amd64" },
    ]);
  });

  it("says in every SARIF profile document that artifact URIs are made source-relative", () => {
    for (const id of [
      "linux-namespace-uv-v1",
      "host-process-uv-v1",
      "docker-hardened-skillspector-v1",
      "docker-host-local-skillspector-v1",
    ])
      expect(resolveDetectorExecutionProfileDocumentV1(id)?.notes.join(" "), id).toMatch(
        /artifact URI is rewritten relative to the declared source root/,
      );
  });

  it("states which detectors complete on an empty source root", () => {
    expect(
      Object.fromEntries(
        listDetectorCapabilitiesV1().map((entry) => [entry.detectorId, entry.emptySource]),
      ),
    ).toEqual({
      "detector.aih-binding-gate": "completes",
      "detector.aih-native": "refused",
      "detector.aih-trust-lint": "completes",
      "detector.cisco": "refused",
      "detector.cisco-mcp-scanner": "refused",
      "detector.semgrep": "completes",
      "detector.skillspector": "completes",
      "detector.snyk-agent-scan": "completes",
    });
  });

  it("exports the in-process trust-lint and binding-gate profiles for every platform, with no prerequisite", () => {
    for (const [profile, id] of [
      [IN_PROCESS_TRUST_LINT_PROFILE_V1, "in-process-trust-lint-v1"],
      [IN_PROCESS_BINDING_GATE_PROFILE_V1, "in-process-binding-gate-v1"],
    ] as const) {
      expect(profile.id).toBe(id);
      expect(profile).toMatchObject({ isolation: "none", network: "none", prerequisites: [] });
      expect(profile.supportedPlatforms).toHaveLength(6);
      expect(Object.isFrozen(profile)).toBe(true);
    }
  });

  it("gates platforms and prerequisites per profile, and the default restates the capability", () => {
    for (const capability of listDetectorCapabilitiesV1()) {
      expect(capability.executionProfile.supportedPlatforms).toEqual(capability.supportedPlatforms);
      expect(capability.executionProfile.prerequisites).toEqual(capability.prerequisites);
      for (const profile of capability.executionProfiles)
        expect(profile.supportedPlatforms.length, profile.id).toBeGreaterThan(0);
    }
    for (const [detectorId, lock] of [
      ["detector.semgrep", "tools/baseline-analyzers/semgrep/uv.lock"],
      ["detector.cisco", "tools/baseline-analyzers/cisco-skill-scanner/uv.lock"],
    ] as const) {
      const host = resolveDetectorCapabilityV1(detectorId)?.executionProfiles.find(
        (entry) => entry.id === "host-process-uv-v1",
      );
      // Exact-pinned binary wheels exist for every dependency on exactly these hosts.
      expect(host?.supportedPlatforms, detectorId).toEqual([
        { os: "darwin", architecture: "arm64" },
        { os: "linux", architecture: "amd64" },
        { os: "linux", architecture: "arm64" },
        { os: "windows", architecture: "amd64" },
      ]);
      expect(
        host?.prerequisites.map((entry) => `${entry.kind}:${entry.id}`),
        detectorId,
      ).toEqual([
        "host-executable:uv",
        "uv-python:3.12",
        `bundled-asset:${lock}`,
        "network:https://pypi.org/simple",
      ]);
    }
    // The default namespace profile's prerequisites are unchanged.
    expect(
      resolveDetectorCapabilityV1("detector.semgrep")?.executionProfile.prerequisites.map(
        (entry) => entry.id,
      ),
    ).toEqual([
      BASELINE_BWRAP_EXECUTABLE_V1,
      BASELINE_UV_EXECUTABLE_V1,
      "tools/baseline-analyzers/semgrep/uv.lock",
      "https://pypi.org/simple",
    ]);
  });

  it("gates the Cisco OCI capture profile on Docker alone, not on the namespace profile's tools", () => {
    const cisco = resolveDetectorCapabilityV1("detector.cisco");
    const oci = cisco?.executionProfiles.find((entry) => entry.id === "oci-hardened-cisco-v1");
    expect(oci?.supportedPlatforms).toEqual([{ os: "linux", architecture: "amd64" }]);
    // The OCI profile runs the Docker CLI against a caller-supplied, already-present image
    // (--pull=never, --network=none): no bubblewrap, no uv, no uv.lock, no acquisition network.
    expect(oci?.prerequisites.map((entry) => `${entry.kind}:${entry.id}`)).toEqual([
      "executable:/usr/bin/docker",
    ]);
    // The default namespace profile keeps its own gates.
    expect(cisco?.executionProfile.prerequisites.map((entry) => entry.id)).toEqual([
      BASELINE_BWRAP_EXECUTABLE_V1,
      BASELINE_UV_EXECUTABLE_V1,
      "tools/baseline-analyzers/cisco-skill-scanner/uv.lock",
      "https://pypi.org/simple",
    ]);
  });

  it("keeps every profile document's field set, so no existing profile digest drifts", () => {
    for (const document of listDetectorExecutionProfileDocumentsV1())
      expect(Object.keys(document).sort(), document.id).toEqual([
        "acquisition",
        "backend",
        "containment",
        "environment",
        "executables",
        "id",
        "image",
        "isolation",
        "mounts",
        "network",
        "notes",
        "protocol",
      ]);
    const namespace = resolveDetectorExecutionProfileDocumentV1("linux-namespace-uv-v1");
    expect(namespace).toMatchObject({
      isolation: "linux-namespace",
      network: "acquisition-only",
      backend: "linux-namespace-uv",
    });
    expect(namespace?.executables).toEqual([
      BASELINE_BWRAP_EXECUTABLE_V1,
      BASELINE_UV_EXECUTABLE_V1,
    ]);
  });
});
