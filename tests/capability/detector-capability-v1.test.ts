import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  BASELINE_ENVIRONMENT_ALLOW_LIST_V1,
  BASELINE_PYTHON_EXECUTABLE_V1,
  type BaselineProcessRunnerV1,
  CISCO_SKILL_SCANNER_VERSION_V1,
  createBaselineAnalyzerRunV1,
  SEMGREP_VERSION_V1,
  SKILLSPECTOR_IMAGE_DIGEST_V1,
  SKILLSPECTOR_IMAGE_V1,
} from "../../src/baseline/runtime-v1.js";
import {
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
    runs: [{ tool: { driver: { name } }, results: [] }],
  }).toString("utf8");

describe("DetectorCapabilityV1", () => {
  it("publishes a frozen, canonical, digest-stable capability for each Scan-owned detector", () => {
    const capabilities = listDetectorCapabilitiesV1();

    expect(capabilities.map((entry) => entry.detectorId)).toEqual([
      "detector.aih-native",
      "detector.cisco",
      "detector.semgrep",
      "detector.skillspector",
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

  it("states honestly that only the in-process analyzer runs off Linux amd64", () => {
    for (const capability of listDetectorCapabilitiesV1()) {
      const platforms = capability.supportedPlatforms.map(
        (entry) => `${entry.os}/${entry.architecture}`,
      );
      if (capability.detectorId === "detector.aih-native") {
        expect(platforms).toContain("windows/amd64");
        expect(capability.executionProfile.isolation).toBe("none");
        expect(capability.prerequisites).toEqual([]);
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
      "host-process-uv-v1",
      "in-process-native-v1",
      "linux-namespace-uv-v1",
      "oci-hardened-cisco-v1",
    ]);
    const inProcess = resolveDetectorExecutionProfileDocumentV1("in-process-native-v1");
    expect(inProcess?.executables).toEqual([]);
    expect(inProcess?.containment).toEqual([]);
    expect(inProcess?.notes.join(" ")).toContain("spawns nothing");
    // Every profile except the host profile keeps its unchanged allow-list-scrub rule.
    for (const document of documents) {
      if (document.id === "host-process-uv-v1") continue;
      expect(document.environment, document.id).toEqual({
        policy: "allow-list-scrub",
        allowed: BASELINE_ENVIRONMENT_ALLOW_LIST_V1,
      });
    }
  });

  it("publishes host-process-uv-v1 as an explicit, truthfully unisolated Semgrep profile", () => {
    const semgrep = resolveDetectorCapabilityV1("detector.semgrep");
    expect(semgrep?.backend).toBe("linux-namespace-uv");
    expect(semgrep?.executionProfile.id).toBe("linux-namespace-uv-v1");
    expect(semgrep?.executionProfiles.map((entry) => entry.id)).toEqual([
      "linux-namespace-uv-v1",
      "host-process-uv-v1",
    ]);
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
    });
    expect(document?.executables).toEqual([BASELINE_UV_EXECUTABLE_V1]);
    expect(document?.acquisition).toEqual(namespace?.acquisition);
    for (const flag of namespace?.containment ?? [])
      expect(document?.containment, flag).not.toContain(flag);
    expect(document?.notes.join(" ")).toMatch(/not enforced/i);
    expect(document?.notes.join(" ")).toMatch(/Windows/);
    // Process-group cleanup is bounded, not guaranteed: a surviving group fails the spawn.
    expect(document?.notes.join(" ")).not.toMatch(/gone before it settles/i);
    expect(document?.notes.join(" ")).toMatch(/not guaranteed/i);

    expect(
      listDetectorCapabilitiesV1()
        .filter((entry) =>
          entry.executionProfiles.some((profile) => profile.id === "host-process-uv-v1"),
        )
        .map((entry) => entry.detectorId),
    ).toEqual(["detector.semgrep"]);
  });

  it("gates platforms and prerequisites per profile, and the default restates the capability", () => {
    for (const capability of listDetectorCapabilitiesV1()) {
      expect(capability.executionProfile.supportedPlatforms).toEqual(capability.supportedPlatforms);
      expect(capability.executionProfile.prerequisites).toEqual(capability.prerequisites);
      for (const profile of capability.executionProfiles)
        expect(profile.supportedPlatforms.length, profile.id).toBeGreaterThan(0);
    }
    const host = resolveDetectorCapabilityV1("detector.semgrep")?.executionProfiles.find(
      (entry) => entry.id === "host-process-uv-v1",
    );
    // Windows has no fail-closed process-tree containment yet and macOS has no hosted proof.
    expect(host?.supportedPlatforms).toEqual([{ os: "linux", architecture: "amd64" }]);
    const ids = host?.prerequisites.map((entry) => entry.id) ?? [];
    expect(ids).toContain(BASELINE_UV_EXECUTABLE_V1);
    expect(ids).toContain("tools/baseline-analyzers/semgrep/uv.lock");
    expect(ids).not.toContain(BASELINE_BWRAP_EXECUTABLE_V1);
    // uv runs with --no-python-downloads, so the pinned interpreter must already exist.
    expect(ids).toContain(BASELINE_PYTHON_EXECUTABLE_V1);
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
