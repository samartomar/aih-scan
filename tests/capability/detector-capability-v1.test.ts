import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
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
      "in-process-native-v1",
      "linux-namespace-uv-v1",
      "oci-hardened-cisco-v1",
    ]);
    const inProcess = resolveDetectorExecutionProfileDocumentV1("in-process-native-v1");
    expect(inProcess?.executables).toEqual([]);
    expect(inProcess?.containment).toEqual([]);
    expect(inProcess?.notes.join(" ")).toContain("spawns nothing");
    for (const document of documents)
      expect(document.environment.allowed).toContain("XDG_CACHE_HOME");
  });
});
