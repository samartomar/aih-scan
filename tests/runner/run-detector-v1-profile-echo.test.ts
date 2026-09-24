import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { listDetectorCapabilitiesV1 } from "../../src/capability/detector-capability-v1.js";
import { runDetectorV1 } from "../../src/runner/run-detector-v1.js";

/**
 * C2a §8.2: every succeeded and failed result carries executionProfile.id equal to the
 * requested executionProfileId, for every observation profile of every detector. Core treats
 * any other id as a failure. The OCI capture profile has its own suite and is not a profile
 * Core requests for trust scans.
 */

const roots: string[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});
function skillRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "aih-scan-echo-"));
  roots.push(root);
  writeFileSync(join(root, "SKILL.md"), "# Skill\n");
  // One MCP server, so detector.cisco-mcp-scanner derives a tool and reaches its analyzer.
  writeFileSync(
    join(root, ".mcp.json"),
    JSON.stringify({ mcpServers: { local: { command: "x" } } }),
  );
  return root;
}

const cases = listDetectorCapabilitiesV1().flatMap((capability) =>
  capability.executionProfiles
    .filter((profile) => profile.evidence === "BaselineAnalyzerObservationV1")
    .map((profile) => [capability.detectorId, profile.id, capability.subjectKinds[0]] as const),
);

/** Detectors that need detectorOptions get the smallest valid ones. */
const OPTIONS: Readonly<Record<string, unknown>> = {
  "detector.aih-trust-lint": { internalScopes: [], mcpConfigPaths: [] },
  "detector.cisco-mcp-scanner": { mcpConfigPaths: [".mcp.json"] },
};

describe("runDetectorV1 execution profile echo", () => {
  it("covers every observation profile Scan publishes", () => {
    expect(cases.map(([detector, profile]) => `${detector}@${profile}`)).toEqual([
      "detector.aih-binding-gate@in-process-binding-gate-v1",
      "detector.aih-native@in-process-native-v1",
      "detector.aih-trust-lint@in-process-trust-lint-v1",
      "detector.cisco@linux-namespace-uv-v1",
      "detector.cisco@host-process-uv-v1",
      "detector.cisco-mcp-scanner@host-process-uv-v1",
      "detector.semgrep@linux-namespace-uv-v1",
      "detector.semgrep@host-process-uv-v1",
      "detector.skillspector@docker-hardened-skillspector-v1",
      "detector.skillspector@docker-host-local-skillspector-v1",
      "detector.snyk-agent-scan@host-process-uv-v1",
    ]);
  });

  it.each(
    cases,
  )("%s under %s reports the requested profile", async (detectorId, profileId, kind) => {
    vi.spyOn(process, "platform", "get").mockReturnValue("linux");
    vi.spyOn(process, "arch", "get").mockReturnValue("x64");
    const outcome = await runDetectorV1({
      detectorId,
      executionProfileId: profileId,
      subject: { kind, sourceRoot: skillRoot(), selectedClosurePaths: ["SKILL.md", ".mcp.json"] },
      ...(OPTIONS[detectorId] === undefined ? {} : { detectorOptions: OPTIONS[detectorId] }),
      ...(detectorId === "detector.snyk-agent-scan" ? { env: { SNYK_TOKEN: "synthetic" } } : {}),
      prerequisiteProbe: () => "present",
      runner: async () => {
        throw new Error("analyzer unavailable in this test");
      },
    });
    expect(["succeeded", "failed"]).toContain(outcome.outcome);
    if (outcome.outcome === "refused") return;
    expect(outcome.executionProfile.id).toBe(profileId);
    // In-process analyzers spawn nothing, so they succeed; every other one fails here.
    expect(outcome.outcome).toBe(profileId.startsWith("in-process-") ? "succeeded" : "failed");
  });
});
