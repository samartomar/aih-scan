import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runBindingGateV1 } from "../../src/detectors/binding-gate/index.js";
import {
  CISCO_MCP_SCANNER_VERSION_V1,
  parseCiscoMcpScannerSarifV1,
} from "../../src/detectors/cisco-mcp-scanner/index.js";
import {
  CISCO_MULTI_SKILL_SCANNER_PROJECT_V1,
  type CiscoMultiSkillRunnerV1,
} from "../../src/detectors/cisco-multi-skill/plan-v1.js";
import { runCiscoSourceTreeScanV1 } from "../../src/detectors/cisco-multi-skill/scan-v1.js";
import { runCiscoShardV1 } from "../../src/detectors/cisco-multi-skill/shard-v1.js";
import { attachScanCompletionV1 } from "../../src/detectors/completion-evidence-v1.js";
import { assertSarifCompletedV1 } from "../../src/detectors/sarif-completion-v1.js";
import {
  parseSnykAgentScanSarifV1,
  SNYK_AGENT_SCAN_VERSION,
} from "../../src/detectors/snyk-agent-scan/index.js";
import { runTrustLintV1 } from "../../src/detectors/trust-lint/index.js";
import { hashComponentTreeV1 } from "../../src/observation/source-hash-v1.js";
import { sarif210RequiredProblemsV1 } from "../runner/completion-evidence-support.js";
import { writeCiscoJobReportV1 } from "../support/cisco-job-report.js";

// S2h (coordinator decision D16, from Core worker W2D): SARIF 2.1.0 requires run.tool.driver
// on every run. Every SARIF shape Scan returns is checked here against the required-field set
// (version, runs, run.tool.driver.name, a results array; a result message, an invocation's
// executionSuccessful): the four logs Scan builds itself, before and after Scan adds its one
// successful invocation, and the Cisco source-tree and shard logs. Analyzer SARIF (Semgrep,
// SkillSpector, Cisco skill-directory) is refused without a driver before Scan returns it;
// every succeeded runDetectorV1 and shard result in the runner tests passes the same check.

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});
function fixture(): string {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "aih-scan-sarif-shape-")));
  roots.push(root);
  mkdirSync(join(root, "skills", "alpha"), { recursive: true });
  writeFileSync(join(root, "skills", "alpha", "SKILL.md"), "# alpha\n", "utf8");
  writeFileSync(join(root, ".mcp.json"), '{"mcpServers":{}}\n', "utf8");
  return root;
}

const EVIDENCE = {
  detectorId: "detector.fixture",
  subjectTreeSha256: "0".repeat(64),
  analyzedFileCount: 1,
  analyzer: { version: "1.0.0", lockSha256: null },
};

/** A Scan-built log as runDetectorV1 returns it: parsed, then its one invocation added. */
function returned(log: unknown): unknown {
  return attachScanCompletionV1(JSON.parse(JSON.stringify(log)), EVIDENCE, { scanBuilt: true });
}

function expectDriver(log: unknown, name: string, version: string): void {
  const runs = (log as { runs: { tool?: { driver?: Record<string, unknown> } }[] }).runs;
  for (const run of runs) expect(run.tool?.driver).toMatchObject({ name, version });
}

describe("every SARIF shape Scan returns has the SARIF 2.1.0 required fields", () => {
  it("aih-trust-lint", () => {
    const outcome = runTrustLintV1({
      sourceRoot: fixture(),
      selectedClosurePaths: ["skills/alpha/SKILL.md"],
      detectorOptions: { internalScopes: [], mcpConfigPaths: [".mcp.json"] },
    });
    if (outcome.kind !== "completed") throw new Error(outcome.kind);
    const log = JSON.parse(outcome.sarifText);
    expect(sarif210RequiredProblemsV1(log)).toEqual([]);
    expect(sarif210RequiredProblemsV1(returned(log))).toEqual([]);
    expectDriver(log, "aih-trust-lint", "1.0.0");
  });

  it("aih-binding-gate", () => {
    const outcome = runBindingGateV1({
      sourceRoot: fixture(),
      selectedClosurePaths: ["skills/alpha/SKILL.md"],
      detectorOptions: undefined,
    });
    if (outcome.kind !== "completed") throw new Error(outcome.kind);
    const log = JSON.parse(outcome.sarifText);
    expect(sarif210RequiredProblemsV1(log)).toEqual([]);
    expect(sarif210RequiredProblemsV1(returned(log))).toEqual([]);
    expectDriver(log, "aih-binding-gate", "1.0.0");
  });

  it("snyk-agent-scan, with and without findings, in the 0.5.17 and 0.6.x shapes", () => {
    const root = fixture();
    // U1g: the 0.6.x ScanResponse builder carries the driver too.
    let checked = 0;
    const skill = (risks: Record<string, unknown>) => ({
      name: "alpha",
      files: [{ name: "SKILL.md", type: "instruction" }],
      risk_indexes: risks,
    });
    const scanResponse = (risks: Record<string, unknown>) => ({
      scan_path_responses: [
        { client: root, path: "~/display/path", server_risks: [], skill_risks: [skill(risks)] },
      ],
    });
    for (const report of [
      { issues: [{ id: "R1", title: "Found", file: "skills/alpha/SKILL.md", line: 1 }] },
      { issues: [] },
      scanResponse({ prompt_injection: { score: 900, evidence: "Injected." } }),
      scanResponse({}),
    ]) {
      checked += 1;
      let log: unknown;
      try {
        log = parseSnykAgentScanSarifV1(JSON.stringify(report), root);
      } catch {
        checked -= 1;
        continue; // An empty report proves no analysis (S2e); the positive shape is the case.
      }
      expect(sarif210RequiredProblemsV1(log)).toEqual([]);
      expect(sarif210RequiredProblemsV1(returned(log))).toEqual([]);
      expectDriver(log, "snyk-agent-scan", SNYK_AGENT_SCAN_VERSION);
    }
    // The 0.5.17 finding and both 0.6.x responses (a risk, and none) are checked.
    expect(checked).toBe(3);
  });

  it("cisco-mcp-scanner, with and without findings", () => {
    for (const [isSafe, threats, total] of [
      [false, ["TOOL POISONING"], 1],
      [true, [], 0],
    ] as const) {
      const report = [
        {
          status: "completed",
          is_safe: isSafe,
          findings: {
            yara_analyzer: {
              severity: isSafe ? "SAFE" : "HIGH",
              threat_names: threats,
              threat_summary: isSafe ? "No threats detected" : "prompt injection",
              total_findings: total,
            },
          },
          tool_name: ".mcp.json:local",
          tool_description: "local fixture",
          item_type: "tool",
        },
      ];
      const log = parseCiscoMcpScannerSarifV1(
        JSON.stringify(report),
        new Map([[".mcp.json:local", ".mcp.json"]]),
      );
      expect(sarif210RequiredProblemsV1(log)).toEqual([]);
      expect(sarif210RequiredProblemsV1(returned(log))).toEqual([]);
      expectDriver(log, "mcp-scanner", CISCO_MCP_SCANNER_VERSION_V1);
    }
  });

  const cisco: CiscoMultiSkillRunnerV1 = async (argv) => {
    if (argv.includes("--version")) return { code: 0, stdout: "skill-scanner 2.1.0\n", stderr: "" };
    writeCiscoJobReportV1(argv);
    const output = argv[argv.indexOf("--output-sarif") + 1] ?? "";
    writeFileSync(
      output,
      JSON.stringify({
        version: "2.1.0",
        runs: [
          {
            tool: { driver: { name: "skill-scanner", version: "2.1.0" } },
            invocations: [{ executionSuccessful: true }],
            results: [
              {
                ruleId: "fixture",
                message: { text: "m" },
                locations: [{ physicalLocation: { artifactLocation: { uri: "SKILL.md" } } }],
              },
            ],
          },
        ],
      }),
      "utf8",
    );
    return { code: 0, stdout: "", stderr: "" };
  };

  it("Cisco source-tree (merged per-skill analyzer runs)", async () => {
    const outcome = await runCiscoSourceTreeScanV1({
      run: cisco,
      platform: "linux",
      env: {},
      sourceRoot: fixture(),
      selectedClosurePaths: ["skills/alpha/SKILL.md"],
    });
    if (outcome.kind !== "completed") throw new Error(outcome.kind);
    expect(sarif210RequiredProblemsV1(JSON.parse(outcome.sarifText))).toEqual([]);
  });

  it("each Cisco shard job output", async () => {
    const root = fixture();
    const outcome = await runCiscoShardV1({
      run: cisco,
      platform: "linux",
      env: {},
      sourceRoot: root,
      jobs: [
        {
          id: "alpha",
          path: "skills/alpha",
          inputSha256: hashComponentTreeV1(root, ["skills/alpha"]).treeSha256,
        },
      ],
      expected: {
        analyzerVersion: "2.1.0",
        lockSha256: createHash("sha256")
          .update(readFileSync(join(CISCO_MULTI_SKILL_SCANNER_PROJECT_V1, "uv.lock")))
          .digest("hex"),
      },
      concurrency: 1,
    });
    if (outcome.kind !== "completed") throw new Error(outcome.kind);
    for (const output of outcome.outputs)
      expect(
        sarif210RequiredProblemsV1(JSON.parse(Buffer.from(output.sarif).toString("utf8"))),
      ).toEqual([]);
  });

  it("analyzer SARIF without a driver or results never reaches a caller", () => {
    for (const run of [
      { results: [], invocations: [{ executionSuccessful: true }] },
      { tool: { driver: {} }, results: [], invocations: [{ executionSuccessful: true }] },
      { tool: { driver: { name: "x" } }, invocations: [{ executionSuccessful: true }] },
    ])
      expect(() => assertSarifCompletedV1({ version: "2.1.0", runs: [run] })).toThrow(
        /tool driver|results/,
      );
  });

  it("the oracle itself refuses each missing required field", () => {
    const good = {
      version: "2.1.0",
      runs: [
        {
          tool: { driver: { name: "x" } },
          results: [{ message: { text: "m" } }],
          invocations: [{ executionSuccessful: true }],
        },
      ],
    };
    expect(sarif210RequiredProblemsV1(good)).toEqual([]);
    for (const bad of [
      { ...good, version: "2.0.0" },
      { version: "2.1.0", runs: [] },
      { version: "2.1.0", runs: [{ results: [] }] },
      { version: "2.1.0", runs: [{ tool: { driver: { name: "x" } } }] },
      { version: "2.1.0", runs: [{ tool: { driver: { name: "x" } }, results: [{}] }] },
      {
        version: "2.1.0",
        runs: [{ tool: { driver: { name: "x" } }, results: [], invocations: [{}] }],
      },
    ])
      expect(sarif210RequiredProblemsV1(bad).length, JSON.stringify(bad)).toBeGreaterThan(0);
  });
});
