import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  CISCO_MCP_SCANNER_ANALYZER_V1,
  CISCO_MCP_SCANNER_PROJECT_V1,
  CISCO_MCP_SCANNER_VERSION_V1,
} from "../../src/detectors/cisco-mcp-scanner/index.js";
import {
  CISCO_MULTI_SKILL_SCANNER_PROJECT_V1,
  CISCO_MULTI_SKILL_SCANNER_VERSION_V1,
} from "../../src/detectors/cisco-multi-skill/index.js";
import {
  SNYK_AGENT_SCAN_ANALYZER,
  SNYK_AGENT_SCAN_PROJECT,
  SNYK_AGENT_SCAN_VERSION,
} from "../../src/detectors/snyk-agent-scan/index.js";

/**
 * Every detector's analyzer identity constant must name the version its bundled
 * uv project pins and locks. A drift makes the engine report one version while
 * running another, or (Cisco) refuse the locked scanner at its `--version` gate.
 */
function pinnedVersion(project: string, distribution: string): string {
  const pyproject = readFileSync(join(project, "pyproject.toml"), "utf8");
  const pin = new RegExp(`"${distribution}==([^"]+)"`).exec(pyproject)?.[1];
  if (pin === undefined) throw new Error(`${project} does not pin ${distribution}`);
  const lock = readFileSync(join(project, "uv.lock"), "utf8");
  const locked = new RegExp(
    `\\[\\[package\\]\\]\\nname = "${distribution}"\\nversion = "([^"]+)"`,
  ).exec(lock.replace(/\r\n/g, "\n"))?.[1];
  expect(locked).toBe(pin);
  return pin;
}

describe("detector analyzer identity matches the bundled uv project", () => {
  it("cisco skill-scanner", () => {
    expect(pinnedVersion(CISCO_MULTI_SKILL_SCANNER_PROJECT_V1, "cisco-ai-skill-scanner")).toBe(
      CISCO_MULTI_SKILL_SCANNER_VERSION_V1,
    );
  });

  it("cisco mcp-scanner", () => {
    expect(pinnedVersion(CISCO_MCP_SCANNER_PROJECT_V1, "cisco-ai-mcp-scanner")).toBe(
      CISCO_MCP_SCANNER_VERSION_V1,
    );
    expect(CISCO_MCP_SCANNER_ANALYZER_V1).toBe(`mcp-scanner@uv:${CISCO_MCP_SCANNER_VERSION_V1}`);
  });

  it("snyk-agent-scan", () => {
    expect(pinnedVersion(SNYK_AGENT_SCAN_PROJECT, "snyk-agent-scan")).toBe(SNYK_AGENT_SCAN_VERSION);
    expect(SNYK_AGENT_SCAN_ANALYZER).toBe(`snyk-agent-scan@uv:${SNYK_AGENT_SCAN_VERSION}`);
  });
});
