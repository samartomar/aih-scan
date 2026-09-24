import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildTrustLintTreeV1 } from "../../../src/detectors/trust-lint/inventory.js";
import {
  collectIncomingMcpConfigFilesV1,
  scanMcpConfigSecretsV1,
  scanPlaintextSecretsV1,
} from "../../../src/detectors/trust-lint/secrets.js";

/**
 * Parity port of the secrets cases in Core's `tests/trust/scan.test.ts`
 * (~lines 789-899) at the detection layer. Core's vibe-posture "warning-only"
 * downgrade assertions are grading (`postureGradeCheck`, Core-owned) and are
 * not ported; the raw detection asserted here is exactly what Core's
 * enterprise posture observes.
 */
let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "aih-trust-secrets-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function write(rel: string, content: string): void {
  const path = join(dir, rel);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content, "utf8");
}

describe("scanPlaintextSecretsV1 (parity: Core plaintextSecretChecks)", () => {
  it("flags a plaintext .env secret on disk", () => {
    write(".env", "API_TOKEN=abc123\n");

    const checks = scanPlaintextSecretsV1(buildTrustLintTreeV1(dir));

    expect(checks).toEqual([
      expect.objectContaining({
        name: "plaintext-secret",
        verdict: "fail",
        code: "secrets.plaintext-detected",
        location: expect.objectContaining({ uri: ".env", startLine: 1 }),
        fingerprint: "plaintext-secret:.env",
      }),
    ]);
  });

  it("flags .env files one level deep but not deeper, and never examples", () => {
    write(".env.local", "A=1\n");
    write("app/.env", "B=2\n");
    write("app/deep/.env", "C=3\n");
    write(".env.example", "A=\n");
    write(".env.sample", "A=\n");

    const paths = scanPlaintextSecretsV1(buildTrustLintTreeV1(dir)).map(
      (check) => check.location.uri,
    );

    expect(paths).toEqual([".env.local", "app/.env"]);
  });

  it("flags a root-level secrets directory only", () => {
    mkdirSync(join(dir, "secrets"), { recursive: true });
    mkdirSync(join(dir, "src", "secrets"), { recursive: true });

    const checks = scanPlaintextSecretsV1(buildTrustLintTreeV1(dir));

    expect(checks.map((check) => check.location.uri)).toEqual(["secrets"]);
  });
});

describe("scanMcpConfigSecretsV1 (parity: Core mcpConfigSecretChecks)", () => {
  it("flags hardcoded secrets inside incoming MCP configs", () => {
    write(
      ".mcp.json",
      JSON.stringify({
        mcpServers: {
          gh: {
            command: "node",
            args: ["server.js"],
            env: { GITHUB_TOKEN: `ghp_${"a".repeat(36)}` },
          },
        },
      }),
    );

    const tree = buildTrustLintTreeV1(dir);
    const checks = scanMcpConfigSecretsV1(tree, collectIncomingMcpConfigFilesV1(tree));

    expect(checks).toEqual([
      expect.objectContaining({
        name: "mcp-hardcoded-secret",
        verdict: "fail",
        code: "mcp.hardcoded-secret",
        location: expect.objectContaining({ uri: ".mcp.json", startLine: 1 }),
        fingerprint: "mcp.hardcoded-secret:.mcp.json:GITHUB_TOKEN",
      }),
    ]);
  });

  it("flags hardcoded secrets inside nested skill MCP configs", () => {
    write("skills/clean/SKILL.md", "# Clean\n");
    write(
      "skills/clean/.mcp.json",
      JSON.stringify({
        mcpServers: {
          gh: {
            command: "node",
            args: ["server.js"],
            env: { GITHUB_TOKEN: `ghp_${"a".repeat(36)}` },
          },
        },
      }),
    );

    const tree = buildTrustLintTreeV1(dir);
    const checks = scanMcpConfigSecretsV1(tree, collectIncomingMcpConfigFilesV1(tree));

    expect(checks).toEqual([
      expect.objectContaining({
        verdict: "fail",
        code: "mcp.hardcoded-secret",
        location: expect.objectContaining({ uri: "skills/clean/.mcp.json" }),
      }),
    ]);
  });

  it("flags hardcoded secrets inside OpenCode MCP configs", () => {
    write(
      "opencode.json",
      JSON.stringify({
        mcp: {
          gh: {
            type: "local",
            command: ["node", "server.js"],
            enabled: true,
            environment: {
              GITHUB_TOKEN: `ghp_${"a".repeat(36)}`,
              API_KEY: `sk-${"b".repeat(24)}`,
            },
          },
        },
      }),
    );

    const tree = buildTrustLintTreeV1(dir);
    const checks = scanMcpConfigSecretsV1(tree, collectIncomingMcpConfigFilesV1(tree));

    expect(checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          verdict: "fail",
          code: "mcp.hardcoded-secret",
          location: expect.objectContaining({ uri: "opencode.json" }),
        }),
      ]),
    );
    expect(checks).toHaveLength(2);
    expect(checks.map((check) => check.fingerprint).sort()).toEqual([
      "mcp.hardcoded-secret:opencode.json:API_KEY",
      "mcp.hardcoded-secret:opencode.json:GITHUB_TOKEN",
    ]);
  });

  it("does not flag env references, placeholders, or path config", () => {
    write(
      ".mcp.json",
      JSON.stringify({
        mcpServers: {
          gh: {
            command: "node",
            args: ["server.js"],
            env: {
              GITHUB_TOKEN: "${GITHUB_TOKEN}",
              API_KEY_PATH: "C:/tools/keys.txt",
            },
            headers: { Authorization: "Bearer ${MCP_TOKEN}" },
          },
        },
      }),
    );

    const tree = buildTrustLintTreeV1(dir);

    expect(scanMcpConfigSecretsV1(tree, collectIncomingMcpConfigFilesV1(tree))).toEqual([]);
  });
});
