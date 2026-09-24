import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildTrustLintTreeV1 } from "../../../src/detectors/trust-lint/inventory.js";
import {
  scanMcpConfigSecretsV1,
  scanPlaintextSecretsV1,
} from "../../../src/detectors/trust-lint/secrets.js";
import { coreMcpConfigPathsV1, coreSelectionV1 } from "./support.js";

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
    const checks = scanMcpConfigSecretsV1(tree, coreMcpConfigPathsV1(dir, coreSelectionV1(tree)));

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
    const checks = scanMcpConfigSecretsV1(tree, coreMcpConfigPathsV1(dir, coreSelectionV1(tree)));

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
    const checks = scanMcpConfigSecretsV1(tree, coreMcpConfigPathsV1(dir, coreSelectionV1(tree)));

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

    expect(scanMcpConfigSecretsV1(tree, coreMcpConfigPathsV1(dir, coreSelectionV1(tree)))).toEqual(
      [],
    );
  });

  it("skips a declared path that is absent and reports a directory as config-invalid", () => {
    mkdirSync(join(dir, ".mcp.json"));
    const tree = buildTrustLintTreeV1(dir);

    expect(scanMcpConfigSecretsV1(tree, ["mcp.json", ".mcp.json"])).toEqual([
      {
        name: "mcp-config-invalid",
        verdict: "fail",
        detail:
          ".mcp.json could not be safely inspected: MCP config path is not a contained regular file",
        code: "mcp.config-invalid",
        location: { uri: ".mcp.json", startLine: 1 },
        fingerprint: "mcp.config-invalid:.mcp.json:",
      },
    ]);
  });
});

describe("symlinks (parity: Core lstat-based discovery)", () => {
  function trySymlink(target: string, rel: string): boolean {
    try {
      symlinkSync(target, join(dir, rel), "file");
      return true;
    } catch {
      return false; // no symlink privilege on this host
    }
  }

  it("never flags a symlinked .env, and reports a symlinked MCP config as config-invalid", (ctx) => {
    write("real.env.txt", "API_TOKEN=abc123\n");
    write(
      "real-mcp.txt",
      JSON.stringify({ mcpServers: { gh: { env: { GITHUB_TOKEN: `ghp_${"a".repeat(36)}` } } } }),
    );
    if (!trySymlink("real.env.txt", ".env") || !trySymlink("real-mcp.txt", ".mcp.json")) {
      ctx.skip();
      return;
    }
    const tree = buildTrustLintTreeV1(dir);

    expect(scanPlaintextSecretsV1(tree)).toEqual([]);
    expect(scanMcpConfigSecretsV1(tree, [".mcp.json"]).map((check) => check.code)).toEqual([
      "mcp.config-invalid",
    ]);
  });
});
