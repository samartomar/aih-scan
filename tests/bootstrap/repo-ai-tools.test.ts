import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../..");

function commandJson(...args: string[]): Record<string, unknown> {
  return JSON.parse(
    execFileSync(process.execPath, ["tools/repo-ai-tools.mjs", ...args], {
      cwd: root,
      encoding: "utf8",
    }),
  ) as Record<string, unknown>;
}

describe("aih-scan repository AI bootstrap", () => {
  it("pins the established helper toolchain with narrow, non-overlapping scopes", () => {
    expect(commandJson("plan")).toMatchObject({
      pins: {
        serena: {
          package: "serena-agent==1.7.0",
          securityOverrides: ["python-multipart==0.0.32", "starlette==1.3.1"],
        },
        tokenSavior: { package: "token-savior-recall[mcp]==4.21.0" },
        codeReviewGraph: { package: "code-review-graph==2.3.7" },
        codebaseMemory: { package: "codebase-memory-mcp==0.10.5" },
        tokenOptimizer: {
          tag: "v5.11.68",
          commit: "ffe3b8007542260b17648a2d9228c3dedda380ad",
          tree: "d044ba6038ac705e8d0da6a4b545cbee00abe7d5",
        },
      },
      runtime: {
        serena: {
          enabledTools: [
            "get_symbols_overview",
            "find_symbol",
            "find_referencing_symbols",
            "find_implementations",
            "get_diagnostics_for_file",
            "search_for_pattern",
            "rename_symbol",
            "replace_symbol_body",
            "insert_before_symbol",
            "insert_after_symbol",
          ],
        },
        tokenSavior: {
          enabledTools: [
            "get_entry_points",
            "search_codebase",
            "find_symbol",
            "get_call_chain",
            "get_function_source",
            "get_full_context",
          ],
          memory: false,
        },
        tokenOptimizer: { integration: "on-demand", commands: ["report", "coach"] },
        codeReviewGraph: { role: "broad-impact-review", advisory: true },
        codebaseMemory: { role: "find-trace-recall", advisory: true },
      },
    });
  });

  it("makes setup-codex dry-run disclose every local mutation class", () => {
    expect(commandJson("setup-codex", "--dry-run")).toEqual({
      command: "setup-codex",
      dryRun: true,
      mutations: [
        "install pinned repo AI tools",
        "write ignored Codex project projection",
        "install or refresh ECC through the native Codex plugin lifecycle",
        "initialize project-scoped graph and memory indexes",
        "enable the repository pre-commit hook path",
      ],
    });
  });

  it("keeps generated local state out of Git and exposes only bootstrap scripts", () => {
    const packageJson = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8")) as {
      private: boolean;
      scripts: Record<string, string>;
    };
    expect(packageJson.private).toBe(true);
    expect(packageJson.scripts["repo:init"]).toBe("node tools/repo-ai-tools.mjs setup-codex");
    expect(packageJson.scripts["repo:doctor"]).toBe("node tools/repo-ai-tools.mjs doctor-codex");
    const gitignore = readFileSync(resolve(root, ".gitignore"), "utf8");
    for (const entry of [
      "/.codex/config.toml",
      "/.codex/hooks.json",
      "/.serena/",
      "/.code-review-graph/",
      "/.codebase-memory/",
      ".token-savior-cache.json",
      "node_modules/",
      "dist/",
      "coverage/",
    ]) {
      expect(gitignore).toContain(entry);
    }
    expect(existsSync(resolve(root, ".codex/config.toml"))).toBe(false);
  });
});
