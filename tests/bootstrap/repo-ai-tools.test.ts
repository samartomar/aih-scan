import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, parse, resolve } from "node:path";
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

type CodebaseMemoryBootstrap = {
  cacheDir: string;
  markerPath: string;
  allowedRoot: string;
  environment: Record<string, string>;
  project: { name: string; rootPath: string };
  projection: string;
  commands: Record<string, string[]>;
};

type BootstrapTools = {
  inspectCodebaseMemoryBootstrap: (override?: string) => CodebaseMemoryBootstrap;
  resolveCodebaseMemoryCacheDir: (override?: string) => string;
  findCodebaseMemoryProject: (projects: unknown[]) => unknown;
  assertCodebaseMemoryScopedResponse: (response: unknown, label: string) => void;
  assertCodebaseMemorySearchResponse: (response: unknown) => void;
};

async function bootstrapTools(): Promise<BootstrapTools> {
  // @ts-expect-error The launcher is deliberately plain ESM, not a TypeScript module.
  return (await import("../../tools/repo-ai-tools.mjs")) as BootstrapTools;
}

function isGitIgnored(path: string): boolean {
  return spawnSync("git", ["check-ignore", "-q", path], { cwd: root }).status === 0;
}

function isGitTracked(path: string): boolean {
  return spawnSync("git", ["ls-files", "--error-unmatch", path], { cwd: root }).status === 0;
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
    expect(isGitIgnored(".codex/config.toml")).toBe(true);
    expect(isGitTracked(".codex/config.toml")).toBe(false);
  });

  it("uses a stable aih-scan-local CBM cache by default and one resolved explicit override everywhere", async () => {
    const tools = await bootstrapTools();
    const defaultBootstrap = tools.inspectCodebaseMemoryBootstrap();
    const override = join(tmpdir(), "aih-scan-cbm-shared-cache");
    const overridden = tools.inspectCodebaseMemoryBootstrap(override);

    expect(isAbsolute(defaultBootstrap.cacheDir)).toBe(true);
    expect(defaultBootstrap.allowedRoot).toBe(resolve(root));
    expect(defaultBootstrap.project).toEqual({ name: "aih-scan", rootPath: resolve(root) });
    expect(overridden.cacheDir).toBe(resolve(override));
    expect(overridden.markerPath).toMatch(
      new RegExp(
        `^${resolve(override).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}[\\\\/]\\.aih-scan-[a-f0-9]{16}\\.indexed\\.json$`,
      ),
    );
    expect(overridden.markerPath).not.toBe(join(resolve(override), "indexed.json"));
    expect(overridden.allowedRoot).toBe(resolve(root));
    expect(overridden.environment).toEqual({
      CBM_CACHE_DIR: resolve(override),
      CBM_ALLOWED_ROOT: resolve(root),
      CBM_LOG_LEVEL: "warn",
    });
    expect(overridden.projection).toContain(`[mcp_servers."codebase-memory-mcp".env]`);
    expect(overridden.projection).toContain(`CBM_CACHE_DIR = ${JSON.stringify(resolve(override))}`);
    expect(overridden.projection).toContain(`CBM_ALLOWED_ROOT = ${JSON.stringify(resolve(root))}`);
    expect(tools.inspectCodebaseMemoryBootstrap(override)).toEqual(overridden);
  });

  it("rejects ambiguous or unsafe CBM cache overrides before a launcher can inherit them", async () => {
    const tools = await bootstrapTools();
    const rootPath = resolve(root);
    const filesystemRoot = parse(rootPath).root;
    for (const override of [
      "",
      "   ",
      "relative-cache",
      `\u0000cache`,
      filesystemRoot,
      rootPath,
      join(rootPath, "nested-cache"),
      join(rootPath, "nested-cache", "deeper-cache"),
    ]) {
      expect(() => tools.resolveCodebaseMemoryCacheDir(override), JSON.stringify(override)).toThrow(
        /CBM_CACHE_DIR/i,
      );
    }
  });

  it("keeps cache locations machine-local and scopes index, discovery, status, and search to aih-scan", async () => {
    const tools = await bootstrapTools();
    const override = join(tmpdir(), "aih-scan-cbm-uncommitted-path");
    const bootstrap = tools.inspectCodebaseMemoryBootstrap(override);
    const trackedFiles = execFileSync("git", ["ls-files", "-z"], { cwd: root, encoding: "utf8" })
      .split("\0")
      .filter(Boolean);
    const trackedContents = trackedFiles
      .filter((path) => existsSync(resolve(root, path)))
      .map((path) => readFileSync(resolve(root, path), "utf8"))
      .join("\n");

    expect(isGitIgnored(".codex/config.toml")).toBe(true);
    expect(isGitTracked(".codex/config.toml")).toBe(false);
    expect(trackedContents).not.toContain(resolve(override));
    expect(bootstrap.commands).toEqual({
      index: [
        "cli",
        "index_repository",
        "--repo-path",
        resolve(root),
        "--name",
        "aih-scan",
        "--mode",
        "moderate",
      ],
      list: ["cli", "list_projects"],
      status: ["cli", "index_status", "--project", "aih-scan"],
      search: [
        "cli",
        "search_code",
        "--project",
        "aih-scan",
        "--pattern",
        "export",
        "--file-pattern",
        "index.ts",
        "--mode",
        "files",
        "--limit",
        "1",
      ],
    });

    const other = {
      name: "other-project",
      root_path: resolve(tmpdir(), "other-project"),
      nodes: 10,
      edges: 20,
    };
    const target = { name: "aih-scan", root_path: resolve(root), nodes: 10, edges: 20 };
    expect(tools.findCodebaseMemoryProject([other, target])).toEqual(target);
    expect(() => tools.findCodebaseMemoryProject([other])).toThrow(/aih-scan/i);
    expect(() =>
      tools.assertCodebaseMemoryScopedResponse(
        { project: "aih-scan", root_path: resolve(tmpdir(), "other-project") },
        "status",
      ),
    ).toThrow(/status/i);
    expect(() =>
      tools.assertCodebaseMemoryScopedResponse(
        { project: "aih-scan", root_path: resolve(root) },
        "status",
      ),
    ).not.toThrow();
    expect(() =>
      tools.assertCodebaseMemorySearchResponse({
        files: ["src/index.ts"],
        directories: { "src/": 1 },
      }),
    ).not.toThrow();
    expect(() =>
      tools.assertCodebaseMemorySearchResponse({ files: ["../ai-harness/src/index.ts"] }),
    ).toThrow(/search/i);
    expect(() =>
      tools.assertCodebaseMemorySearchResponse({ files: ["C:/dev/ai-harness/src/index.ts"] }),
    ).toThrow(/search/i);
    expect(() =>
      tools.assertCodebaseMemorySearchResponse({
        results: [{ file_path: "../ai-harness/src/index.ts" }],
      }),
    ).toThrow(/search/i);
    expect(() =>
      tools.assertCodebaseMemorySearchResponse({ rows: [{ path: "src/index.ts" }] }),
    ).not.toThrow();
    expect(() => tools.assertCodebaseMemorySearchResponse({ ok: true })).toThrow(/search/i);
  });
});
