import { lstatSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  deriveCiscoMcpToolsV1,
  MCP_DECLARED_CONFIG_PATHS_MAX_V1,
  planCiscoMcpScannerRequestV1,
  serializeMcpToolsManifestV1,
  validateCiscoMcpScannerDetectorOptionsV1,
} from "../../../src/detectors/cisco-mcp-scanner/index.js";

/**
 * C2a §4 tests for the Core-declared-paths flow of `detector.cisco-mcp-scanner`:
 * §4.1 options validation (typed `detector-options-invalid` refusals, never a
 * throw) and §4.2 tool derivation over exactly the declared paths (typed
 * `subject-requirement-unmet` refusals before spawning). Verified against
 * Core's `mcpStaticTools`/`mcpStaticToolsFromConfig` in
 * `D:/dev/ai-harness/src/trust/detectors.ts`.
 */

const roots: string[] = [];

function fixture(): string {
  const root = mkdtempSync(join(tmpdir(), "aih-cisco-mcp-scanner-request-"));
  roots.push(root);
  return root;
}

function write(root: string, rel: string, content: string): void {
  const abs = join(root, ...rel.split("/"));
  mkdirSync(dirname(abs), { recursive: true });
  writeFileSync(abs, content, "utf8");
}

afterEach(() => {
  while (roots.length > 0) {
    const root = roots.pop();
    if (root !== undefined) rmSync(root, { recursive: true, force: true });
  }
});

function serverConfig(description?: string): string {
  return JSON.stringify({
    mcpServers: { local: description === undefined ? {} : { description } },
  });
}

describe("validateCiscoMcpScannerDetectorOptionsV1 (C2a §4.1, validated as §2.1)", () => {
  it("requires a plain object with exactly the mcpConfigPaths key", () => {
    const root = fixture();
    const request = { root, selectedClosurePaths: [] };

    for (const options of [
      undefined,
      null,
      [],
      "mcpConfigPaths",
      {},
      { mcpConfigPaths: [], extra: true },
      { paths: [] },
    ]) {
      const outcome = validateCiscoMcpScannerDetectorOptionsV1(options, request);
      expect(outcome.ok).toBe(false);
      if (outcome.ok) continue;
      expect(outcome.refusal.reason).toBe("detector-options-invalid");
    }
  });

  it("accepts an empty path list (applicability is Core's decision)", () => {
    const root = fixture();
    const outcome = validateCiscoMcpScannerDetectorOptionsV1(
      { mcpConfigPaths: [] },
      { root, selectedClosurePaths: [] },
    );
    expect(outcome).toEqual({ ok: true, mcpConfigPaths: [] });
  });

  it.each([
    "/abs/.mcp.json",
    "C:/tree/.mcp.json",
    "file:///.mcp.json",
    ".\\mcp.json",
    "../.mcp.json",
    "./.mcp.json",
    "skills//mcp.json",
    "",
  ])("refuses a path that is not source-relative POSIX: %s", (path) => {
    const root = fixture();
    const outcome = validateCiscoMcpScannerDetectorOptionsV1(
      { mcpConfigPaths: [path] },
      { root, selectedClosurePaths: [] },
    );
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.refusal.reason).toBe("detector-options-invalid");
  });

  it("refuses duplicate and over-bound path lists", () => {
    const root = fixture();
    write(root, ".mcp.json", serverConfig());

    const duplicate = validateCiscoMcpScannerDetectorOptionsV1(
      { mcpConfigPaths: [".mcp.json", ".mcp.json"] },
      { root, selectedClosurePaths: [] },
    );
    expect(duplicate).toMatchObject({
      ok: false,
      refusal: { reason: "detector-options-invalid" },
    });

    const overBound = validateCiscoMcpScannerDetectorOptionsV1(
      {
        mcpConfigPaths: Array.from(
          { length: MCP_DECLARED_CONFIG_PATHS_MAX_V1 + 1 },
          () => ".mcp.json",
        ),
      },
      { root, selectedClosurePaths: [] },
    );
    expect(overBound).toMatchObject({
      ok: false,
      refusal: { reason: "detector-options-invalid" },
    });
  });

  it("refuses names outside Core's incoming config set, and configs under non-skill dirs", () => {
    const root = fixture();
    write(root, "random.json", "{}");
    write(root, "docs/mcp.json", "{}");
    write(root, "skills/clean/SKILL.md", "# Clean\n");
    write(root, "skills/clean/.cursor/mcp.json", "{}");

    const request = { root, selectedClosurePaths: ["skills/clean/SKILL.md"] };
    for (const path of ["random.json", "docs/mcp.json", ".cursor/mcp.json/extra"]) {
      const outcome = validateCiscoMcpScannerDetectorOptionsV1({ mcpConfigPaths: [path] }, request);
      expect(outcome.ok).toBe(false);
      if (!outcome.ok) expect(outcome.refusal.reason).toBe("detector-options-invalid");
    }

    // A config under a selected SKILL.md directory, including a nested config name.
    expect(
      validateCiscoMcpScannerDetectorOptionsV1(
        { mcpConfigPaths: ["skills/clean/.cursor/mcp.json"] },
        request,
      ).ok,
    ).toBe(true);
    // The nested name matches as a whole, so `skills/clean/.cursor/mcp.json` is not
    // treated as a bare `mcp.json` under the non-skill dir `skills/clean/.cursor`:
    // declare it via a skill-less prefix and it is refused.
    write(root, "other/.cursor/mcp.json", "{}");
    expect(
      validateCiscoMcpScannerDetectorOptionsV1(
        { mcpConfigPaths: ["other/.cursor/mcp.json"] },
        request,
      ).ok,
    ).toBe(false);
  });

  it("refuses a path that does not exist in the sealed tree", () => {
    const root = fixture();
    const outcome = validateCiscoMcpScannerDetectorOptionsV1(
      { mcpConfigPaths: [".mcp.json"] },
      { root, selectedClosurePaths: [] },
    );
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.refusal.reason).toBe("detector-options-invalid");
      expect(outcome.refusal.detail).toContain("does not exist");
    }
  });

  it("accepts a declared directory (Core handles it as a malformed config)", () => {
    const root = fixture();
    mkdirSync(join(root, ".mcp.json"), { recursive: true });
    expect(lstatSync(join(root, ".mcp.json")).isDirectory()).toBe(true);

    const validated = validateCiscoMcpScannerDetectorOptionsV1(
      { mcpConfigPaths: [".mcp.json"] },
      { root, selectedClosurePaths: [] },
    );
    expect(validated.ok).toBe(true);

    const derived = deriveCiscoMcpToolsV1(root, [".mcp.json"]);
    expect(derived.status).toBe("derived");
    if (derived.status !== "derived") return;
    expect(derived.manifest.tools).toEqual([
      {
        name: ".mcp.json:malformed",
        description: "Malformed MCP config declared in .mcp.json",
        inputSchema: { type: "object", properties: {} },
      },
    ]);
  });
});

describe("validateCiscoMcpScannerDetectorOptionsV1 shares trust-lint's §2.1 path rules", () => {
  // One validator for both detectors: Core's discovery order (root first,
  // then each selected SKILL.md directory in localeCompare order, names in
  // Core's incoming order) and assertSafeRelativePosixPathV1 semantics.
  function tree(): { root: string; selectedClosurePaths: string[] } {
    const root = fixture();
    for (const dir of ["a", "a-b", "odd%41", "skills/x"]) write(root, `${dir}/SKILL.md`, "# S\n");
    for (const path of [
      ".mcp.json",
      "mcp.json",
      "a/.mcp.json",
      "a-b/.mcp.json",
      "odd%41/.mcp.json",
      "skills/x/.mcp.json",
      "skills/x/mcp.json",
    ]) {
      write(root, path, serverConfig());
    }
    return {
      root,
      selectedClosurePaths: ["a-b/SKILL.md", "a/SKILL.md", "odd%41/SKILL.md", "skills/x/SKILL.md"],
    };
  }

  it("accepts paths in Core's discovery order", () => {
    const request = tree();
    const mcpConfigPaths = [
      ".mcp.json",
      "mcp.json",
      "a/.mcp.json",
      "a-b/.mcp.json",
      "skills/x/.mcp.json",
      "skills/x/mcp.json",
    ];
    expect(validateCiscoMcpScannerDetectorOptionsV1({ mcpConfigPaths }, request)).toEqual({
      ok: true,
      mcpConfigPaths,
    });
  });

  it.each([
    [["mcp.json", ".mcp.json"]],
    [["skills/x/.mcp.json", ".mcp.json"]],
    [["a-b/.mcp.json", "a/.mcp.json"]],
    [["skills/x/mcp.json", "skills/x/.mcp.json"]],
  ])("refuses paths out of Core's discovery order: %j", (mcpConfigPaths) => {
    const outcome = validateCiscoMcpScannerDetectorOptionsV1({ mcpConfigPaths }, tree());
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.refusal.reason).toBe("detector-options-invalid");
    expect(outcome.refusal.detail).toContain("discovery order");
  });

  it.each([
    ["odd%41/.mcp.json"],
    ["sk\u0001/.mcp.json"],
  ])("refuses a path assertSafeRelativePosixPathV1 rejects: %j", (path) => {
    const outcome = validateCiscoMcpScannerDetectorOptionsV1({ mcpConfigPaths: [path] }, tree());
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.refusal.reason).toBe("detector-options-invalid");
    expect(outcome.refusal.detail).toContain("safe source-relative POSIX path");
    // The refusal is bounded and free of control characters (§8.4).
    expect(/[\p{C}]/u.test(outcome.refusal.detail)).toBe(false);
  });
});

describe("deriveCiscoMcpToolsV1 (C2a §4.2, verbatim from Core mcpStaticTools)", () => {
  it("consumes exactly the declared paths, in declared order, never discovered ones", () => {
    const root = fixture();
    write(root, ".mcp.json", serverConfig("root config"));
    write(root, "mcp.json", serverConfig("second declared"));
    write(root, "opencode.json", serverConfig("present but not declared"));

    const derived = deriveCiscoMcpToolsV1(root, ["mcp.json", ".mcp.json"]);

    expect(derived.status).toBe("derived");
    if (derived.status !== "derived") return;
    expect(derived.manifest.tools.map((tool) => tool.name)).toEqual([
      "mcp.json:local",
      ".mcp.json:local",
    ]);
    expect(serializeMcpToolsManifestV1(derived.manifest)).toBe(
      `${JSON.stringify({ tools: derived.manifest.tools }, null, 2)}\n`,
    );
  });

  it("matches golden mcp-configs ordering across the four config shapes", () => {
    const root = fixture();
    write(root, ".mcp.json", JSON.stringify({ mcpServers: { a: {}, b: {}, c: {} } }));
    write(root, "opencode.json", JSON.stringify({ mcp: { x: {}, y: {} } }));
    write(root, "mcp.json", JSON.stringify({ servers: { s: {} } }));
    write(root, "skills/mcp-skill/SKILL.md", "# Skill\n");
    write(root, "skills/mcp-skill/.mcp.json", JSON.stringify({ mcpServers: { nested: {} } }));

    const derived = deriveCiscoMcpToolsV1(root, [
      ".mcp.json",
      "opencode.json",
      "mcp.json",
      "skills/mcp-skill/.mcp.json",
    ]);

    expect(derived.status).toBe("derived");
    if (derived.status !== "derived") return;
    expect(derived.manifest.tools.map((tool) => tool.name)).toEqual([
      ".mcp.json:a",
      ".mcp.json:b",
      ".mcp.json:c",
      "opencode.json:x",
      "opencode.json:y",
      "mcp.json:s",
      "skills_mcp-skill_.mcp.json:nested",
    ]);
    expect(derived.manifest.sourceUriByToolName.get("skills_mcp-skill_.mcp.json:nested")).toBe(
      "skills/mcp-skill/.mcp.json",
    );
  });

  it("yields one malformed placeholder tool for an unparseable declared config", () => {
    const root = fixture();
    write(root, ".mcp.json", "{ not json");

    const derived = deriveCiscoMcpToolsV1(root, [".mcp.json"]);
    expect(derived.status).toBe("derived");
    if (derived.status !== "derived") return;
    expect(derived.manifest.tools.map((tool) => tool.name)).toEqual([".mcp.json:malformed"]);
  });

  it("ignores non-object maps and non-object documents like Core", () => {
    const root = fixture();
    write(root, ".mcp.json", JSON.stringify({ mcpServers: "nope", servers: 42, mcp: null }));
    write(root, "mcp.json", JSON.stringify(["not", "an", "object"]));

    const derived = deriveCiscoMcpToolsV1(root, [".mcp.json", "mcp.json"]);
    expect(derived).toEqual({
      status: "refused",
      refusal: {
        reason: "subject-requirement-unmet",
        detail: "mcp-scanner received an MCP config with no scannable tools",
      },
    });
  });

  it("refuses a duplicate derived tool name before spawning", () => {
    const root = fixture();
    write(root, ".mcp.json", JSON.stringify({ mcpServers: { local: {} }, servers: { local: {} } }));

    const derived = deriveCiscoMcpToolsV1(root, [".mcp.json"]);
    expect(derived).toEqual({
      status: "refused",
      refusal: {
        reason: "subject-requirement-unmet",
        detail: "derived duplicate MCP tool name: .mcp.json:local",
      },
    });
  });
});

describe("planCiscoMcpScannerRequestV1 (C2a §4 request flow)", () => {
  it("refuses invalid options before deriving anything", () => {
    const root = fixture();
    const outcome = planCiscoMcpScannerRequestV1({
      root,
      selectedClosurePaths: [],
      detectorOptions: { wrong: [] },
      platform: "linux",
      env: {},
      inputPath: join(root, "work", "tools.json"),
    });
    expect(outcome.status).toBe("refused");
    if (outcome.status !== "refused") return;
    expect(outcome.refusal.reason).toBe("detector-options-invalid");
  });

  it("refuses a declared set that yields no scannable tools", () => {
    const root = fixture();
    write(root, ".mcp.json", JSON.stringify({}));
    const outcome = planCiscoMcpScannerRequestV1({
      root,
      selectedClosurePaths: [],
      detectorOptions: { mcpConfigPaths: [".mcp.json"] },
      platform: "linux",
      env: {},
      inputPath: join(root, "work", "tools.json"),
    });
    expect(outcome).toEqual({
      status: "refused",
      refusal: {
        reason: "subject-requirement-unmet",
        detail: "mcp-scanner received an MCP config with no scannable tools",
      },
    });
  });

  it("plans the §4.3 argv and manifest bytes from the declared paths", () => {
    const root = fixture();
    write(root, ".mcp.json", serverConfig("local fixture"));
    write(root, "opencode.json", serverConfig("not declared"));
    const inputPath = join(root, "work", "tools.json");

    const outcome = planCiscoMcpScannerRequestV1({
      root,
      selectedClosurePaths: [],
      detectorOptions: { mcpConfigPaths: [".mcp.json"] },
      platform: "linux",
      env: { PATH: "bin", GITHUB_TOKEN: "ghp_fixture_not_a_secret" },
      inputPath,
    });

    expect(outcome.status).toBe("planned");
    if (outcome.status !== "planned") return;
    expect(outcome.plan.argv.slice(-6)).toEqual([
      "--raw",
      "--analyzers",
      "yara",
      "static",
      "--tools",
      inputPath,
    ]);
    expect(outcome.plan.env).toEqual({ PATH: "bin" });
    expect(outcome.plan.timeoutMs).toBe(120_000);
    expect(outcome.plan.toolCount).toBe(1);
    expect(outcome.plan.inputBytes).toContain(".mcp.json:local");
    expect(outcome.plan.inputBytes).not.toContain("opencode");
    expect(outcome.plan.sourceUriByToolName.get(".mcp.json:local")).toBe(".mcp.json");
    expect(Object.isFrozen(outcome.plan)).toBe(true);
  });
});
