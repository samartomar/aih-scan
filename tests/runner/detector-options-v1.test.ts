import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  detectorOptionsSealRefusalV1,
  readDetectorOptionsV1,
} from "../../src/runner/detector-options-v1.js";
import { runDetectorV1 } from "../../src/runner/run-detector-v1.js";

/**
 * C2a §2.1, §3.3, §4.1: `detectorOptions` is validated strictly per detector, snapshotted
 * once, never coerced, and refused with `detector-options-invalid` before anything is read.
 */

const temporaryDirectories: string[] = [];
afterEach(() => {
  for (const directory of temporaryDirectories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

function sourceFixture(): string {
  const root = mkdtempSync(join(tmpdir(), "aih-scan-detector-options-"));
  temporaryDirectories.push(root);
  writeFileSync(join(root, "README.md"), "# Readme\n", "utf8");
  return root;
}

const selection = ["README.md", "skills/a/SKILL.md", "skills/b/SKILL.md"];

function refusal(detectorId: string, options: unknown, selected = selection): string | undefined {
  const read = readDetectorOptionsV1(detectorId, options, selected);
  return read.ok ? undefined : read.detail;
}

describe("readDetectorOptionsV1", () => {
  it("accepts absent options for detectors that take none, and refuses any value there", () => {
    for (const detectorId of ["detector.semgrep", "detector.skillspector", "detector.aih-native"]) {
      expect(readDetectorOptionsV1(detectorId, undefined, selection)).toEqual({
        ok: true,
        options: undefined,
      });
      expect(refusal(detectorId, {})).toMatch(/takes no detectorOptions/);
      expect(refusal(detectorId, { concurrency: 4 })).toMatch(/takes no detectorOptions/);
    }
  });

  it("refuses cisco concurrency, valid or not, because no profile applies it yet", () => {
    for (const valid of [1, 4, 64])
      expect(refusal("detector.cisco", { concurrency: valid }), String(valid)).toMatch(
        /concurrency is not applied by this profile/,
      );
    expect(readDetectorOptionsV1("detector.cisco", undefined, selection)).toEqual({
      ok: true,
      options: undefined,
    });
    for (const bad of [0, 65, 1.5, "4", Number.NaN, null, -1])
      expect(refusal("detector.cisco", { concurrency: bad }), String(bad)).toMatch(
        /concurrency must be a whole number from 1 to 64/,
      );
    expect(refusal("detector.cisco", {})).toMatch(/missing concurrency/);
    expect(refusal("detector.cisco", { concurrency: 4, extra: 1 })).toMatch(/unknown key extra/);
    expect(refusal("detector.cisco", [4])).toMatch(/must be a plain object/);
    expect(refusal("detector.cisco", "x")).toMatch(/must be a plain object/);
  });

  it("requires trust-lint options with normalized internal scopes", () => {
    const ok = readDetectorOptionsV1(
      "detector.aih-trust-lint",
      { internalScopes: ["@acme", "@acme.internal"], mcpConfigPaths: [] },
      selection,
    );
    expect(ok).toEqual({
      ok: true,
      options: { internalScopes: ["@acme", "@acme.internal"], mcpConfigPaths: [] },
    });
    expect(refusal("detector.aih-trust-lint", undefined)).toMatch(/requires detectorOptions/);
    expect(refusal("detector.aih-trust-lint", { internalScopes: [] })).toMatch(
      /missing mcpConfigPaths/,
    );
    for (const scope of ["@My", "acme", "@ acme", "@", " @acme", "@acme/x", 7])
      expect(
        refusal("detector.aih-trust-lint", { internalScopes: [scope], mcpConfigPaths: [] }),
        String(scope),
      ).toMatch(/internalScopes/);
    expect(
      refusal("detector.aih-trust-lint", { internalScopes: ["@b", "@a"], mcpConfigPaths: [] }),
    ).toMatch(/sorted/);
    expect(
      refusal("detector.aih-trust-lint", { internalScopes: ["@a", "@a"], mcpConfigPaths: [] }),
    ).toMatch(/sorted|unique/);
    expect(
      refusal("detector.aih-trust-lint", {
        internalScopes: Array.from({ length: 257 }, (_, i) => `@s${String(i).padStart(3, "0")}`),
        mcpConfigPaths: [],
      }),
    ).toMatch(/at most 256/);
  });

  it("accepts MCP config paths only under the root or a selected skill directory, in discovery order", () => {
    const valid = [
      ".mcp.json",
      ".vscode/mcp.json",
      "mcp.json",
      "skills/a/.cursor/mcp.json",
      "skills/a/opencode.json",
      "skills/b/.kiro/settings/mcp.json",
      "skills/b/mcp-configs/mcp-servers.json",
    ];
    for (const detectorId of ["detector.aih-trust-lint", "detector.cisco-mcp-scanner"]) {
      const options =
        detectorId === "detector.aih-trust-lint"
          ? { internalScopes: [], mcpConfigPaths: valid }
          : { mcpConfigPaths: valid };
      expect(readDetectorOptionsV1(detectorId, options, selection).ok, detectorId).toBe(true);
    }
    const mcp = (paths: unknown) =>
      refusal("detector.cisco-mcp-scanner", { mcpConfigPaths: paths });
    expect(mcp(["skills/c/mcp.json"])).toMatch(
      /not an MCP config name under the root or a selected skill directory/,
    );
    expect(mcp(["docs/mcp.json"])).toMatch(/not an MCP config name/);
    expect(mcp(["servers.json"])).toMatch(/not an MCP config name/);
    expect(mcp(["mcp.json", ".mcp.json"])).toMatch(/discovery order/);
    expect(mcp(["skills/b/mcp.json", "skills/a/mcp.json"])).toMatch(/discovery order/);
    expect(mcp(["mcp.json", "mcp.json"])).toMatch(/discovery order|unique/);
    for (const unsafe of ["/mcp.json", "../mcp.json", "skills\\a\\mcp.json", "./mcp.json", ""])
      expect(mcp([unsafe]), unsafe).toBeDefined();
    expect(mcp(Array.from({ length: 1025 }, () => "mcp.json"))).toMatch(/at most 1024/);
    expect(refusal("detector.cisco-mcp-scanner", undefined)).toMatch(/requires detectorOptions/);
    expect(
      refusal("detector.cisco-mcp-scanner", { mcpConfigPaths: [], internalScopes: [] }),
    ).toMatch(/unknown key internalScopes/);
  });

  it("reads each caller field once and keeps no reference to caller arrays", () => {
    let reads = 0;
    const scopes = ["@a"];
    const options = {
      get internalScopes() {
        reads += 1;
        return scopes;
      },
      mcpConfigPaths: [],
    };
    const read = readDetectorOptionsV1("detector.aih-trust-lint", options, selection);
    expect(reads).toBe(1);
    scopes.push("@z");
    expect(read.ok && read.options).toEqual({ internalScopes: ["@a"], mcpConfigPaths: [] });
    const hostile = {
      get concurrency(): number {
        throw new Error("boom");
      },
    };
    expect(refusal("detector.cisco", hostile)).toMatch(
      /could not be read: reading concurrency threw: boom/,
    );
  });

  it("refuses a config path that the sealed tree does not hold", () => {
    const entries = [
      { kind: "file" as const, path: "mcp.json" },
      { kind: "directory" as const, path: "skills" },
      { kind: "directory" as const, path: "skills/a" },
      { kind: "directory" as const, path: "skills/a/opencode.json" },
    ];
    expect(
      detectorOptionsSealRefusalV1(
        { mcpConfigPaths: ["mcp.json", "skills/a/opencode.json"] },
        entries,
      ),
    ).toBeUndefined();
    expect(detectorOptionsSealRefusalV1({ mcpConfigPaths: [".mcp.json"] }, entries)).toMatch(
      /\.mcp\.json does not exist in the sealed source tree/,
    );
    expect(detectorOptionsSealRefusalV1({ concurrency: 2 }, entries)).toBeUndefined();
    expect(detectorOptionsSealRefusalV1(undefined, [])).toBeUndefined();
  });
});

describe("runDetectorV1 detectorOptions boundary", () => {
  it("refuses options for a detector that takes none, before sealing", async () => {
    const result = await runDetectorV1({
      detectorId: "detector.semgrep",
      executionProfileId: "host-process-uv-v1",
      subject: {
        kind: "source-tree",
        sourceRoot: join(tmpdir(), "does-not-exist-aih"),
        selectedClosurePaths: ["x"],
      },
      detectorOptions: { concurrency: 2 },
    });
    expect(result.outcome).toBe("refused");
    if (result.outcome !== "refused") return;
    expect(result.reason).toBe("detector-options-invalid");
    expect(result.detail).toMatch(/detector\.semgrep takes no detectorOptions/);
  });

  it("refuses Cisco concurrency, out of range or not, since no Cisco profile applies it", async () => {
    const root = sourceFixture();
    const bad = await runDetectorV1({
      detectorId: "detector.cisco",
      subject: { kind: "skill-directory", sourceRoot: root, selectedClosurePaths: ["README.md"] },
      detectorOptions: { concurrency: 65 },
    });
    expect(bad.outcome === "refused" && bad.reason).toBe("detector-options-invalid");
    const good = await runDetectorV1({
      detectorId: "detector.cisco",
      subject: { kind: "skill-directory", sourceRoot: root, selectedClosurePaths: ["README.md"] },
      detectorOptions: { concurrency: 4 },
    });
    expect(good.outcome === "refused" && good.reason).toBe("detector-options-invalid");
    expect(good.outcome === "refused" && good.detail).toMatch(
      /concurrency is not applied by this profile/,
    );
    for (const executionProfileId of ["linux-namespace-uv-v1", "host-process-uv-v1"]) {
      const named = await runDetectorV1({
        detectorId: "detector.cisco",
        executionProfileId,
        subject: { kind: "skill-directory", sourceRoot: root, selectedClosurePaths: ["README.md"] },
        detectorOptions: { concurrency: 1 },
      });
      expect(named.outcome === "refused" && named.reason, executionProfileId).toBe(
        "detector-options-invalid",
      );
    }
  });

  it("refuses a detectorOptions accessor that throws as an unreadable option, not a rejection", async () => {
    const request = {
      detectorId: "detector.cisco",
      subject: {
        kind: "skill-directory",
        sourceRoot: sourceFixture(),
        selectedClosurePaths: ["README.md"],
      },
      get detectorOptions(): unknown {
        throw new Error("nope");
      },
    };
    const result = await runDetectorV1(request);
    expect(result.outcome).toBe("refused");
  });

  it("does not let a skill directory elsewhere widen the MCP config rule", () => {
    const root = sourceFixture();
    mkdirSync(join(root, "skills", "a"), { recursive: true });
    expect(
      refusal("detector.cisco-mcp-scanner", { mcpConfigPaths: ["skills/a/mcp.json"] }, [
        "README.md",
      ]),
    ).toMatch(/not an MCP config name/);
  });
});
