import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, expect, type TestContext, test } from "vitest";
import { runScan } from "../../src/assessment/run.js";
import { runScanCommand, type ScanCommandIo } from "../../src/cli/scan-command.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});
/** A disposable directory. The real path keeps expectations independent of tmpdir links. */
function fixture(files: Record<string, string> = {}): string {
  const root = realpathSync.native(mkdtempSync(join(tmpdir(), "aih-scan-inputs-test-")));
  roots.push(root);
  for (const [name, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, name)), { recursive: true });
    writeFileSync(join(root, name), text);
  }
  return root;
}
function harness(extra: Partial<ScanCommandIo> = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const io: ScanCommandIo = {
    stdout: (text) => out.push(text),
    stderr: (text) => err.push(text),
    ...extra,
  };
  return { io, stdout: () => out.join(""), stderr: () => err.join("") };
}
/** The detectors of one built request, as `[detectorId, configuration]` pairs. */
function requestedConfigurations(requests: unknown[]): [string, unknown][] {
  return (requests as { detectors: { detectorId: string; configuration: unknown }[] }[]).flatMap(
    (request) =>
      request.detectors.map((detector): [string, unknown] => [
        detector.detectorId,
        detector.configuration,
      ]),
  );
}
function observing(requests: unknown[]): Partial<ScanCommandIo> {
  return {
    runScan: (request, options) => {
      requests.push(request);
      return runScan(request, options);
    },
  };
}

test("discovers MCP configuration at the root and in skill directories, in Core order", async () => {
  const parent = fixture({
    // Decoy: the target's parent is outside the target and never discovered.
    ".mcp.json": "{}\n",
    "target/.mcp.json": "{}\n",
    "target/.cursor/mcp.json": "{}\n",
    "target/opencode.json": "{}\n",
    "target/mcp.json": "{}\n",
    "target/skills/alpha/SKILL.md": "# Alpha\n",
    "target/skills/alpha/.mcp.json": "{}\n",
    "target/skills/alpha/mcp.json": "{}\n",
    // Decoy: a config in a directory without a SKILL.md is never discovered.
    "target/docs/mcp.json": "{}\n",
    // Decoy: the root .git is omitted, exactly as capture omits it.
    "target/.git/mcp.json": "{}\n",
    "target/notes.txt": "notes\n",
  });
  const target = join(parent, "target");
  const requests: unknown[] = [];
  const run = harness(observing(requests));
  expect(await runScanCommand([target], run.io)).toBe(0);
  expect(requestedConfigurations(requests)).toEqual([
    ["detector.aih-native", {}],
    [
      "detector.aih-trust-lint",
      {
        internalScopes: [],
        mcpConfigPaths: [
          ".mcp.json",
          ".cursor/mcp.json",
          "opencode.json",
          "mcp.json",
          "skills/alpha/.mcp.json",
          "skills/alpha/mcp.json",
        ],
      },
    ],
  ]);
});

test("a discovered .mcp.json with a hardcoded secret yields mcp.hardcoded-secret without leaking the value", async () => {
  const secret = `ghp_${"a1".repeat(18)}`;
  const root = fixture({
    ".mcp.json": `${JSON.stringify({
      mcpServers: { demo: { env: { GITHUB_TOKEN: secret } } },
    })}\n`,
    "SKILL.md": "# Fixture\n",
  });
  const run = harness();
  expect(await runScanCommand([root], run.io)).toBe(0);
  expect(run.stdout()).toContain("mcp.hardcoded-secret");
  expect(run.stdout()).not.toContain(secret);
  expect(run.stderr()).not.toContain(secret);
});

test("explicit --mcp-config values, relative or absolute, are accepted in any order and sorted into Core order", async () => {
  const root = fixture({
    ".mcp.json": "{}\n",
    "mcp.json": "{}\n",
    "skills/alpha/SKILL.md": "# Alpha\n",
    "skills/alpha/mcp.json": "{}\n",
  });
  const requests: unknown[] = [];
  const run = harness(observing(requests));
  expect(
    await runScanCommand(
      [
        root,
        "--detector",
        "detector.aih-trust-lint",
        "--mcp-config",
        "skills/alpha/mcp.json",
        "--mcp-config",
        join(root, "mcp.json"),
        "--mcp-config",
        ".mcp.json",
      ],
      run.io,
    ),
  ).toBe(0);
  expect(requestedConfigurations(requests)).toEqual([
    [
      "detector.aih-trust-lint",
      {
        internalScopes: [],
        mcpConfigPaths: [".mcp.json", "mcp.json", "skills/alpha/mcp.json"],
      },
    ],
  ]);
});

test("detector.cisco-mcp-scanner takes exactly { mcpConfigPaths } from the same inputs", async () => {
  const root = fixture({ "mcp.json": "{}\n" });
  const requests: unknown[] = [];
  const run = harness(observing(requests));
  // The scanner itself is unavailable in this host; the built request is what matters.
  expect(
    await runScanCommand(
      [root, "--detector", "detector.cisco-mcp-scanner", "--mcp-config", "mcp.json"],
      run.io,
    ),
  ).toBe(1);
  expect(requestedConfigurations(requests)).toEqual([
    ["detector.cisco-mcp-scanner", { mcpConfigPaths: ["mcp.json"] }],
  ]);
});

/** A harness whose runScan must never be called, recording any call. */
function refusing(calls: unknown[]): Partial<ScanCommandIo> {
  return {
    runScan: async (request) => {
      calls.push(request);
      throw new Error("a refused command must not run a scan");
    },
  };
}

test.each([
  ["an escape through ..", "../.mcp.json"],
  ["../..", "../../.mcp.json"],
])("--mcp-config refuses %s", async (_name, value) => {
  const parent = fixture({ ".mcp.json": "{}\n", "target/mcp.json": "{}\n" });
  const target = join(parent, "target");
  const calls: unknown[] = [];
  const run = harness(refusing(calls));
  expect(
    await runScanCommand(
      [target, "--detector", "detector.aih-trust-lint", "--mcp-config", value],
      run.io,
    ),
  ).toBe(2);
  expect(run.stderr()).toMatch(/^aih-scan: /);
  expect(run.stderr()).toContain("outside the target directory");
  expect(run.stdout()).toBe("");
  expect(calls).toEqual([]);
});

test("--mcp-config refuses an absolute path outside the target", async () => {
  const parent = fixture({ ".mcp.json": "{}\n", "target/mcp.json": "{}\n" });
  const target = join(parent, "target");
  const calls: unknown[] = [];
  const run = harness(refusing(calls));
  expect(
    await runScanCommand(
      [target, "--detector", "detector.aih-trust-lint", "--mcp-config", join(parent, ".mcp.json")],
      run.io,
    ),
  ).toBe(2);
  expect(run.stderr()).toContain("outside the target directory");
  expect(calls).toEqual([]);
});

test("a contained name merely starting with .. is not an escape; the validator still rejects the name", async () => {
  const root = fixture({ "..mcp.json": "{}\n", "mcp.json": "{}\n" });
  const calls: unknown[] = [];
  const run = harness(refusing(calls));
  expect(
    await runScanCommand(
      [root, "--detector", "detector.aih-trust-lint", "--mcp-config", "..mcp.json"],
      run.io,
    ),
  ).toBe(2);
  expect(run.stderr()).not.toContain("outside the target directory");
  expect(run.stderr()).toContain("is not an incoming MCP config name");
  expect(calls).toEqual([]);
});

test("--mcp-config refuses a path through a linked directory", async (context) => {
  const root = fixture({ "real/SKILL.md": "# Alpha\n", "real/mcp.json": "{}\n" });
  try {
    symlinkSync(join(root, "real"), join(root, "linked"), "junction");
  } catch {
    return context.skip();
  }
  const calls: unknown[] = [];
  const run = harness(refusing(calls));
  expect(
    await runScanCommand(
      [root, "--detector", "detector.aih-trust-lint", "--mcp-config", "linked/mcp.json"],
      run.io,
    ),
  ).toBe(2);
  expect(run.stderr()).toContain("linked or non-directory parent");
  expect(calls).toEqual([]);
});

test("--mcp-config refuses a path through a regular file", async () => {
  const root = fixture({ "notes.txt": "notes\n" });
  const calls: unknown[] = [];
  const run = harness(refusing(calls));
  expect(
    await runScanCommand(
      [root, "--detector", "detector.aih-trust-lint", "--mcp-config", "notes.txt/mcp.json"],
      run.io,
    ),
  ).toBe(2);
  expect(run.stderr()).toContain("linked or non-directory parent");
  expect(calls).toEqual([]);
});

test("--mcp-config refuses a nonexistent entry", async () => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const calls: unknown[] = [];
  const run = harness(refusing(calls));
  expect(
    await runScanCommand(
      [root, "--detector", "detector.aih-trust-lint", "--mcp-config", "mcp.json"],
      run.io,
    ),
  ).toBe(2);
  expect(run.stderr()).toContain("does not exist inside the target");
  expect(calls).toEqual([]);
});

test("--mcp-config refuses duplicates, even spelled differently", async () => {
  const root = fixture({ ".mcp.json": "{}\n" });
  const calls: unknown[] = [];
  const run = harness(refusing(calls));
  expect(
    await runScanCommand(
      [
        root,
        "--detector",
        "detector.aih-trust-lint",
        "--mcp-config",
        ".mcp.json",
        "--mcp-config",
        join(root, ".mcp.json"),
      ],
      run.io,
    ),
  ).toBe(2);
  expect(run.stderr()).toContain("duplicates an earlier --mcp-config");
  expect(calls).toEqual([]);
});

test("--mcp-config refuses an existing name the validator rejects (not a skill directory)", async () => {
  const root = fixture({ "docs/mcp.json": "{}\n" });
  const calls: unknown[] = [];
  const run = harness(refusing(calls));
  expect(
    await runScanCommand(
      [root, "--detector", "detector.aih-trust-lint", "--mcp-config", "docs/mcp.json"],
      run.io,
    ),
  ).toBe(2);
  expect(run.stderr()).toContain("is not an incoming MCP config name");
  expect(calls).toEqual([]);
});

test("discovery never walks into a linked directory", async (context) => {
  const root = fixture({
    "mcp.json": "{}\n",
    "real/SKILL.md": "# Alpha\n",
    "real/mcp.json": "{}\n",
  });
  try {
    symlinkSync(join(root, "real"), join(root, "linked"), "junction");
  } catch {
    return context.skip();
  }
  const requests: unknown[] = [];
  const run = harness(observing(requests));
  // The directory-link leaves the detectors refused (partial); the built request matters.
  await runScanCommand([root, "--detector", "detector.aih-trust-lint"], run.io);
  expect(requestedConfigurations(requests)).toEqual([
    [
      "detector.aih-trust-lint",
      { internalScopes: [], mcpConfigPaths: ["mcp.json", "real/mcp.json"] },
    ],
  ]);
});

test("--internal-scope values normalize like Core and produce a real trust.dependency-confusion finding", async () => {
  const root = fixture({
    "package.json": `${JSON.stringify({
      name: "fixture",
      version: "1.0.0",
      dependencies: { "@acme/widget": "1.0.0", "@zeta/tool": "1.0.0" },
    })}\n`,
  });
  const requests: unknown[] = [];
  const run = harness(observing(requests));
  expect(
    await runScanCommand(
      [
        root,
        "--detector",
        "detector.aih-trust-lint",
        "--internal-scope",
        " Zeta",
        "--internal-scope",
        "@acme",
        "--internal-scope",
        "ACME",
      ],
      run.io,
    ),
  ).toBe(0);
  expect(requestedConfigurations(requests)).toEqual([
    ["detector.aih-trust-lint", { internalScopes: ["@acme", "@zeta"], mcpConfigPaths: [] }],
  ]);
  expect(run.stdout()).toContain("trust.dependency-confusion");
});

test("--internal-scope refuses a value that is not a normalized scope", async () => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const calls: unknown[] = [];
  const run = harness(refusing(calls));
  expect(
    await runScanCommand(
      [root, "--detector", "detector.aih-trust-lint", "--internal-scope", "not a scope!"],
      run.io,
    ),
  ).toBe(2);
  expect(run.stderr()).toMatch(/^aih-scan: /);
  expect(run.stderr()).toContain("is not a normalized internal scope");
  expect(run.stdout()).toBe("");
  expect(calls).toEqual([]);
});

test("--mcp-config with no selected MCP-reading detector fails closed before running", async () => {
  const root = fixture({ "mcp.json": "{}\n" });
  const calls: unknown[] = [];
  const run = harness(refusing(calls));
  expect(
    await runScanCommand(
      [root, "--detector", "detector.aih-native", "--mcp-config", "mcp.json"],
      run.io,
    ),
  ).toBe(2);
  expect(run.stderr()).toMatch(/^aih-scan: /);
  expect(run.stderr()).toContain("requires a selected detector that reads MCP configuration");
  expect(run.stdout()).toBe("");
  expect(calls).toEqual([]);
});

test.each([
  ["detector.aih-native"],
  ["detector.cisco-mcp-scanner"],
])("--internal-scope without detector.aih-trust-lint fails closed before running (%s)", async (detectorId) => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const calls: unknown[] = [];
  const run = harness(refusing(calls));
  expect(
    await runScanCommand([root, "--detector", detectorId, "--internal-scope", "@acme"], run.io),
  ).toBe(2);
  expect(run.stderr()).toMatch(/^aih-scan: /);
  expect(run.stderr()).toContain("requires detector.aih-trust-lint to be selected");
  expect(run.stdout()).toBe("");
  expect(calls).toEqual([]);
});

test("missing specialized inputs are reported as notes in the human output", async () => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const run = harness();
  expect(await runScanCommand([root], run.io)).toBe(0);
  const lines = run.stdout().split("\n");
  expect(lines).toContain("Inputs (2):");
  expect(lines).toContain(
    "  detector.aih-trust-lint: no MCP configuration found inside the target",
  );
  expect(lines).toContain("  detector.aih-trust-lint: no internal scopes supplied");
});

test("with --json the notes go to stderr as aih-scan: note: lines and stdout stays the result", async () => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const run = harness();
  expect(await runScanCommand(["--json", root], run.io)).toBe(0);
  expect(run.stderr()).toContain(
    "aih-scan: note: detector.aih-trust-lint: no MCP configuration found inside the target\n",
  );
  expect(run.stderr()).toContain(
    "aih-scan: note: detector.aih-trust-lint: no internal scopes supplied\n",
  );
  const written = JSON.parse(run.stdout());
  expect(written.status).toBe("assessment");
});

test("discovered MCP configuration paths are reported as a note", async () => {
  const root = fixture({ ".mcp.json": "{}\n", "mcp.json": "{}\n", "SKILL.md": "# Fixture\n" });
  const run = harness();
  expect(await runScanCommand(["--detector", "detector.aih-trust-lint", root], run.io)).toBe(0);
  expect(run.stdout()).toContain(
    "  detector.aih-trust-lint: discovered MCP configuration inside the target: .mcp.json, mcp.json",
  );
  expect(run.stdout()).not.toContain("no MCP configuration found");
});

test("supplied MCP configuration paths are reported as a note", async () => {
  const root = fixture({ "mcp.json": "{}\n" });
  const run = harness();
  expect(
    await runScanCommand(
      [root, "--detector", "detector.aih-trust-lint", "--mcp-config", "mcp.json"],
      run.io,
    ),
  ).toBe(0);
  expect(run.stdout()).toContain(
    "  detector.aih-trust-lint: using supplied MCP configuration: mcp.json",
  );
});

test("a scan without specialized inputs says Inputs: none", async () => {
  const root = fixture({ "SKILL.md": "# Fixture\n" });
  const run = harness();
  expect(await runScanCommand(["--detector", "detector.aih-native", root], run.io)).toBe(0);
  expect(run.stdout().split("\n")).toContain("Inputs: none");
});

/** Links `path` to the directory `target`; false where the platform cannot create the link. */
function linkDirectory(target: string, path: string): boolean {
  try {
    symlinkSync(target, path, "junction");
    return true;
  } catch {
    return false;
  }
}
/** The trust-lint detector alone, with explicit `--mcp-config` values. */
function trustLintWithConfigs(target: string, ...configs: string[]): string[] {
  return [
    target,
    "--detector",
    "detector.aih-trust-lint",
    ...configs.flatMap((config) => ["--mcp-config", config]),
  ];
}

test("--mcp-config accepts an absolute path spelled through a link in an ancestor of the target", async (context) => {
  const parent = fixture({ "real/target/mcp.json": "{}\n" });
  if (!linkDirectory(join(parent, "real"), join(parent, "alias"))) return context.skip();
  const requests: unknown[] = [];
  const run = harness(observing(requests));
  expect(
    await runScanCommand(
      trustLintWithConfigs(
        join(parent, "real", "target"),
        join(parent, "alias", "target", "mcp.json"),
      ),
      run.io,
    ),
  ).toBe(0);
  expect(requestedConfigurations(requests)).toEqual([
    ["detector.aih-trust-lint", { internalScopes: [], mcpConfigPaths: ["mcp.json"] }],
  ]);
});

test("--mcp-config accepts an absolute path spelled through a link to the target itself", async (context) => {
  const parent = fixture({ "target/skill/SKILL.md": "# S\n", "target/skill/mcp.json": "{}\n" });
  if (!linkDirectory(join(parent, "target"), join(parent, "alias"))) return context.skip();
  const requests: unknown[] = [];
  const run = harness(observing(requests));
  expect(
    await runScanCommand(
      trustLintWithConfigs(join(parent, "target"), join(parent, "alias", "skill", "mcp.json")),
      run.io,
    ),
  ).toBe(0);
  expect(requestedConfigurations(requests)).toEqual([
    ["detector.aih-trust-lint", { internalScopes: [], mcpConfigPaths: ["skill/mcp.json"] }],
  ]);
});

test("--mcp-config refuses an aliased absolute path that never reaches the target", async (context) => {
  const parent = fixture({ "real/target/mcp.json": "{}\n", "real/other/mcp.json": "{}\n" });
  if (!linkDirectory(join(parent, "real"), join(parent, "alias"))) return context.skip();
  const calls: unknown[] = [];
  const run = harness(refusing(calls));
  expect(
    await runScanCommand(
      trustLintWithConfigs(
        join(parent, "real", "target"),
        join(parent, "alias", "other", "mcp.json"),
      ),
      run.io,
    ),
  ).toBe(2);
  expect(run.stderr()).toContain("outside the target directory");
  expect(calls).toEqual([]);
});

/** An aliased absolute path whose components below the target include a link: always refused. */
async function expectLinkInsideTargetRefused(
  context: TestContext,
  linkName: string,
  linkTarget: (target: string) => string,
): Promise<void> {
  const parent = fixture({
    "real/target/inner/SKILL.md": "# S\n",
    "real/target/inner/mcp.json": "{}\n",
  });
  const target = join(parent, "real", "target");
  if (
    !linkDirectory(join(parent, "real"), join(parent, "alias")) ||
    !linkDirectory(linkTarget(target), join(target, linkName))
  )
    return context.skip();
  const calls: unknown[] = [];
  const run = harness(refusing(calls));
  expect(
    await runScanCommand(
      trustLintWithConfigs(target, join(parent, "alias", "target", linkName, "mcp.json")),
      run.io,
    ),
  ).toBe(2);
  expect(run.stderr()).toContain("linked or non-directory parent");
  expect(calls).toEqual([]);
}
test("--mcp-config refuses an aliased absolute path through a link inside the target", async (context) => {
  await expectLinkInsideTargetRefused(context, "link", (target) => join(target, "inner"));
});
test("--mcp-config refuses an aliased absolute path through a link inside the target that points back at the target", async (context) => {
  await expectLinkInsideTargetRefused(context, "loop", (target) => target);
});

test("discovery ignores a SKILL.md directory, so its sibling configuration is not discovered", async () => {
  const root = fixture({ "skill/SKILL.md/.keep": "", "skill/mcp.json": "{}\n" });
  const requests: unknown[] = [];
  const run = harness(observing(requests));
  expect(await runScanCommand([root, "--detector", "detector.aih-trust-lint"], run.io)).toBe(0);
  expect(requestedConfigurations(requests)).toEqual([
    ["detector.aih-trust-lint", { internalScopes: [], mcpConfigPaths: [] }],
  ]);
  expect(run.stdout()).toContain("detector.aih-trust-lint: succeeded");
});

test("discovery ignores a SKILL.md that links to a directory, so its sibling configuration is not discovered", async (context) => {
  const root = fixture({ "other/.keep": "", "skill/mcp.json": "{}\n" });
  if (!linkDirectory(join(root, "other"), join(root, "skill", "SKILL.md"))) return context.skip();
  const requests: unknown[] = [];
  const run = harness(observing(requests));
  // The detector refuses any directory link in its source ("unsupported-source-entry"), so
  // the scan is partial. What matters is that the request itself is valid: nothing was
  // discovered for a directory that capture does not treat as a skill directory.
  expect(await runScanCommand([root, "--detector", "detector.aih-trust-lint"], run.io)).toBe(1);
  expect(requestedConfigurations(requests)).toEqual([
    ["detector.aih-trust-lint", { internalScopes: [], mcpConfigPaths: [] }],
  ]);
  expect(run.stdout()).toContain("unsupported-source-entry");
  expect(run.stdout()).not.toContain("detector-options-invalid");
});

test("discovery treats a SKILL.md that links to a file as marking a skill directory", async (context) => {
  const root = fixture({ "docs/skill-text.md": "# S\n", "skill/mcp.json": "{}\n" });
  try {
    symlinkSync(join(root, "docs", "skill-text.md"), join(root, "skill", "SKILL.md"), "file");
  } catch {
    return context.skip();
  }
  const requests: unknown[] = [];
  const run = harness(observing(requests));
  expect(await runScanCommand([root, "--detector", "detector.aih-trust-lint"], run.io)).toBe(0);
  expect(requestedConfigurations(requests)).toEqual([
    ["detector.aih-trust-lint", { internalScopes: [], mcpConfigPaths: ["skill/mcp.json"] }],
  ]);
});

test("discovery lists a path once when the root and a skill directory both name it", async () => {
  // `.cursor/mcp.json` is a root name and also `mcp.json` inside a `.cursor` skill directory.
  const root = fixture({ ".cursor/SKILL.md": "# S\n", ".cursor/mcp.json": "{}\n" });
  const requests: unknown[] = [];
  const run = harness(observing(requests));
  expect(await runScanCommand([root, "--detector", "detector.aih-trust-lint"], run.io)).toBe(0);
  expect(requestedConfigurations(requests)).toEqual([
    ["detector.aih-trust-lint", { internalScopes: [], mcpConfigPaths: [".cursor/mcp.json"] }],
  ]);
});
