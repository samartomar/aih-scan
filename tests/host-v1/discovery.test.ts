import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { scanWith } from "../../src/host/scan.js";
import type { ToolAdapter } from "../../src/host/tools.js";
import { scan } from "../../src/public/host.js";
import { readSummary } from "../../src/public/read.js";
import { type FixtureRoot, fixtureRoot } from "../support/scan-v1-fixture.js";

let fixture: FixtureRoot;
beforeEach(() => {
  fixture = fixtureRoot("aih-scan-v1-discovery-");
});
afterEach(() => fixture.dispose());

const fixedNow = () => new Date("2026-11-01T00:30:00.000Z");
const sourceRequest = (path: string, extra: Record<string, unknown> = {}) => ({
  format: "aih-scan-request/1",
  origin: "local",
  source: { type: "folder", path },
  ...extra,
});

/** A SkillSpector stand-in that ran with no findings, so coverage can be complete. */
const ranSkillSpector: ToolAdapter = {
  id: "skillspector",
  version: "2.13.2",
  async run() {
    return { status: "ran", version: "2.13.2", mode: "static", findings: [] };
  },
};
const complete = { adapters: { skillspector: ranSkillSpector }, now: fixedNow };

type Result = Awaited<ReturnType<typeof scan>>;
function byPath(result: Result) {
  return Object.fromEntries(
    result.results.map((entry) => [`${entry.kind ?? "?"}:${entry.path}`, entry]),
  );
}
function summaryOf(entry: Result["results"][number] | undefined) {
  if (entry?.status !== "ok")
    throw new Error(`expected a scanned result: ${JSON.stringify(entry)}`);
  const read = readSummary(new Uint8Array(readFileSync(entry.summaryPath)));
  if (read.status !== "ok") throw new Error(JSON.stringify(read));
  return read.summary;
}

const skill = (name: string, extra: Record<string, string> = {}) => ({
  [`${name}/SKILL.md`]: `---\nname: ${name.split("/").at(-1)}\ndescription: fixture\n---\n# Skill\n\nSummarise text.\n`,
  ...extra,
});

/** One source holding every recognised layout plus remaining files. */
const multiLayout = {
  ...skill("skills/alpha", {
    "skills/alpha/rules/style.md": "Keep answers short.\n",
    "skills/alpha/agents/openai.yaml": "name: alpha\n",
    "skills/alpha/nested/SKILL.md": "---\nname: nested\ndescription: inner\n---\n# Inner\n",
  }),
  ...skill(".kiro/skills/alpha", {
    ".kiro/skills/alpha/rules/style.md": "Keep answers short.\n",
    ".kiro/skills/alpha/agents/openai.yaml": "name: alpha\n",
    ".kiro/skills/alpha/nested/SKILL.md": "---\nname: nested\ndescription: inner\n---\n# Inner\n",
  }),
  ...skill("docs/ja-JP/skills/alpha", {
    "docs/ja-JP/skills/alpha/rules/style.md": "回答は短く。\n",
  }),
  "agents/reviewer.md": "# Reviewer\n\nReview the diff.\n",
  ".kiro/agents/reviewer.json": '{ "name": "reviewer", "prompt": "Review the diff." }\n',
  ".codex/agents/reviewer.toml": 'name = "reviewer"\nprompt = "Review the diff."\n',
  "commands/ship.md": "# Ship\n\nRun the checks.\n",
  "rules/common.md": "Be precise.\n",
  "rules/typescript/style.md": "Prefer const.\n",
  ".cursor/rules/style.mdc": "---\ndescription: style\n---\nPrefer const.\n",
  ".kiro/steering/product.md": "# Product\n\nWe build tools.\n",
  "hooks/hooks.json":
    '{ "hooks": { "Stop": [ { "hooks": [ { "type": "command", "command": "./hooks/stop.sh" } ] } ] } }\n',
  "hooks/stop.sh": "#!/bin/sh\necho stop\n",
  "hooks/hooks.cursor.json": "{}\n",
  "config/hooks.json": '{ "hooks": { "Stop": [ { "command": "echo hi" } ] } }\n',
  ".mcp.json":
    '{ "mcpServers": { "fs": { "command": "npx", "args": ["-y", "@scope/fs@1.0.0"] } } }\n',
  "servers/mcp.json": '{ "mcpServers": { "web": { "url": "https://example.invalid/mcp" } } }\n',
  ".claude-plugin/plugin.json": '{ "name": "fixture" }\n',
  ".claude-plugin/marketplace.json": '{ "name": "fixture" }\n',
  "README.md": "# Fixture repository\n",
};

describe("source route discovery for a folder", () => {
  it("finds every layout anywhere, applies ownership and gives one result per item plus remaining files", async () => {
    const root = fixture.folder("repo", multiLayout, ["hooks/stop.sh"]);
    const result = await scanWith(sourceRequest(root), { outDir: fixture.path("out") }, complete);
    expect(result.status).toBe("ok");
    const found = byPath(result);
    expect(Object.keys(found).sort()).toEqual(
      [
        "agent:.codex/agents/reviewer.toml",
        "agent:.kiro/agents/reviewer.json",
        "agent:agents/reviewer.md",
        "command:commands/ship.md",
        "hook:config/hooks.json",
        "hook:hooks",
        "mcp:.mcp.json",
        "mcp:servers/mcp.json",
        "remaining-files:.",
        "rule:.cursor/rules/style.mdc",
        "rule:.kiro/steering/product.md",
        "rule:rules/common.md",
        "rule:rules/typescript/style.md",
        "skill:.kiro/skills/alpha",
        "skill:docs/ja-JP/skills/alpha",
        "skill:skills/alpha",
      ].sort(),
    );
    // The outermost skill owns nested skills, rules and agents; the folder is kept whole.
    expect(summaryOf(found["skill:skills/alpha"]).files.map((file) => file.path)).toEqual([
      "SKILL.md",
      "agents/openai.yaml",
      "nested/SKILL.md",
      "rules/style.md",
    ]);
    // A hooks folder is one item with its scripts and variant files; modes are kept.
    expect(
      summaryOf(found["hook:hooks"]).files.map((file) => [file.path, file.mode, file.part]),
    ).toEqual([
      ["hooks.cursor.json", "100644", "text"],
      ["hooks.json", "100644", "config"],
      ["stop.sh", "100755", "code"],
    ]);
    // A single-file item is a one-file folder.
    expect(summaryOf(found["agent:.kiro/agents/reviewer.json"]).files).toMatchObject([
      { path: "reviewer.json", part: "text" },
    ]);
    // plugin.json, marketplace.json and everything unrecognised are the remaining files.
    expect(summaryOf(found["remaining-files:."]).files.map((file) => file.path)).toEqual([
      ".claude-plugin/marketplace.json",
      ".claude-plugin/plugin.json",
      "README.md",
    ]);
    // Identical copies share a key and are scanned once; a different copy has its own key.
    const alpha = found["skill:skills/alpha"];
    const kiro = found["skill:.kiro/skills/alpha"];
    const ja = found["skill:docs/ja-JP/skills/alpha"];
    if (alpha?.status !== "ok" || kiro?.status !== "ok" || ja?.status !== "ok")
      throw new Error("expected scanned skills");
    expect(kiro.scanKey).toBe(alpha.scanKey);
    expect(kiro.summaryPath).toBe(alpha.summaryPath);
    expect(ja.scanKey).not.toBe(alpha.scanKey);
    // Pins: the folder, the item path inside it; never in the summary.
    expect(alpha.source).toEqual({ type: "folder", path: root, item: "skills/alpha" });
    expect(readFileSync(alpha.summaryPath, "utf8")).not.toContain("skills/alpha");
    expect(result.rollup).toMatchObject({
      label: "SAFE",
      coverage: "complete",
      items: 16,
      partial: 0,
      notAssessed: 0,
      found: { skill: 3, agent: 3, command: 1, rule: 4, hook: 2, mcp: 2 },
      notSelected: {},
      remainingFiles: 3,
    });
  });

  it("gives each item the key it would have as a prepared folder, independent of order and siblings", async () => {
    const root = fixture.folder("repo", multiLayout, ["hooks/stop.sh"]);
    const first = byPath(
      await scanWith(sourceRequest(root), { outDir: fixture.path("out1") }, complete),
    );
    // Prepared copies of the same item-relative inventories.
    const prepared = await scanWith(
      {
        format: "aih-scan-request/1",
        origin: "local",
        items: [
          {
            path: fixture.folder("p/mdc", { "style.mdc": multiLayout[".cursor/rules/style.mdc"] }),
          },
          {
            path: fixture.folder("p/toml", {
              "reviewer.toml": multiLayout[".codex/agents/reviewer.toml"],
            }),
          },
          {
            path: fixture.folder("p/json", {
              "reviewer.json": multiLayout[".kiro/agents/reviewer.json"],
            }),
          },
        ],
      },
      { outDir: fixture.path("out2") },
      complete,
    );
    const pairs: [string, number][] = [
      ["rule:.cursor/rules/style.mdc", 0],
      ["agent:.codex/agents/reviewer.toml", 1],
      ["agent:.kiro/agents/reviewer.json", 2],
    ];
    for (const [key, index] of pairs) {
      const discovered = first[key];
      const handed = prepared.results[index];
      if (discovered?.status !== "ok" || handed?.status !== "ok") throw new Error(key);
      expect(handed.scanKey).toBe(discovered.scanKey);
      expect(readFileSync(handed.summaryPath)).toEqual(readFileSync(discovered.summaryPath));
    }
    // Changing a sibling changes only that sibling's key.
    writeFileSync(join(root, "agents", "reviewer.md"), "# Reviewer\n\nReview carefully.\n");
    const second = byPath(
      await scanWith(sourceRequest(root), { outDir: fixture.path("out3") }, complete),
    );
    for (const key of Object.keys(first)) {
      const before = first[key];
      const after = second[key];
      if (before?.status !== "ok" || after?.status !== "ok") throw new Error(key);
      if (key === "agent:agents/reviewer.md") expect(after.scanKey).not.toBe(before.scanKey);
      else expect(after.scanKey).toBe(before.scanKey);
    }
  });
});

describe("kinds filtering and the repository roll-up", () => {
  it("scans only selected kinds, counts the rest as not selected and marks the roll-up partial", async () => {
    const root = fixture.folder("repo", multiLayout, ["hooks/stop.sh"]);
    const result = await scanWith(
      sourceRequest(root, { kinds: ["hook", "skill"] }),
      { outDir: fixture.path("out") },
      complete,
    );
    expect(result.status).toBe("ok");
    expect(result.results.map((entry) => `${entry.kind}:${entry.path}`).sort()).toEqual([
      "hook:config/hooks.json",
      "hook:hooks",
      "skill:.kiro/skills/alpha",
      "skill:docs/ja-JP/skills/alpha",
      "skill:skills/alpha",
    ]);
    // Each selected item keeps its own coverage.
    for (const entry of result.results) expect(summaryOf(entry).coverage).toBe("complete");
    expect(result.rollup).toMatchObject({
      label: "SAFE",
      coverage: "partial",
      reason: "not selected",
      items: 5,
      notSelected: { agent: 3, command: 1, rule: 4, mcp: 2, "remaining-files": 1 },
    });
  });

  it("refuses an unknown kind as invalid", async () => {
    const root = fixture.folder("repo", multiLayout);
    const result = await scan(sourceRequest(root, { kinds: ["plugin"] }), {
      outDir: fixture.path("out"),
    });
    expect(result.status).toBe("invalid");
  });

  it("shows the remaining-files label when no items are found, and NOT ASSESSED when nothing is routable", async () => {
    const plain = fixture.folder("plain", {
      "setup.sh": "#!/bin/sh\necho aGk= | base64 -d | bash\n",
    });
    const result = await scanWith(sourceRequest(plain), { outDir: fixture.path("o1") }, complete);
    expect(result.results.map((entry) => entry.kind)).toEqual(["remaining-files"]);
    const remaining = summaryOf(result.results[0]);
    expect(result.rollup).toMatchObject({ label: remaining.label, items: 1, found: {} });
    expect(remaining.label).not.toBe("SAFE");

    const binary = fixture.folder("binary", { "image.png": new Uint8Array([0x89, 0, 1, 2]) });
    const none = await scanWith(sourceRequest(binary), { outDir: fixture.path("o2") }, complete);
    expect(summaryOf(none.results[0]).label).toBe("NOT ASSESSED");
    expect(none.rollup).toMatchObject({ label: "NOT ASSESSED", notAssessed: 1 });
  });

  it("counts partial and NOT ASSESSED outcomes, including the remaining files as one more item", async () => {
    // Default adapters: SkillSpector is unavailable, so routable items are partial.
    const root = fixture.folder("mixed", {
      ...skill("skills/a"),
      "rules/logo.png": new Uint8Array([0x89, 0, 1]),
      "notes.bin": new Uint8Array([0, 1, 2]),
    } as Record<string, string | Uint8Array>);
    const result = await scanWith(
      sourceRequest(root),
      { outDir: fixture.path("out") },
      {
        now: fixedNow,
      },
    );
    expect(result.status).toBe("ok");
    expect(result.rollup).toMatchObject({
      label: "CAUTION",
      coverage: "partial",
      reason: "unavailable",
      items: 3,
      partial: 1,
      notAssessed: 2,
    });
  });
});
