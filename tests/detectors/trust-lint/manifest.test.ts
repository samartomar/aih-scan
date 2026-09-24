import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildTrustLintTreeV1 } from "../../../src/detectors/trust-lint/inventory.js";
import { scanTrustManifestsV1 } from "../../../src/detectors/trust-lint/manifest.js";

/**
 * Parity port of Core's `tests/trust/manifest.test.ts` against
 * `scanTrustManifestsV1(buildTrustLintTreeV1(dir))`. Identical fixtures and
 * asserted outputs; only the wiring changed.
 */
let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "aih-trust-manifest-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function write(rel: string, content: string): void {
  const path = join(dir, rel);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content, "utf8");
}

function scan() {
  return scanTrustManifestsV1(buildTrustLintTreeV1(dir));
}

function codes(): string[] {
  return scan().map((check) => check.code);
}

describe("scanTrustManifestsV1 (parity: Core scanTrustManifests)", () => {
  it.each([
    [
      "array Bash(*)",
      "skills/bash-array/SKILL.md",
      "---\nallowed-tools:\n  - Bash(*)\n---\n# X\n",
      "trust.permission-risk",
    ],
    [
      "flow Bash(*)",
      "agents/bash-flow.md",
      "---\nallowed-tools: [Read, Bash(*)]\n---\n# Agent\n",
      "trust.permission-risk",
    ],
    [
      "quoted Bash(*)",
      "commands/bash-quoted.md",
      "---\nallowed-tools: ['Bash(*)']\n---\n# Command\n",
      "trust.permission-risk",
    ],
    [
      "comma-scalar Bash(*)",
      "skills/bash-comma/SKILL.md",
      "---\nallowed-tools: Read, Write, Bash(*)\n---\n# X\n",
      "trust.permission-risk",
    ],
    [
      "scoped Bash wildcard",
      "skills/bash-scoped/SKILL.md",
      "---\nallowed-tools: Bash(rm:*)\n---\n# X\n",
      "trust.permission-risk",
    ],
    [
      "block scalar Bash(*)",
      "skills/bash-block/SKILL.md",
      "---\nallowed-tools: |\n  Read, Write, Bash(*)\n---\n# X\n",
      "trust.permission-risk",
    ],
    [
      "bare Bash",
      "skills/bash-bare/SKILL.md",
      "---\nallowed-tools: Bash\n---\n# X\n",
      "trust.permission-risk",
    ],
    [
      "permissionMode bypass",
      "skills/bypass/SKILL.md",
      "---\npermissionMode: bypassPermissions\n---\n# X\n",
      "trust.auto-exec-hook",
    ],
    [
      "dangerously skip permissions",
      "skills/danger/SKILL.md",
      "---\ndangerously-skip-permissions: true\n---\n# X\n",
      "trust.auto-exec-hook",
    ],
    ["bang auto-run", "skills/bang/SKILL.md", "# Bang\n\n  !npm install\n", "trust.auto-exec-hook"],
    [
      "malformed frontmatter",
      "skills/bad-yaml/SKILL.md",
      "---\nallowed-tools: [\n---\n# X\n",
      "trust.auto-exec-hook",
    ],
  ])("classifies skill frontmatter/body behavior: %s", (_name, rel, content, code) => {
    write(rel, content);

    const [check] = scan();

    expect(check).toMatchObject({
      verdict: "fail",
      code,
      location: expect.objectContaining({ uri: rel }),
    });
    expect(check?.fingerprint).toMatch(
      /^trust-(?:auto-exec-hook|permission-risk):.+:[0-9a-f]{64}$/,
    );
  });

  it("keeps auto-exec identity stable when only its display line shifts", () => {
    write("skills/bang/SKILL.md", "# Bang\n!npm install\n");
    const first = scan().find((check) => check.detail.includes("leading ! auto-run line"));

    write("skills/bang/SKILL.md", "# Bang\nUnrelated prose\n!npm install\n");
    const shifted = scan().find((check) => check.detail.includes("leading ! auto-run line"));

    expect(first?.location.startLine).toBe(2);
    expect(shifted?.location.startLine).toBe(3);
    expect(shifted?.fingerprint).toBe(first?.fingerprint);
  });

  it.each([
    [
      "unresolved alias",
      "skills/alias-missing/SKILL.md",
      "---\nallowed-tools: *missing\n---\n# X\n",
    ],
    [
      "alias expansion bomb",
      "skills/alias-bomb/SKILL.md",
      [
        "---",
        "a: &a [LOL, LOL, LOL, LOL, LOL, LOL, LOL, LOL, LOL]",
        "b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]",
        "c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b]",
        "d: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c]",
        "allowed-tools: *d",
        "---",
        "# X",
      ].join("\n"),
    ],
  ])("fails closed without throwing on YAML alias frontmatter: %s", (_name, rel, content) => {
    write(rel, content);

    let checks: ReturnType<typeof scan> = [];
    expect(() => {
      checks = scan();
    }).not.toThrow();

    expect(checks).toEqual([
      expect.objectContaining({
        verdict: "fail",
        code: "trust.auto-exec-hook",
        detail: expect.stringContaining("unparseable YAML frontmatter in trust document"),
        location: expect.objectContaining({ uri: rel, startLine: 1 }),
      }),
    ]);
  });

  it("does not flag benign comma-scalar allowed-tools", () => {
    write("skills/clean-comma/SKILL.md", "---\nallowed-tools: Read, Write\n---\n# Clean\n");

    expect(scan()).toEqual([]);
  });

  it("fails closed on map-shaped allowed-tools frontmatter", () => {
    write("skills/map-allowed-tools/SKILL.md", "---\nallowed-tools:\n  Bash(*): true\n---\n# X\n");

    const [check] = scan();

    expect(check).toMatchObject({
      verdict: "fail",
      code: "trust.auto-exec-hook",
      detail: expect.stringContaining("allowed-tools"),
      location: expect.objectContaining({ uri: "skills/map-allowed-tools/SKILL.md" }),
    });
  });

  it.each([
    ["postinstall", { scripts: { postinstall: "node setup.js" } }],
    ["preinstall", { scripts: { preinstall: "node setup.js" } }],
    ["install", { scripts: { install: "node setup.js" } }],
    ["prepare", { scripts: { prepare: "node setup.js" } }],
    ["prepublish", { scripts: { prepublish: "node setup.js" } }],
  ])("flags package lifecycle script %s", (_script, pkg) => {
    write("package.json", JSON.stringify(pkg));

    expect(codes()).toContain("trust.auto-exec-hook");
  });

  it("classifies prepublishOnly as reviewable publish permission, not install auto-exec", () => {
    write("package.json", JSON.stringify({ scripts: { prepublishOnly: "npm run build" } }));

    expect(scan()).toEqual([
      expect.objectContaining({
        code: "trust.permission-risk",
        detail: expect.stringContaining("prepublishOnly"),
      }),
    ]);
  });

  it("fails closed on unparseable package.json", () => {
    write("package.json", "{");

    expect(codes()).toContain("trust.auto-exec-hook");
  });

  it("flags npmrc ignore-scripts=false", () => {
    write(".npmrc", "ignore-scripts = false\n");

    expect(codes()).toContain("trust.auto-exec-hook");
  });

  it("flags Claude hooks directory", () => {
    mkdirSync(join(dir, ".claude", "hooks"), { recursive: true });

    expect(codes()).toContain("trust.auto-exec-hook");
  });

  it.each(["settings.json", ".claude/settings.json"])("flags hooks key in %s", (rel) => {
    write(rel, JSON.stringify({ hooks: { Stop: [] } }));

    expect(codes()).toContain("trust.auto-exec-hook");
  });

  it("does not treat markdown image syntax as bang auto-run", () => {
    write("skills/image/SKILL.md", "# Image\n\n![diagram](./x.png)\n");

    expect(scan()).toEqual([]);
  });

  it.each([
    "!input.is_empty()",
    "!isOwner(user)",
  ])("does not treat boolean negation as a bang auto-run directive: %s", (expression) => {
    write("skills/boolean/SKILL.md", `# Boolean example\n\n\`\`\`rust\n${expression}\n\`\`\`\n`);

    expect(scan()).toEqual([]);
  });

  it("does not treat a multiline boolean-negation continuation as bang auto-run", () => {
    write(
      "skills/quarkus-security/SKILL.md",
      [
        "# Quarkus authorization example",
        "```java",
        'if (!securityIdentity.hasRole("admin") &&',
        "    !isOwner(id, securityIdentity.getPrincipal().getName())) {",
        "  throw new ForbiddenException();",
        "}",
        "```",
      ].join("\n"),
    );

    expect(scan()).toEqual([]);
  });

  it("does not interpret translated documentation mirrors as executable manifests", () => {
    write("docs/ja-JP/agents/go-reviewer.md", "---\nname: [invalid\n---\n# Translation\n");
    write(
      "docs/tr/skills/quarkus-security/SKILL.md",
      "# Translation\n```java\n!isOwner(id, principal)) {\n```\n",
    );

    expect(scan()).toEqual([]);
  });

  it("still flags non-image bang auto-run lines", () => {
    write("skills/bang-command/SKILL.md", "# Bang\n\n!somecommand\n");

    expect(codes()).toContain("trust.auto-exec-hook");
  });

  it("passes a clean tree", () => {
    write("skills/clean/SKILL.md", "---\nallowed-tools:\n  - Read\n---\n# Clean\n");
    write("package.json", JSON.stringify({ scripts: { test: "vitest run" } }));
    write(".npmrc", "ignore-scripts=true\n");

    expect(scan()).toEqual([]);
  });

  // YAML features only the real `yaml` parser (Core's parser) handles; the
  // expectations below are what Core produces with the same parseDocument
  // semantics.
  it("detects a Bash wildcard behind a resolvable anchor/alias", () => {
    write(
      "skills/anchored/SKILL.md",
      "---\ncommon: &tools [Read, Bash(*)]\nallowed-tools: *tools\n---\n# X\n",
    );

    const [check] = scan();

    expect(check).toMatchObject({
      verdict: "fail",
      code: "trust.permission-risk",
      detail: expect.stringContaining("broad Bash permission"),
      location: expect.objectContaining({ uri: "skills/anchored/SKILL.md" }),
    });
  });

  it("parses frontmatter with comments like Core", () => {
    write(
      "skills/commented-yaml/SKILL.md",
      "---\n# leading comment\nallowed-tools: Read, Write # trailing comment\n---\n# Clean\n",
    );

    expect(scan()).toEqual([]);
  });

  it("detects quoted frontmatter keys like Core", () => {
    write("skills/quoted-key/SKILL.md", '---\n"permissionMode": bypassPermissions\n---\n# X\n');

    const [check] = scan();

    expect(check).toMatchObject({
      verdict: "fail",
      code: "trust.auto-exec-hook",
      detail: expect.stringContaining("permissionMode bypasses permissions"),
      location: expect.objectContaining({ uri: "skills/quoted-key/SKILL.md", startLine: 1 }),
    });
  });

  it("detects a Bash wildcard in a folded multi-line scalar", () => {
    write("skills/folded/SKILL.md", "---\nallowed-tools: >\n  Read, Write,\n  Bash(*)\n---\n# X\n");

    const [check] = scan();

    expect(check).toMatchObject({
      verdict: "fail",
      code: "trust.permission-risk",
      detail: expect.stringContaining("broad Bash permission"),
      location: expect.objectContaining({ uri: "skills/folded/SKILL.md" }),
    });
  });

  it("fails closed on a flow-mapping allowed-tools value", () => {
    write("skills/flow-map/SKILL.md", "---\nallowed-tools: {Bash(*): true}\n---\n# X\n");

    const [check] = scan();

    expect(check).toMatchObject({
      verdict: "fail",
      code: "trust.auto-exec-hook",
      detail: expect.stringContaining("invalid map shape"),
      location: expect.objectContaining({ uri: "skills/flow-map/SKILL.md" }),
    });
  });
});
