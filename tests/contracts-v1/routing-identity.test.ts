import { describe, expect, it } from "vitest";
import { routeFile, scanKeyOf, sha256Hex } from "../../src/public/contracts.js";

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
    expect(await scanKeyOf([{ path: ".mcp.json", mode: "100644", bytes: file }])).toBe(
      "git-sha1:23f948e8a00fa0cb22c78c7c51eeb6f0a6f7cb44",
    );
  });

  it("matches Git's own tree hashes, including nesting, modes and ordering", async () => {
    // Expected values computed independently with `git mktree`/`git write-tree`.
    expect(await scanKeyOf([])).toBe("git-sha1:4b825dc642cb6eb9a060e54bf8d69288fbee4904");
    const key = await scanKeyOf([
      { path: "a.b", mode: "100644", bytes: bytes("x\n") },
      { path: "a/c", mode: "100755", bytes: bytes("y\n") },
    ]);
    expect(key).toBe(GIT_NESTED_KEY);
    const reordered = await scanKeyOf([
      { path: "a/c", mode: "100755", bytes: bytes("y\n") },
      { path: "a.b", mode: "100644", bytes: bytes("x\n") },
    ]);
    expect(reordered).toBe(key);
    const modeChanged = await scanKeyOf([
      { path: "a.b", mode: "100644", bytes: bytes("x\n") },
      { path: "a/c", mode: "100644", bytes: bytes("y\n") },
    ]);
    expect(modeChanged).not.toBe(key);
  });
});

// git: printf 'x\n' > a.b; mkdir a; printf 'y\n' > a/c; chmod +x a/c; git add -A; git write-tree
const GIT_NESTED_KEY = "git-sha1:4a891ed6f66d0326f32b7db82d30665294eb7cd3";
