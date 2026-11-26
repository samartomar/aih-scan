import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "vitest";

const executable = process.env.AIH_SCAN_TEST_SKILLSPECTOR;
const fixture = fileURLToPath(new URL("../offline/provider-batching.py", import.meta.url));

describe.runIf(executable)("offline provider wire requests", () => {
  it.each([
    ["openai", "gpt-5"],
    ["azure_openai", "gpt-4o"],
    ["openai_compatible", "llama-3.1-70b-versatile"],
    ["anthropic", "claude-sonnet-4-6"],
    ["anthropic_proxy", "claude-sonnet-4-6"],
    ["bedrock", "us.anthropic.claude-sonnet-4-6"],
    ["nv_build", "z-ai/glm-5.3-flash"],
    ["nv_inference", "z-ai/glm-5.3-flash"],
    ["ollama", "llama3.1:8b"],
    ["gemini_cli", "gemini-2.5-pro"],
    ["opencode_cli", "anthropic/claude-sonnet-4-6"],
  ])(
    "%s groups eligible inputs into one attributable request",
    (provider, model) => {
      const root = mkdtempSync(join(tmpdir(), "scan-batching-test-"));
      try {
        const python = join(
          dirname(executable ?? ""),
          process.platform === "win32" ? "python.exe" : "python",
        );
        // Exercise a wider group on one route to catch a fixed item-count ceiling.
        const count = provider === "openai" ? "40" : "2";
        const deployment = provider === "azure_openai" ? ["test-deployment"] : [];
        execFileSync(python, ["-I", fixture, provider, model, count, ...deployment], {
          cwd: root,
          env: {
            PATH: process.env.PATH,
            SystemRoot: process.env.SystemRoot,
            HOME: root,
            USERPROFILE: root,
            TEMP: root,
            TMP: root,
          },
          timeout: 90_000,
          windowsHide: true,
          stdio: "pipe",
        });
      } finally {
        rmSync(root, { recursive: true, force: true });
      }
    },
    95_000,
  );
});
