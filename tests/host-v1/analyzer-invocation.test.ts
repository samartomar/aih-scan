import { describe, expect, it } from "vitest";
import { readJsonStdout, selectAnalyzer } from "../../src/host/analyzer-process.js";
import { ciscoInvocation } from "../../src/host/cisco.js";
import { skillSpectorAiSetup, skillSpectorInvocation } from "../../src/host/skillspector.js";

// Command construction runs on every platform; installed-analyzer tests exercise the
// actual native transport when the pinned executables are provided.

const windowsEnv = {
  Path: "C:\\Users\\dev\\.local\\bin;C:\\Windows\\System32",
  PATHEXT: ".COM;.EXE;.BAT;.CMD",
  SystemRoot: "C:\\Windows",
  windir: "C:\\Windows",
  USERPROFILE: "C:\\Users\\dev",
  APPDATA: "C:\\Users\\dev\\AppData\\Roaming",
  HTTPS_PROXY: "http://proxy.invalid:3128",
  OPENAI_API_KEY: "sk-test-not-a-real-key",
  SKILLSPECTOR_PROVIDER: "openai",
  PYTHONPATH: "C:\\caller\\python",
};

describe("SkillSpector command construction", () => {
  it("accepts only complete UTF-8 JSON stdout reports", () => {
    expect(readJsonStdout({ stdout: '{"issues":[]}', truncated: false })).toEqual({ issues: [] });
    for (const stdout of ["", "{", 'progress\n{"issues":[]}'])
      expect(readJsonStdout({ stdout, truncated: false })).toBeUndefined();
    expect(readJsonStdout({ stdout: "{}", truncated: true })).toBeUndefined();
    expect(
      readJsonStdout({ stdout: "{}", truncated: false, stdoutMalformedUtf8: true }),
    ).toBeUndefined();
  });
  it("builds a shell-free Windows static run: .exe path, working copy input, --no-llm, scrubbed env", () => {
    const invocation = skillSpectorInvocation({
      executable: "C:\\Users\\dev\\.local\\bin\\skillspector.exe",
      mode: "static",
      folder: "C:\\Temp\\aih-scan-snapshot-x\\item",
      report: "C:\\Temp\\aih-scan-skillspector-y\\skillspector-report.json",
      scratch: "C:\\Temp\\aih-scan-skillspector-y",
      env: windowsEnv,
      platform: "win32",
    });
    expect(invocation.argv).toEqual([
      "C:\\Users\\dev\\.local\\bin\\skillspector.exe",
      "scan",
      "C:\\Temp\\aih-scan-snapshot-x\\item",
      "--format",
      "json",
      "--no-llm",
    ]);
    expect(invocation.cwd).toBe("C:\\Temp\\aih-scan-skillspector-y");
    expect(invocation.env).toEqual({
      PATH: windowsEnv.Path,
      PATHEXT: windowsEnv.PATHEXT,
      SYSTEMROOT: "C:\\Windows",
      WINDIR: "C:\\Windows",
      USERPROFILE: "C:\\Temp\\aih-scan-skillspector-y",
      APPDATA: "C:\\Temp\\aih-scan-skillspector-y",
      LOCALAPPDATA: "C:\\Temp\\aih-scan-skillspector-y",
      TEMP: "C:\\Temp\\aih-scan-skillspector-y",
      TMP: "C:\\Temp\\aih-scan-skillspector-y",
      PYTHONUTF8: "1",
      PYTHONIOENCODING: "utf-8",
      PYTHONDONTWRITEBYTECODE: "1",
      PYTHONNOUSERSITE: "1",
      NO_COLOR: "1",
      SKILLSPECTOR_OSV_TIMEOUT: "0",
    });
    for (const flag of ["--transitive", "--mcp-registry", "--use-shipped-baseline"])
      expect(invocation.argv.join(" ")).not.toContain(flag);
  });

  it("builds a Windows AI run that passes the caller's settings through, minus Python loader variables", () => {
    const invocation = skillSpectorInvocation({
      executable: "C:\\Users\\dev\\.local\\bin\\skillspector.exe",
      mode: "ai",
      folder: "C:\\Temp\\snap\\item",
      report: "C:\\Temp\\s\\r.json",
      scratch: "C:\\Temp\\s",
      env: windowsEnv,
      platform: "win32",
    });
    expect(invocation.argv).not.toContain("--no-llm");
    expect(invocation.env).toMatchObject({
      Path: windowsEnv.Path,
      USERPROFILE: "C:\\Users\\dev",
      HTTPS_PROXY: windowsEnv.HTTPS_PROXY,
      OPENAI_API_KEY: windowsEnv.OPENAI_API_KEY,
      SKILLSPECTOR_PROVIDER: "openai",
      SKILLSPECTOR_OSV_TIMEOUT: "0",
    });
    expect(invocation.env.PYTHONPATH).toBeUndefined();
  });

  it("builds the Cisco run from inside the working copy on Windows, static and offline", () => {
    const invocation = ciscoInvocation({
      executable: "C:\\tools\\skill-scanner.exe",
      folder: "C:\\Temp\\snap\\item",
      report: "C:\\Temp\\c\\cisco.json",
      scratch: "C:\\Temp\\c",
      env: windowsEnv,
      platform: "win32",
    });
    expect(invocation.argv).toEqual([
      "C:\\tools\\skill-scanner.exe",
      "scan",
      ".",
      "--use-behavioral",
      "--format",
      "json",
      "--output-json",
      "C:\\Temp\\c\\cisco.json",
    ]);
    expect(invocation.cwd).toBe("C:\\Temp\\snap\\item");
    expect(invocation.env.OPENAI_API_KEY).toBeUndefined();
    expect(invocation.env.HTTPS_PROXY).toBeUndefined();
    for (const flag of [
      "--use-llm",
      "--use-virustotal",
      "--use-aidefense",
      "--use-osv",
      "--enable-meta",
    ])
      expect(invocation.argv).not.toContain(flag);
  });

  it("accepts only <name>.exe as a selected Windows analyzer", () => {
    expect(
      selectAnalyzer(
        "skillspector",
        "AIH_SCAN_SKILLSPECTOR",
        {
          AIH_SCAN_SKILLSPECTOR: "C:\\tools\\skillspector.cmd",
        },
        "win32",
      ),
    ).toEqual({
      status: "missing",
      detail: "AIH_SCAN_SKILLSPECTOR does not name an executable skillspector",
    });
    expect(
      selectAnalyzer(
        "skillspector",
        "AIH_SCAN_SKILLSPECTOR",
        {
          AIH_SCAN_SKILLSPECTOR: "relative\\skillspector.exe",
        },
        "win32",
      ).status,
    ).toBe("missing");
  });
});

describe("SkillSpector AI setup (reads which settings exist, never their values)", () => {
  it.each([
    [{}, "SKILLSPECTOR_PROVIDER is not set"],
    [{ SKILLSPECTOR_PROVIDER: "codex_cli" }, "SkillSpector 2.13.3 disables the codex_cli provider"],
    [
      { SKILLSPECTOR_PROVIDER: "made_up" },
      "SKILLSPECTOR_PROVIDER names a provider SkillSpector does not support",
    ],
    [{ SKILLSPECTOR_PROVIDER: "openai" }, "OPENAI_API_KEY is not set for provider openai"],
    [
      {
        SKILLSPECTOR_PROVIDER: "openai_compatible",
        SKILLSPECTOR_COMPAT_BASE_URL: "https://api.deepseek.com",
        SKILLSPECTOR_MODEL: "deepseek-flash",
      },
      "SKILLSPECTOR_COMPAT_API_KEY is not set for provider openai_compatible",
    ],
    [
      { SKILLSPECTOR_PROVIDER: "openai_compatible", SKILLSPECTOR_COMPAT_API_KEY: "not-a-real-key" },
      "SKILLSPECTOR_COMPAT_BASE_URL is not set for provider openai_compatible",
    ],
    [
      { SKILLSPECTOR_PROVIDER: "azure_openai", AZURE_OPENAI_API_KEY: "x" },
      "AZURE_OPENAI_ENDPOINT is not set for provider azure_openai",
    ],
    [
      { SKILLSPECTOR_PROVIDER: "bedrock" },
      "AWS_PROFILE or AWS_ACCESS_KEY_ID is not set for provider bedrock",
    ],
    [
      { SKILLSPECTOR_PROVIDER: "gemini_cli", PATH: "/nonexistent" },
      "the gemini CLI for provider gemini_cli is not on PATH",
    ],
  ])("is not available for %j", (env, reason) => {
    expect(skillSpectorAiSetup(env, "linux")).toEqual({ available: false, reason });
  });

  it("classifies provider, local and OpenAI-compatible setups and keeps the caller's model", () => {
    expect(
      skillSpectorAiSetup({ SKILLSPECTOR_PROVIDER: "Anthropic ", ANTHROPIC_API_KEY: "k" }, "linux"),
    ).toEqual({ available: true, provider: "anthropic", via: "provider" });
    expect(
      skillSpectorAiSetup(
        { SKILLSPECTOR_PROVIDER: "ollama", SKILLSPECTOR_MODEL: "llama3" },
        "linux",
      ),
    ).toEqual({
      available: true,
      provider: "ollama",
      via: "local",
      model: "llama3",
    });
    expect(
      skillSpectorAiSetup(
        {
          SKILLSPECTOR_PROVIDER: "openai_compatible",
          SKILLSPECTOR_COMPAT_API_KEY: "local-placeholder",
          SKILLSPECTOR_COMPAT_BASE_URL: "http://127.0.0.1:8080/v1",
        },
        "linux",
      ),
    ).toMatchObject({ available: true, via: "local" });
    expect(
      skillSpectorAiSetup(
        {
          SKILLSPECTOR_PROVIDER: "openai_compatible",
          SKILLSPECTOR_COMPAT_API_KEY: "not-a-real-key",
          SKILLSPECTOR_COMPAT_BASE_URL: "https://api.example.com/v1",
        },
        "linux",
      ),
    ).toMatchObject({ available: true, via: "provider" });
  });

  it("keeps the selected DeepSeek model and caller controls in a native HTTP-provider invocation", () => {
    const settings = {
      SKILLSPECTOR_PROVIDER: "openai_compatible",
      SKILLSPECTOR_COMPAT_BASE_URL: "https://api.deepseek.com",
      SKILLSPECTOR_COMPAT_API_KEY: "not-a-real-key",
      SKILLSPECTOR_MODEL: "deepseek-flash",
      SKILLSPECTOR_REASONING_EFFORT: "none",
      SKILLSPECTOR_STRUCTURED_OUTPUT_METHOD: "function_calling",
    };
    const env = { ...windowsEnv, ...settings };
    expect(skillSpectorAiSetup(env, "win32")).toEqual({
      available: true,
      provider: "openai_compatible",
      via: "provider",
      model: "deepseek-flash",
    });
    const invocation = skillSpectorInvocation({
      executable: "C:\\tools\\skillspector.exe",
      mode: "ai",
      folder: "C:\\Temp\\snapshot\\item",
      report: "C:\\Temp\\report.json",
      scratch: "C:\\Temp\\scratch",
      env,
      platform: "win32",
    });
    expect(invocation.env).toMatchObject(settings);
    expect(invocation.argv).not.toContain("--no-llm");
  });
});
