import { type ChildProcess, execFileSync, type SpawnOptions } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { join, resolve } from "node:path";
import { afterAll, expect, it } from "vitest";
import { runUnderWindowsJobV1 } from "../../src/cli/windows-job-supervisor.js";
import { staticAnalyzerEnv } from "../../src/host/analyzer-process.js";
import { scanWith } from "../../src/host/scan.js";
import { SKILLSPECTOR_MAINTENANCE_VERSION } from "../../src/host/skillspector.js";
import { readSummary } from "../../src/public/read.js";
import { fakeAnalyzer, skillSpectorReport } from "./analyzer-cli-v1.js";
import { fixtureRoot } from "./scan-v1-fixture.js";

// [DEBUG-retro-native] Temporary bounded module-autoload diagnosis; removed before merge.
const fixture = fixtureRoot("aih-ps-module-diagnostic-");
afterAll(() => fixture.dispose());
const systemRoot = process.env.SystemRoot ?? "C:\\Windows";
const powershell = join(systemRoot, "System32/WindowsPowerShell/v1.0/powershell.exe");
const moduleRoot = join(systemRoot, "System32/WindowsPowerShell/v1.0/Modules");
const report = (value: unknown) => process.stdout.write(`${JSON.stringify(value)}\n`);
const explicitImport =
  "Import-Module ([IO.Path]::Combine($PSHOME, 'Modules\\Microsoft.PowerShell.Utility\\Microsoft.PowerShell.Utility.psd1'))";
const sourceText = readFileSync(
  resolve(import.meta.dirname, "../../src/cli/windows-job-supervisor.ts"),
  "utf8",
);
const source = sourceText.match(/const SUPERVISOR_CSHARP = String.raw`([\s\S]*?)`;/u)?.[1];
if (!source) throw new Error("Supervisor source unavailable for exact diagnostic environment");
let selected: "module-path" | "explicit-import" | undefined;
const childProcesses = createRequire(import.meta.url)(
  "node:child_process",
) as typeof import("node:child_process");
const originalSpawn = childProcesses.spawn;
Object.defineProperty(childProcesses, "spawn", {
  value: (...values: unknown[]) => {
    const [command, argv, options] = values as [string, string[], SpawnOptions];
    if (!selected || typeof options?.env?.AIH_SCAN_WINDOWS_JOB_SPEC !== "string")
      return Reflect.apply(originalSpawn, childProcesses, values);
    if (selected === "module-path")
      return originalSpawn(command, argv, {
        ...options,
        env: { ...options.env, PSModulePath: moduleRoot },
      });
    const script = `${explicitImport}\n${Buffer.from(argv.at(-1) ?? "", "base64").toString("utf16le")}`;
    return originalSpawn(
      command,
      [...argv.slice(0, -1), Buffer.from(script, "utf16le").toString("base64")],
      options,
    );
  },
});
syncBuiltinESMExports();
afterAll(() => {
  Object.defineProperty(childProcesses, "spawn", { value: originalSpawn });
  syncBuiltinESMExports();
});

function standalone(variant: string, environment: NodeJS.ProcessEnv, script: string, cwd: string) {
  return new Promise<{ code: number | null; stdout: string; stderr: string }>(
    (resolveResult, reject) => {
      const child = originalSpawn(
        powershell,
        [
          "-NoLogo",
          "-NoProfile",
          "-NonInteractive",
          "-ExecutionPolicy",
          "Bypass",
          "-EncodedCommand",
          Buffer.from(script, "utf16le").toString("base64"),
        ],
        {
          env: environment,
          cwd,
          windowsHide: true,
          stdio: ["pipe", "pipe", "pipe"],
        },
      ) as ChildProcess;
      let stdout = "",
        stderr = "";
      child.stdout?.on("data", (bytes) => {
        stdout += bytes;
      });
      child.stderr?.on("data", (bytes) => {
        stderr += bytes;
      });
      const timer = setTimeout(() => {
        report({ stage: "standalone-timeout", variant, pid: child.pid, stdout, stderr });
        if (child.pid !== undefined && child.exitCode === null && child.signalCode === null) {
          try {
            execFileSync(
              join(systemRoot, "System32/taskkill.exe"),
              ["/PID", String(child.pid), "/T", "/F"],
              { windowsHide: true, stdio: "pipe", timeout: 5000 },
            );
          } catch (error) {
            reject(error);
          }
        }
      }, 5000);
      child.once("error", (error) => {
        clearTimeout(timer);
        reject(error);
      });
      child.once("close", (code) => {
        clearTimeout(timer);
        resolveResult({ code, stdout, stderr });
      });
    },
  );
}

it.runIf(process.platform === "win32")(
  "isolates built-in JSON module loading and validates the candidate supervisor environment",
  async () => {
    const results = new Map<string, { code: number | null; stdout: string; stderr: string }>();
    for (const variant of ["baseline", "module-path", "explicit-import"] as const) {
      const cwd = fixture.path(variant);
      mkdirSync(cwd);
      const spec = {
        application: process.execPath,
        commandLine: "diagnostic",
        directory: cwd,
        environment: [],
        statusPath: join(cwd, "status.json"),
        residualGraceMs: 250,
        pauseAfterCreateMs: 0,
      };
      const environment = {
        SystemRoot: systemRoot,
        windir: systemRoot,
        PATH: `${join(systemRoot, "System32")};${systemRoot}`,
        TEMP: cwd,
        TMP: cwd,
        AIH_SCAN_WINDOWS_JOB_SPEC: Buffer.from(JSON.stringify(spec)).toString("base64"),
        AIH_SCAN_WINDOWS_JOB_SOURCE: Buffer.from(source).toString("base64"),
        ...(variant === "module-path" ? { PSModulePath: moduleRoot } : {}),
      };
      const script = [
        "$ErrorActionPreference = 'Stop'",
        "$ProgressPreference = 'SilentlyContinue'",
        "[Console]::WriteLine('ps-start')",
        ...(variant === "explicit-import"
          ? [
              "[Console]::WriteLine('before-import')",
              explicitImport,
              "[Console]::WriteLine('after-import')",
            ]
          : []),
        "[Console]::WriteLine('before-json')",
        "$spec = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:AIH_SCAN_WINDOWS_JOB_SPEC)) | ConvertFrom-Json",
        "[Console]::WriteLine('after-json')",
        "exit 0",
      ].join("\n");
      const started = performance.now();
      const result = await standalone(variant, environment, script, cwd);
      report({ variant, durationMs: performance.now() - started, result });
      results.set(variant, result);
    }
    selected =
      results.get("module-path")?.code === 0
        ? "module-path"
        : results.get("explicit-import")?.code === 0
          ? "explicit-import"
          : undefined;
    report({ candidate: selected ?? "none" });
    expect(selected).toBeDefined();
    const scratch = fixture.folder("candidate-scratch", {});
    const environment = staticAnalyzerEnv(
      { PATH: process.env.PATH, SystemRoot: systemRoot },
      scratch,
      "win32",
    );
    const document = skillSpectorReport([], { version: SKILLSPECTOR_MAINTENANCE_VERSION });
    (document.metadata as Record<string, unknown>).aih_scan_tp4_limits = {
      maxFiles: 128,
      maxFindings: 64,
      maxBatches: 256,
    };
    const fake = fakeAnalyzer(fixture.root, "skillspector", {
      versionText: `SkillSpector v${SKILLSPECTOR_MAINTENANCE_VERSION}`,
      outputFlag: "--output",
      report: document,
    });
    const started = performance.now();
    const version = await runUnderWindowsJobV1([fake.path, "--version"], {
      cwd: scratch,
      env: environment,
      timeoutMs: 5000,
      maxStdoutBytes: 1024 * 1024,
      maxStderrBytes: 1024 * 1024,
      containProcessTree: true,
    });
    report({
      stage: "candidate-real-supervisor",
      durationMs: performance.now() - started,
      result: version,
    });
    expect(version.code).toBe(0);
    const item = fixture.folder("candidate-item", {
      "SKILL.md": "---\nname: fixture\ndescription: fixture\n---\n# Fixture\n",
    });
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);
    try {
      const scanStarted = performance.now();
      const scanned = await scanWith(
        { format: "aih-scan-request/1", origin: "local", items: [{ path: item }] },
        { outDir: fixture.path("candidate-out"), signal: controller.signal },
        {
          env: { ...environment, AIH_SCAN_SKILLSPECTOR: fake.path, AIH_SCAN_SKILL_SCANNER: "none" },
        },
      );
      report({
        stage: "candidate-public-scan",
        durationMs: performance.now() - scanStarted,
        status: scanned.status,
      });
      const entry = scanned.results[0];
      expect(entry?.status).toBe("ok");
      if (entry?.status !== "ok") throw new Error("No candidate summary");
      const loaded = readSummary(new Uint8Array(readFileSync(entry.summaryPath)));
      expect(loaded.status).toBe("ok");
      if (loaded.status !== "ok") throw new Error("Invalid candidate summary");
      expect(loaded.summary.coverage).toBe("complete");
      expect(loaded.summary.tools).toContainEqual(
        expect.objectContaining({
          tool: "skillspector",
          version: SKILLSPECTOR_MAINTENANCE_VERSION,
          result: "pass",
        }),
      );
    } finally {
      clearTimeout(timer);
    }
  },
  90000,
);
