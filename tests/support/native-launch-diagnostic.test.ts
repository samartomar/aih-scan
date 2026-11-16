import { execFileSync, spawn } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, expect, it } from "vitest";
import { runUnderWindowsJobV1 } from "../../src/cli/windows-job-supervisor.js";
import { staticAnalyzerEnv } from "../../src/host/analyzer-process.js";
import { scanWith } from "../../src/host/scan.js";
import { SKILLSPECTOR_MAINTENANCE_VERSION } from "../../src/host/skillspector.js";
import { fakeAnalyzer, skillSpectorReport } from "./analyzer-cli-v1.js";
import { nativeNodeCli } from "./native-node-cli.js";
import { fixtureRoot } from "./scan-v1-fixture.js";

// [DEBUG-retro-native] Temporary bounded hosted diagnostic, removed before final merge.
const fixture = fixtureRoot("aih-native-diagnostic-");
afterAll(() => fixture.dispose());
const systemRoot = process.env.SystemRoot ?? "C:\\Windows";
const systemTool = (name: string) => join(systemRoot, "System32", name);
const report = (value: unknown) => process.stdout.write(`${JSON.stringify(value)}\n`);
const traces = (directory: string) =>
  ["launcher-trace.log", "node-trace.log"].flatMap((name) => {
    const file = join(directory, name);
    return existsSync(file) ? readFileSync(file, "utf8").trim().split("\n") : [];
  });

async function direct(path: string, env: NodeJS.ProcessEnv, directory: string, cwd: string) {
  return new Promise<{
    code: number | null;
    signal: NodeJS.Signals | null;
    stdout: string;
    stderr: string;
  }>((resolve, reject) => {
    const child = spawn(path, ["--version"], {
      env,
      cwd,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "",
      stderr = "";
    child.stdout.on("data", (data) => {
      stdout += data;
    });
    child.stderr.on("data", (data) => {
      stderr += data;
    });
    const timer = setTimeout(() => {
      report({ stage: "direct-timeout", pid: child.pid, trace: traces(directory) });
      if (child.exitCode === null && child.signalCode === null && child.pid !== undefined) {
        const query = `Get-CimInstance Win32_Process -Filter "ProcessId=${child.pid} OR ParentProcessId=${child.pid}" | Select-Object ProcessId,ParentProcessId,Name | ConvertTo-Json -Compress`;
        try {
          report({
            stage: "owned-process-tree",
            processes: execFileSync(
              systemTool("WindowsPowerShell/v1.0/powershell.exe"),
              ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", query],
              { encoding: "utf8", windowsHide: true, timeout: 5000 },
            ).trim(),
          });
        } catch (error) {
          report({ stage: "process-query-error", code: (error as NodeJS.ErrnoException).code });
        } finally {
          try {
            execFileSync(systemTool("taskkill.exe"), ["/PID", String(child.pid), "/T", "/F"], {
              windowsHide: true,
              stdio: "pipe",
              timeout: 5000,
            });
          } catch (error) {
            reject(error);
          }
        }
      }
    }, 5000);
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal, stdout, stderr });
    });
  });
}

it.runIf(process.platform === "win32")(
  "traces direct and contained native fixture version launches",
  async () => {
    const results = [];
    for (const variant of [
      "simple-full",
      "simple-minimal",
      "fake-minimal",
      "fake-job",
      "fake-job-scan",
      "public-scan",
    ]) {
      const directory = fixture.path(variant);
      mkdirSync(directory);
      const scratch = fixture.path(`${variant}-scratch`);
      mkdirSync(scratch);
      const minimal = staticAnalyzerEnv(
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
      const fake =
        variant.startsWith("fake") || variant === "public-scan"
          ? fakeAnalyzer(directory, "skillspector", {
              versionText: `SkillSpector v${SKILLSPECTOR_MAINTENANCE_VERSION}`,
              outputFlag: "--output",
              report: document,
            })
          : undefined;
      const path =
        fake?.path ??
        nativeNodeCli(directory, "probe", 'console.log("simple-version"); process.exit(0);');
      const working = fake?.dir ?? directory;
      const item = join(directory, "item");
      mkdirSync(item);
      writeFileSync(
        join(item, "SKILL.md"),
        "---\nname: fixture\ndescription: fixture\n---\n# Fixture\n",
      );
      chmodSync(join(item, "SKILL.md"), 0o444);
      const started = performance.now();
      let result:
        | Awaited<ReturnType<typeof direct>>
        | Awaited<ReturnType<typeof runUnderWindowsJobV1>>
        | { code: number; scanned: Awaited<ReturnType<typeof scanWith>> };
      if (variant === "public-scan") {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 10000);
        try {
          const scanned = await scanWith(
            { format: "aih-scan-request/1", origin: "local", items: [{ path: item }] },
            { outDir: join(directory, "out"), signal: controller.signal },
            { env: { ...minimal, AIH_SCAN_SKILLSPECTOR: path, AIH_SCAN_SKILL_SCANNER: "none" } },
          );
          result = { code: scanned.status === "ok" ? 0 : 1, scanned };
        } finally {
          clearTimeout(timer);
        }
      } else if (variant === "fake-job" || variant === "fake-job-scan") {
        result = await runUnderWindowsJobV1(
          variant === "fake-job"
            ? [path, "--version"]
            : [path, "scan", item, "--format", "json", "--no-llm"],
          {
            cwd: scratch,
            env: minimal,
            timeoutMs: 5000,
            maxStdoutBytes: 1024 * 1024,
            maxStderrBytes: 1024 * 1024,
            containProcessTree: true,
          },
        );
      } else
        result = await direct(
          path,
          variant === "simple-full" ? process.env : minimal,
          working,
          scratch,
        );
      report({
        variant,
        durationMs: performance.now() - started,
        result,
        trace: traces(working),
      });
      results.push(result);
    }
    expect(results).toHaveLength(6);
    expect(results.map((result) => result.code)).toEqual([0, 0, 0, 0, 0, 0]);
  },
  90000,
);
