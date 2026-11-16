import { type ChildProcess, execFileSync, type SpawnOptions, spawn } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire, syncBuiltinESMExports } from "node:module";
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
let variantInFlight = "";
let instrumentSupervisor = false;
let launchCount = 0;
const childProcesses = createRequire(import.meta.url)(
  "node:child_process",
) as typeof import("node:child_process");
const originalSpawn = childProcesses.spawn;
const supervisorTraces: string[] = [];
Object.defineProperty(childProcesses, "spawn", {
  value: (...values: unknown[]) => {
    const [command, argv, options] = values as [string, string[], SpawnOptions];
    const environment = options?.env;
    if (typeof environment?.AIH_SCAN_WINDOWS_JOB_SPEC !== "string")
      return Reflect.apply(originalSpawn, childProcesses, values);
    const variant = variantInFlight;
    const trace = fixture.path(`supervisor-${++launchCount}.log`);
    supervisorTraces.push(trace);
    let actualArguments = argv;
    let actualOptions = options;
    if (instrumentSupervisor) {
      const script = Buffer.from(argv.at(-1)!, "base64").toString("utf16le");
      const marker = (stage: string) =>
        `[IO.File]::AppendAllText($env:AIH_NATIVE_TRACE, "${stage}\n")`;
      const observed = [
        marker("ps-start"),
        ...script
          .split("\n")
          .flatMap((line) =>
            line.startsWith("Add-Type")
              ? [marker("before-add-type"), line, marker("after-add-type")]
              : line.startsWith("$code =")
                ? [marker("before-managed-run"), line, marker("after-managed-run")]
                : [line],
          ),
      ].join("\n");
      let source = Buffer.from(environment.AIH_SCAN_WINDOWS_JOB_SOURCE!, "base64").toString("utf8");
      source = source.replace(
        "public static class AihScanWindowsJobSupervisorV1\n{",
        `public static class AihScanWindowsJobSupervisorV1\n{\nstatic void Trace(string stage) { File.AppendAllText(Environment.GetEnvironmentVariable("AIH_NATIVE_TRACE"), DateTime.UtcNow.ToString("O") + "|" + stage + "\\n"); }`,
      );
      for (const [before, stage] of [
        ["        IntPtr job = CreateJobObjectW", "managed-enter"],
        ["        watcher.Start();", "before-watcher-start"],
        ["        if (Cancelled()) return ReportCancelled(job, statusPath);", "watcher-started"],
        ["            if (!CreateProcessW", "before-create-process"],
        ["        if (pauseAfterCreateMs > 0)", "process-created"],
        ["        if (!Cancelled() && ResumeThread", "before-resume"],
        ["        WaitForSingleObject(information.hProcess, Infinite);", "before-leader-wait"],
        ["        uint leaderExit;", "leader-wait-ended"],
      ])
        source = source.replace(before!, `        Trace("${stage}");\n${before}`);
      actualArguments = [...argv.slice(0, -1), Buffer.from(observed, "utf16le").toString("base64")];
      actualOptions = {
        ...options,
        env: {
          ...environment,
          AIH_NATIVE_TRACE: trace,
          AIH_SCAN_WINDOWS_JOB_SOURCE: Buffer.from(source).toString("base64"),
        },
      };
    }
    const child = originalSpawn(command, actualArguments, actualOptions) as ChildProcess;
    report({
      stage: "supervisor-spawn",
      variant,
      pid: child.pid,
      instrumented: instrumentSupervisor,
      temporaryPathHasTilde: environment.TEMP?.includes("~"),
    });
    const timer = setTimeout(() => {
      if (child.exitCode !== null || child.signalCode !== null || child.pid === undefined) return;
      try {
        const query = `Get-CimInstance -Query "SELECT ProcessId,ParentProcessId,Name FROM Win32_Process WHERE ProcessId=${child.pid} OR ParentProcessId=${child.pid}" | ConvertTo-Json -Compress`;
        report({
          stage: "supervisor-process-tree",
          variant,
          processes: execFileSync(
            systemTool("WindowsPowerShell/v1.0/powershell.exe"),
            ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", query],
            { encoding: "utf8", windowsHide: true, timeout: 5000 },
          ).trim(),
          trace: existsSync(trace) ? readFileSync(trace, "utf8") : "",
        });
      } catch (error) {
        report({
          stage: "supervisor-query-error",
          variant,
          code: (error as NodeJS.ErrnoException).code,
        });
      }
    }, 3500);
    child.once("close", () => clearTimeout(timer));
    child.once("error", () => clearTimeout(timer));
    return child;
  },
});
syncBuiltinESMExports();
afterAll(() => {
  Object.defineProperty(childProcesses, "spawn", { value: originalSpawn });
  syncBuiltinESMExports();
});
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
      "fake-minimal",
      "node-job-basic",
      "node-job-minimal",
      "node-job-traced",
      "simple-job-minimal",
      "fake-job",
      "fake-job-scan",
      "public-scan",
    ]) {
      variantInFlight = variant;
      instrumentSupervisor = !["node-job-basic", "node-job-minimal"].includes(variant);
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
      } else if (variant.includes("-job")) {
        const nodeControl = variant.startsWith("node-job");
        result = await runUnderWindowsJobV1(
          nodeControl
            ? [process.execPath, "-e", 'console.log("node-control");']
            : variant !== "fake-job-scan"
              ? [path, "--version"]
              : [path, "scan", item, "--format", "json", "--no-llm"],
          {
            cwd: scratch,
            env:
              variant === "node-job-basic"
                ? {
                    SystemRoot: systemRoot,
                    PATH: `${systemRoot}\\System32;${systemRoot}`,
                    TEMP: scratch,
                    TMP: scratch,
                  }
                : minimal,
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
        supervisorTrace: supervisorTraces.map((path) =>
          existsSync(path) ? readFileSync(path, "utf8") : "",
        ),
      });
      results.push(result);
    }
    expect(results).toHaveLength(8);
    expect(results.map((result) => result.code)).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
  },
  150000,
);
