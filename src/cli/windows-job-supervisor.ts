import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, win32 } from "node:path";
import { parseStrictJsonObjectV1 } from "../contract/strict-json-v1.js";
import type {
  ProcessRunnerOptions,
  ProcessRunnerResult,
  ProcessTerminationV1,
} from "./process-runner.js";

/**
 * Windows process-tree containment without a native addon.
 *
 * Windows PowerShell 5.1 (present on every supported Windows) compiles the small C# helper
 * below and runs it as a supervisor. The helper creates a Job Object with
 * JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE and no breakaway flags, creates the analyzer
 * CREATE_SUSPENDED with the exact command line, the fixed environment block and the
 * supervisor's own standard handles, assigns it to the job, then resumes it. Every
 * descendant is created inside that job and cannot break away from it.
 *
 * - When the analyzer exits, the helper counts the job's live processes. Any process still
 *   running after a short grace period outlived its leader: the helper terminates the whole
 *   job and reports the residue, and the run fails closed.
 * - On timeout or abort Scan terminates the supervisor. Its job handle is the only one, so
 *   closing it kills the analyzer and every descendant (KILL_ON_JOB_CLOSE).
 *
 * libuv's own per-process job uses JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK, so a grandchild of
 * a Node child is not in it; this job is what contains the tree.
 */

const SUPERVISOR_STATUS_PROTOCOL = "AihScanWindowsJobStatusV1";
const RESIDUAL_GRACE_MS = 250;
const SUPERVISOR_CLOSE_GRACE_MS = 10_000;
const MAX_STATUS_BYTES = 64 * 1024;

const SUPERVISOR_CSHARP = String.raw`
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public static class AihScanWindowsJobSupervisorV1
{
    [StructLayout(LayoutKind.Sequential)]
    struct BasicLimit
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IoCounters
    {
        public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
        public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ExtendedLimit
    {
        public BasicLimit Basic;
        public IoCounters Io;
        public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct Accounting
    {
        public long TotalUserTime, TotalKernelTime, ThisPeriodTotalUserTime, ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount, TotalProcesses, ActiveProcesses, TotalTerminatedProcesses;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct StartupInfo
    {
        public int cb;
        public string lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ProcessInformation
    {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateJobObjectW(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref ExtendedLimit info, int length);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool QueryInformationJobObject(IntPtr job, int infoClass, out Accounting info, int length, IntPtr returned);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool QueryInformationJobObject(IntPtr job, int infoClass, IntPtr info, int length, IntPtr returned);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool TerminateJobObject(IntPtr job, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessW(string application, StringBuilder commandLine, IntPtr processAttributes,
        IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string directory,
        ref StartupInfo startup, out ProcessInformation information);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool TerminateProcess(IntPtr process, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetStdHandle(int which);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int processId);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool QueryFullProcessImageNameW(IntPtr process, int flags, StringBuilder name, ref int size);

    const uint KillOnJobClose = 0x2000;
    const uint DieOnUnhandledException = 0x400;
    const uint CreateSuspended = 0x4;
    const uint CreateUnicodeEnvironment = 0x400;
    const int UseStdHandles = 0x100;
    const int UseShowWindow = 0x1;
    const uint HandleFlagInherit = 0x1;
    const uint Infinite = 0xFFFFFFFF;
    const int MaxMembers = 16;

    static Exception Failure(string call, int code)
    {
        return new Exception(call + " failed: " + new Win32Exception(code).Message + " (" + code + ")");
    }

    static string Json(string value)
    {
        var builder = new StringBuilder("\"");
        foreach (char c in value)
        {
            if (c == '"' || c == '\\') builder.Append('\\').Append(c);
            else if (c < 0x20 || c > 0x7e) builder.AppendFormat("\\u{0:x4}", (int)c);
            else builder.Append(c);
        }
        return builder.Append('"').ToString();
    }

    static void WriteStatus(string path, string body)
    {
        string partial = path + ".partial";
        File.WriteAllText(partial, body, new UTF8Encoding(false));
        File.Move(partial, path);
    }

    static uint ActiveProcesses(IntPtr job)
    {
        Accounting accounting;
        if (!QueryInformationJobObject(job, 1, out accounting, Marshal.SizeOf(typeof(Accounting)), IntPtr.Zero))
            throw Failure("QueryInformationJobObject", Marshal.GetLastWin32Error());
        return accounting.ActiveProcesses;
    }

    static List<string> Members(IntPtr job)
    {
        var members = new List<string>();
        int size = 8 + MaxMembers * IntPtr.Size;
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (!QueryInformationJobObject(job, 3, buffer, size, IntPtr.Zero)) return members;
            int listed = Marshal.ReadInt32(buffer, 4);
            for (int index = 0; index < listed && index < MaxMembers; index++)
            {
                long pid = Marshal.ReadIntPtr(buffer, 8 + index * IntPtr.Size).ToInt64();
                string image = "unknown";
                IntPtr process = OpenProcess(0x1000, false, (int)pid);
                if (process != IntPtr.Zero)
                {
                    var name = new StringBuilder(1024);
                    int length = name.Capacity;
                    if (QueryFullProcessImageNameW(process, 0, name, ref length)) image = Path.GetFileName(name.ToString());
                    CloseHandle(process);
                }
                members.Add(pid + ":" + image);
            }
        }
        finally { Marshal.FreeHGlobal(buffer); }
        return members;
    }

    public static int Run(string application, string commandLine, string directory, string[] environment,
        string statusPath, int residualGraceMs)
    {
        try
        {
            return Supervise(application, commandLine, directory, environment ?? new string[0], statusPath, residualGraceMs);
        }
        catch (Exception error)
        {
            WriteStatus(statusPath, "{\"protocol\":\"AihScanWindowsJobStatusV1\",\"error\":" + Json(error.Message) + "}");
            return 3;
        }
    }

    static int Supervise(string application, string commandLine, string directory, string[] environment,
        string statusPath, int residualGraceMs)
    {
        IntPtr job = CreateJobObjectW(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw Failure("CreateJobObjectW", Marshal.GetLastWin32Error());
        var limits = new ExtendedLimit();
        limits.Basic.LimitFlags = KillOnJobClose | DieOnUnhandledException;
        if (!SetInformationJobObject(job, 9, ref limits, Marshal.SizeOf(typeof(ExtendedLimit))))
            throw Failure("SetInformationJobObject", Marshal.GetLastWin32Error());

        var sorted = new List<string>(environment);
        sorted.Sort(StringComparer.OrdinalIgnoreCase);
        var block = new StringBuilder();
        foreach (string entry in sorted) block.Append(entry).Append('\0');
        block.Append('\0');
        IntPtr environmentBlock = Marshal.StringToHGlobalUni(block.ToString());

        var startup = new StartupInfo();
        startup.cb = Marshal.SizeOf(typeof(StartupInfo));
        startup.dwFlags = UseStdHandles | UseShowWindow;
        startup.wShowWindow = 0;
        startup.hStdInput = GetStdHandle(-10);
        startup.hStdOutput = GetStdHandle(-11);
        startup.hStdError = GetStdHandle(-12);
        foreach (IntPtr handle in new[] { startup.hStdInput, startup.hStdOutput, startup.hStdError })
            if (handle != IntPtr.Zero && handle != new IntPtr(-1)) SetHandleInformation(handle, HandleFlagInherit, HandleFlagInherit);

        ProcessInformation information;
        var line = new StringBuilder(commandLine);
        try
        {
            if (!CreateProcessW(application, line, IntPtr.Zero, IntPtr.Zero, true,
                    CreateSuspended | CreateUnicodeEnvironment, environmentBlock, directory, ref startup, out information))
                throw Failure("CreateProcessW", Marshal.GetLastWin32Error());
        }
        finally { Marshal.FreeHGlobal(environmentBlock); }

        if (!AssignProcessToJobObject(job, information.hProcess))
        {
            int error = Marshal.GetLastWin32Error();
            TerminateProcess(information.hProcess, 1);
            throw Failure("AssignProcessToJobObject", error);
        }
        if (ResumeThread(information.hThread) == 0xFFFFFFFF)
        {
            int error = Marshal.GetLastWin32Error();
            TerminateJobObject(job, 1);
            throw Failure("ResumeThread", error);
        }
        CloseHandle(information.hThread);
        WaitForSingleObject(information.hProcess, Infinite);
        uint leaderExit;
        GetExitCodeProcess(information.hProcess, out leaderExit);
        CloseHandle(information.hProcess);

        uint active = ActiveProcesses(job);
        int waited = 0;
        while (active > 0 && waited < residualGraceMs)
        {
            Thread.Sleep(10);
            waited += 10;
            active = ActiveProcesses(job);
        }
        var residualMembers = new List<string>();
        if (active > 0)
        {
            residualMembers = Members(job);
            TerminateJobObject(job, 1);
            int spent = 0;
            while (ActiveProcesses(job) > 0 && spent < 5000) { Thread.Sleep(10); spent += 10; }
        }
        uint remaining = ActiveProcesses(job);
        var members = new StringBuilder("[");
        for (int index = 0; index < residualMembers.Count; index++)
        {
            if (index > 0) members.Append(',');
            members.Append(Json(residualMembers[index]));
        }
        members.Append(']');
        WriteStatus(statusPath,
            "{\"protocol\":\"AihScanWindowsJobStatusV1\",\"leaderExitCode\":" + leaderExit +
            ",\"residualProcesses\":" + active + ",\"residualMembers\":" + members +
            ",\"remainingProcesses\":" + remaining + "}");
        CloseHandle(job);
        return 0;
    }
}
`;

const SUPERVISOR_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  "$ProgressPreference = 'SilentlyContinue'",
  "$spec = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:AIH_SCAN_WINDOWS_JOB_SPEC)) | ConvertFrom-Json",
  `Add-Type -TypeDefinition @'${SUPERVISOR_CSHARP}'@`,
  "$code = [AihScanWindowsJobSupervisorV1]::Run([string]$spec.application, [string]$spec.commandLine, [string]$spec.directory, [string[]]$spec.environment, [string]$spec.statusPath, [int]$spec.residualGraceMs)",
  "exit $code",
].join("\n");

const ENCODED_SUPERVISOR_SCRIPT = Buffer.from(SUPERVISOR_SCRIPT, "utf16le").toString("base64");

/** The fixed supervisor argv, in the order Scan passes it. */
export const WINDOWS_JOB_SUPERVISOR_ARGUMENTS_V1: readonly string[] = Object.freeze([
  "-NoLogo",
  "-NoProfile",
  "-NonInteractive",
  "-ExecutionPolicy",
  "Bypass",
  "-EncodedCommand",
]);

function fail(message: string): never {
  throw new TypeError(`aih-scan Windows job supervisor: ${message}`);
}

/** `%SystemRoot%`, validated as an absolute drive path; never taken from a caller's environment. */
export function windowsSystemRootV1(env: Readonly<NodeJS.ProcessEnv> = process.env): string {
  const value = env.SystemRoot ?? env.SYSTEMROOT ?? env.windir ?? env.WINDIR;
  if (typeof value !== "string" || !/^[A-Za-z]:\\[^\0\r\n"]*$/u.test(value))
    fail("SystemRoot is not an absolute Windows directory");
  return win32.normalize(value);
}

/** The Windows PowerShell 5.1 executable under `%SystemRoot%`; never resolved through PATH. */
export function windowsJobSupervisorExecutableV1(
  env: Readonly<NodeJS.ProcessEnv> = process.env,
): string {
  return win32.join(
    windowsSystemRootV1(env),
    "System32",
    "WindowsPowerShell",
    "v1.0",
    "powershell.exe",
  );
}

/**
 * One Windows command line for `argv`, quoted so the Microsoft C runtime (and every parser
 * that follows its rules, such as Rust's and CPython's) reads back exactly `argv`.
 */
export function windowsCommandLineV1(argv: readonly string[]): string {
  if (argv.length === 0) fail("empty argv");
  return argv
    .map((argument) => {
      if (argument.includes("\0")) fail("argv holds a NUL character");
      if (argument.length > 0 && !/[\s"]/u.test(argument)) return argument;
      let quoted = '"';
      let backslashes = 0;
      for (const character of argument) {
        if (character === "\\") {
          backslashes += 1;
          continue;
        }
        if (character === '"') {
          quoted += `${"\\".repeat(backslashes * 2 + 1)}"`;
          backslashes = 0;
          continue;
        }
        quoted += `${"\\".repeat(backslashes)}${character}`;
        backslashes = 0;
      }
      return `${quoted}${"\\".repeat(backslashes * 2)}"`;
    })
    .join(" ");
}

function environmentEntries(env: Readonly<Record<string, string>>): string[] {
  const seen = new Set<string>();
  return Object.entries(env).map(([name, value]) => {
    if (!name || name.includes("=") || name.includes("\0") || value.includes("\0"))
      fail(`environment variable ${JSON.stringify(name)} cannot be represented`);
    const folded = name.toUpperCase();
    if (seen.has(folded)) fail(`environment variable ${name} is declared twice`);
    seen.add(folded);
    return `${name}=${value}`;
  });
}

type SupervisorStatus =
  | Readonly<{
      leaderExitCode: number;
      residualProcesses: number;
      residualMembers: readonly string[];
      remainingProcesses: number;
    }>
  | Readonly<{ error: string }>;

function readStatus(path: string): SupervisorStatus | undefined {
  if (!existsSync(path)) return undefined;
  const size = statSync(path).size;
  if (size <= 0 || size > MAX_STATUS_BYTES) fail("status file size");
  const parsed = parseStrictJsonObjectV1(readFileSync(path, "utf8"), "Windows job status");
  if (parsed.protocol !== SUPERVISOR_STATUS_PROTOCOL) fail("status protocol");
  if (typeof parsed.error === "string") return Object.freeze({ error: parsed.error });
  const count = (value: unknown) =>
    typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
  const leaderExitCode = count(parsed.leaderExitCode);
  const residualProcesses = count(parsed.residualProcesses);
  const remainingProcesses = count(parsed.remainingProcesses);
  const members = parsed.residualMembers;
  if (
    leaderExitCode === undefined ||
    residualProcesses === undefined ||
    remainingProcesses === undefined ||
    !Array.isArray(members) ||
    !members.every((entry) => typeof entry === "string")
  )
    fail("status fields");
  return Object.freeze({
    leaderExitCode,
    residualProcesses,
    residualMembers: Object.freeze([...(members as string[])]),
    remainingProcesses,
  });
}

/**
 * Runs `argv` inside a fresh Job Object and returns once the whole tree is gone.
 *
 * `argv[0]` must be an absolute executable path: the supervisor passes it to
 * CreateProcessW as the application name, so nothing is searched for.
 */
export function runUnderWindowsJobV1(
  argv: readonly string[],
  options: ProcessRunnerOptions,
): Promise<ProcessRunnerResult> {
  if (process.platform !== "win32") fail("requires a Windows host");
  const application = argv[0];
  if (application === undefined || !win32.isAbsolute(application))
    fail("the analyzer executable must be an absolute path");
  const directory = options.cwd;
  if (directory === undefined || !win32.isAbsolute(directory))
    fail("the analyzer working directory must be an absolute path");
  const supervisor = windowsJobSupervisorExecutableV1();
  const commandLine = windowsCommandLineV1(argv);
  const environment = environmentEntries(options.env);
  const privateRoot = mkdtempSync(join(tmpdir(), "aihj-"));
  const statusPath = join(privateRoot, "status.json");
  const spec = Buffer.from(
    JSON.stringify({
      application,
      commandLine,
      directory,
      environment,
      statusPath,
      residualGraceMs: RESIDUAL_GRACE_MS,
    }),
    "utf8",
  ).toString("base64");
  const systemRoot = windowsSystemRootV1();
  const supervisorEnvironment: Record<string, string> = {
    SystemRoot: systemRoot,
    windir: systemRoot,
    PATH: `${win32.join(systemRoot, "System32")};${systemRoot}`,
    TEMP: privateRoot,
    TMP: privateRoot,
    AIH_SCAN_WINDOWS_JOB_SPEC: spec,
  };
  return new Promise((resolveResult, reject) => {
    const cleanup = () => {
      try {
        rmSync(privateRoot, { recursive: true, force: true });
      } catch {
        // The supervisor may still hold the compiled helper briefly; the run already settled.
      }
    };
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(
        supervisor,
        [...WINDOWS_JOB_SUPERVISOR_ARGUMENTS_V1, ENCODED_SUPERVISOR_SCRIPT],
        {
          shell: false,
          windowsHide: true,
          cwd: privateRoot,
          env: supervisorEnvironment,
          stdio: ["ignore", "pipe", "pipe"],
        },
      );
    } catch (error) {
      cleanup();
      reject(error);
      return;
    }
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutSize = 0;
    let stderrSize = 0;
    let termination: ProcessTerminationV1 | undefined;
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let closeTimer: ReturnType<typeof setTimeout> | undefined;
    const onAbort = () => terminate("abort");
    const settle = (outcome: { result: ProcessRunnerResult } | { error: unknown }) => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      if (closeTimer !== undefined) clearTimeout(closeTimer);
      options.signal?.removeEventListener("abort", onAbort);
      cleanup();
      if ("error" in outcome) reject(outcome.error);
      else resolveResult(Object.freeze(outcome.result));
    };
    const output = () => ({
      stdout: Buffer.concat(stdout).toString("utf8"),
      stderr: Buffer.concat(stderr).toString("utf8"),
    });
    function terminate(reason: ProcessTerminationV1): void {
      if (settled || termination !== undefined) return;
      termination = reason;
      try {
        child.kill();
      } catch {
        // The supervisor may already be gone; its job handle closed with it.
      }
      closeTimer = setTimeout(
        () =>
          settle({
            result: { code: 1, ...output(), truncated: true, termination: "containment-failure" },
          }),
        SUPERVISOR_CLOSE_GRACE_MS,
      );
    }
    timer = setTimeout(() => terminate("timeout"), options.timeoutMs);
    if (options.signal?.aborted) terminate("abort");
    else options.signal?.addEventListener("abort", onAbort, { once: true });
    child.stdout?.on("data", (chunk: Buffer) => {
      if (settled) return;
      stdoutSize += chunk.byteLength;
      if (stdoutSize > options.maxStdoutBytes) terminate("output-limit");
      else stdout.push(chunk);
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      if (settled) return;
      stderrSize += chunk.byteLength;
      if (stderrSize > options.maxStderrBytes) terminate("output-limit");
      else stderr.push(chunk);
    });
    child.once("error", (error) => settle({ error }));
    child.once("close", () => {
      if (termination !== undefined) {
        settle({ result: { code: 1, ...output(), truncated: true, termination } });
        return;
      }
      let status: SupervisorStatus | undefined;
      try {
        status = readStatus(statusPath);
      } catch (error) {
        settle({
          result: {
            code: 1,
            ...output(),
            truncated: true,
            termination: "containment-failure",
            containmentDetail: error instanceof Error ? error.message : "status unreadable",
          },
        });
        return;
      }
      if (status === undefined || "error" in status) {
        const detail =
          status === undefined
            ? "the Windows job supervisor exited without a status record"
            : `the Windows job supervisor could not run the analyzer: ${status.error}`;
        if (status !== undefined && /CreateProcessW/u.test(status.error)) {
          settle({ error: new Error(`aih-scan: ${detail}`) });
          return;
        }
        settle({
          result: {
            code: 1,
            ...output(),
            truncated: true,
            termination: "containment-failure",
            containmentDetail: detail,
          },
        });
        return;
      }
      if (status.residualProcesses > 0 || status.remainingProcesses > 0) {
        settle({
          result: {
            code: 1,
            ...output(),
            truncated: true,
            termination:
              status.remainingProcesses > 0 ? "containment-failure" : "residual-descendants",
            containmentDetail: `${status.residualProcesses} process${
              status.residualProcesses === 1 ? "" : "es"
            } outlived the analyzer and ${
              status.remainingProcesses > 0 ? "could not all be" : "were"
            } terminated with its job: ${status.residualMembers.join(", ")}`,
          },
        });
        return;
      }
      settle({
        result: { code: status.leaderExitCode, ...output(), truncated: false },
      });
    });
  });
}
