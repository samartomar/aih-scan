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
 * JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE and no breakaway flags, then creates the analyzer
 * already inside that job (STARTUPINFOEX with PROC_THREAD_ATTRIBUTE_JOB_LIST,
 * CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT) with the exact command line, the fixed
 * environment block, NUL as stdin and the supervisor's stdout and stderr as the only
 * inherited handles, then resumes it. Membership is part of process creation, so there is
 * no moment at which the analyzer exists outside the job; every descendant is created
 * inside it and cannot break away.
 *
 * - When the analyzer exits, the helper counts the job's live processes. Any process still
 *   running after a short grace period outlived its leader: the helper terminates the whole
 *   job and reports the residue, and the run fails closed.
 * - On timeout, abort or an output cap Scan closes the supervisor's stdin. The supervisor
 *   terminates the job, waits for it to empty and reports the cancellation (it does the same
 *   if Scan itself dies). Only if it has not exited after a bounded grace does Scan kill it;
 *   its job handle is the only one, so that kills every job member (KILL_ON_JOB_CLOSE).
 *
 * libuv's own per-process job uses JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK, so a grandchild of
 * a Node child is not in it; this job is what contains the tree.
 */

const SUPERVISOR_STATUS_PROTOCOL = "AihScanWindowsJobStatusV1";
const RESIDUAL_GRACE_MS = 250;
const SUPERVISOR_COOPERATIVE_GRACE_MS = 10_000;
const SUPERVISOR_CLOSE_GRACE_MS = 10_000;
const MAX_STATUS_BYTES = 64 * 1024;
const MAX_PAUSE_AFTER_CREATE_MS = 60_000;

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
    struct StartupInfoEx
    {
        public StartupInfo StartupInfo;
        public IntPtr lpAttributeList;
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
    static extern bool TerminateJobObject(IntPtr job, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessW(string application, StringBuilder commandLine, IntPtr processAttributes,
        IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string directory,
        ref StartupInfoEx startup, out ProcessInformation information);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value,
        IntPtr size, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll")]
    static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition,
        uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadFile(IntPtr file, byte[] buffer, uint toRead, out uint read, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr thread);
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
    const uint ExtendedStartupInfoPresent = 0x80000;
    const int ProcThreadAttributeHandleList = 0x20002;
    const int ProcThreadAttributeJobList = 0x2000D;
    const uint GenericRead = 0x80000000;
    const uint FileShareReadWrite = 0x3;
    const uint OpenExisting = 3;
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
        string statusPath, int residualGraceMs, int pauseAfterCreateMs)
    {
        try
        {
            return Supervise(application, commandLine, directory, environment ?? new string[0], statusPath, residualGraceMs, pauseAfterCreateMs);
        }
        catch (Exception error)
        {
            WriteStatus(statusPath, "{\"protocol\":\"AihScanWindowsJobStatusV1\",\"error\":" + Json(error.Message) + "}");
            return 3;
        }
    }

    static int cancelled;

    static bool Cancelled() { return Thread.VolatileRead(ref cancelled) != 0; }

    static bool Usable(IntPtr handle) { return handle != IntPtr.Zero && handle != new IntPtr(-1); }

    // Scan cancels by closing the supervisor's standard input; a Scan that dies closes it too.
    // The watcher then terminates the job. It sets the flag first, so the main thread either
    // sees the flag after creating the analyzer or the terminate comes after the creation.
    static void WatchForCancellation(IntPtr job)
    {
        IntPtr input = GetStdHandle(-10);
        var buffer = new byte[64];
        uint read;
        while (Usable(input) && ReadFile(input, buffer, (uint)buffer.Length, out read, IntPtr.Zero) && read > 0) { }
        Interlocked.Exchange(ref cancelled, 1);
        TerminateJobObject(job, 1);
    }

    static uint EndJob(IntPtr job)
    {
        TerminateJobObject(job, 1);
        int spent = 0;
        while (ActiveProcesses(job) > 0 && spent < 5000) { Thread.Sleep(10); spent += 10; }
        return ActiveProcesses(job);
    }

    static int ReportCancelled(IntPtr job, string statusPath)
    {
        WriteStatus(statusPath, "{\"protocol\":\"AihScanWindowsJobStatusV1\",\"cancelled\":true,\"remainingProcesses\":" +
            EndJob(job) + "}");
        return 0;
    }

    // The job handle is never closed explicitly: the watcher may still terminate it, and the
    // supervisor's exit closes it, which (KILL_ON_JOB_CLOSE) ends anything left in it.
    static int Supervise(string application, string commandLine, string directory, string[] environment,
        string statusPath, int residualGraceMs, int pauseAfterCreateMs)
    {
        IntPtr job = CreateJobObjectW(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw Failure("CreateJobObjectW", Marshal.GetLastWin32Error());
        var limits = new ExtendedLimit();
        limits.Basic.LimitFlags = KillOnJobClose | DieOnUnhandledException;
        if (!SetInformationJobObject(job, 9, ref limits, Marshal.SizeOf(typeof(ExtendedLimit))))
            throw Failure("SetInformationJobObject", Marshal.GetLastWin32Error());
        var watcher = new Thread(() => WatchForCancellation(job));
        watcher.IsBackground = true;
        watcher.Start();
        if (Cancelled()) return ReportCancelled(job, statusPath);

        var sorted = new List<string>(environment);
        sorted.Sort(StringComparer.OrdinalIgnoreCase);
        var block = new StringBuilder();
        foreach (string entry in sorted) block.Append(entry).Append('\0');
        block.Append('\0');

        // The analyzer reads NUL and writes to the supervisor's own stdout and stderr; those
        // three are the only handles it inherits.
        IntPtr nul = CreateFileW("NUL", GenericRead, FileShareReadWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        if (!Usable(nul)) throw Failure("CreateFileW(NUL)", Marshal.GetLastWin32Error());
        var inherited = new List<IntPtr>();
        foreach (IntPtr handle in new[] { nul, GetStdHandle(-11), GetStdHandle(-12) })
        {
            if (!Usable(handle) || inherited.Contains(handle)) continue;
            if (!SetHandleInformation(handle, HandleFlagInherit, HandleFlagInherit))
                throw Failure("SetHandleInformation", Marshal.GetLastWin32Error());
            inherited.Add(handle);
        }

        var startup = new StartupInfoEx();
        startup.StartupInfo.cb = Marshal.SizeOf(typeof(StartupInfoEx));
        startup.StartupInfo.dwFlags = UseStdHandles | UseShowWindow;
        startup.StartupInfo.wShowWindow = 0;
        startup.StartupInfo.hStdInput = nul;
        startup.StartupInfo.hStdOutput = GetStdHandle(-11);
        startup.StartupInfo.hStdError = GetStdHandle(-12);

        IntPtr environmentBlock = Marshal.StringToHGlobalUni(block.ToString());
        IntPtr jobList = Marshal.AllocHGlobal(IntPtr.Size);
        IntPtr handleList = Marshal.AllocHGlobal(IntPtr.Size * inherited.Count);
        IntPtr attributeSize = IntPtr.Zero;
        InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref attributeSize);
        IntPtr attributes = Marshal.AllocHGlobal(attributeSize);
        bool initialized = false;
        ProcessInformation information;
        try
        {
            if (!InitializeProcThreadAttributeList(attributes, 2, 0, ref attributeSize))
                throw Failure("InitializeProcThreadAttributeList", Marshal.GetLastWin32Error());
            initialized = true;
            // PROC_THREAD_ATTRIBUTE_JOB_LIST: the analyzer is a member of the job from the
            // moment it exists, so no cancellation or supervisor death can leave it outside.
            Marshal.WriteIntPtr(jobList, job);
            if (!UpdateProcThreadAttribute(attributes, 0, new IntPtr(ProcThreadAttributeJobList), jobList,
                    new IntPtr(IntPtr.Size), IntPtr.Zero, IntPtr.Zero))
                throw Failure("UpdateProcThreadAttribute(JOB_LIST)", Marshal.GetLastWin32Error());
            for (int index = 0; index < inherited.Count; index++)
                Marshal.WriteIntPtr(handleList, index * IntPtr.Size, inherited[index]);
            if (!UpdateProcThreadAttribute(attributes, 0, new IntPtr(ProcThreadAttributeHandleList), handleList,
                    new IntPtr(IntPtr.Size * inherited.Count), IntPtr.Zero, IntPtr.Zero))
                throw Failure("UpdateProcThreadAttribute(HANDLE_LIST)", Marshal.GetLastWin32Error());
            startup.lpAttributeList = attributes;
            var line = new StringBuilder(commandLine);
            if (!CreateProcessW(application, line, IntPtr.Zero, IntPtr.Zero, true,
                    CreateSuspended | CreateUnicodeEnvironment | ExtendedStartupInfoPresent, environmentBlock,
                    directory, ref startup, out information))
                throw Failure("CreateProcessW", Marshal.GetLastWin32Error());
        }
        finally
        {
            if (initialized) DeleteProcThreadAttributeList(attributes);
            Marshal.FreeHGlobal(attributes);
            Marshal.FreeHGlobal(handleList);
            Marshal.FreeHGlobal(jobList);
            Marshal.FreeHGlobal(environmentBlock);
            CloseHandle(nul);
        }
        if (pauseAfterCreateMs > 0) Thread.Sleep(pauseAfterCreateMs);

        if (!Cancelled() && ResumeThread(information.hThread) == 0xFFFFFFFF && !Cancelled())
        {
            int error = Marshal.GetLastWin32Error();
            EndJob(job);
            throw Failure("ResumeThread", error);
        }
        CloseHandle(information.hThread);
        if (Cancelled()) TerminateJobObject(job, 1);
        WaitForSingleObject(information.hProcess, Infinite);
        uint leaderExit;
        GetExitCodeProcess(information.hProcess, out leaderExit);
        CloseHandle(information.hProcess);
        if (Cancelled()) return ReportCancelled(job, statusPath);

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
            EndJob(job);
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
        return 0;
    }
}
`;

const SUPERVISOR_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  "$ProgressPreference = 'SilentlyContinue'",
  "$spec = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:AIH_SCAN_WINDOWS_JOB_SPEC)) | ConvertFrom-Json",
  "Add-Type -TypeDefinition ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:AIH_SCAN_WINDOWS_JOB_SOURCE)))",
  "$code = [AihScanWindowsJobSupervisorV1]::Run([string]$spec.application, [string]$spec.commandLine, [string]$spec.directory, [string[]]$spec.environment, [string]$spec.statusPath, [int]$spec.residualGraceMs, [int]$spec.pauseAfterCreateMs)",
  "exit $code",
].join("\n");

const ENCODED_SUPERVISOR_SCRIPT = Buffer.from(SUPERVISOR_SCRIPT, "utf16le").toString("base64");
// The helper source travels in the environment: encoded into the command line it would
// pass the 32,767-character limit.
const ENCODED_SUPERVISOR_SOURCE = Buffer.from(SUPERVISOR_CSHARP, "utf8").toString("base64");

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
  | Readonly<{ cancelled: true; remainingProcesses: number }>
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
  if (parsed.cancelled === true) {
    const remainingProcesses = count(parsed.remainingProcesses);
    if (remainingProcesses === undefined) fail("status fields");
    return Object.freeze({ cancelled: true, remainingProcesses });
  }
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
 * Test seams, never set by Scan itself: `pauseAfterCreateMs` holds the supervisor between
 * creating the suspended analyzer and resuming it, so a test can cancel or kill it there.
 */
export type WindowsJobSupervisorSeamsV1 = Readonly<{ pauseAfterCreateMs?: number }>;

/**
 * Runs `argv` inside a fresh Job Object and returns once the whole tree is gone.
 *
 * `argv[0]` must be an absolute executable path: the supervisor passes it to
 * CreateProcessW as the application name, so nothing is searched for.
 */
export function runUnderWindowsJobV1(
  argv: readonly string[],
  options: ProcessRunnerOptions,
  seams: WindowsJobSupervisorSeamsV1 = {},
): Promise<ProcessRunnerResult> {
  if (process.platform !== "win32") fail("requires a Windows host");
  const application = argv[0];
  if (application === undefined || !win32.isAbsolute(application))
    fail("the analyzer executable must be an absolute path");
  const pauseAfterCreateMs = seams.pauseAfterCreateMs ?? 0;
  if (
    !Number.isSafeInteger(pauseAfterCreateMs) ||
    pauseAfterCreateMs < 0 ||
    pauseAfterCreateMs > MAX_PAUSE_AFTER_CREATE_MS
  )
    fail("pauseAfterCreateMs is not a whole number of milliseconds within bounds");
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
      pauseAfterCreateMs,
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
    AIH_SCAN_WINDOWS_JOB_SOURCE: ENCODED_SUPERVISOR_SOURCE,
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
          stdio: ["pipe", "pipe", "pipe"],
        },
      );
      // Closing stdin is the cancellation signal; the supervisor never reads data from it.
      child.stdin?.on("error", () => undefined);
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
    let killTimer: ReturnType<typeof setTimeout> | undefined;
    let closeTimer: ReturnType<typeof setTimeout> | undefined;
    const onAbort = () => terminate("abort");
    const settle = (outcome: { result: ProcessRunnerResult } | { error: unknown }) => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      if (killTimer !== undefined) clearTimeout(killTimer);
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
      // Cooperative first: the supervisor terminates its job when its stdin closes.
      child.stdin?.destroy();
      killTimer = setTimeout(() => {
        try {
          child.kill();
        } catch {
          // The supervisor may already be gone; its job handle closed with it.
        }
      }, SUPERVISOR_COOPERATIVE_GRACE_MS);
      closeTimer = setTimeout(
        () =>
          settle({
            result: { code: 1, ...output(), truncated: true, termination: "containment-failure" },
          }),
        SUPERVISOR_COOPERATIVE_GRACE_MS + SUPERVISOR_CLOSE_GRACE_MS,
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
        let remaining = 0;
        try {
          const status = readStatus(statusPath);
          if (status !== undefined && "remainingProcesses" in status)
            remaining = status.remainingProcesses;
        } catch {
          // A supervisor killed after its grace wrote no status; its job closed with it.
        }
        settle({
          result:
            remaining > 0
              ? {
                  code: 1,
                  ...output(),
                  truncated: true,
                  termination: "containment-failure",
                  containmentDetail: `${remaining} job process${remaining === 1 ? "" : "es"} survived termination`,
                }
              : { code: 1, ...output(), truncated: true, termination },
        });
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
      if (status === undefined || "error" in status || "cancelled" in status) {
        const detail =
          status === undefined
            ? "the Windows job supervisor exited without a status record"
            : "cancelled" in status
              ? "the Windows job supervisor lost its stdin and ended the job unasked"
              : `the Windows job supervisor could not run the analyzer: ${status.error}`;
        if (status !== undefined && "error" in status && /CreateProcessW/u.test(status.error)) {
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
