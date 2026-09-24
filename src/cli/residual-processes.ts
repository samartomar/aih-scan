import { spawn } from "node:child_process";
import { readdirSync, readFileSync, readlinkSync } from "node:fs";
import { windowsJobSupervisorExecutableV1, windowsSystemRootV1 } from "./windows-job-supervisor.js";

/**
 * Finds live processes tied to a run by one of its unique private-directory names. Scan sweeps
 * for them after every host-process run: the containment (a Job Object on Windows, a process
 * group on POSIX) should have left none, so any survivor is killed and the run fails closed
 * instead of claiming cleanup.
 *
 * - Linux matches `/proc/<pid>/cmdline`, the inherited environment `/proc/<pid>/environ` and
 *   the working directory `/proc/<pid>/cwd`, and spawns nothing.
 * - macOS matches the arguments and environment from `/bin/ps -axwwE -o pid= -o args=` and
 *   the working directory from `/usr/sbin/lsof -a -d cwd`.
 * - Windows asks CIM (`Win32_Process`) for the command line and executable path through
 *   Windows PowerShell 5.1 under `%SystemRoot%`; the Job Object is its containment.
 *
 * Residual limit on POSIX: a descendant that leaves the session (setsid) and also clears its
 * environment and moves its working directory out of the run carries no trace of the run and
 * is not detectable. The Linux namespace profile is the containment option for that threat.
 *
 * Markers are matched case-insensitively on Windows and exactly elsewhere. A marker must be a
 * run-unique token such as an `mkdtemp` directory name, never a shared parent directory.
 */

export type LiveProcessV1 = Readonly<{ pid: number; command: string }>;

const SWEEP_TIMEOUT_MS = 60_000;
const MAX_SWEEP_OUTPUT_BYTES = 4 * 1024 * 1024;
const SAFE_MARKER = /^[A-Za-z0-9._-]{8,128}$/u;

function fail(message: string): never {
  throw new TypeError(`aih-scan residual process sweep: ${message}`);
}

function validMarkers(markers: readonly string[]): string[] {
  if (markers.length === 0) fail("no markers");
  for (const marker of markers) if (!SAFE_MARKER.test(marker)) fail(`unsafe marker ${marker}`);
  return [...markers];
}

function linuxProcesses(markers: readonly string[]): LiveProcessV1[] {
  const found: LiveProcessV1[] = [];
  for (const entry of readdirSync("/proc")) {
    if (!/^\d+$/u.test(entry)) continue;
    const pid = Number(entry);
    if (pid === process.pid) continue;
    let command: string;
    try {
      command = readFileSync(`/proc/${entry}/cmdline`)
        .toString("utf8")
        .split("\0")
        .join(" ")
        .trim();
    } catch {
      continue;
    }
    // A process that exited since the listing, or belongs to another user, has no readable
    // environment or working directory; it can then only match by its command line.
    let environment = "";
    try {
      environment = readFileSync(`/proc/${entry}/environ`).toString("utf8");
    } catch {}
    let cwd = "";
    try {
      cwd = readlinkSync(`/proc/${entry}/cwd`);
    } catch {}
    if (markers.some((marker) => [command, environment, cwd].some((text) => text.includes(marker))))
      found.push(Object.freeze({ pid, command: command || `[pid ${pid}] cwd ${cwd}` }));
  }
  return found;
}

function collect(
  executable: string,
  argv: readonly string[],
  env: Record<string, string>,
  allowedCodes: readonly number[] = [0],
) {
  return new Promise<string>((resolveOutput, reject) => {
    const child = spawn(executable, argv, {
      shell: false,
      windowsHide: true,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const chunks: Buffer[] = [];
    let size = 0;
    const timer = setTimeout(() => {
      child.kill();
      reject(new TypeError("aih-scan residual process sweep: timed out"));
    }, SWEEP_TIMEOUT_MS);
    child.stdout.on("data", (chunk: Buffer) => {
      size += chunk.byteLength;
      if (size > MAX_SWEEP_OUTPUT_BYTES) {
        child.kill();
        return;
      }
      chunks.push(chunk);
    });
    child.stderr.resume();
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (code) => {
      clearTimeout(timer);
      if (code === null || !allowedCodes.includes(code) || size > MAX_SWEEP_OUTPUT_BYTES)
        reject(new TypeError(`aih-scan residual process sweep: exit ${code ?? "signal"}`));
      else resolveOutput(Buffer.concat(chunks).toString("utf8"));
    });
  });
}

const DARWIN_SWEEP_ENV = { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LANG: "C" };

async function darwinProcesses(markers: readonly string[]): Promise<LiveProcessV1[]> {
  // -E appends each process's environment to its arguments (for this user's processes).
  const output = await collect(
    "/bin/ps",
    ["-axwwE", "-o", "pid=", "-o", "args="],
    DARWIN_SWEEP_ENV,
  );
  const found = new Map<number, LiveProcessV1>();
  for (const line of output.split("\n")) {
    const match = /^\s*(\d+)\s+(.*)$/u.exec(line);
    if (match === null) continue;
    const pid = Number(match[1]);
    const command = match[2] ?? "";
    if (pid !== process.pid && markers.some((marker) => command.includes(marker)))
      found.set(pid, Object.freeze({ pid, command }));
  }
  // lsof exits 1 when it could not inspect some process (another user's); what it printed
  // for the rest is still complete, so 1 is accepted and any other exit fails the sweep.
  const cwdOutput = await collect(
    "/usr/sbin/lsof",
    ["-w", "-n", "-P", "-a", "-d", "cwd", "-F", "pn"],
    DARWIN_SWEEP_ENV,
    [0, 1],
  );
  let pid = 0;
  for (const line of cwdOutput.split("\n")) {
    if (line.startsWith("p")) pid = Number(line.slice(1));
    else if (line.startsWith("n") && Number.isSafeInteger(pid) && pid > 0) {
      const cwd = line.slice(1);
      if (pid !== process.pid && !found.has(pid) && markers.some((marker) => cwd.includes(marker)))
        found.set(pid, Object.freeze({ pid, command: `[pid ${pid}] cwd ${cwd}` }));
    }
  }
  return [...found.values()];
}

const WINDOWS_SWEEP_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  "$ProgressPreference = 'SilentlyContinue'",
  '$markers = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:AIH_SCAN_SWEEP_MARKERS)) -split "`n"',
  "foreach ($process in Get-CimInstance -ClassName Win32_Process -Property ProcessId,CommandLine,ExecutablePath) {",
  "  if ($process.ProcessId -eq $PID) { continue }",
  '  $text = [string]$process.CommandLine + "`t" + [string]$process.ExecutablePath',
  "  foreach ($marker in $markers) {",
  "    if ($marker -and $text.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase) -ge 0) {",
  '      $line = [string]$process.ProcessId + "`t" + ($text -replace "[`r`n]", \' \')',
  "      [Console]::Out.WriteLine($line)",
  "      break",
  "    }",
  "  }",
  "}",
].join("\n");

async function windowsProcesses(markers: readonly string[]): Promise<LiveProcessV1[]> {
  const systemRoot = windowsSystemRootV1();
  const output = await collect(
    windowsJobSupervisorExecutableV1(),
    [
      "-NoLogo",
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy",
      "Bypass",
      "-EncodedCommand",
      Buffer.from(WINDOWS_SWEEP_SCRIPT, "utf16le").toString("base64"),
    ],
    {
      SystemRoot: systemRoot,
      windir: systemRoot,
      PATH: `${systemRoot}\\System32;${systemRoot}`,
      AIH_SCAN_SWEEP_MARKERS: Buffer.from(markers.join("\n"), "utf8").toString("base64"),
    },
  );
  const found: LiveProcessV1[] = [];
  for (const line of output.split(/\r?\n/u)) {
    const tab = line.indexOf("\t");
    if (tab <= 0) continue;
    const pid = Number(line.slice(0, tab));
    if (!Number.isSafeInteger(pid) || pid === process.pid) continue;
    found.push(Object.freeze({ pid, command: line.slice(tab + 1).trim() }));
  }
  return found;
}

/** Live processes (other than this one) that reference any of `markers`. */
export async function findProcessesReferencingV1(
  markers: readonly string[],
): Promise<readonly LiveProcessV1[]> {
  const checked = validMarkers(markers);
  const found =
    process.platform === "linux"
      ? linuxProcesses(checked)
      : process.platform === "darwin"
        ? await darwinProcesses(checked)
        : process.platform === "win32"
          ? await windowsProcesses(checked)
          : fail(`no residual process sweep for ${process.platform}`);
  return Object.freeze(found);
}

/**
 * Kills every live process that references `markers`, then sweeps again. Returns what was
 * found first and what still survives the kill; a caller fails closed on any of either.
 */
export async function sweepResidualProcessesV1(markers: readonly string[]): Promise<
  Readonly<{
    found: readonly LiveProcessV1[];
    surviving: readonly LiveProcessV1[];
  }>
> {
  const found = await findProcessesReferencingV1(markers);
  if (found.length === 0) return Object.freeze({ found, surviving: found });
  for (const entry of found) {
    try {
      process.kill(entry.pid, "SIGKILL");
    } catch {
      // Already gone, or not ours to kill; the second sweep decides.
    }
  }
  let surviving = found;
  for (let attempt = 0; attempt < 20 && surviving.length > 0; attempt += 1) {
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 100));
    surviving = await findProcessesReferencingV1(markers);
  }
  return Object.freeze({ found, surviving });
}
