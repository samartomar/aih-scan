import { execFileSync, spawn } from "node:child_process";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, expect, it } from "vitest";
import { fixtureRoot } from "./scan-v1-fixture.js";

// [DEBUG-retro-cim] Temporary bounded autoload proof; no environment or command lines printed.
const fixture = fixtureRoot("aih-cim-diagnostic-");
afterAll(() => fixture.dispose());
const systemRoot = process.env.SystemRoot ?? "C:\\Windows";
const powershell = join(systemRoot, "System32/WindowsPowerShell/v1.0/powershell.exe");
type Mode = "baseline" | "utility-manifest" | "utility-manifest-temp" | "utility-binary";
function probe(mode: Mode) {
  const script = [
    "$ErrorActionPreference = 'Stop'",
    "$ProgressPreference = 'SilentlyContinue'",
    "[Console]::WriteLine('ps-start')",
    ...(mode !== "baseline"
      ? [
          "[Console]::WriteLine('before-utility')",
          "Import-Module ([IO.Path]::Combine($PSHOME, 'Modules\\Microsoft.PowerShell.Utility\\Microsoft.PowerShell.Utility.psd1'))",
          "[Console]::WriteLine('imported-utility')",
          "[Console]::WriteLine('before-import-cim')",
          mode !== "utility-binary"
            ? "Import-Module ([IO.Path]::Combine($PSHOME, 'Modules\\CimCmdlets\\CimCmdlets.psd1'))"
            : "Import-Module ([IO.Path]::Combine($env:SystemRoot, 'Microsoft.Net\\assembly\\GAC_MSIL\\Microsoft.Management.Infrastructure.CimCmdlets\\v4.0_1.0.0.0__31bf3856ad364e35\\Microsoft.Management.Infrastructure.CimCmdlets.dll'))",
          "[Console]::WriteLine('imported-cim')",
        ]
      : []),
    "[Console]::WriteLine('before-cim')",
    '$process = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$PID" -Property ProcessId,Name',
    '[Console]::WriteLine([string]$process.ProcessId + "`t" + [string]$process.Name)',
    "[Console]::WriteLine('after-cim')",
  ].join("\n");
  return new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve, reject) => {
    const child = spawn(
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
        cwd: fixture.root,
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"],
        env: {
          SystemRoot: systemRoot,
          windir: systemRoot,
          PATH: `${systemRoot}\\System32;${systemRoot}`,
          AIH_SCAN_SWEEP_MARKERS: Buffer.from("aih-cim-probe").toString("base64"),
          ...(mode === "utility-manifest-temp" ? { TEMP: fixture.root, TMP: fixture.root } : {}),
        },
      },
    );
    let stdout = "",
      stderr = "";
    child.stdout.on("data", (bytes) => {
      stdout += bytes;
    });
    child.stderr.on("data", (bytes) => {
      stderr += bytes;
    });
    const timer = setTimeout(() => {
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
    }, 15000);
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}
it.runIf(process.platform === "win32")(
  "compares scrubbed CIM autoload with trusted Utility-first imports",
  async () => {
    let selected: Mode | undefined;
    for (const mode of [
      "baseline",
      "utility-manifest",
      "utility-manifest-temp",
      "utility-binary",
    ] as const) {
      const started = performance.now();
      const result = await probe(mode);
      process.stdout.write(
        `${JSON.stringify({ mode, durationMs: performance.now() - started, result })}\n`,
      );
      if (mode !== "baseline" && result.code === 0 && result.stdout.includes("after-cim"))
        selected ??= mode;
    }
    expect(selected, "at least one trusted import must complete").toBeDefined();
    const receipt = process.env.AIH_SCAN_SWEEP_CANDIDATE_OUT;
    if (receipt !== undefined && selected !== undefined) writeFileSync(receipt, selected);
    process.stdout.write(`${JSON.stringify({ selected })}\n`);
  },
  85000,
);
