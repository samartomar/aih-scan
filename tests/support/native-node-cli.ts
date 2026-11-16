import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

let launcher: Buffer | undefined;

/** A native Windows fixture executable, whose Node child stays in Scan's real Job Object. */
export function nativeNodeCli(directory: string, name: string, program: string): string {
  const path = join(directory, process.platform === "win32" ? `${name}.exe` : name);
  if (process.platform !== "win32") {
    writeFileSync(path, `#!${process.execPath}\n${program}`, { mode: 0o755 });
    return path;
  }
  if (launcher === undefined) {
    const source = join(directory, "launcher.cs");
    const compiled = join(directory, "launcher.exe");
    writeFileSync(
      source,
      String.raw`
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
class Fixture {
  // [DEBUG-retro-native] Temporary hosted launcher-stage evidence; no environment values.
  static void Trace(string directory, string stage) {
    File.AppendAllText(Path.Combine(directory, "launcher-trace.log"), DateTime.UtcNow.ToString("O") + "|" + Process.GetCurrentProcess().Id + "|" + Process.GetCurrentProcess().ProcessName + "|" + stage + "\n");
  }
  static string Quote(string value) {
    var result = new StringBuilder("\"");
    int slashes = 0;
    foreach (char c in value) {
      if (c == '\\') { slashes++; continue; }
      result.Append('\\', c == '"' ? slashes * 2 + 1 : slashes);
      result.Append(c); slashes = 0;
    }
    return result.Append('\\', slashes * 2).Append('"').ToString();
  }
  static int Main(string[] args) {
    string directory = AppDomain.CurrentDomain.BaseDirectory;
    Trace(directory, "main");
    string name = Path.GetFileNameWithoutExtension(Environment.GetCommandLineArgs()[0]);
    var arguments = new StringBuilder(Quote(Path.Combine(directory, name + ".cjs")));
    foreach (string arg in args) arguments.Append(' ').Append(Quote(arg));
    var start = new ProcessStartInfo(File.ReadAllText(Path.Combine(directory, "node-path.txt")), arguments.ToString());
    start.UseShellExecute = false;
    start.CreateNoWindow = true;
    start.RedirectStandardOutput = true;
    start.RedirectStandardError = true;
    Trace(directory, "before-child-start");
    using (var child = Process.Start(start)) {
      Trace(directory, "child-started:" + child.Id);
      var output = child.StandardOutput.BaseStream.CopyToAsync(Console.OpenStandardOutput());
      var error = child.StandardError.BaseStream.CopyToAsync(Console.OpenStandardError());
      Trace(directory, "streams-copying");
      child.WaitForExit();
      Trace(directory, "child-exited:" + child.ExitCode);
      System.Threading.Tasks.Task.WaitAll(output, error);
      Trace(directory, "streams-ended");
      return child.ExitCode;
    }
  }
}
`,
    );
    execFileSync(
      join(process.env.SystemRoot ?? "C:\\Windows", "Microsoft.NET/Framework64/v4.0.30319/csc.exe"),
      ["/nologo", "/target:exe", `/out:${compiled}`, source],
      { windowsHide: true, stdio: "pipe" },
    );
    launcher = readFileSync(compiled);
  }
  writeFileSync(path, launcher);
  writeFileSync(join(directory, `${name}.cjs`), program);
  writeFileSync(join(directory, "node-path.txt"), process.execPath);
  return path;
}
