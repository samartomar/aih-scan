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
    string name = Path.GetFileNameWithoutExtension(Environment.GetCommandLineArgs()[0]);
    var arguments = new StringBuilder(Quote(Path.Combine(directory, name + ".cjs")));
    foreach (string arg in args) arguments.Append(' ').Append(Quote(arg));
    var start = new ProcessStartInfo(File.ReadAllText(Path.Combine(directory, "node-path.txt")), arguments.ToString());
    start.UseShellExecute = false;
    start.CreateNoWindow = true;
    start.RedirectStandardOutput = true;
    start.RedirectStandardError = true;
    using (var child = Process.Start(start)) {
      var output = child.StandardOutput.BaseStream.CopyToAsync(Console.OpenStandardOutput());
      var error = child.StandardError.BaseStream.CopyToAsync(Console.OpenStandardError());
      child.WaitForExit(); System.Threading.Tasks.Task.WaitAll(output, error); return child.ExitCode;
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
