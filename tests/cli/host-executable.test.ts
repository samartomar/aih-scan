import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  isRegisteredHostExecutableV1,
  pathDirectoriesV1,
  resolveHostExecutableV1,
  wellKnownExecutableDirectoriesV1,
} from "../../src/cli/host-executable.js";
import { processRunner } from "../../src/cli/process-runner.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function directory(label: string): string {
  const root = mkdtempSync(join(tmpdir(), `aih-scan-exe-${label}-`));
  roots.push(root);
  return root;
}

/** Writes a file that counts as an executable for `name` on this host. */
function executable(parent: string, name: "uv" | "docker"): string {
  mkdirSync(parent, { recursive: true });
  const file = join(parent, process.platform === "win32" ? `${name}.exe` : name);
  writeFileSync(file, "not a real program\n");
  if (process.platform !== "win32") chmodSync(file, 0o755);
  return realpathSync.native(file);
}

describe("host executable resolution", () => {
  it("searches only absolute PATH entries, in order, honouring Windows quoting", () => {
    expect(pathDirectoriesV1({ PATH: "/a:relative::/b" }, "linux")).toEqual(["/a", "/b"]);
    expect(
      pathDirectoriesV1({ Path: 'C:\\x;"C:\\y z";.;\\\\server\\share;d:/w' }, "win32"),
    ).toEqual(["C:\\x", "C:\\y z", "d:/w"]);
    expect(pathDirectoriesV1({}, "darwin")).toEqual([]);
  });

  it("lists the fixed well-known directories for each OS after PATH", () => {
    expect(wellKnownExecutableDirectoriesV1("uv", { HOME: "/home/u" }, "linux")).toEqual([
      "/home/u/.local/bin",
      "/home/u/.cargo/bin",
      "/usr/local/bin",
      "/usr/bin",
      "/home/linuxbrew/.linuxbrew/bin",
    ]);
    expect(wellKnownExecutableDirectoriesV1("uv", { HOME: "/Users/u" }, "darwin")).toEqual([
      "/Users/u/.local/bin",
      "/Users/u/.cargo/bin",
      "/opt/homebrew/bin",
      "/usr/local/bin",
    ]);
    expect(wellKnownExecutableDirectoriesV1("docker", { HOME: "relative" }, "darwin")).toEqual([
      "/opt/homebrew/bin",
      "/usr/local/bin",
      "/Applications/Docker.app/Contents/Resources/bin",
    ]);
    expect(
      wellKnownExecutableDirectoriesV1(
        "docker",
        {
          USERPROFILE: "C:\\Users\\u",
          ProgramFiles: "C:\\Program Files",
          LOCALAPPDATA: "C:\\Users\\u\\AppData\\Local",
        },
        "win32",
      ),
    ).toEqual([
      "C:\\Users\\u\\.local\\bin",
      "C:\\Users\\u\\.cargo\\bin",
      "C:\\Program Files\\Docker\\Docker\\resources\\bin",
      "C:\\Users\\u\\AppData\\Local\\Programs\\DockerDesktop\\resources\\bin",
    ]);
  });

  it("finds PATH before a well-known directory, records where, and resolves the real path", () => {
    const home = directory("home");
    const onPath = directory("path");
    const wellKnown = executable(join(home, ".local", "bin"), "uv");
    const first = executable(onPath, "uv");
    const env =
      process.platform === "win32"
        ? { PATH: onPath, USERPROFILE: home }
        : { PATH: onPath, HOME: home };

    expect(resolveHostExecutableV1("uv", env)).toEqual({
      name: "uv",
      path: first,
      foundIn: "PATH",
    });
    const fallback = resolveHostExecutableV1("uv", { ...env, PATH: directory("empty") });
    expect(fallback).toEqual({ name: "uv", path: wellKnown, foundIn: "well-known-directory" });
  });

  it("returns nothing when the executable is on neither PATH nor a well-known directory", () => {
    const home = directory("nohome");
    const env =
      process.platform === "win32"
        ? { PATH: directory("nopath"), USERPROFILE: home }
        : { PATH: directory("nopath"), HOME: home };
    const found = resolveHostExecutableV1("uv", env);
    // A host may have uv in a shared well-known directory (/usr/local/bin); only a private
    // home and PATH are under this test's control.
    if (found !== undefined) expect(found.foundIn).toBe("well-known-directory");
    else expect(found).toBeUndefined();
  });

  it.runIf(process.platform === "win32")(
    "accepts only <name>.exe on Windows, never a shell shim",
    () => {
      const onPath = directory("shim");
      writeFileSync(join(onPath, "uv.cmd"), "@echo off\n");
      writeFileSync(join(onPath, "uv.bat"), "@echo off\n");
      writeFileSync(join(onPath, "uv"), "#!/bin/sh\n");
      const found = resolveHostExecutableV1("uv", { PATH: onPath, USERPROFILE: directory("h") });
      if (found !== undefined) expect(found.path.toLowerCase()).not.toContain(onPath.toLowerCase());
    },
  );

  it.runIf(process.platform !== "win32")("skips a file without an execute bit", () => {
    const onPath = directory("noexec");
    writeFileSync(join(onPath, "uv"), "#!/bin/sh\n");
    chmodSync(join(onPath, "uv"), 0o644);
    const found = resolveHostExecutableV1("uv", { PATH: onPath, HOME: directory("h") });
    if (found !== undefined) expect(found.path).not.toContain(onPath);
  });

  it("lets Scan's runner spawn only a path this resolver returned", () => {
    const onPath = directory("registered");
    const path = executable(onPath, "docker");
    expect(isRegisteredHostExecutableV1(path)).toBe(false);
    expect(() =>
      processRunner([path, "version"], {
        env: {},
        timeoutMs: 1,
        maxStdoutBytes: 1,
        maxStderrBytes: 1,
      }),
    ).toThrow("registered process argv");
    const env =
      process.platform === "win32"
        ? { PATH: onPath, USERPROFILE: directory("h") }
        : { PATH: onPath, HOME: directory("h") };
    expect(resolveHostExecutableV1("docker", env)?.path).toBe(path);
    expect(isRegisteredHostExecutableV1(path)).toBe(true);
  });
});
