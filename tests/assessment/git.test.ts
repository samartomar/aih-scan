import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { afterEach, expect, test, vi } from "vitest";
import * as processBoundary from "../../src/cli/process-runner.js";
import { runScan } from "../../src/public/host.js";

const roots: string[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});
test.each([
  ["y/../file", "Git link target traverses a link or absent entry"],
  ["file/../sub/file", "Git link target traverses a non-directory entry"],
  ["file/.", "Git link target traverses a non-directory entry"],
  ["file/", "Git link target traverses a non-directory entry"],
])("pinned Git refuses target %s rather than changing its traversal meaning", async (linkTarget, detail) => {
  const root = mkdtempSync(join(tmpdir(), "aih-pinned-link-test-"));
  roots.push(root);
  const command = (args: string[], input?: string) =>
    execFileSync("git", args, {
      cwd: root,
      input,
      windowsHide: true,
      env: {
        ...process.env,
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
      },
    });
  command(["init", "--quiet"]);
  mkdirSync(join(root, "sub", "deep"), { recursive: true });
  writeFileSync(join(root, "file"), "lexically resolved but wrong target\n");
  writeFileSync(join(root, "sub", "file"), "actual POSIX link resolution target\n");
  writeFileSync(join(root, "sub", "deep", "member"), "fixture\n");
  command(["add", "."]);
  for (const [path, target] of [
    ["x", linkTarget],
    ["y", "sub/deep"],
  ]) {
    const oid = command(["hash-object", "-w", "--stdin"], target).toString().trim();
    command(["update-index", "--add", "--cacheinfo", `120000,${oid},${path}`]);
  }
  command([
    "-c",
    "user.name=Scan fixture",
    "-c",
    "user.email=scan-fixture@example.invalid",
    "commit",
    "--quiet",
    "-m",
    "Links",
  ]);
  const commit = command(["rev-parse", "HEAD"]).toString().trim();
  vi.spyOn(processBoundary, "spawnBoundedV1").mockImplementation(async (argv) => {
    const args = JSON.parse(argv[2]!) as string[],
      start = args.findIndex((arg) =>
        ["init", "fetch", "rev-parse", "ls-tree", "cat-file"].includes(arg),
      ),
      tail = args.slice(start),
      bytes = ["init", "fetch"].includes(tail[0]!) ? Buffer.alloc(0) : command(tail);
    return {
      code: 0,
      stdout: JSON.stringify({ bytesBase64: bytes.toString("base64") }),
      stderr: "",
      truncated: false,
    };
  });
  const result = await runScan({
    schema: "urn:aihq:scan:request:1.0.0",
    source: { kind: "git", repository: "https://example.invalid/fixture.git", commit },
    selection: { paths: "all", excludedPaths: [] },
    detectors: [{ detectorId: "detector.unavailable", configuration: {} }],
  });
  expect(result).toMatchObject({
    status: "diagnostic",
    phase: "capture",
    diagnostics: [{ code: "invalid-input", detail }],
  });
  expect(result).not.toHaveProperty("scanId");
});
test("pinned Git material uses exact blob bytes and cannot execute source checkout hooks", async () => {
  const root = mkdtempSync(join(tmpdir(), "aih-pinned-git-test-"));
  roots.push(root);
  const command = (args: string[]) =>
    execFileSync("git", args, {
      cwd: root,
      env: {
        ...process.env,
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
      },
      windowsHide: true,
    });
  command(["init", "--quiet"]);
  writeFileSync(join(root, ".gitattributes"), "payload text eol=crlf\n");
  writeFileSync(join(root, "payload"), "hello\n");
  mkdirSync(join(root, "hooks-disabled"));
  writeFileSync(
    join(root, "hooks-disabled", "post-checkout"),
    "#!/bin/sh\nprintf bad > checkout-hook-effect\n",
    { mode: 0o700 },
  );
  command(["-c", "core.autocrlf=false", "add", "."]);
  command([
    "-c",
    "user.name=Scan fixture",
    "-c",
    "user.email=scan-fixture@example.invalid",
    "commit",
    "--quiet",
    "-m",
    "Pinned fixture",
  ]);
  const commit = command(["rev-parse", "HEAD"]).toString("utf8").trim();
  writeFileSync(join(root, "payload"), "different live material\n");
  vi.spyOn(processBoundary, "spawnBoundedV1").mockImplementation(async (argv, options) => {
    // External Git subprocess responses are supplied from a disposable real object store.
    expect(options.containProcessTree).toBe(true);
    const args = JSON.parse(argv[2]!) as string[],
      hookIndex = args.indexOf("core.hooksPath") /* separate key=value form below */;
    expect(hookIndex).toBe(-1);
    const hooks = args
      .find((arg) => arg.startsWith("core.hooksPath="))!
      .slice("core.hooksPath=".length);
    expect(isAbsolute(hooks)).toBe(true);
    expect(hooks.startsWith(options.cwd!)).toBe(false);
    const operation = args.findIndex((arg) =>
      ["init", "fetch", "rev-parse", "ls-tree", "cat-file", "checkout"].includes(arg),
    );
    const tail = args.slice(operation);
    expect(tail[0]).not.toBe("checkout");
    const bytes = tail[0] === "init" || tail[0] === "fetch" ? Buffer.alloc(0) : command(tail);
    return {
      code: 0,
      stdout: JSON.stringify({ bytesBase64: bytes.toString("base64") }),
      stderr: "",
      truncated: false,
    };
  });
  const result = await runScan({
    schema: "urn:aihq:scan:request:1.0.0",
    source: { kind: "git", repository: "https://example.invalid/fixture.git", commit },
    selection: { paths: "all", excludedPaths: [] },
    detectors: [{ detectorId: "detector.unavailable", configuration: {} }],
  });
  expect(result).toMatchObject({
    status: "assessment",
    report: {
      source: {
        kind: "git",
        commit,
        capture: {
          entries: expect.arrayContaining([
            {
              kind: "file",
              path: "payload",
              byteLength: 6,
              sha256: "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
            },
          ]),
        },
      },
    },
  });
  expect(existsSync(join(root, "checkout-hook-effect"))).toBe(false);
});
