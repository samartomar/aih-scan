import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test, vi } from "vitest";
import * as processBoundary from "../../src/cli/process-runner.js";
import { runScan } from "../../src/public/host.js";

const roots: string[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});
const request = (commit: string) => ({
  schema: "urn:aihq:scan:request:2.0.0",
  source: { kind: "git", repository: "https://example.invalid/fixture.git", commit },
  selection: { paths: "all", excludedPaths: [] },
  detectors: [{ detectorId: "detector.unavailable", configuration: {} }],
});

test("a consumer can explain an oversized pinned repository even with one selected file", async () => {
  const root = mkdtempSync(join(tmpdir(), "aih-git-diagnostic-"));
  roots.push(root);
  const command = (args: string[]) =>
    execFileSync("git", args, {
      cwd: root,
      windowsHide: true,
      env: {
        ...process.env,
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
      },
    });
  command(["init", "--quiet"]);
  writeFileSync(join(root, "SKILL.md"), "# grill-me\n");
  writeFileSync(join(root, "other"), "unselected content\n");
  command(["add", "."]);
  command([
    "-c",
    "user.name=Fixture",
    "-c",
    "user.email=fixture@example.invalid",
    "commit",
    "-qm",
    "oversized",
  ]);
  const commit = command(["rev-parse", "HEAD"]).toString().trim();
  // Only the external process boundary is doubled; pinned objects come from real Git.
  vi.spyOn(processBoundary, "spawnBoundedV1").mockImplementation(async (argv) => {
    const args = JSON.parse(argv[2]!) as string[];
    const operation = args.findIndex((arg) =>
      ["init", "fetch", "rev-parse", "ls-tree", "cat-file"].includes(arg),
    );
    const tail = args.slice(operation);
    const bytes = ["init", "fetch"].includes(tail[0]!) ? Buffer.alloc(0) : command(tail);
    return {
      code: 0,
      stdout: JSON.stringify({ bytesBase64: bytes.toString("base64") }),
      stderr: "",
      truncated: false,
    };
  });
  const result = await runScan({
    ...request(commit),
    selection: { paths: ["SKILL.md"], excludedPaths: [] },
    limits: { maxSourceEntries: 1 },
  });
  expect(result).toMatchObject({
    status: "diagnostic",
    phase: "capture",
    diagnostics: [
      {
        code: "resource-limit",
        detail: expect.stringMatching(/validate tree.*maxSourceEntries.*1.*observed 2/i),
      },
    ],
  });
  expect(result).not.toHaveProperty("scanId");
});

test("an uncontained Git process names the operation without becoming invalid input", async () => {
  vi.spyOn(processBoundary, "spawnBoundedV1").mockResolvedValue({
    code: 1,
    stdout: "",
    stderr: "private upstream text",
    truncated: true,
    termination: "containment-failure",
  });
  const result = await runScan(request("0".repeat(40)));
  expect(result).toMatchObject({
    status: "diagnostic",
    phase: "capture",
    diagnostics: [
      {
        code: "git-containment-failed",
        detail: expect.stringMatching(/git init.*process-tree cleanup/i),
      },
    ],
  });
  expect(JSON.stringify(result)).not.toContain("private upstream text");
  expect(result).not.toHaveProperty("scanId");
});

test.each([
  "d81f3a1",
  "main",
  "refs/tags/v1",
  "A".repeat(40),
])("request commit %s explains exact accepted form", async (commit) => {
  const result = await runScan(request(commit));
  expect(result).toMatchObject({
    status: "diagnostic",
    phase: "request",
    diagnostics: [
      {
        code: "invalid-input",
        detail: expect.stringMatching(/commit.*40.*lowercase.*hexadecimal/i),
      },
    ],
  });
});
test.each([
  "owner/name",
  "http://example.invalid/repo",
  "https://user:secret@example.invalid/repo",
  "https://example.invalid/repo?token=secret",
])("request repository %s explains accepted URL without echoing input", async (repository) => {
  const result = await runScan({
    ...request("0".repeat(40)),
    source: { kind: "git", repository, commit: "0".repeat(40) },
  });
  expect(result).toMatchObject({
    status: "diagnostic",
    phase: "request",
    diagnostics: [
      {
        code: "invalid-input",
        detail: expect.stringMatching(/repository.*credential-free HTTPS.*query.*fragment/i),
      },
    ],
  });
  expect(JSON.stringify(result)).not.toContain("secret");
});

test.each([
  [undefined, "git-acquisition-failed", /exit code 1/],
  ["timeout", "resource-limit", /gitCommandTimeoutMs.*600000.*observed.*600000/],
  ["abort", "git-acquisition-failed", /cancelled/],
  ["output-limit", "resource-limit", /maxStdoutBytes.*maxStderrBytes.*observed/],
] as const)("Git operation failure %s stays actionable", async (termination, code, detail) => {
  vi.spyOn(processBoundary, "spawnBoundedV1").mockResolvedValue({
    code: 1,
    stdout: "",
    stderr: "sensitive upstream message",
    truncated: !!termination,
    ...(termination ? { termination } : {}),
  });
  const result = await runScan(request("0".repeat(40)));
  expect(result).toMatchObject({
    status: "diagnostic",
    phase: "capture",
    diagnostics: [{ code, detail: expect.stringMatching(detail) }],
  });
  expect(result.diagnostics[0]?.detail).toMatch(/git init/);
  expect(JSON.stringify(result)).not.toContain("sensitive upstream");
});
