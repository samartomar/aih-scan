import { execFileSync } from "node:child_process";
import { chmodSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { parseGitIndex } from "../../src/host/git-index.js";
import { scanWith } from "../../src/host/scan.js";
import { hostNameProblem, readFolder } from "../../src/host/snapshot.js";
import { type FixtureRoot, fixtureRoot } from "../support/scan-v1-fixture.js";

let fixture: FixtureRoot;
beforeEach(() => {
  fixture = fixtureRoot("aih-scan-v1-names-");
});
afterEach(() => fixture.dispose());

const gitEnv = {
  ...process.env,
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
};
const git = (cwd: string, args: string[]) =>
  execFileSync("git", args, { cwd, env: gitEnv, encoding: "utf8" }).trim();
const itemsRequest = (items: unknown[]) => ({
  format: "aih-scan-request/1",
  origin: "local",
  items,
});
const modesOf = (summaryPath: string) =>
  (JSON.parse(readFileSync(summaryPath, "utf8")).files as { path: string; mode: string }[]).map(
    (file) => [file.path, file.mode],
  );

/** A clone whose index marks run.sh executable while the disk does not. */
function clone(name: string, init: string[] = []) {
  const root = fixture.folder(name, {
    "SKILL.md": "---\nname: x\ndescription: fixture\n---\n# X\n",
    "scripts/run.sh": "echo run\n",
    "scripts/extra.sh": "echo extra\n",
  });
  git(root, ["init", "-q", ...init]);
  git(root, ["add", "SKILL.md", "scripts/run.sh"]);
  git(root, ["update-index", "--chmod=+x", "scripts/run.sh"]);
  chmodSync(join(root, "scripts", "run.sh"), 0o644);
  return root;
}

describe("modes from Git's index when the disk cannot say (section 5)", () => {
  it.each([
    ["a SHA-1 clone (index v2)", [], []],
    ["an index v4 clone", [], ["update-index", "--index-version", "4"]],
    ["a SHA-256 clone", ["--object-format=sha256"], []],
  ])("reads %s as data on Windows, then the executable list, then normal", (_name, init, after) => {
    const root = clone("clone", init as string[]);
    if ((after as string[]).length > 0) git(root, after as string[]);
    const read = readFolder(root, { platform: "win32", executable: ["scripts/extra.sh"] });
    if (read.status !== "ok") throw new Error(JSON.stringify(read));
    expect(read.files.map((file) => [file.path, file.mode])).toEqual([
      ["SKILL.md", "100644"],
      ["scripts/extra.sh", "100755"],
      ["scripts/run.sh", "100755"],
    ]);
    // The disk wins where it records modes.
    const posix = readFolder(root, { platform: "linux" });
    if (posix.status !== "ok") throw new Error(JSON.stringify(posix));
    expect(posix.files.find((file) => file.path === "scripts/run.sh")?.mode).toBe("100644");
  });

  it("gives a Windows folder scan of a clone the key Git computes for its index", async () => {
    const root = clone("clone");
    git(root, ["add", "scripts/extra.sh"]);
    const tree = git(root, ["write-tree"]);
    const result = await scanWith(
      {
        format: "aih-scan-request/1",
        origin: "local",
        source: { type: "folder", path: root },
      },
      { outDir: fixture.path("out") },
      { platform: "win32" },
    );
    const skill = result.results.find((entry) => entry.kind === "skill");
    expect(skill?.status).toBe("ok");
    if (skill?.status !== "ok") return;
    expect(modesOf(skill.summaryPath)).toEqual([
      ["SKILL.md", "100644"],
      ["scripts/extra.sh", "100644"],
      ["scripts/run.sh", "100755"],
    ]);
    expect(skill.scanKey).toBe(`git-sha1:${tree}`);
  });

  it("ignores an index that is not well formed", () => {
    expect(parseGitIndex(new Uint8Array(0))).toBeUndefined();
    expect(parseGitIndex(new TextEncoder().encode("DIRC\0\0\0\x09\0\0\0\x01"))).toBeUndefined();
    const root = clone("clone");
    writeFileSync(join(root, ".git", "index"), "not an index");
    const read = readFolder(root, { platform: "win32" });
    if (read.status !== "ok") throw new Error(JSON.stringify(read));
    expect(read.files.every((file) => file.mode === "100644")).toBe(true);
  });
});

describe("names a host cannot write", () => {
  it("returns invalid item results on Windows instead of rejecting", async () => {
    const reserved = fixture.folder("reserved", { "SKILL.md": "# X\n", "aux.md": "x" });
    const colon = fixture.folder("colon", { "SKILL.md": "# X\n", "notes:1.md": "x" });
    const trailing = fixture.folder("trailing", { "SKILL.md": "# X\n", "dir./a.md": "x" });
    const fine = fixture.folder("fine", { "SKILL.md": "# X\n" });
    const result = await scanWith(
      itemsRequest([{ path: reserved }, { path: colon }, { path: trailing }, { path: fine }]),
      { outDir: fixture.path("out") },
      { platform: "win32" },
    );
    expect(result.status).toBe("refused");
    expect(
      result.results.map((entry) => [entry.status, "reason" in entry && entry.reason]),
    ).toEqual([
      ["invalid", "reserved-name"],
      ["invalid", "reserved-name"],
      ["invalid", "reserved-name"],
      ["ok", false],
    ]);
  });

  it("detects case and normalisation collisions where the file system folds names", () => {
    const files = (...paths: string[]) => paths.map((path) => ({ path }));
    expect(hostNameProblem(files("README.md", "readme.md"), "win32")?.reason).toBe(
      "case-collision",
    );
    expect(hostNameProblem(files("Docs", "docs/a.md"), "darwin")?.reason).toBe("case-collision");
    expect(hostNameProblem(files("caf\u00e9.md", "cafe\u0301.md"), "darwin")?.reason).toBe(
      "case-collision",
    );
    expect(hostNameProblem(files("caf\u00e9.md", "cafe\u0301.md"), "win32")).toBeUndefined();
    expect(hostNameProblem(files("README.md", "readme.md"), "linux")).toBeUndefined();
    expect(hostNameProblem(files("A/x.md", "a/y.md"), "darwin")).toBeUndefined();
  });

  it("scans case-distinct names where the host keeps them apart, and reports them elsewhere", async () => {
    const item = fixture.folder("item", { "SKILL.md": "# X\n", "skill.md": "# y\n" });
    const linux = await scanWith(
      itemsRequest([{ path: item }]),
      { outDir: fixture.path("out1") },
      { platform: "linux" },
    );
    expect(linux.status).toBe("ok");
    const mac = await scanWith(
      itemsRequest([{ path: item }]),
      { outDir: fixture.path("out2") },
      { platform: "darwin" },
    );
    expect(mac.results[0]).toMatchObject({ status: "invalid", reason: "case-collision" });
  });

  it("turns a working copy that cannot be written into a refused item result", async () => {
    const item = fixture.folder("item", { "SKILL.md": "# X\n" });
    const result = await scanWith(
      itemsRequest([{ path: item }]),
      { outDir: fixture.path("out") },
      { snapshotParent: fixture.path("missing/parent") },
    );
    expect(result.status).toBe("refused");
    expect(result.results[0]).toMatchObject({ status: "refused", reason: "snapshot-failed" });
  });
});
