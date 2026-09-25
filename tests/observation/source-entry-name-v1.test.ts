import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CISCO_MULTI_SKILL_SCANNER_PROJECT_V1 } from "../../src/detectors/cisco-multi-skill/plan-v1.js";
import { runCiscoShardV1 } from "../../src/detectors/cisco-multi-skill/shard-v1.js";
import {
  representableSourceNameProblemV1,
  UnrepresentableSourcePathErrorV1,
} from "../../src/observation/source-entry-name-v1.js";
import { hashComponentTreeV1, hashSourceTreeV1 } from "../../src/observation/source-hash-v1.js";
import { sealSourceObservationV1 } from "../../src/observation/source-observation-seal-v1.js";
import { sealSourceV2 } from "../../src/observation/source-seal-v2.js";
import { runDetectorV1 } from "../../src/runner/run-detector-v1.js";

// S2h (review of S2g): on Linux the literal file name `a\b.txt` became inventory path
// `a/b.txt`, so a result naming a file that does not exist was bound and the completion
// digest hashed the wrong path name. A POSIX name the source-relative form cannot carry
// exactly is refused, typed and named, before any seal; Windows is unchanged.

const bytes = (text: string) => Buffer.from(text, "utf8");

describe("representableSourceNameProblemV1", () => {
  it("refuses a POSIX name with a backslash, a control character or bytes that are not UTF-8", () => {
    for (const name of [
      bytes("a\\b.txt"),
      bytes("\\"),
      bytes(`a${String.fromCharCode(1)}b`),
      bytes(`tab${String.fromCharCode(9)}`),
      bytes(`nl${String.fromCharCode(10)}`),
      bytes(`del${String.fromCharCode(0x7f)}`),
      Buffer.from([0x61, 0xff]),
      Buffer.from([0xc0, 0xaf]),
      Buffer.from([0xed, 0xa0, 0x80]),
      Buffer.from([0xe9]),
    ])
      for (const platform of ["linux", "darwin"] as const)
        expect(representableSourceNameProblemV1(name, platform), name.toString("hex")).toMatch(
          /backslash|control character|not UTF-8/,
        );
  });

  it("accepts every other name, and keeps Windows behaviour unchanged", () => {
    for (const name of [
      "SKILL.md",
      "é.md",
      "a b",
      "100%.md",
      "q?#:.md",
      `${String.fromCharCode(0xfffd)}.md`,
      ".git",
    ])
      expect(representableSourceNameProblemV1(bytes(name), "linux"), name).toBeUndefined();
    expect(representableSourceNameProblemV1(bytes("a\\b.txt"), "win32")).toBeUndefined();
    expect(representableSourceNameProblemV1(Buffer.from([0xff]), "win32")).toBeUndefined();
  });
});

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});
function fixture(): string {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "aih-scan-entry-name-")));
  roots.push(root);
  mkdirSync(join(root, "skills", "alpha"), { recursive: true });
  writeFileSync(join(root, "skills", "alpha", "SKILL.md"), "# alpha\n", "utf8");
  return root;
}
/** Writes one file whose last path segment is the given raw name bytes. */
function writeRaw(root: string, name: Buffer): void {
  writeFileSync(Buffer.concat([bytes(`${join(root, "skills", "alpha")}/`), name]), "x\n");
}

const HOSTILE = [
  ["a backslash (reviewer: a\\b.txt)", bytes("a\\b.txt"), /backslash/],
  ["a control character", bytes(`a${String.fromCharCode(1)}b`), /control character/],
  ["bytes that are not UTF-8", Buffer.from([0x61, 0xff]), /not UTF-8/],
] as const;

describe.runIf(process.platform !== "win32")("every seal refuses an unrepresentable name", () => {
  it.each(HOSTILE)("%s", async (_label, name, reason) => {
    const root = fixture();
    writeRaw(root, name);
    const typed = (seal: () => unknown) => {
      let thrown: unknown;
      try {
        seal();
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(UnrepresentableSourcePathErrorV1);
      const error = thrown as UnrepresentableSourcePathErrorV1;
      expect(error.path.startsWith("skills/alpha/")).toBe(true);
      expect(error.message).toMatch(reason);
      expect(error.message).toContain("skills/alpha/");
    };
    typed(() => hashComponentTreeV1(root, ["skills/alpha"]));
    typed(() => hashSourceTreeV1(root));
    typed(() => sealSourceObservationV1({ sourceRoot: root, selectedClosurePaths: [] }));
    typed(() =>
      sealSourceV2({ sourceRoot: root, selectedClosurePaths: ["skills/alpha/SKILL.md"] }),
    );

    const outcome = await runDetectorV1({
      detectorId: "detector.aih-native",
      subject: { kind: "source-tree", sourceRoot: root, selectedClosurePaths: [] },
    });
    expect(outcome.outcome).toBe("refused");
    if (outcome.outcome === "refused") {
      expect(outcome.reason).toBe("subject-requirement-unmet");
      expect(outcome.detail).toMatch(reason);
      expect(outcome.detail).toContain("skills/alpha/");
    }
  });

  it.each(
    HOSTILE,
  )("the Cisco shard refuses %s before any analyzer runs", async (_l, name, reason) => {
    const root = fixture();
    const inputSha256 = hashComponentTreeV1(root, ["skills/alpha"]).treeSha256;
    writeRaw(root, name);
    const calls: string[][] = [];
    const outcome = await runCiscoShardV1({
      run: async (argv) => {
        calls.push([...argv]);
        return { code: 2, stdout: "", stderr: "not expected" };
      },
      platform: "linux",
      env: {},
      sourceRoot: root,
      jobs: [{ id: "alpha", path: "skills/alpha", inputSha256 }],
      expected: {
        analyzerVersion: "2.0.14",
        lockSha256: createHash("sha256")
          .update(readFileSync(join(CISCO_MULTI_SKILL_SCANNER_PROJECT_V1, "uv.lock")))
          .digest("hex"),
      },
      concurrency: 1,
    });
    expect(outcome).toMatchObject({ kind: "refused", reason: "shard-request-invalid" });
    if (outcome.kind === "refused") {
      expect(outcome.detail).toMatch(reason);
      expect(outcome.detail).toContain("skills/alpha/");
    }
    expect(calls).toEqual([]);
  });

  it("never reads a backslash as a separator: a/b.txt is not a sealed path", () => {
    const root = fixture();
    mkdirSync(join(root, "skills", "alpha", "a"));
    writeFileSync(join(root, "skills", "alpha", "a", "b.txt"), "x\n", "utf8");
    expect(hashComponentTreeV1(root, ["skills/alpha"]).files.map((file) => file.path)).toEqual([
      "skills/alpha/SKILL.md",
      "skills/alpha/a/b.txt",
    ]);
    writeRaw(root, bytes("a\\b.txt"));
    expect(() => hashComponentTreeV1(root, ["skills/alpha"])).toThrow(/backslash/);
  });
});
