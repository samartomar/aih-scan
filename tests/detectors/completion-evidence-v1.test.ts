import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  attachScanCompletionV1,
  SCAN_COMPLETION_PROPERTY_V1,
  type ScanCompletionEvidenceV1,
  scanCompletionEvidenceV1,
  scanCompletionSubjectFilesV1,
  subjectFilesDigestV1,
} from "../../src/detectors/completion-evidence-v1.js";
import type { SourceObservationEntryV1 } from "../../src/observation/source-observation-seal-v1.js";

// S2g (C2a §1.6): every succeeded SARIF run names the subject Scan proved was analyzed, as a
// digest Core can recompute over the exact sealed files the analyzer received.
const sha = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");
const EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

describe("subject-files-v1 digest", () => {
  it("matches the contract's test vector and its empty set", () => {
    expect(
      subjectFilesDigestV1([
        { path: "scripts/run.sh", sha256: sha("echo\n") },
        { path: "SKILL.md", sha256: sha("# alpha\n") },
      ]),
    ).toEqual({
      subjectTreeSha256: "adc6c170f014a8d238d3f18b3cd44e82cbfbe1f7fa9b4bafae6f5aab1cece047",
      analyzedFileCount: 2,
    });
    expect(subjectFilesDigestV1([])).toEqual({
      subjectTreeSha256: EMPTY_SHA256,
      analyzedFileCount: 0,
    });
  });

  it("frames path NUL digest LF over code-unit order, never locale order", () => {
    const files = [
      { path: "b.md", sha256: sha("b") },
      { path: "B.md", sha256: sha("B") },
      { path: "é.md", sha256: sha("e") },
      { path: "a/b.md", sha256: sha("ab") },
    ];
    const ordered = ["B.md", "a/b.md", "b.md", "é.md"];
    const byPath = new Map(files.map((file) => [file.path, file.sha256]));
    const bytes = Buffer.concat(
      ordered.map((path) => Buffer.from(`${path}\u0000${byPath.get(path)}\n`, "utf8")),
    );
    expect(subjectFilesDigestV1(files).subjectTreeSha256).toBe(
      createHash("sha256").update(bytes).digest("hex"),
    );
  });

  it.each([
    [
      "a duplicate path",
      [
        { path: "a.md", sha256: sha("1") },
        { path: "a.md", sha256: sha("2") },
      ],
    ],
    ["an empty path", [{ path: "", sha256: sha("1") }]],
    ["a NUL in a path", [{ path: "a\u0000b", sha256: sha("1") }]],
    ["an uppercase digest", [{ path: "a.md", sha256: sha("1").toUpperCase() }]],
    ["a short digest", [{ path: "a.md", sha256: "abc" }]],
  ])("refuses %s", (_label, files) => {
    expect(() => subjectFilesDigestV1(files)).toThrow(TypeError);
  });
});

describe("the evidence record", () => {
  const analyzer = { version: "2.0.14+uvlock.0123456789ab", lockSha256: "a".repeat(64) };

  it("digests the subject and names the detector and analyzer", () => {
    const files = [{ path: "SKILL.md", sha256: sha("# alpha\n") }];
    expect(
      scanCompletionEvidenceV1({
        detectorId: "detector.cisco",
        files,
        emptyAllowed: false,
        analyzer,
      }),
    ).toEqual({ detectorId: "detector.cisco", ...subjectFilesDigestV1(files), analyzer });
  });

  it("allows a zero count only where the detector completes on an empty source", () => {
    expect(
      scanCompletionEvidenceV1({
        detectorId: "detector.semgrep",
        files: [],
        emptyAllowed: true,
        analyzer,
      }).analyzedFileCount,
    ).toBe(0);
    expect(() =>
      scanCompletionEvidenceV1({
        detectorId: "detector.cisco",
        files: [],
        emptyAllowed: false,
        analyzer,
      }),
    ).toThrow(/detector\.cisco analyzed no file/);
  });

  it("refuses an analyzer identity it cannot publish", () => {
    for (const bad of [
      { version: "", lockSha256: null },
      { version: "1.0.0", lockSha256: "ABC" },
    ])
      expect(() =>
        scanCompletionEvidenceV1({
          detectorId: "detector.semgrep",
          files: [],
          emptyAllowed: true,
          analyzer: bad,
        }),
      ).toThrow(/completion evidence/);
  });
});

describe("the subject file set per detector", () => {
  const entries: SourceObservationEntryV1[] = [
    { kind: "directory", path: ".git" },
    { kind: "file", path: ".git/HEAD", sha256: sha("head"), byteLength: 4 },
    { kind: "file", path: ".gitignore", sha256: sha("ignore"), byteLength: 6 },
    { kind: "file", path: "README.md", sha256: sha("readme"), byteLength: 6 },
    { kind: "file", path: "SKILL.md", sha256: sha("root"), byteLength: 4 },
    { kind: "directory", path: "skills" },
    { kind: "directory", path: "skills/a" },
    { kind: "file", path: "skills/a/SKILL.md", sha256: sha("a"), byteLength: 1 },
    {
      kind: "file-link",
      path: "skills/a/linked.md",
      target: "README.md",
      sha256: sha("readme"),
      byteLength: 6,
    },
    { kind: "directory-link", path: "skills/a/up", target: "skills" },
    { kind: "directory", path: "skills/a/nested" },
    { kind: "file", path: "skills/a/nested/SKILL.md", sha256: sha("n"), byteLength: 1 },
    { kind: "directory", path: "skills/b" },
    { kind: "file", path: "skills/b/SKILL.md", sha256: sha("b"), byteLength: 1 },
    { kind: "file", path: "skills/b/.mcp.json", sha256: sha("{}"), byteLength: 2 },
  ];
  const paths = (
    engine: Parameters<typeof scanCompletionSubjectFilesV1>[0]["engine"],
    selectedClosurePaths: readonly string[] = [],
    detectorOptions?: unknown,
  ) =>
    scanCompletionSubjectFilesV1({ engine, entries, selectedClosurePaths, detectorOptions }).map(
      (file) => file.path,
    );
  const outsideGit = [
    ".gitignore",
    "README.md",
    "SKILL.md",
    "skills/a/SKILL.md",
    "skills/a/linked.md",
    "skills/a/nested/SKILL.md",
    "skills/b/.mcp.json",
    "skills/b/SKILL.md",
  ];

  it("gives Semgrep and SkillSpector every sealed file, top-level .git included", () => {
    for (const engine of ["semgrep", "skillspector"] as const)
      expect(paths(engine)).toEqual([".git/HEAD", ...outsideGit]);
  });

  it("gives Cisco skill-directory and Snyk the snapshot: every file outside top-level .git", () => {
    for (const engine of ["cisco", "snyk-agent-scan"] as const)
      expect(paths(engine)).toEqual(outsideGit);
    const gitFile = scanCompletionSubjectFilesV1({
      engine: "cisco",
      entries: [
        { kind: "file", path: ".git", sha256: sha("gitdir: x"), byteLength: 9 },
        { kind: "file", path: ".gitx", sha256: sha("x"), byteLength: 1 },
      ],
      selectedClosurePaths: [],
    });
    expect(gitFile.map((file) => file.path)).toEqual([".gitx"]);
  });

  it("gives Cisco source-tree the snapshot files inside its job directories, each once", () => {
    expect(paths("cisco-source-tree", ["skills/a/SKILL.md", "skills/a/nested/SKILL.md"])).toEqual([
      "skills/a/SKILL.md",
      "skills/a/linked.md",
      "skills/a/nested/SKILL.md",
    ]);
    expect(paths("cisco-source-tree", ["SKILL.md", "skills/b/SKILL.md"])).toEqual(outsideGit);
    // "skills/a" does not contain "skills/ab".
    const prefix = scanCompletionSubjectFilesV1({
      engine: "cisco-source-tree",
      entries: [
        { kind: "file", path: "skills/a/SKILL.md", sha256: sha("a"), byteLength: 1 },
        { kind: "file", path: "skills/ab/x.md", sha256: sha("x"), byteLength: 1 },
      ],
      selectedClosurePaths: ["skills/a/SKILL.md"],
    });
    expect(prefix.map((file) => file.path)).toEqual(["skills/a/SKILL.md"]);
  });

  it("gives mcp-scanner the sealed config files it was told to read", () => {
    expect(
      paths("cisco-mcp-scanner", [], { mcpConfigPaths: ["skills/b/.mcp.json", "skills/a/up"] }),
    ).toEqual(["skills/b/.mcp.json"]);
  });

  it("gives the in-process engines the declared selection", () => {
    for (const engine of ["aih-trust-lint", "aih-binding-gate"] as const) {
      expect(paths(engine, ["skills/b/SKILL.md", "README.md"])).toEqual([
        "README.md",
        "skills/b/SKILL.md",
      ]);
      expect(paths(engine, [])).toEqual([]);
    }
  });

  it("carries each file's sealed digest, a file link's being its target's bytes", () => {
    const files = scanCompletionSubjectFilesV1({
      engine: "cisco",
      entries,
      selectedClosurePaths: [],
    });
    expect(files.find((file) => file.path === "skills/a/linked.md")?.sha256).toBe(sha("readme"));
  });

  it("refuses a selected or configured path the seal holds no file for", () => {
    expect(() => paths("aih-trust-lint", ["missing.md"])).toThrow(TypeError);
    expect(() => paths("cisco-mcp-scanner", [], { mcpConfigPaths: "x" })).toThrow(TypeError);
  });
});

describe("attaching the evidence", () => {
  const evidence: ScanCompletionEvidenceV1 = Object.freeze({
    detectorId: "detector.semgrep",
    subjectTreeSha256: EMPTY_SHA256,
    analyzedFileCount: 0,
    analyzer: Object.freeze({ version: "1.2.3+uvlock.0123456789ab", lockSha256: null }),
  });
  const run = (extra: Record<string, unknown> = {}) => ({
    tool: { driver: { name: "tool" } },
    results: [],
    ...extra,
  });

  it("adds the key to an analyzer's first invocation and keeps everything else", () => {
    const log = {
      version: "2.1.0",
      runs: [
        run({
          invocations: [
            { executionSuccessful: true, properties: { vendor: 1 } },
            { executionSuccessful: true },
          ],
        }),
        run({ invocations: [{ executionSuccessful: true }] }),
      ],
    };
    const attached = attachScanCompletionV1(log, evidence, { scanBuilt: false });
    expect(attached.runs).toEqual([
      run({
        invocations: [
          {
            executionSuccessful: true,
            properties: { vendor: 1, [SCAN_COMPLETION_PROPERTY_V1]: evidence },
          },
          { executionSuccessful: true },
        ],
      }),
      run({
        invocations: [
          { executionSuccessful: true, properties: { [SCAN_COMPLETION_PROPERTY_V1]: evidence } },
        ],
      }),
    ]);
  });

  it("writes one successful invocation into a Scan-built run", () => {
    const attached = attachScanCompletionV1({ version: "2.1.0", runs: [run()] }, evidence, {
      scanBuilt: true,
    });
    expect(attached.runs).toEqual([
      run({
        invocations: [
          { executionSuccessful: true, properties: { [SCAN_COMPLETION_PROPERTY_V1]: evidence } },
        ],
      }),
    ]);
  });

  it.each([
    ["a log with no runs", { version: "2.1.0", runs: [] }, true],
    ["runs that are not a list", { version: "2.1.0", runs: {} }, true],
    ["a run that is not an object", { version: "2.1.0", runs: [1] }, true],
    ["an analyzer run without invocations", { version: "2.1.0", runs: [run()] }, false],
    ["an empty invocation list", { version: "2.1.0", runs: [run({ invocations: [] })] }, true],
    [
      "a first invocation that did not succeed",
      { version: "2.1.0", runs: [run({ invocations: [{ executionSuccessful: false }] })] },
      false,
    ],
    [
      "a first invocation without executionSuccessful",
      { version: "2.1.0", runs: [run({ invocations: [{}] })] },
      false,
    ],
    [
      "properties that are not an object",
      {
        version: "2.1.0",
        runs: [run({ invocations: [{ executionSuccessful: true, properties: [] }] })],
      },
      false,
    ],
  ])("fails closed on %s", (_label, log, scanBuilt) => {
    expect(() => attachScanCompletionV1(log, evidence, { scanBuilt })).toThrow(
      /completion evidence/,
    );
  });

  it("treats an analyzer-supplied completion key on any invocation as a forgery", () => {
    for (const index of [0, 1]) {
      const invocations = [{ executionSuccessful: true }, { executionSuccessful: true }] as Record<
        string,
        unknown
      >[];
      (invocations[index] as Record<string, unknown>).properties = {
        [SCAN_COMPLETION_PROPERTY_V1]: evidence,
      };
      for (const scanBuilt of [false, true])
        expect(() =>
          attachScanCompletionV1({ version: "2.1.0", runs: [run({ invocations })] }, evidence, {
            scanBuilt,
          }),
        ).toThrow(/forged/);
    }
  });
});
