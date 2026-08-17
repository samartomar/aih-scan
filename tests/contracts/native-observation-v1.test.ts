import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  assessNativeObservationReuseV1,
  createNativeObservationV1,
  createSealedSourceSnapshotV1,
  describeNativeObservationSourceV1,
  sealNativeObservationSourceV1,
} from "../../src/observation/native-observation-v1.js";
import { hashComponentTreeV1, hashSourceTreeV1 } from "../../src/observation/source-hash-v1.js";

const sha = (digit: string) => digit.repeat(64);
const snapshotInput = {
  protocol: "SealedSourceSnapshotV1",
  sourceTreeSha256: sha("a"),
  selectedClosureSha256: sha("b"),
  sourceFiles: [{ path: "skills/demo/SKILL.md", bytes: 5, sha256: sha("c") }],
  selectedClosureFiles: [{ path: "skills/demo/SKILL.md", bytes: 5, sha256: sha("c") }],
};
const keyContext = {
  protocol: "NativeObservationV1",
  nativeAnalyzerIdentity: "native.0123456789ab",
  observationConfigurationSha256: sha("d"),
  platform: { os: "linux", architecture: "amd64", relevantFactsSha256: sha("e") },
};

function liveFixture() {
  const sourceRoot = mkdtempSync(join(tmpdir(), "aih-scan-native-"));
  const selectedClosurePaths = ["selected/SKILL.md"];
  mkdirSync(join(sourceRoot, "selected"), { recursive: true });
  writeFileSync(join(sourceRoot, "selected", "SKILL.md"), "# initial\n");
  const sealedSnapshot = describeNativeObservationSourceV1({ sourceRoot, selectedClosurePaths });
  const sourceSeal = sealNativeObservationSourceV1({ sourceRoot, selectedClosurePaths });
  const input = {
    ...keyContext,
    sourceSeal,
    facts: [],
    coverage: [
      { coverageKind: "selected-closure" as const, coverageSha256: sha("f") },
      { coverageKind: "source-tree" as const, coverageSha256: sha("0") },
    ],
  };
  const observation = createNativeObservationV1(input);
  return {
    sourceRoot,
    selectedClosurePaths,
    sealedSnapshot,
    input,
    observation,
    cleanup: () => rmSync(sourceRoot, { recursive: true, force: true }),
  };
}

describe("NativeObservationV1", () => {
  it("seals source tree and selected closure separately, accepts zero facts only with coverage, and stays local-only", () => {
    const snapshot = createSealedSourceSnapshotV1(snapshotInput);
    const seal = {
      protocol: "SourceSealV1",
      sourceTreeSha256: snapshot.sourceTreeSha256,
      selectedClosureSha256: snapshot.selectedClosureSha256,
      sealedSnapshotSha256: snapshot.sealedSnapshotSha256,
    };
    const observation = createNativeObservationV1({
      ...keyContext,
      sourceSeal: seal,
      facts: [],
      coverage: [{ coverageKind: "selected-closure", coverageSha256: sha("f") }],
    });
    expect(Object.keys(observation).sort()).toEqual([
      "coverage",
      "facts",
      "nativeAnalyzerIdentity",
      "observationConfigurationSha256",
      "observationKeySha256",
      "platform",
      "protocol",
      "resultSha256",
      "reuseScope",
      "sourceSeal",
    ]);
    expect(Object.keys(observation.sourceSeal).sort()).toEqual([
      "protocol",
      "sealedSnapshotSha256",
      "selectedClosureSha256",
      "sourceTreeSha256",
    ]);
    expect(observation.reuseScope).toBe("local-optimization-only");
    expect(observation.resultSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(Object.isFrozen(observation.sourceSeal)).toBe(true);
    expect(Object.isFrozen(observation.platform)).toBe(true);
    expect(JSON.stringify(observation)).not.toMatch(
      /PASS|policy|verdict|acceptance|acknowledg|timestamp|runId|message|[A-Za-z]:\\/i,
    );
  });

  it("fails closed for unsafe snapshots, duplicate facts/coverage, invalid multiplicity, and incomplete reuse context", () => {
    expect(() =>
      createSealedSourceSnapshotV1({
        ...snapshotInput,
        sourceFiles: [{ ...snapshotInput.sourceFiles[0], path: "../escape" }],
      }),
    ).toThrow();
    expect(() =>
      createNativeObservationV1({
        ...keyContext,
        sourceSeal: {
          protocol: "SourceSealV1",
          sourceTreeSha256: sha("0"),
          selectedClosureSha256: sha("0"),
          sealedSnapshotSha256: sha("0"),
        },
        facts: [{ rawOccurrenceFingerprint: `raw-occurrence-v1:${sha("1")}`, multiplicity: 0 }],
        coverage: [{ coverageKind: "selected-closure", coverageSha256: sha("2") }],
      }),
    ).toThrow();
    for (const fact of [
      { rawOccurrenceFingerprint: sha("1"), multiplicity: 1 },
      { rawOccurrenceFingerprint: `raw-occurrence-v1:${sha("1")}`, multiplicity: 1.5 },
      { rawOccurrenceFingerprint: `raw-occurrence-v1:${sha("1")}`, multiplicity: -1 },
      {
        rawOccurrenceFingerprint: `raw-occurrence-v1:${sha("1")}`,
        multiplicity: Number.MAX_SAFE_INTEGER + 1,
      },
    ]) {
      expect(() =>
        createNativeObservationV1({
          ...keyContext,
          sourceSeal: {
            protocol: "SourceSealV1",
            sourceTreeSha256: sha("0"),
            selectedClosureSha256: sha("0"),
            sealedSnapshotSha256: sha("0"),
          },
          facts: [fact],
          coverage: [{ coverageKind: "selected-closure", coverageSha256: sha("2") }],
        }),
      ).toThrow();
    }
    expect(() =>
      createNativeObservationV1({
        ...keyContext,
        sourceSeal: {
          protocol: "SourceSealV1",
          sourceTreeSha256: sha("0"),
          selectedClosureSha256: sha("0"),
          sealedSnapshotSha256: sha("0"),
        },
        facts: [
          { rawOccurrenceFingerprint: `raw-occurrence-v1:${sha("1")}`, multiplicity: 1 },
          { rawOccurrenceFingerprint: `raw-occurrence-v1:${sha("1")}`, multiplicity: 2 },
        ],
        coverage: [{ coverageKind: "selected-closure", coverageSha256: sha("2") }],
      }),
    ).toThrow();
    expect(() =>
      createNativeObservationV1({
        ...keyContext,
        sourceSeal: {
          protocol: "SourceSealV1",
          sourceTreeSha256: sha("0"),
          selectedClosureSha256: sha("0"),
          sealedSnapshotSha256: sha("0"),
        },
        facts: [],
        coverage: [
          { coverageKind: "selected-closure", coverageSha256: sha("2") },
          { coverageKind: "selected-closure", coverageSha256: sha("3") },
        ],
      }),
    ).toThrow();
    expect(assessNativeObservationReuseV1({ observation: {} } as never)).toMatchObject({
      kind: "required",
      code: "NATIVE_OBSERVATION_REQUIRED",
    });
  });

  it("uses a branded live snapshot and exact factual context to distinguish every closed reuse reason", () => {
    const reusable = liveFixture();
    try {
      const base = {
        observation: reusable.observation,
        sealedSnapshot: reusable.sealedSnapshot,
        sourceRoot: reusable.sourceRoot,
        selectedClosurePaths: reusable.selectedClosurePaths,
        expectedKeyContext: {
          protocol: reusable.input.protocol,
          nativeAnalyzerIdentity: reusable.input.nativeAnalyzerIdentity,
          observationConfigurationSha256: reusable.input.observationConfigurationSha256,
          platform: reusable.input.platform,
        },
      };
      expect(assessNativeObservationReuseV1(base)).toEqual({ kind: "reusable-local" });
      expect(
        assessNativeObservationReuseV1({ ...base, observation: structuredClone(base.observation) }),
      ).toEqual({
        kind: "required",
        code: "NATIVE_OBSERVATION_REQUIRED",
        reason: "invalid-observation",
      });
      expect(
        assessNativeObservationReuseV1({ ...base, sealedSnapshot: undefined } as never),
      ).toEqual({
        kind: "required",
        code: "NATIVE_OBSERVATION_REQUIRED",
        reason: "sealed-snapshot-required",
      });
      expect(
        assessNativeObservationReuseV1({ ...base, expectedKeyContext: undefined } as never),
      ).toEqual({
        kind: "required",
        code: "NATIVE_OBSERVATION_REQUIRED",
        reason: "expected-key-context-required",
      });
      expect(
        assessNativeObservationReuseV1({
          ...base,
          expectedKeyContext: {
            ...base.expectedKeyContext,
            nativeAnalyzerIdentity: "native.fedcba987654",
          },
        }),
      ).toEqual({
        kind: "required",
        code: "NATIVE_OBSERVATION_REQUIRED",
        reason: "expected-key-context-mismatch",
      });
      expect(
        assessNativeObservationReuseV1({
          ...base,
          sourceRoot: join(reusable.sourceRoot, "missing"),
        }),
      ).toEqual({
        kind: "required",
        code: "NATIVE_OBSERVATION_REQUIRED",
        reason: "source-bytes-unavailable",
      });
      const mismatchedObservation = createNativeObservationV1({
        ...reusable.input,
        sourceSeal: { ...reusable.input.sourceSeal, sealedSnapshotSha256: sha("9") },
      });
      expect(
        assessNativeObservationReuseV1({ ...base, observation: mismatchedObservation }),
      ).toEqual({
        kind: "required",
        code: "NATIVE_OBSERVATION_REQUIRED",
        reason: "sealed-snapshot-mismatch",
      });
    } finally {
      reusable.cleanup();
    }

    const closure = liveFixture();
    try {
      writeFileSync(join(closure.sourceRoot, "selected", "SKILL.md"), "# changed\n");
      expect(
        assessNativeObservationReuseV1({
          observation: closure.observation,
          sealedSnapshot: describeNativeObservationSourceV1({
            sourceRoot: closure.sourceRoot,
            selectedClosurePaths: closure.selectedClosurePaths,
          }),
          sourceRoot: closure.sourceRoot,
          selectedClosurePaths: closure.selectedClosurePaths,
          expectedKeyContext: {
            protocol: closure.input.protocol,
            nativeAnalyzerIdentity: closure.input.nativeAnalyzerIdentity,
            observationConfigurationSha256: closure.input.observationConfigurationSha256,
            platform: closure.input.platform,
          },
        }),
      ).toEqual({
        kind: "required",
        code: "NATIVE_OBSERVATION_REQUIRED",
        reason: "selected-closure-mismatch",
      });
    } finally {
      closure.cleanup();
    }

    const tree = liveFixture();
    try {
      writeFileSync(join(tree.sourceRoot, "UNSELECTED.md"), "# tree changed\n");
      expect(
        assessNativeObservationReuseV1({
          observation: tree.observation,
          sealedSnapshot: describeNativeObservationSourceV1({
            sourceRoot: tree.sourceRoot,
            selectedClosurePaths: tree.selectedClosurePaths,
          }),
          sourceRoot: tree.sourceRoot,
          selectedClosurePaths: tree.selectedClosurePaths,
          expectedKeyContext: {
            protocol: tree.input.protocol,
            nativeAnalyzerIdentity: tree.input.nativeAnalyzerIdentity,
            observationConfigurationSha256: tree.input.observationConfigurationSha256,
            platform: tree.input.platform,
          },
        }),
      ).toEqual({
        kind: "required",
        code: "NATIVE_OBSERVATION_REQUIRED",
        reason: "source-tree-mismatch",
      });
    } finally {
      tree.cleanup();
    }
  });

  it("uses source-tree and component hashes that preserve directory entries and reject normalized duplicate roots", () => {
    const sourceRoot = mkdtempSync(join(tmpdir(), "aih-scan-source-hash-"));
    try {
      mkdirSync(join(sourceRoot, "alpha"), { recursive: true });
      writeFileSync(join(sourceRoot, "alpha", "note.txt"), "ASCII\n");
      const source = hashSourceTreeV1(sourceRoot);
      const component = hashComponentTreeV1(sourceRoot, ["alpha"]);
      expect(source.files).toEqual([
        {
          path: "alpha/note.txt",
          bytes: 6,
          sha256: createHash("sha256").update("ASCII\n", "utf8").digest("hex"),
        },
      ]);
      expect(component.files).toEqual(source.files);
      expect(() => hashComponentTreeV1(sourceRoot, ["alpha", "alpha/./"])).toThrow();
    } finally {
      rmSync(sourceRoot, { recursive: true, force: true });
    }
  });

  it("enforces public V1 collection bounds", () => {
    const sourceFile = snapshotInput.sourceFiles[0];
    const selectedFile = snapshotInput.selectedClosureFiles[0];
    if (sourceFile === undefined || selectedFile === undefined)
      throw new Error("snapshot fixture missing");
    const files = Array.from({ length: 100_001 }, (_, index) => ({
      ...sourceFile,
      path: `files/${String(index)}.txt`,
    }));
    expect(() =>
      createSealedSourceSnapshotV1({
        ...snapshotInput,
        sourceFiles: files,
        selectedClosureFiles: [{ ...selectedFile, path: "files/0.txt" }],
      }),
    ).toThrow();
    const seal = {
      protocol: "SourceSealV1",
      sourceTreeSha256: sha("0"),
      selectedClosureSha256: sha("1"),
      sealedSnapshotSha256: sha("2"),
    };
    const fact = { rawOccurrenceFingerprint: `raw-occurrence-v1:${sha("3")}`, multiplicity: 1 };
    const coverage = { coverageKind: "selected-closure" as const, coverageSha256: sha("4") };
    expect(() =>
      createNativeObservationV1({
        ...keyContext,
        sourceSeal: seal,
        facts: Array.from({ length: 4097 }, (_, index) => ({
          ...fact,
          rawOccurrenceFingerprint: `raw-occurrence-v1:${index.toString(16).padStart(64, "0")}`,
        })),
        coverage: [coverage],
      }),
    ).toThrow();
    expect(() =>
      createNativeObservationV1({
        ...keyContext,
        sourceSeal: seal,
        facts: [],
        coverage: Array.from({ length: 4097 }, () => coverage),
      }),
    ).toThrow();
  });

  it("returns expected-key-context-required without reading hostile context properties", () => {
    const fixture = liveFixture();
    try {
      const base = {
        observation: fixture.observation,
        sealedSnapshot: fixture.sealedSnapshot,
        sourceRoot: fixture.sourceRoot,
        selectedClosurePaths: fixture.selectedClosurePaths,
      };
      const accessor: Record<string, unknown> = {};
      Object.defineProperty(accessor, "protocol", {
        enumerable: true,
        get: () => {
          throw new Error("must not execute accessor");
        },
      });
      for (const expectedKeyContext of [
        Object.create({ protocol: "NativeObservationV1" }),
        accessor,
        { protocol: "NativeObservationV1", nativeAnalyzerIdentity: 1 },
        { protocol: "NativeObservationV1", nativeAnalyzerIdentity: "native.bad" },
        {
          protocol: "NativeObservationV1",
          nativeAnalyzerIdentity: "native.0123456789ab",
          observationConfigurationSha256: "bad",
        },
      ]) {
        expect(assessNativeObservationReuseV1({ ...base, expectedKeyContext } as never)).toEqual({
          kind: "required",
          code: "NATIVE_OBSERVATION_REQUIRED",
          reason: "expected-key-context-required",
        });
      }
    } finally {
      fixture.cleanup();
    }
  });
});
