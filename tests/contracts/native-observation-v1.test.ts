import { describe, expect, it } from "vitest";
import {
  assessNativeObservationReuseV1,
  createNativeObservationV1,
  createSealedSourceSnapshotV1,
} from "../../src/observation/native-observation-v1.js";

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
});
