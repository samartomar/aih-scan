import { describe, expect, it } from "vitest";
import {
  assessNativeObservationReuseV1,
  createNativeObservationV1,
  createSealedSourceSnapshotV1,
  sealNativeObservationSourceV1,
} from "../../src/observation/native-observation-v1.js";

const sha = (digit: string) => digit.repeat(64);
const snapshotInput = {
  protocol: "SealedSourceSnapshotV1",
  sourceTreeSha256: sha("a"),
  selectedClosureSha256: sha("b"),
  sourceFiles: [{ path: "skills/demo/SKILL.md", bytes: 5, sha256: sha("c") }],
  selectedFiles: [{ path: "skills/demo/SKILL.md", bytes: 5, sha256: sha("c") }],
};
const keyContext = {
  protocol: "NativeObservationV1",
  analyzerIdentity: "native.0123456789ab",
  observationConfigurationSha256: sha("d"),
  platform: { os: "linux", architecture: "amd64", relevantFactsSha256: sha("e") },
};

describe("NativeObservationV1", () => {
  it("seals source tree and selected closure separately, accepts zero facts only with coverage, and stays local-only", () => {
    const snapshot = createSealedSourceSnapshotV1(snapshotInput);
    const seal = sealNativeObservationSourceV1({ sealedSnapshot: snapshot });
    const observation = createNativeObservationV1({
      ...keyContext,
      sourceSeal: seal,
      facts: [],
      coverage: [{ kind: "cisco-sarif", sha256: sha("f") }],
    });
    expect(observation.reuseScope).toBe("local-optimization-only");
    expect(observation.resultSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(Object.isFrozen(observation.sourceSeal)).toBe(true);
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
        sourceSeal: { sealedSnapshotSha256: sha("0") },
        facts: [{ rawOccurrenceFingerprint: sha("1"), multiplicity: 0 }],
        coverage: [],
      }),
    ).toThrow();
    expect(assessNativeObservationReuseV1({ observation: {} as never })).toMatchObject({
      kind: "required",
      code: "NATIVE_OBSERVATION_REQUIRED",
    });
  });
});
