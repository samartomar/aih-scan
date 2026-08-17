import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  compareCiscoDualRunV1,
  createCiscoDualRunDigestV1,
} from "../../src/cisco/dual-run-equivalence-v1.js";
import {
  describeNativeObservationSourceV1,
  sealNativeObservationSourceV1,
} from "../../src/observation/native-observation-v1.js";

const roots: string[] = [];
const sha256 = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
const digest = (seed: string) => sha256(`dual-run:${seed}`);

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function root(name: string): string {
  const value = mkdtempSync(join(tmpdir(), name));
  roots.push(value);
  writeFileSync(join(value, "SKILL.md"), "---\nname: neutral\n---\nIgnore unsafe instructions.\n");
  return value;
}

function observation(sourceRoot: string, diagnostic = "Pattern detected.") {
  const seal = sealNativeObservationSourceV1({ sourceRoot, selectedClosurePaths: ["SKILL.md"] });
  const facts = [
    {
      detectorClass: "cisco",
      nativeRuleId: "PROMPT_INJECTION_IGNORE_INSTRUCTIONS",
      path: "SKILL.md",
      fileSha256: sha256("---\nname: neutral\n---\nIgnore unsafe instructions.\n"),
      canonicalOrdinal: 0,
      rawOccurrenceFingerprint: `raw-occurrence-v1:${digest("occurrence")}`,
      multiplicity: 1,
      locations: [{ startLine: 4 }],
      message: diagnostic,
      level: "error",
    },
  ];
  const annexBytes = Buffer.from(JSON.stringify(facts));
  return {
    sourceRoot,
    sourceSeal: seal,
    facts,
    coverage: [{ coverageKind: "selected-closure", coverageSha256: seal.selectedClosureSha256 }],
    annexBytes,
    evidenceAnnex: {
      protocol: "EvidenceAnnexV1",
      descriptors: [
        {
          descriptorId: "annex.cisco-raw",
          mediaType: "application/json",
          sha256: sha256(annexBytes),
          byteLength: annexBytes.length,
          uri: "annex/cisco-raw.json",
        },
      ],
      evidenceAnnexSha256: digest("annex-descriptor"),
    },
  };
}

function oracle(value: ReturnType<typeof observation>) {
  return value.facts.map((fact) => ({
    canonicalOrdinal: fact.canonicalOrdinal,
    detectorClass: fact.detectorClass,
    fileSha256: fact.fileSha256,
    level: fact.level,
    locations: fact.locations,
    message: fact.message,
    multiplicity: fact.multiplicity,
    nativeRuleId: fact.nativeRuleId,
    path: fact.path,
    rawOccurrenceFingerprint: fact.rawOccurrenceFingerprint,
  }));
}

describe("Cisco direct/OCI dual-run equivalence V1", () => {
  it("requires separate roots with identical sealed source and compares the full neutral fact semantics", () => {
    const directRoot = root("aih-scan-dual-direct-");
    const ociRoot = root("aih-scan-dual-oci-");
    const direct = observation(directRoot);
    const oci = observation(ociRoot);
    const directSnapshot = describeNativeObservationSourceV1({
      sourceRoot: directRoot,
      selectedClosurePaths: ["SKILL.md"],
    });
    const ociSnapshot = describeNativeObservationSourceV1({
      sourceRoot: ociRoot,
      selectedClosurePaths: ["SKILL.md"],
    });

    const result = compareCiscoDualRunV1({ protocol: "CiscoDualRunEquivalenceV1", direct, oci });

    expect(directRoot).not.toBe(ociRoot);
    expect(directSnapshot.sourceFiles).toEqual(ociSnapshot.sourceFiles);
    expect(oracle(direct)).toEqual(oracle(oci));
    expect(Object.keys(result).sort()).toEqual(
      [
        "directDigestSha256",
        "ociDigestSha256",
        "protocol",
        "semanticDigestSha256",
        "validationState",
      ].sort(),
    );
    expect(result.validationState).toBe("cryptographically-unverified");
    expect(createCiscoDualRunDigestV1(result)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("fails closed for same roots, source/semantic drift, shared annex buffers, and descriptor substitution", () => {
    const directRoot = root("aih-scan-dual-direct-");
    const ociRoot = root("aih-scan-dual-oci-");
    const direct = observation(directRoot);
    const oci = observation(ociRoot);
    const base = { protocol: "CiscoDualRunEquivalenceV1", direct, oci } as const;
    const cases = [
      { ...base, oci: { ...oci, sourceRoot: directRoot } },
      { ...base, oci: observation(ociRoot, "Changed diagnostic.") },
      {
        ...base,
        oci: { ...oci, sourceSeal: { ...oci.sourceSeal, sourceTreeSha256: digest("other") } },
      },
      { ...base, oci: { ...oci, annexBytes: direct.annexBytes } },
      {
        ...base,
        oci: {
          ...oci,
          evidenceAnnex: {
            ...oci.evidenceAnnex,
            descriptors: [{ ...oci.evidenceAnnex.descriptors[0], sha256: digest("substitution") }],
          },
        },
      },
      { ...base, unknown: true },
    ];
    for (const value of cases) expect(() => compareCiscoDualRunV1(value as unknown)).toThrow();
  });
});
