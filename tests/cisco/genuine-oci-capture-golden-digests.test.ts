import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  listDetectorCapabilitiesV1,
  listDetectorExecutionProfileDocumentsV1,
} from "../../src/capability/detector-capability-v1.js";
import { canonicalStrictJsonSha256V1 } from "../../src/contract/strict-json-v1.js";
import { buildScanFindingsV1 } from "../../src/findings/scan-findings-v1.js";
import {
  canonicalScanCandidateBytesV2,
  parseScanCandidateV2Json,
} from "../../src/observation/scan-attestation-v2.js";

/**
 * A byte-for-byte copy of a genuine Cisco OCI capture produced on a Linux amd64 host.
 *
 * It is committed unchanged so this repository can prove that its canonical digests
 * still reproduce. It is capture evidence only: it carries no approval, no
 * qualification and no adoption authority, and nothing here executes a detector.
 */
const root = resolve(import.meta.dirname, "..");
const candidateText = readFileSync(
  resolve(root, "fixtures/cisco/genuine-oci-capture-candidate.json"),
  "utf8",
);
const rawAnnexBytes = readFileSync(
  resolve(root, "fixtures/cisco/genuine-oci-capture-annex.cisco-raw.json"),
);

describe("genuine Cisco OCI capture golden digests", () => {
  it("still reproduces the candidate, observation-set and applied-facts digests", () => {
    const candidate = parseScanCandidateV2Json(candidateText);

    expect(candidate.candidateSha256).toBe(
      "b3f4a192b521ccd3af667dc5e1ef1c2317880473bb214483e2c514eda9b2ddd1",
    );
    expect(candidate.observation.setSha256).toBe(
      "bab898928441cd75b03f1491965b1bed610d42c334134c42722719e5936fd538",
    );
    expect(candidate.observation.keySha256).toBe(
      "e85448c645aa1164079c30ffe269e2bf5982b22b1078aec1422f0a3a470ad429",
    );
    expect(candidate.scanner.detector.broker.appliedFactsSha256).toBe(
      "d9785af9911253fb50e925f55020bcc49de706209d77aaf39ec4bd6615e5975d",
    );
    expect(candidate.coverage).toEqual({
      kind: "selected-closure",
      sha256: "061b88e1b63a8b12cd8883a1a8c9f901ded8d05bbcaadf8b5b23defba2ec1c50",
      complete: true,
    });
    expect(canonicalScanCandidateBytesV2(candidate).toString("utf8")).toBe(candidateText);
  });

  it("binds the genuine empty raw annex without inventing a finding", () => {
    const candidate = parseScanCandidateV2Json(candidateText);
    const detector = candidate.scanner.detector;

    const findings = buildScanFindingsV1({
      detector: { id: detector.detectorId, analyzerIdentity: detector.analyzerIdentity },
      facts: detector.observation.facts,
      annexDescriptors: candidate.annexes,
      annexArtifacts: [{ descriptorId: "annex.cisco-raw", bytes: rawAnnexBytes }],
    });

    expect(detector.observation.facts).toEqual([]);
    expect(findings.source).toBe("annex");
    expect(findings.findings).toEqual([]);
    // An empty list is reported with the gaps that say what was and was not read.
    expect(findings.gaps.map((entry) => entry.kind)).toEqual([
      "vendor-severity-not-projected",
      "sarif-not-interpreted",
      "no-effect-or-qualification-authority",
    ]);
  });

  it("records that the author-supplied execution profile digest is not a readable document", () => {
    const candidate = parseScanCandidateV2Json(candidateText);

    // Reproduced from tools/create-cisco-oci-capture-request.mjs: the author-supplied
    // digest is taken over that capture's OCI build inputs, not over any document that
    // states isolation, network or argv. No published profile document matches it.
    expect(candidate.scanner.detector.executionProfileSha256).toBe(
      "29219617faff7ca12f223fdd4d44ff129ea3793f28dc2ba038dd41d87b48d960",
    );
    const publishedProfileDigests = listDetectorExecutionProfileDocumentsV1().map((document) =>
      canonicalStrictJsonSha256V1(document),
    );
    expect(publishedProfileDigests).not.toContain(
      candidate.scanner.detector.executionProfileSha256,
    );
    const capabilityProfileDigests = listDetectorCapabilitiesV1().flatMap((capability) =>
      capability.executionProfiles.map((profile) => profile.sha256),
    );
    expect(capabilityProfileDigests).not.toContain(
      candidate.scanner.detector.executionProfileSha256,
    );
    expect(new Set(capabilityProfileDigests)).toEqual(new Set(publishedProfileDigests));
  });
});
