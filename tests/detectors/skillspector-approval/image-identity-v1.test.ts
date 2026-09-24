import { describe, expect, it } from "vitest";
import {
  parseSkillspectorImageApprovalsV1,
  SKILLSPECTOR_IMAGE_DIGEST_V1,
  SKILLSPECTOR_IMAGE_TAG_V1,
  SKILLSPECTOR_SOURCE_REVISION_V1,
  verifiedSkillspectorImageReferenceV1,
} from "../../../src/detectors/skillspector-approval/index.js";

/**
 * Ported from Core's `tests/trust/scan.test.ts` describe block
 * "verifiedSkillspectorImageReference" (lines 377-514), with imports rewired to
 * this engine. Assertions are unchanged; identical inputs must produce
 * identical accept/reject decisions.
 */
describe("verifiedSkillspectorImageReferenceV1", () => {
  const unrelatedDigest = `sha256:${"b".repeat(64)}`;
  const approvedLocalDigest = `sha256:${"c".repeat(64)}`;
  const differentDigest = `sha256:${"d".repeat(64)}`;
  const ghcrRepoDigest = `ghcr.io/samartomar/skillspector@${SKILLSPECTOR_IMAGE_DIGEST_V1}`;

  it("accepts a pulled image whose RepoDigests carries the controlled digest even when .Id is a config hash", () => {
    // Arrange: containerd/legacy-graphdriver pulled-image shape — `.Id` is not the manifest digest.
    const stdout = JSON.stringify({
      Id: unrelatedDigest,
      RepoDigests: [ghcrRepoDigest],
    });

    // Act
    const result = verifiedSkillspectorImageReferenceV1(stdout);

    // Assert: returns the full repo@digest entry, not just the bare digest, so it stays runnable.
    expect(result).toBe(ghcrRepoDigest);
  });

  it("accepts a local build whose .Id matches the controlled digest with empty RepoDigests", () => {
    // Arrange: existing local-build shape — pins prior behavior unchanged.
    const stdout = JSON.stringify({
      Id: SKILLSPECTOR_IMAGE_DIGEST_V1,
      RepoDigests: [],
    });

    // Act
    const result = verifiedSkillspectorImageReferenceV1(stdout);

    // Assert
    expect(result).toBe(SKILLSPECTOR_IMAGE_DIGEST_V1);
  });

  it("rejects fail-closed when neither .Id nor any RepoDigests entry match", () => {
    // Arrange
    const stdout = JSON.stringify({
      Id: unrelatedDigest,
      RepoDigests: [],
    });

    // Act
    const result = verifiedSkillspectorImageReferenceV1(stdout);

    // Assert
    expect(result).toBeUndefined();
  });

  it("rejects a RepoDigests entry carrying a different digest than the controlled one", () => {
    // Arrange
    const stdout = JSON.stringify({
      Id: unrelatedDigest,
      RepoDigests: [`ghcr.io/samartomar/skillspector@${differentDigest}`],
    });

    // Act
    const result = verifiedSkillspectorImageReferenceV1(stdout);

    // Assert
    expect(result).toBeUndefined();
  });

  it("accepts an org-approved digest found only in RepoDigests under the same tag/sourceRevision constraints", () => {
    // Arrange
    const approvedRepoDigest = `ghcr.io/samartomar/skillspector@${approvedLocalDigest}`;
    const stdout = JSON.stringify({
      Id: unrelatedDigest,
      RepoDigests: [approvedRepoDigest],
    });

    // Act
    const result = verifiedSkillspectorImageReferenceV1(stdout, [
      {
        imageTag: SKILLSPECTOR_IMAGE_TAG_V1,
        imageDigest: approvedLocalDigest,
        sourceRevision: SKILLSPECTOR_SOURCE_REVISION_V1,
      },
    ]);

    // Assert: returns the full matching RepoDigests entry, unambiguous for `docker run`.
    expect(result).toBe(approvedRepoDigest);
  });

  it("rejects an org-approved digest in RepoDigests when the approval's sourceRevision does not match", () => {
    // Arrange: pins that the tag/sourceRevision constraint still gates the RepoDigests path.
    const approvedRepoDigest = `ghcr.io/samartomar/skillspector@${approvedLocalDigest}`;
    const stdout = JSON.stringify({
      Id: unrelatedDigest,
      RepoDigests: [approvedRepoDigest],
    });

    // Act
    const result = verifiedSkillspectorImageReferenceV1(stdout, [
      {
        imageTag: SKILLSPECTOR_IMAGE_TAG_V1,
        imageDigest: approvedLocalDigest,
        sourceRevision: "f".repeat(40),
      },
    ]);

    // Assert
    expect(result).toBeUndefined();
  });

  it("accepts a local build whose .Id matches an org-approved digest", () => {
    // Arrange: preserves pre-widening coverage of the .Id + approvedImages path.
    const stdout = JSON.stringify({
      Id: approvedLocalDigest,
      RepoDigests: [],
    });

    // Act
    const result = verifiedSkillspectorImageReferenceV1(stdout, [
      {
        imageTag: SKILLSPECTOR_IMAGE_TAG_V1,
        imageDigest: approvedLocalDigest,
        sourceRevision: SKILLSPECTOR_SOURCE_REVISION_V1,
      },
    ]);

    // Assert
    expect(result).toBe(approvedLocalDigest);
  });

  it("prefers a direct .Id match over RepoDigests when both are present", () => {
    // Arrange: retains today's precedence — `.Id` wins and is returned as-is.
    const stdout = JSON.stringify({
      Id: SKILLSPECTOR_IMAGE_DIGEST_V1,
      RepoDigests: [`skillspector@${SKILLSPECTOR_IMAGE_DIGEST_V1}`],
    });

    // Act
    const result = verifiedSkillspectorImageReferenceV1(stdout);

    // Assert
    expect(result).toBe(SKILLSPECTOR_IMAGE_DIGEST_V1);
  });
});

/**
 * Engine-level port of the approval-accept/reject decisions Core's
 * `tests/trust/commands.test.ts` and org-policy schema pin: an approval counts
 * only when tag, source revision and digest shape all hold. Malformed approvals
 * are rejected — the in-engine filter never admits them even if a caller
 * skipped boundary validation.
 */
describe("SkillSpector approval constraints", () => {
  const approvedLocalDigest = `sha256:${"c".repeat(64)}`;

  it("rejects an approval whose imageTag does not match the pinned tag", () => {
    const stdout = JSON.stringify({ Id: approvedLocalDigest, RepoDigests: [] });

    const result = verifiedSkillspectorImageReferenceV1(stdout, [
      {
        imageTag: "skillspector:aih-bbbbbbbbbb",
        imageDigest: approvedLocalDigest,
        sourceRevision: SKILLSPECTOR_SOURCE_REVISION_V1,
      },
    ]);

    expect(result).toBeUndefined();
  });

  it.each([
    ["uppercase hex", `sha256:${"C".repeat(64)}`],
    ["a truncated digest", "sha256:c5d4a181"],
    ["a non-sha256 algorithm", `sha512:${"c".repeat(128)}`],
    ["a bare hex string", "c".repeat(64)],
  ])("rejects a malformed approval digest (%s) even when .Id carries it", (_label, malformed) => {
    // Arrange: the approval filter demands sha256:<64 lowercase hex>; a malformed
    // approval never widens the accepted set, so an image carrying exactly that
    // string is still rejected.
    const stdout = JSON.stringify({ Id: malformed, RepoDigests: [] });

    const result = verifiedSkillspectorImageReferenceV1(stdout, [
      {
        imageTag: SKILLSPECTOR_IMAGE_TAG_V1,
        imageDigest: malformed,
        sourceRevision: SKILLSPECTOR_SOURCE_REVISION_V1,
      },
    ]);

    expect(result).toBeUndefined();
  });

  it("rejects unparseable inspect output fail-closed", () => {
    expect(verifiedSkillspectorImageReferenceV1("not json")).toBeUndefined();
    expect(
      verifiedSkillspectorImageReferenceV1(JSON.stringify(["not", "an", "object"])),
    ).toBeUndefined();
    expect(
      verifiedSkillspectorImageReferenceV1(JSON.stringify({ Id: 42, RepoDigests: "no" })),
    ).toBeUndefined();
  });

  it("validates an approval list at the module boundary", () => {
    const approvals = parseSkillspectorImageApprovalsV1([
      {
        imageTag: SKILLSPECTOR_IMAGE_TAG_V1,
        imageDigest: approvedLocalDigest,
        sourceRevision: SKILLSPECTOR_SOURCE_REVISION_V1,
      },
    ]);
    expect(approvals).toHaveLength(1);
    expect(Object.isFrozen(approvals)).toBe(true);
  });

  it.each([
    [
      "a malformed digest",
      {
        imageTag: SKILLSPECTOR_IMAGE_TAG_V1,
        imageDigest: "sha256:not-hex",
        sourceRevision: SKILLSPECTOR_SOURCE_REVISION_V1,
      },
    ],
    [
      "an unknown field",
      {
        imageTag: SKILLSPECTOR_IMAGE_TAG_V1,
        imageDigest: approvedLocalDigest,
        sourceRevision: SKILLSPECTOR_SOURCE_REVISION_V1,
        reviewer: "someone",
      },
    ],
    [
      "a missing tag",
      {
        imageDigest: approvedLocalDigest,
        sourceRevision: SKILLSPECTOR_SOURCE_REVISION_V1,
      },
    ],
  ])("refuses malformed approval input at the boundary (%s)", (_label, candidate) => {
    expect(() => parseSkillspectorImageApprovalsV1([candidate])).toThrow(
      /invalid SkillSpector image approvals/,
    );
  });
});
