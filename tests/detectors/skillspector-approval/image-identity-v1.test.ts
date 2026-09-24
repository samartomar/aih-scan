import { describe, expect, it } from "vitest";
import {
  admitLocalSkillspectorImageV1,
  SKILLSPECTOR_IMAGE_DIGEST_V1,
  skillspectorAcceptedImageDigestsRefusalV1,
} from "../../../src/detectors/skillspector-approval/index.js";

describe("admitLocalSkillspectorImageV1 (C2a §6.1 local-mode admission)", () => {
  const callerDigest = `sha256:${"c".repeat(64)}`;
  const unrelatedDigest = `sha256:${"b".repeat(64)}`;
  const ghcrRepoDigest = `ghcr.io/samartomar/skillspector@${SKILLSPECTOR_IMAGE_DIGEST_V1}`;

  it("admits the pinned digest via .Id as a bare-digest pinned reference", () => {
    expect(
      admitLocalSkillspectorImageV1(JSON.stringify({ Id: SKILLSPECTOR_IMAGE_DIGEST_V1 })),
    ).toEqual({
      reference: SKILLSPECTOR_IMAGE_DIGEST_V1,
      digest: SKILLSPECTOR_IMAGE_DIGEST_V1,
      acceptance: "pinned",
    });
  });

  it("admits a caller-accepted digest via .Id and records it as caller-accepted", () => {
    expect(
      admitLocalSkillspectorImageV1(JSON.stringify({ Id: callerDigest }), [callerDigest]),
    ).toEqual({ reference: callerDigest, digest: callerDigest, acceptance: "caller-accepted" });
  });

  it("admits via a RepoDigests @-suffix and runs the full repo@digest entry", () => {
    expect(
      admitLocalSkillspectorImageV1(
        JSON.stringify({ Id: unrelatedDigest, RepoDigests: [ghcrRepoDigest] }),
      ),
    ).toEqual({
      reference: ghcrRepoDigest,
      digest: SKILLSPECTOR_IMAGE_DIGEST_V1,
      acceptance: "pinned",
    });
  });

  it("admits a caller-accepted RepoDigests entry and records the admitting digest", () => {
    const entry = `local/skillspector@${callerDigest}`;
    expect(
      admitLocalSkillspectorImageV1(JSON.stringify({ Id: unrelatedDigest, RepoDigests: [entry] }), [
        callerDigest,
      ]),
    ).toEqual({ reference: entry, digest: callerDigest, acceptance: "caller-accepted" });
  });

  it("prefers a direct .Id match over RepoDigests when both are present (Core precedence)", () => {
    const stdout = JSON.stringify({
      Id: SKILLSPECTOR_IMAGE_DIGEST_V1,
      RepoDigests: [`skillspector@${SKILLSPECTOR_IMAGE_DIGEST_V1}`],
    });
    expect(admitLocalSkillspectorImageV1(stdout)).toEqual({
      reference: SKILLSPECTOR_IMAGE_DIGEST_V1,
      digest: SKILLSPECTOR_IMAGE_DIGEST_V1,
      acceptance: "pinned",
    });
  });

  it("admits nothing when neither .Id nor RepoDigests match, or the output is not inspect JSON", () => {
    expect(admitLocalSkillspectorImageV1(JSON.stringify({ Id: unrelatedDigest }))).toBeUndefined();
    expect(admitLocalSkillspectorImageV1("not json")).toBeUndefined();
    expect(admitLocalSkillspectorImageV1("[1,2]")).toBeUndefined();
    expect(
      admitLocalSkillspectorImageV1(JSON.stringify({ Id: unrelatedDigest, RepoDigests: "nope" })),
    ).toBeUndefined();
  });
});

describe("skillspectorAcceptedImageDigestsRefusalV1 (C2a §6.2)", () => {
  it("accepts undefined-shaped valid lists, including empty", () => {
    expect(skillspectorAcceptedImageDigestsRefusalV1([])).toBeUndefined();
    expect(
      skillspectorAcceptedImageDigestsRefusalV1([
        `sha256:${"b".repeat(64)}`,
        `sha256:${"c".repeat(64)}`,
      ]),
    ).toBeUndefined();
  });

  it("refuses a non-array, a malformed entry, a duplicate and an over-bound list", () => {
    expect(skillspectorAcceptedImageDigestsRefusalV1("sha256:abc")).toBe(
      "acceptedImageDigests must be an array of sha256:<64 lowercase hex> image digests.",
    );
    expect(skillspectorAcceptedImageDigestsRefusalV1([`SHA256:${"b".repeat(64)}`])).toBe(
      "acceptedImageDigests[0] is not a sha256:<64 lowercase hex> image digest.",
    );
    expect(
      skillspectorAcceptedImageDigestsRefusalV1([
        `sha256:${"b".repeat(64)}`,
        `sha256:${"b".repeat(64)}`,
      ]),
    ).toBe(`acceptedImageDigests[1] repeats sha256:${"b".repeat(64)}.`);
    expect(
      skillspectorAcceptedImageDigestsRefusalV1(
        Array.from({ length: 17 }, (_, index) => `sha256:${String(index).padStart(64, "0")}`),
      ),
    ).toBe("acceptedImageDigests names 17 digests; at most 16 are consulted.");
  });
});
