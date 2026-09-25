import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  SKILLSPECTOR_IMAGE_DIGEST_V1,
  SKILLSPECTOR_IMAGE_V1,
  SKILLSPECTOR_LOCAL_IMAGE_TAG_V1,
  SKILLSPECTOR_SOURCE_REVISION_V1,
} from "../../src/baseline/runtime-v1.js";
import * as approval from "../../src/detectors/skillspector-approval/image-identity-v1.js";

/**
 * Rotation step 4 (Core docs/security/skillspector.md, "Rotating the Pin"): the source
 * revision, the controlled digest it produced, the published image and the local tag move
 * together. v2.12.0 (c7958a32) built twice to manifest efe47bd7 (U1c, with a perturbation
 * control that differs) and is published at ghcr.io/samartomar/skillspector by digest.
 */
const REVISION = "c7958a3268d9498644b22edb75d0f051bbc8cbfc";
const DIGEST = "sha256:efe47bd7e073064426541381c8cb284162086950748424d1b4633788a2275bc6";

describe("SkillSpector pin", () => {
  it("names the v2.12.0 controlled build in every constant, moved as one unit", () => {
    expect(SKILLSPECTOR_SOURCE_REVISION_V1).toBe(REVISION);
    expect(SKILLSPECTOR_IMAGE_DIGEST_V1).toBe(DIGEST);
    expect(SKILLSPECTOR_IMAGE_V1).toBe(`ghcr.io/samartomar/skillspector@${DIGEST}`);
    expect(SKILLSPECTOR_LOCAL_IMAGE_TAG_V1).toBe(`skillspector:aih-${REVISION.slice(0, 12)}`);
    expect(approval.SKILLSPECTOR_SOURCE_REVISION_V1).toBe(SKILLSPECTOR_SOURCE_REVISION_V1);
    expect(approval.SKILLSPECTOR_IMAGE_DIGEST_V1).toBe(SKILLSPECTOR_IMAGE_DIGEST_V1);
    expect(approval.SKILLSPECTOR_IMAGE_TAG_V1).toBe(SKILLSPECTOR_LOCAL_IMAGE_TAG_V1);
  });

  it("matches the revision the bundled image recipe labels", () => {
    const recipe = readFileSync(
      join(import.meta.dirname, "..", "..", "tools", "skillspector", "Dockerfile"),
      "utf8",
    );
    expect(recipe).toContain(`LABEL org.opencontainers.image.revision="${REVISION}"`);
  });
});
