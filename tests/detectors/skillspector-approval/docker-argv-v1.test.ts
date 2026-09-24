import { describe, expect, it } from "vitest";
import {
  SKILLSPECTOR_IMAGE_DIGEST_V1,
  SKILLSPECTOR_IMAGE_TAG_V1,
  skillspectorDockerCleanupArgvV1,
  skillspectorDockerRunArgvV1,
  skillspectorDockerVersionArgvV1,
  skillspectorImageInspectArgvV1,
} from "../../../src/detectors/skillspector-approval/index.js";

/**
 * Ported from Core's `tests/trust/scan.test.ts` (lines 5109-5165, the
 * SkillSpector halves). The planned argv must be byte-identical to Core's.
 */
describe("skillspectorDockerRunArgvV1", () => {
  it("invokes SkillSpector with a read-only, no-network Docker sandbox", () => {
    expect(
      skillspectorDockerRunArgvV1("windows", "C:\\scan-root", SKILLSPECTOR_IMAGE_DIGEST_V1),
    ).toEqual([
      "docker",
      "run",
      "--rm",
      "--name",
      expect.stringMatching(/^aih-skillspector-[0-9a-f-]{36}$/),
      "--network",
      "none",
      "--cpus",
      "2",
      "--memory",
      "4g",
      "--memory-swap",
      "4g",
      "--pids-limit",
      "256",
      "--cap-drop",
      "ALL",
      "--cap-add",
      "DAC_OVERRIDE",
      "--security-opt",
      "no-new-privileges",
      "--read-only",
      "--tmpfs",
      "/tmp:rw,noexec,nosuid,size=64m",
      "--mount",
      "type=bind,source=C:\\scan-root,target=/scan,readonly",
      SKILLSPECTOR_IMAGE_DIGEST_V1,
      "scan",
      "/scan",
      "--no-llm",
      "--format",
      "sarif",
    ]);
  });

  it("rejects ambiguous Docker bind mount source paths", () => {
    expect(() =>
      skillspectorDockerRunArgvV1("linux", "/tmp/scan-root,readonly", SKILLSPECTOR_IMAGE_DIGEST_V1),
    ).toThrow(/unsupported.*bind mount source/i);
    expect(() =>
      skillspectorDockerRunArgvV1("linux", "/tmp/scan-root\nforged", SKILLSPECTOR_IMAGE_DIGEST_V1),
    ).toThrow(/unsupported.*bind mount source/i);
  });

  it("defaults the image to the pinned tag; a verified digest replaces it", () => {
    const argv = skillspectorDockerRunArgvV1("linux", "/tmp/scan-root");

    expect(argv).toContain(SKILLSPECTOR_IMAGE_TAG_V1);
    expect(argv).not.toContain(SKILLSPECTOR_IMAGE_DIGEST_V1);
  });

  it("keeps the planned argv unchanged on every platform (docker is no .cmd shim)", () => {
    const linux = skillspectorDockerRunArgvV1(
      "linux",
      "/tmp/scan-root",
      SKILLSPECTOR_IMAGE_DIGEST_V1,
      "aih-skillspector-fixed",
    );
    const windows = skillspectorDockerRunArgvV1(
      "windows",
      "/tmp/scan-root",
      SKILLSPECTOR_IMAGE_DIGEST_V1,
      "aih-skillspector-fixed",
    );

    expect(windows).toEqual(linux);
    expect(windows[0]).toBe("docker");
  });
});

describe("probe and cleanup argv", () => {
  it("plans the Docker availability probe", () => {
    expect(skillspectorDockerVersionArgvV1("linux")).toEqual(["docker", "--version"]);
  });

  it("plans the pinned-tag image inspect probe and never pulls", () => {
    const argv = skillspectorImageInspectArgvV1("linux");

    expect(argv).toEqual([
      "docker",
      "image",
      "inspect",
      SKILLSPECTOR_IMAGE_TAG_V1,
      "--format",
      "{{json .}}",
    ]);
    expect(argv).not.toContain("pull");
  });

  it("plans the force-removal cleanup for a bounded container", () => {
    expect(skillspectorDockerCleanupArgvV1("linux", "aih-skillspector-abc")).toEqual([
      "docker",
      "rm",
      "--force",
      "--volumes",
      "aih-skillspector-abc",
    ]);
  });
});
