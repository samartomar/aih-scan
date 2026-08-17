import { describe, expect, it } from "vitest";
import { runCiscoOciEquivalenceLiveV1 } from "../../src/cisco/dual-run-equivalence-v1.js";

describe("Cisco OCI equivalence live seam", () => {
  it("is opt-in and requires isolated absolute roots plus an immutable config image ID", async () => {
    await expect(
      runCiscoOciEquivalenceLiveV1({
        protocol: "CiscoOciEquivalenceLiveV1",
        enabled: false,
        directRoot: "C:/tmp/direct",
        ociRoot: "C:/tmp/oci",
        configDigestSha256: `sha256:${"a".repeat(64)}`,
      }),
    ).resolves.toEqual({
      protocol: "CiscoOciEquivalenceLiveV1",
      kind: "not-run",
      reason: "opt-in-required",
    });
    for (const value of [
      {
        protocol: "CiscoOciEquivalenceLiveV1",
        enabled: true,
        directRoot: "same",
        ociRoot: "same",
        configDigestSha256: `sha256:${"a".repeat(64)}`,
      },
      {
        protocol: "CiscoOciEquivalenceLiveV1",
        enabled: true,
        directRoot: "../direct",
        ociRoot: "C:/tmp/oci",
        configDigestSha256: `sha256:${"a".repeat(64)}`,
      },
      {
        protocol: "CiscoOciEquivalenceLiveV1",
        enabled: true,
        directRoot: "C:/tmp/direct",
        ociRoot: "C:/tmp/oci",
        configDigestSha256: "latest",
      },
    ])
      await expect(runCiscoOciEquivalenceLiveV1(value as unknown)).rejects.toThrow();
  });
});
