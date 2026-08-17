import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  canonicalCiscoOciVerifierBytesV1,
  verifyCiscoOciCandidateV1,
} from "../../tools/verify-cisco-oci-candidate.mjs";

const hash = (value: string) => createHash("sha256").update(value).digest("hex");
const manifest = `sha256:${hash("manifest")}`;
const config = `sha256:${hash("config")}`;
const input = () => ({
  protocol: "CiscoOciVerifierV1",
  layout: {
    protocol: "CiscoOciLayoutV1",
    manifestDigestSha256: manifest,
    configDigestSha256: config,
    logicalReference: `local.invalid/aih-scan/cisco@${manifest}`,
    manifestPlatform: { os: "linux", architecture: "amd64" },
    manifestDescriptor: {
      mediaType: "application/vnd.oci.image.manifest.v1+json",
      digest: manifest,
      size: 1,
      platform: { os: "linux", architecture: "amd64" },
      annotations: { "org.opencontainers.image.ref.name": "candidate" },
    },
  },
  metadata: { manifestDigestSha256: manifest, configDigestSha256: config },
  loadedImageId: config,
  dockerTarPath: "candidate-image.tar",
});

describe("Cisco OCI candidate verifier V1", () => {
  it("produces only a strict neutral digest summary when layout, metadata, and loaded config agree", () => {
    const result = verifyCiscoOciCandidateV1(input());
    expect(Object.keys(result).sort()).toEqual(
      [
        "configDigestSha256",
        "logicalReference",
        "manifestDigestSha256",
        "protocol",
        "summarySha256",
      ].sort(),
    );
    expect(result.manifestDigestSha256).toBe(manifest);
    expect(result.configDigestSha256).toBe(config);
    expect(canonicalCiscoOciVerifierBytesV1(result)).toBeInstanceOf(Buffer);
  });

  it("fails closed for bad paths, tar boundary/missing metadata, and any identity substitution", () => {
    const cases = [
      { ...input(), unknown: true },
      { ...input(), dockerTarPath: "../candidate-image.tar" },
      { ...input(), dockerTarPath: "candidate\u0000image.tar" },
      { ...input(), loadedImageId: manifest },
      { ...input(), metadata: { manifestDigestSha256: manifest, configDigestSha256: manifest } },
      { ...input(), metadata: { manifestDigestSha256: config, configDigestSha256: config } },
      { ...input(), layout: { ...input().layout } },
    ];
    for (const value of cases) expect(() => verifyCiscoOciCandidateV1(value as unknown)).toThrow();
  });
});
