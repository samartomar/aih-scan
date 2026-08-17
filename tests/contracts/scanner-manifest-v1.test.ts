import { describe, expect, it } from "vitest";
import {
  createScannerManifestV1,
  parseScannerManifestV1Json,
} from "../../src/observation/scanner-manifest-v1.js";

const sha = (digit: string) => digit.repeat(64);
type ManifestDetector = {
  detectorId: string;
  scannerManifestEntrySha256: string;
  ociImage: Record<string, unknown>;
  adapter: Record<string, unknown>;
};
const entry = {
  detectorId: "detector.cisco",
  analyzerIdentity: "native.0123456789ab",
  ociImage: { reference: `example.invalid/cisco@sha256:${sha("a")}`, sha256: sha("a") },
  adapter: { identity: "adapter.0123456789ab", sha256: sha("b") },
  observationConfigurationSha256: sha("c"),
  executionProfileSha256: sha("d"),
  supportedPlatforms: [{ os: "linux", architecture: "amd64" }],
  sbom: { mediaType: "application/spdx+json", sha256: sha("e") },
  provenance: { mediaType: "application/vnd.in-toto+json", sha256: sha("f") },
};

describe("ScannerManifestV1", () => {
  it("binds immutable caller-supplied per-detector metadata separately from aggregate assembly", () => {
    const unrelated = {
      ...entry,
      detectorId: "detector.other",
      ociImage: { reference: `example.invalid/other@sha256:${sha("0")}`, sha256: sha("0") },
    };
    const one = createScannerManifestV1({
      protocol: "ScannerManifestV1",
      detectors: [entry, unrelated],
    });
    const changed = createScannerManifestV1({
      protocol: "ScannerManifestV1",
      detectors: [entry, { ...unrelated, adapter: { ...unrelated.adapter, sha256: sha("1") } }],
    });
    const cisco = (one.detectors as ManifestDetector[]).find(
      (detector) => detector.detectorId === "detector.cisco",
    );
    const changedCisco = (changed.detectors as ManifestDetector[]).find(
      (detector) => detector.detectorId === "detector.cisco",
    );
    if (cisco === undefined || changedCisco === undefined)
      throw new Error("Cisco detector is missing");
    expect(Object.keys(one).sort()).toEqual(["detectors", "protocol", "scannerManifestSha256"]);
    expect(Object.keys(cisco).sort()).toEqual([
      "adapter",
      "analyzerIdentity",
      "detectorId",
      "executionProfileSha256",
      "observationConfigurationSha256",
      "ociImage",
      "provenance",
      "sbom",
      "scannerManifestEntrySha256",
      "supportedPlatforms",
    ]);
    expect(Object.keys(cisco.ociImage).sort()).toEqual(["reference", "sha256"]);
    expect(Object.keys(cisco.adapter).sort()).toEqual(["identity", "sha256"]);
    expect(cisco.scannerManifestEntrySha256).toMatch(/^[a-f0-9]{64}$/);
    expect(one.scannerManifestSha256).not.toBe(changed.scannerManifestSha256);
    expect(cisco.scannerManifestEntrySha256).toBe(changedCisco.scannerManifestEntrySha256);
    expect(Object.isFrozen(cisco)).toBe(true);
    expect(Object.isFrozen(cisco.ociImage)).toBe(true);
  });

  it("rejects mutable OCI identity, malformed digests, duplicate/ambiguous rows, and unknown fields", () => {
    for (const input of [
      { ...entry, ociImage: { ...entry.ociImage, reference: "example.invalid/cisco:latest" } },
      { ...entry, ociImage: { ...entry.ociImage, sha256: sha("A") } },
      {
        ...entry,
        supportedPlatforms: [
          { os: "linux", architecture: "amd64" },
          { os: "linux", architecture: "amd64" },
        ],
      },
      { ...entry, extra: true },
    ]) {
      expect(() =>
        createScannerManifestV1({ protocol: "ScannerManifestV1", detectors: [input] }),
      ).toThrow();
    }
    expect(() =>
      createScannerManifestV1({ protocol: "ScannerManifestV1", detectors: [entry, entry] }),
    ).toThrow();
    expect(() =>
      parseScannerManifestV1Json('{"protocol":"ScannerManifestV1","protocol":"x"}'),
    ).toThrow();
  });

  it("sorts supported platforms canonically and permits Windows only as a structural platform shape", () => {
    const platforms = [
      { os: "windows" as const, architecture: "amd64" as const },
      { os: "linux" as const, architecture: "amd64" as const },
    ];
    const forward = createScannerManifestV1({
      protocol: "ScannerManifestV1",
      detectors: [{ ...entry, supportedPlatforms: platforms }],
    });
    const reverse = createScannerManifestV1({
      protocol: "ScannerManifestV1",
      detectors: [{ ...entry, supportedPlatforms: [...platforms].reverse() }],
    });
    expect(forward).toEqual(reverse);
    expect(forward.detectors[0]?.supportedPlatforms).toContainEqual({
      os: "windows",
      architecture: "amd64",
    });
  });
});
