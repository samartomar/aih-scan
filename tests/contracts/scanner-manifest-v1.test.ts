import { describe, expect, it } from "vitest";
import {
  createScannerManifestV1,
  parseScannerManifestV1Json,
} from "../../src/observation/scanner-manifest-v1.js";

const sha = (digit: string) => digit.repeat(64);
const entry = {
  detectorId: "cisco",
  analyzerIdentity: "cisco.0123456789ab",
  image: { reference: `example.invalid/cisco@sha256:${sha("a")}`, sha256: sha("a") },
  adapter: { identity: "cisco-sarif-v1", sha256: sha("b") },
  observationConfiguration: { identity: "facts-only-v1", sha256: sha("c") },
  executionProfile: { identity: "offline", sha256: sha("d") },
  platforms: [{ os: "linux", architecture: "amd64" }],
  sbom: { sha256: sha("e"), byteLength: 1 },
  provenance: { sha256: sha("f"), byteLength: 1 },
};

describe("ScannerManifestV1", () => {
  it("binds immutable caller-supplied per-detector metadata separately from aggregate assembly", () => {
    const one = createScannerManifestV1({ protocol: "ScannerManifestV1", entries: [entry] });
    const changed = createScannerManifestV1({
      protocol: "ScannerManifestV1",
      entries: [{ ...entry, adapter: { ...entry.adapter, sha256: sha("0") } }],
    });
    expect(one.entries[0]?.entrySha256).toMatch(/^[a-f0-9]{64}$/);
    expect(one.scannerManifestSha256).not.toBe(changed.scannerManifestSha256);
    expect(one.entries[0]?.entrySha256).not.toBe(changed.entries[0]?.entrySha256);
    expect(Object.isFrozen(one.entries[0])).toBe(true);
  });

  it("rejects mutable OCI identity, malformed digests, duplicate/ambiguous rows, and unknown fields", () => {
    for (const input of [
      { ...entry, image: { ...entry.image, reference: "example.invalid/cisco:latest" } },
      { ...entry, image: { ...entry.image, sha256: sha("A") } },
      {
        ...entry,
        platforms: [
          { os: "linux", architecture: "amd64" },
          { os: "linux", architecture: "amd64" },
        ],
      },
      { ...entry, extra: true },
    ]) {
      expect(() =>
        createScannerManifestV1({ protocol: "ScannerManifestV1", entries: [input] }),
      ).toThrow();
    }
    expect(() =>
      createScannerManifestV1({ protocol: "ScannerManifestV1", entries: [entry, entry] }),
    ).toThrow();
    expect(() =>
      parseScannerManifestV1Json('{"protocol":"ScannerManifestV1","protocol":"x"}'),
    ).toThrow();
  });
});
