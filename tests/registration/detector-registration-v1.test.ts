import { describe, expect, it } from "vitest";
import {
  canonicalDetectorRegistrationV1Bytes,
  createDetectorRegistrationV1,
  parseDetectorRegistrationV1Json,
} from "../../src/registration/detector-registration-v1.js";

const sha = (digit: string) => digit.repeat(64);
const registration = {
  protocol: "DetectorRegistrationV1",
  registrations: [
    {
      detector: {
        detectorId: "detector.acme.policy",
        analyzerIdentity: "native.0123456789ab",
        ociImage: {
          reference: `example.invalid/acme/policy@sha256:${sha("a")}`,
          sha256: sha("a"),
        },
        adapter: { identity: "adapter.0123456789ab", sha256: sha("b") },
        observationConfigurationSha256: sha("c"),
        executionProfileSha256: sha("d"),
        supportedPlatforms: [{ os: "linux", architecture: "amd64" }],
        sbom: { mediaType: "application/spdx+json", sha256: sha("e") },
        provenance: { mediaType: "application/vnd.in-toto+json", sha256: sha("f") },
      },
      runtime: {
        sourceReference: `example.invalid/acme/policy@sha256:${sha("a")}`,
        sourceSha256: sha("a"),
        configSha256: sha("0"),
      },
      adapterCapability: "cisco-oci-v1",
      broker: { identity: "broker.0123456789ab", capability: "cisco-oci-v1" },
    },
  ],
};

describe("DetectorRegistrationV1", () => {
  it("canonically binds the selected detector to one exact registered adapter/runtime", () => {
    const result = createDetectorRegistrationV1(registration);
    const entry = result.registrations[0];
    if (entry === undefined) throw new Error("registration entry missing");
    expect(entry.detector.detectorId).toBe("detector.acme.policy");
    expect(entry.runtime.sourceSha256).toBe(sha("a"));
    expect(entry.registrationEntrySha256).toMatch(/^[a-f0-9]{64}$/);
    expect(result.registrationSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(Object.isFrozen(entry)).toBe(true);
    expect(canonicalDetectorRegistrationV1Bytes(result).toString("utf8")).toContain(
      '"protocol":"DetectorRegistrationV1"',
    );
  });

  it("sorts registrations deterministically by namespaced detector ID", () => {
    const policy = registration.registrations[0];
    if (policy === undefined) throw new Error("registration fixture missing");
    const alpha = {
      ...policy,
      detector: { ...policy.detector, detectorId: "detector.acme.alpha" },
    };
    const first = createDetectorRegistrationV1({
      protocol: "DetectorRegistrationV1",
      registrations: [policy, alpha],
    });
    const second = createDetectorRegistrationV1({
      protocol: "DetectorRegistrationV1",
      registrations: [alpha, policy],
    });
    expect(first.registrations.map((entry) => entry.detector.detectorId)).toEqual([
      "detector.acme.alpha",
      "detector.acme.policy",
    ]);
    expect(canonicalDetectorRegistrationV1Bytes(first)).toEqual(
      canonicalDetectorRegistrationV1Bytes(second),
    );
  });

  it("rejects duplicates, unknowns, mutable refs, unsupported platforms, and capability substitution", () => {
    const item = registration.registrations[0];
    if (item === undefined) throw new Error("registration fixture missing");
    for (const invalid of [
      {
        ...item,
        detector: {
          ...item.detector,
          ociImage: { ...item.detector.ociImage, reference: "example.invalid/acme/policy:latest" },
        },
      },
      {
        ...item,
        runtime: { ...item.runtime, sourceReference: "example.invalid/acme/policy:latest" },
      },
      { ...item, runtime: { ...item.runtime, sourceSha256: sha("1") } },
      {
        ...item,
        detector: {
          ...item.detector,
          supportedPlatforms: [{ os: "windows", architecture: "amd64" }],
        },
      },
      { ...item, adapterCapability: "unregistered-adapter" },
      { ...item, broker: { ...item.broker, capability: "unregistered-adapter" } },
      { ...item, detector: { ...item.detector, detectorId: "detector.cisco" } },
      { ...item, unexpected: true },
    ]) {
      expect(() =>
        createDetectorRegistrationV1({
          protocol: "DetectorRegistrationV1",
          registrations: [invalid],
        }),
      ).toThrow();
    }
    expect(() =>
      createDetectorRegistrationV1({
        protocol: "DetectorRegistrationV1",
        registrations: [item, item],
      }),
    ).toThrow(/duplicate|ambiguous/i);
  });

  it("round-trips only its exact bounded canonical wire and verifies derived digests", () => {
    const created = createDetectorRegistrationV1(registration);
    const bytes = canonicalDetectorRegistrationV1Bytes(created);
    const parsed = parseDetectorRegistrationV1Json(bytes.toString("utf8"));
    expect(canonicalDetectorRegistrationV1Bytes(parsed)).toEqual(bytes);
    const wire = JSON.parse(bytes.toString("utf8")) as {
      registrationSha256: string;
      registrations: { registrationEntrySha256: string }[];
    };
    expect(() =>
      parseDetectorRegistrationV1Json(JSON.stringify({ ...wire, registrationSha256: sha("0") })),
    ).toThrow(/canonical wire binding/i);
    const first = wire.registrations[0];
    if (first === undefined) throw new Error("canonical registration missing entry");
    expect(() =>
      parseDetectorRegistrationV1Json(
        JSON.stringify({
          ...wire,
          registrations: [{ ...first, registrationEntrySha256: sha("1") }],
        }),
      ),
    ).toThrow(/canonical wire binding/i);
    expect(() =>
      parseDetectorRegistrationV1Json(JSON.stringify({ ...wire, unexpected: true })),
    ).toThrow();
    expect(() => parseDetectorRegistrationV1Json("x".repeat(512 * 1024 + 1))).toThrow(/bounds/i);
  });
});
