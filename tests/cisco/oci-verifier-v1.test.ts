import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  canonicalCiscoOciVerifierBytesV1,
  canonicalCiscoOciVerifierLayoutBytesV1,
  verifyCiscoOciCandidateV1,
} from "../../tools/verify-cisco-oci-candidate.mjs";

const roots: string[] = [];
const hash = (value: Buffer | string) =>
  `sha256:${createHash("sha256").update(value).digest("hex")}`;
const manifestMediaType = "application/vnd.oci.image.manifest.v1+json";
const configMediaType = "application/vnd.oci.image.config.v1+json";
const indexMediaType = "application/vnd.oci.image.index.v1+json";
const verifierPath = resolve(
  import.meta.dirname,
  "..",
  "..",
  "tools",
  "verify-cisco-oci-candidate.mjs",
);

type LayoutFixture = Readonly<{
  readonly root: string;
  readonly manifest: string;
  readonly config: string;
  readonly index: Readonly<Record<string, unknown>>;
  readonly metadata: Readonly<Record<string, unknown>>;
}>;

const write = (root: string, digest: string, bytes: Buffer): void =>
  writeFileSync(join(root, "blobs", "sha256", digest.slice("sha256:".length)), bytes);

const layoutFixture = (
  options: {
    readonly configExtras?: Readonly<Record<string, unknown>>;
    readonly rawConfig?: Buffer;
    readonly rawManifest?: Buffer;
    readonly rootfs?: unknown;
    readonly legacyManifest?: boolean;
  } = {},
): LayoutFixture => {
  const root = mkdtempSync(join(tmpdir(), "aih-scan-oci-layout-"));
  roots.push(root);
  mkdirSync(join(root, "blobs", "sha256"), { recursive: true });
  const layer = Buffer.from("candidate layer", "utf8");
  const layerDigest = hash(layer);
  const config =
    options.rawConfig ??
    Buffer.from(
      JSON.stringify({
        architecture: "amd64",
        os: "linux",
        rootfs: options.rootfs ?? {
          type: "layers",
          diff_ids: [hash("uncompressed candidate layer")],
        },
        ...options.configExtras,
      }),
    );
  const configDigest = hash(config);
  const manifest =
    options.rawManifest ??
    Buffer.from(
      JSON.stringify({
        schemaVersion: 2,
        mediaType: manifestMediaType,
        config: { mediaType: configMediaType, digest: configDigest, size: config.length },
        layers: [
          {
            mediaType: "application/vnd.oci.image.layer.v1.tar",
            digest: layerDigest,
            size: layer.length,
          },
        ],
      }),
    );
  const manifestDigest = hash(manifest);
  const descriptor = {
    mediaType: manifestMediaType,
    digest: manifestDigest,
    size: manifest.length,
    platform: { os: "linux", architecture: "amd64" },
    annotations: { "org.opencontainers.image.ref.name": "candidate" },
  };
  writeFileSync(join(root, "oci-layout"), JSON.stringify({ imageLayoutVersion: "1.0.0" }));
  const index = { schemaVersion: 2, mediaType: indexMediaType, manifests: [descriptor] };
  writeFileSync(join(root, "index.json"), JSON.stringify(index));
  if (options.legacyManifest === true)
    writeFileSync(join(root, "manifest.json"), JSON.stringify([{ Config: "legacy.json" }]));
  write(root, layerDigest, layer);
  write(root, configDigest, config);
  write(root, manifestDigest, manifest);
  return {
    root,
    manifest: manifestDigest,
    config: configDigest,
    index,
    metadata: {
      "buildx.build.provenance": {},
      "buildx.build.ref": "aih-scan-cisco-oci-equivalence/build0/example",
      "buildx.build.warnings": {},
      "containerimage.digest": manifestDigest,
      "containerimage.config.digest": configDigest,
      "containerimage.descriptor": {
        mediaType: manifestMediaType,
        digest: manifestDigest,
        size: manifest.length,
        annotations: {
          "config.digest": configDigest,
          "org.opencontainers.image.created": "2026-08-17T00:00:00Z",
        },
      },
    },
  };
};

const input = (fixture = layoutFixture()) => ({
  protocol: "CiscoOciVerifierV1",
  layoutRoot: fixture.root,
  metadata: fixture.metadata,
  loadedImageId: fixture.config,
});

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("Cisco OCI candidate verifier V1", () => {
  it("activates the standalone CLI for the current Node path form and fails closed for --help", () => {
    const result = spawnSync(process.execPath, [verifierPath, "--help"], {
      encoding: "utf8",
      shell: false,
      windowsHide: true,
    });
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("Cisco OCI verifier rejected input: CLI arguments\n");
  });

  it("emits only a static rejection reason when hostile CLI values reach a filesystem boundary", () => {
    const hostile = "C:\\do-not-leak\\digest-sha256-deadbeef\\metadata-content.json";
    const result = spawnSync(
      process.execPath,
      [
        verifierPath,
        "--metadata",
        hostile,
        "--layout-root",
        hostile,
        "--image-id",
        hostile,
        "--summary",
        hostile,
        "--canonical-layout",
        hostile,
      ],
      { encoding: "utf8", shell: false, windowsHide: true },
    );
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("Cisco OCI verifier rejected input: rejected\n");
    expect(result.stderr).not.toMatch(/do-not-leak|digest|metadata|content|Error|stack/i);
  });

  it("loads a real local OCI layout with documented Buildx metadata, binds the loaded config ID, and emits canonical layout bytes", () => {
    const fixture = layoutFixture();
    const result = verifyCiscoOciCandidateV1(input(fixture));
    expect(Object.keys(result).sort()).toEqual(
      [
        "configDigestSha256",
        "logicalReference",
        "manifestDigestSha256",
        "protocol",
        "summarySha256",
      ].sort(),
    );
    expect(result.manifestDigestSha256).toBe(fixture.manifest);
    expect(result.configDigestSha256).toBe(fixture.config);
    expect(result.logicalReference).toBe(`local.invalid/aih-scan/cisco@${fixture.manifest}`);
    expect(canonicalCiscoOciVerifierBytesV1(result)).toBeInstanceOf(Buffer);
    expect(canonicalCiscoOciVerifierLayoutBytesV1(result)).toBeInstanceOf(Buffer);
  });

  it("permits only a bounded regular legacy manifest.json root entry when present", () => {
    const fixture = layoutFixture({ legacyManifest: true });
    expect(verifyCiscoOciCandidateV1(input(fixture)).manifestDigestSha256).toBe(fixture.manifest);
    writeFileSync(join(fixture.root, "unexpected"), "extra");
    expect(() => verifyCiscoOciCandidateV1(input(fixture))).toThrow();
  });

  it("rejects malformed UTF-8 at the index, manifest, and config JSON byte boundaries", () => {
    const indexFixture = layoutFixture();
    writeFileSync(join(indexFixture.root, "index.json"), Buffer.from([0xff]));
    expect(() => verifyCiscoOciCandidateV1(input(indexFixture))).toThrow();

    const manifestFixture = layoutFixture({ rawManifest: Buffer.from([0xff]) });
    expect(() => verifyCiscoOciCandidateV1(input(manifestFixture))).toThrow();

    const configFixture = layoutFixture({ rawConfig: Buffer.from([0xff]) });
    expect(() => verifyCiscoOciCandidateV1(input(configFixture))).toThrow();
  });

  it("rejects every negative-zero spelling, malformed diff ID, and unknown config/rootfs field", () => {
    for (const spelling of ["-0", "-0.0", "-0e+1"]) {
      const negativeZeroFixture = layoutFixture();
      const indexPath = join(negativeZeroFixture.root, "index.json");
      const firstManifest = (
        negativeZeroFixture.index.manifests as ReadonlyArray<Record<string, unknown>>
      )[0];
      if (firstManifest === undefined)
        throw new Error("test fixture index must contain one manifest");
      writeFileSync(
        indexPath,
        readFileSync(indexPath, "utf8").replace(
          `"size":${String(firstManifest.size)}`,
          `"size":${spelling}`,
        ),
      );
      expect(() => verifyCiscoOciCandidateV1(input(negativeZeroFixture))).toThrow();
    }
    expect(() =>
      verifyCiscoOciCandidateV1(
        input(layoutFixture({ rootfs: { type: "layers", diff_ids: ["not-a-sha256-digest"] } })),
      ),
    ).toThrow();
    expect(() =>
      verifyCiscoOciCandidateV1(
        input(
          layoutFixture({
            rootfs: {
              type: "layers",
              diff_ids: [hash("uncompressed candidate layer")],
              unexpected: true,
            },
          }),
        ),
      ),
    ).toThrow();
    expect(() =>
      verifyCiscoOciCandidateV1(input(layoutFixture({ configExtras: { unexpected: true } }))),
    ).toThrow();
  });

  it("fails closed for malformed layout paths, raw blobs, metadata, platform, reference, or loaded-image substitutions", () => {
    const fixture = layoutFixture();
    const cases = [
      { ...input(fixture), unknown: true },
      { ...input(fixture), layoutRoot: "../candidate-layout" },
      { ...input(fixture), layoutRoot: `${fixture.root}\u0000` },
      { ...input(fixture), loadedImageId: fixture.manifest },
      { ...input(fixture), metadata: { "containerimage.config.digest": fixture.config } },
      {
        ...input(fixture),
        metadata: {
          ...fixture.metadata,
          "containerimage.descriptor": {
            ...(fixture.metadata["containerimage.descriptor"] as Record<string, unknown>),
            annotations: {
              "config.digest": fixture.manifest,
              "org.opencontainers.image.created": "2026-08-17T00:00:00Z",
            },
          },
        },
      },
      {
        ...input(fixture),
        metadata: {
          ...fixture.metadata,
          unexpected: true,
        },
      },
    ];
    for (const value of cases) expect(() => verifyCiscoOciCandidateV1(value)).toThrow();
    writeFileSync(join(fixture.root, "blobs", "sha256", fixture.manifest.slice(7)), "{}");
    expect(() => verifyCiscoOciCandidateV1(input(fixture))).toThrow();
    const platformFixture = layoutFixture();
    const windowsIndex = structuredClone(platformFixture.index) as Record<string, unknown>;
    const manifests = windowsIndex.manifests;
    if (!Array.isArray(manifests) || manifests[0] === undefined)
      throw new Error("test fixture index must contain one manifest");
    (manifests[0] as Record<string, unknown>).platform = {
      os: "windows",
      architecture: "amd64",
    };
    writeFileSync(join(platformFixture.root, "index.json"), JSON.stringify(windowsIndex));
    expect(() => verifyCiscoOciCandidateV1(input(platformFixture))).toThrow();
  });
});
