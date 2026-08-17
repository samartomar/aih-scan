import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
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
    readonly nestedIndex?: boolean;
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
  const manifestDescriptor = {
    mediaType: manifestMediaType,
    digest: manifestDigest,
    size: manifest.length,
    platform: { os: "linux", architecture: "amd64" },
    annotations: { "org.opencontainers.image.ref.name": "candidate" },
  };
  const nestedIndex =
    options.nestedIndex === true
      ? Buffer.from(
          JSON.stringify({
            schemaVersion: 2,
            mediaType: indexMediaType,
            manifests: [
              {
                digest: manifestDigest,
                mediaType: manifestMediaType,
                platform: { architecture: "amd64", os: "linux" },
                size: manifest.length,
              },
            ],
          }),
        )
      : undefined;
  const descriptor =
    nestedIndex === undefined
      ? manifestDescriptor
      : {
          annotations: { "org.opencontainers.image.ref.name": "candidate" },
          digest: hash(nestedIndex),
          mediaType: indexMediaType,
          size: nestedIndex.length,
        };
  writeFileSync(join(root, "oci-layout"), JSON.stringify({ imageLayoutVersion: "1.0.0" }));
  const index = { schemaVersion: 2, mediaType: indexMediaType, manifests: [descriptor] };
  writeFileSync(join(root, "index.json"), JSON.stringify(index));
  if (options.legacyManifest === true)
    writeFileSync(join(root, "manifest.json"), JSON.stringify([{ Config: "legacy.json" }]));
  write(root, layerDigest, layer);
  write(root, configDigest, config);
  write(root, manifestDigest, manifest);
  if (nestedIndex !== undefined) write(root, descriptor.digest, nestedIndex);
  return {
    root,
    manifest: manifestDigest,
    config: configDigest,
    index,
    metadata: {
      "buildx.build.provenance": {},
      "buildx.build.ref": "aih-scan-cisco-oci-equivalence/build0/example",
      "buildx.build.warnings": {},
      "containerimage.digest": descriptor.digest,
      "containerimage.config.digest": configDigest,
      "containerimage.descriptor": {
        mediaType: descriptor.mediaType,
        digest: descriptor.digest,
        size: descriptor.size,
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

const setRootManifestAnnotations = (
  fixture: LayoutFixture,
  annotations: Readonly<Record<string, string>>,
): void => {
  const index = JSON.parse(readFileSync(join(fixture.root, "index.json"), "utf8")) as {
    readonly manifests?: unknown;
  };
  if (!Array.isArray(index.manifests) || index.manifests[0] === undefined)
    throw new Error("test fixture index must contain one manifest descriptor");
  (index.manifests[0] as Record<string, unknown>).annotations = annotations;
  writeFileSync(join(fixture.root, "index.json"), JSON.stringify(index));
};

const rewriteNestedIndex = (
  fixture: LayoutFixture,
  mutate: (index: Record<string, unknown>) => void,
): void => {
  const rootIndex = JSON.parse(readFileSync(join(fixture.root, "index.json"), "utf8")) as {
    readonly manifests?: unknown;
  };
  if (!Array.isArray(rootIndex.manifests) || rootIndex.manifests[0] === undefined)
    throw new Error("test fixture must contain one root index descriptor");
  const rootDescriptor = rootIndex.manifests[0] as Record<string, unknown>;
  const priorDigest = rootDescriptor.digest;
  if (typeof priorDigest !== "string")
    throw new Error("test fixture root descriptor digest is required");
  const nested = JSON.parse(
    readFileSync(
      join(fixture.root, "blobs", "sha256", priorDigest.slice("sha256:".length)),
      "utf8",
    ),
  ) as Record<string, unknown>;
  mutate(nested);
  const bytes = Buffer.from(JSON.stringify(nested));
  const nextDigest = hash(bytes);
  write(fixture.root, nextDigest, bytes);
  unlinkSync(join(fixture.root, "blobs", "sha256", priorDigest.slice("sha256:".length)));
  rootDescriptor.digest = nextDigest;
  rootDescriptor.size = bytes.length;
  writeFileSync(join(fixture.root, "index.json"), JSON.stringify(rootIndex));
};

const replaceWithSingleLayer = (fixture: LayoutFixture, layer: Buffer): string => {
  const index = JSON.parse(readFileSync(join(fixture.root, "index.json"), "utf8")) as {
    readonly manifests?: unknown;
  };
  if (!Array.isArray(index.manifests) || index.manifests[0] === undefined)
    throw new Error("test fixture index must contain one manifest descriptor");
  const rootDescriptor = index.manifests[0] as Record<string, unknown>;
  const manifestDigest = rootDescriptor.digest;
  if (typeof manifestDigest !== "string")
    throw new Error("test fixture manifest digest is required");
  const manifest = JSON.parse(
    readFileSync(
      join(fixture.root, "blobs", "sha256", manifestDigest.slice("sha256:".length)),
      "utf8",
    ),
  ) as Record<string, unknown>;
  const configDescriptor = manifest.config as Record<string, unknown>;
  const configDigest = configDescriptor.digest;
  if (typeof configDigest !== "string") throw new Error("test fixture config digest is required");
  const config = JSON.parse(
    readFileSync(
      join(fixture.root, "blobs", "sha256", configDigest.slice("sha256:".length)),
      "utf8",
    ),
  ) as Record<string, unknown>;
  const oldLayers = manifest.layers as ReadonlyArray<Record<string, unknown>>;
  const layerDigest = hash(layer);
  const rootfs = config.rootfs as Record<string, unknown>;
  config.rootfs = {
    ...rootfs,
    diff_ids: [hash(`uncompressed:${layerDigest}`)],
  };
  const configBytes = Buffer.from(JSON.stringify(config));
  const nextConfigDigest = hash(configBytes);
  manifest.config = { ...configDescriptor, digest: nextConfigDigest, size: configBytes.length };
  manifest.layers = [
    {
      digest: layerDigest,
      mediaType: "application/vnd.oci.image.layer.v1.tar",
      size: layer.length,
    },
  ];
  const manifestBytes = Buffer.from(JSON.stringify(manifest));
  const nextManifestDigest = hash(manifestBytes);
  const oldDigests = new Set([manifestDigest, configDigest]);
  for (const oldLayer of oldLayers) {
    if (typeof oldLayer.digest === "string") oldDigests.add(oldLayer.digest);
  }
  write(fixture.root, nextConfigDigest, configBytes);
  write(fixture.root, nextManifestDigest, manifestBytes);
  write(fixture.root, layerDigest, layer);
  for (const digest of oldDigests) {
    unlinkSync(join(fixture.root, "blobs", "sha256", digest.slice("sha256:".length)));
  }
  rootDescriptor.digest = nextManifestDigest;
  rootDescriptor.size = manifestBytes.length;
  const metadata = fixture.metadata as Record<string, unknown>;
  metadata["containerimage.digest"] = nextManifestDigest;
  metadata["containerimage.config.digest"] = nextConfigDigest;
  const metadataDescriptor = metadata["containerimage.descriptor"] as Record<string, unknown>;
  metadataDescriptor.digest = nextManifestDigest;
  metadataDescriptor.size = manifestBytes.length;
  metadataDescriptor.annotations = {
    "config.digest": nextConfigDigest,
    "org.opencontainers.image.created": "2026-08-17T00:00:00Z",
  };
  writeFileSync(join(fixture.root, "index.json"), JSON.stringify(index));
  return nextConfigDigest;
};

const replaceWithExactTotalLayout = (fixture: LayoutFixture, extraBytes: number): string => {
  const mib = 1024 * 1024;
  const target = 256 * mib + extraBytes;
  const index = JSON.parse(readFileSync(join(fixture.root, "index.json"), "utf8")) as {
    readonly manifests?: unknown;
  };
  if (!Array.isArray(index.manifests) || index.manifests[0] === undefined)
    throw new Error("test fixture index must contain one manifest descriptor");
  const rootDescriptor = index.manifests[0] as Record<string, unknown>;
  const originalManifestDigest = rootDescriptor.digest;
  if (typeof originalManifestDigest !== "string")
    throw new Error("test fixture manifest digest is required");
  const originalManifest = JSON.parse(
    readFileSync(
      join(fixture.root, "blobs", "sha256", originalManifestDigest.slice("sha256:".length)),
      "utf8",
    ),
  ) as Record<string, unknown>;
  const originalConfigDescriptor = originalManifest.config as Record<string, unknown>;
  const originalConfigDigest = originalConfigDescriptor.digest;
  if (typeof originalConfigDigest !== "string")
    throw new Error("test fixture config digest is required");
  const originalConfig = JSON.parse(
    readFileSync(
      join(fixture.root, "blobs", "sha256", originalConfigDigest.slice("sha256:".length)),
      "utf8",
    ),
  ) as Record<string, unknown>;
  const originalLayers = originalManifest.layers as ReadonlyArray<Record<string, unknown>>;
  const firstLength = 128 * mib;
  let first = Buffer.alloc(firstLength, 1);
  const firstDigest = hash(first);
  write(fixture.root, firstDigest, first);
  first = Buffer.alloc(0);
  const build = (secondDigest: string, secondLength: number) => {
    const config = structuredClone(originalConfig) as Record<string, unknown>;
    const rootfs = config.rootfs as Record<string, unknown>;
    config.rootfs = {
      ...rootfs,
      diff_ids: [hash(`uncompressed:${firstDigest}`), hash(`uncompressed:${secondDigest}`)],
    };
    const configBytes = Buffer.from(JSON.stringify(config));
    const configDigest = hash(configBytes);
    const manifest = structuredClone(originalManifest) as Record<string, unknown>;
    manifest.config = {
      ...originalConfigDescriptor,
      digest: configDigest,
      size: configBytes.length,
    };
    manifest.layers = [
      {
        digest: firstDigest,
        mediaType: "application/vnd.oci.image.layer.v1.tar",
        size: firstLength,
      },
      {
        digest: secondDigest,
        mediaType: "application/vnd.oci.image.layer.v1.tar",
        size: secondLength,
      },
    ];
    const manifestBytes = Buffer.from(JSON.stringify(manifest));
    const manifestDigest = hash(manifestBytes);
    const nextIndex = structuredClone(index) as Record<string, unknown>;
    const descriptors = nextIndex.manifests as Array<Record<string, unknown>>;
    descriptors[0] = { ...rootDescriptor, digest: manifestDigest, size: manifestBytes.length };
    const indexBytes = Buffer.from(JSON.stringify(nextIndex));
    return { configBytes, configDigest, indexBytes, manifestBytes, manifestDigest, nextIndex };
  };
  const provisional = build(hash("provisional-layer"), 128 * mib - 4096);
  const overhead =
    readFileSync(join(fixture.root, "oci-layout")).length +
    provisional.indexBytes.length +
    provisional.configBytes.length +
    provisional.manifestBytes.length;
  const secondLength = target - firstLength - overhead;
  if (secondLength < 1 || secondLength > 128 * mib)
    throw new Error("test fixture total layout construction is out of bounds");
  let second = Buffer.alloc(secondLength, 2);
  const secondDigest = hash(second);
  const output = build(secondDigest, secondLength);
  write(fixture.root, output.configDigest, output.configBytes);
  write(fixture.root, output.manifestDigest, output.manifestBytes);
  write(fixture.root, secondDigest, second);
  second = Buffer.alloc(0);
  const oldDigests = new Set([originalManifestDigest, originalConfigDigest]);
  for (const layer of originalLayers) {
    if (typeof layer.digest === "string") oldDigests.add(layer.digest);
  }
  for (const digest of oldDigests) {
    unlinkSync(join(fixture.root, "blobs", "sha256", digest.slice("sha256:".length)));
  }
  writeFileSync(join(fixture.root, "index.json"), output.indexBytes);
  const metadata = fixture.metadata as Record<string, unknown>;
  metadata["containerimage.digest"] = output.manifestDigest;
  metadata["containerimage.config.digest"] = output.configDigest;
  const metadataDescriptor = metadata["containerimage.descriptor"] as Record<string, unknown>;
  metadataDescriptor.digest = output.manifestDigest;
  metadataDescriptor.size = output.manifestBytes.length;
  metadataDescriptor.annotations = {
    "config.digest": output.configDigest,
    "org.opencontainers.image.created": "2026-08-17T00:00:00Z",
  };
  return output.configDigest;
};

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

  it("emits a bounded verifier-owned reason for known internal validation failures", () => {
    const fixture = layoutFixture();
    const invocationRoot = mkdtempSync(join(tmpdir(), "aih-scan-oci-verifier-invocation-"));
    roots.push(invocationRoot);
    const metadataPath = join(invocationRoot, "metadata.json");
    const imageIdPath = join(invocationRoot, "image-id.txt");
    const summaryPath = join(invocationRoot, "summary.json");
    const canonicalLayoutPath = join(invocationRoot, "layout.json");
    writeFileSync(
      metadataPath,
      JSON.stringify({
        ...fixture.metadata,
        "containerimage.config.digest":
          "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      }),
    );
    writeFileSync(imageIdPath, fixture.config);
    const result = spawnSync(
      process.execPath,
      [
        verifierPath,
        "--metadata",
        metadataPath,
        "--layout-root",
        fixture.root,
        "--image-id",
        imageIdPath,
        "--summary",
        summaryPath,
        "--canonical-layout",
        canonicalLayoutPath,
      ],
      { encoding: "utf8", shell: false, windowsHide: true },
    );
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("Cisco OCI verifier rejected input: metadata digest\n");
  });

  it("profiles a rejected root inventory without exposing hostile entry names", () => {
    const fixture = layoutFixture();
    const invocationRoot = mkdtempSync(join(tmpdir(), "aih-scan-oci-verifier-invocation-"));
    roots.push(invocationRoot);
    const metadataPath = join(invocationRoot, "metadata.json");
    const imageIdPath = join(invocationRoot, "image-id.txt");
    const hostileName = "unexpected-do-not-leak-digest-content";
    writeFileSync(join(fixture.root, hostileName), "unexpected");
    writeFileSync(metadataPath, JSON.stringify(fixture.metadata));
    writeFileSync(imageIdPath, fixture.config);
    const result = spawnSync(
      process.execPath,
      [
        verifierPath,
        "--metadata",
        metadataPath,
        "--layout-root",
        fixture.root,
        "--image-id",
        imageIdPath,
        "--summary",
        join(invocationRoot, "summary.json"),
        "--canonical-layout",
        join(invocationRoot, "layout.json"),
      ],
      { encoding: "utf8", shell: false, windowsHide: true },
    );
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe(
      "Cisco OCI verifier rejected input: layout entries required 111 total 4 files 3 directories 1 other 0\n",
    );
    expect(result.stderr).not.toMatch(/do-not-leak|digest|content|unexpected|Error|stack/i);
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

  it("resolves the pinned BuildKit nested OCI index to its sole linux amd64 manifest", () => {
    const fixture = layoutFixture({ nestedIndex: true });
    const result = verifyCiscoOciCandidateV1(input(fixture));
    expect(result.manifestDigestSha256).toBe(fixture.manifest);
    expect(result.configDigestSha256).toBe(fixture.config);
    expect(result.logicalReference).toBe(`local.invalid/aih-scan/cisco@${fixture.manifest}`);
  });

  it("rejects Docker, artifact, and ambiguous nested OCI index descriptor shapes", () => {
    const docker = layoutFixture({ nestedIndex: true });
    const dockerRoot = JSON.parse(readFileSync(join(docker.root, "index.json"), "utf8")) as {
      readonly manifests?: unknown;
    };
    if (!Array.isArray(dockerRoot.manifests) || dockerRoot.manifests[0] === undefined)
      throw new Error("test fixture must contain one root index descriptor");
    (dockerRoot.manifests[0] as Record<string, unknown>).mediaType =
      "application/vnd.docker.distribution.manifest.list.v2+json";
    writeFileSync(join(docker.root, "index.json"), JSON.stringify(dockerRoot));
    expect(() => verifyCiscoOciCandidateV1(input(docker))).toThrow();

    const artifact = layoutFixture({ nestedIndex: true });
    const artifactRoot = JSON.parse(readFileSync(join(artifact.root, "index.json"), "utf8")) as {
      readonly manifests?: unknown;
    };
    if (!Array.isArray(artifactRoot.manifests) || artifactRoot.manifests[0] === undefined)
      throw new Error("test fixture must contain one root index descriptor");
    (artifactRoot.manifests[0] as Record<string, unknown>).mediaType =
      "application/vnd.oci.artifact.manifest.v1+json";
    writeFileSync(join(artifact.root, "index.json"), JSON.stringify(artifactRoot));
    expect(() => verifyCiscoOciCandidateV1(input(artifact))).toThrow();

    const multiple = layoutFixture({ nestedIndex: true });
    rewriteNestedIndex(multiple, (nested) => {
      const manifests = nested.manifests as unknown[];
      nested.manifests = [...manifests, structuredClone(manifests[0])];
    });
    expect(() => verifyCiscoOciCandidateV1(input(multiple))).toThrow();

    const wrongPlatform = layoutFixture({ nestedIndex: true });
    rewriteNestedIndex(wrongPlatform, (nested) => {
      const manifests = nested.manifests as Array<Record<string, unknown>>;
      manifests[0] = { ...manifests[0], platform: { architecture: "amd64", os: "windows" } };
    });
    expect(() => verifyCiscoOciCandidateV1(input(wrongPlatform))).toThrow();

    const digestSubstitution = layoutFixture({ nestedIndex: true });
    const substitutionRoot = JSON.parse(
      readFileSync(join(digestSubstitution.root, "index.json"), "utf8"),
    ) as { readonly manifests?: unknown };
    if (!Array.isArray(substitutionRoot.manifests) || substitutionRoot.manifests[0] === undefined)
      throw new Error("test fixture must contain one root index descriptor");
    const substituted = substitutionRoot.manifests[0] as Record<string, unknown>;
    substituted.digest = digestSubstitution.manifest;
    substituted.size = readFileSync(
      join(
        digestSubstitution.root,
        "blobs",
        "sha256",
        digestSubstitution.manifest.slice("sha256:".length),
      ),
    ).length;
    writeFileSync(join(digestSubstitution.root, "index.json"), JSON.stringify(substitutionRoot));
    expect(() => verifyCiscoOciCandidateV1(input(digestSubstitution))).toThrow();

    const sizeSubstitution = layoutFixture({ nestedIndex: true });
    const sizeRoot = JSON.parse(
      readFileSync(join(sizeSubstitution.root, "index.json"), "utf8"),
    ) as {
      readonly manifests?: unknown;
    };
    if (!Array.isArray(sizeRoot.manifests) || sizeRoot.manifests[0] === undefined)
      throw new Error("test fixture must contain one root index descriptor");
    (sizeRoot.manifests[0] as Record<string, unknown>).size = 0;
    writeFileSync(join(sizeSubstitution.root, "index.json"), JSON.stringify(sizeRoot));
    expect(() => verifyCiscoOciCandidateV1(input(sizeSubstitution))).toThrow();
  });

  it("permits only a bounded regular legacy manifest.json root entry when present", () => {
    const fixture = layoutFixture({ legacyManifest: true });
    expect(verifyCiscoOciCandidateV1(input(fixture)).manifestDigestSha256).toBe(fixture.manifest);
    writeFileSync(join(fixture.root, "unexpected"), "extra");
    expect(() => verifyCiscoOciCandidateV1(input(fixture))).toThrow();
  });

  it("permits only an empty BuildKit ingest directory at the OCI layout root", () => {
    // Public BuildKit v0.30.0 source compatibility: https://github.com/moby/buildkit/tree/v0.30.0
    const fixture = layoutFixture();
    const ingest = join(fixture.root, "ingest");
    mkdirSync(ingest);
    expect(verifyCiscoOciCandidateV1(input(fixture)).manifestDigestSha256).toBe(fixture.manifest);

    writeFileSync(join(ingest, "unexpected"), "extra");
    expect(() => verifyCiscoOciCandidateV1(input(fixture))).toThrow();
    rmSync(ingest, { force: true, recursive: true });

    const linkTarget = mkdtempSync(join(tmpdir(), "aih-scan-oci-ingest-target-"));
    roots.push(linkTarget);
    symlinkSync(linkTarget, ingest, process.platform === "win32" ? "junction" : "dir");
    expect(() => verifyCiscoOciCandidateV1(input(fixture))).toThrow();
    rmSync(ingest, { force: true });

    mkdirSync(join(fixture.root, "unexpected-directory"));
    expect(() => verifyCiscoOciCandidateV1(input(fixture))).toThrow();
    rmSync(join(fixture.root, "unexpected-directory"), { force: true, recursive: true });

    writeFileSync(join(fixture.root, "unexpected-file"), "extra");
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

  it("reports each OCI descriptor field rejection without exposing supplied values", () => {
    const cases: ReadonlyArray<{
      readonly reason: string;
      readonly mutate: (descriptor: Record<string, unknown>) => void;
    }> = [
      {
        reason: "media type unknown",
        mutate: (descriptor) => {
          descriptor.mediaType = "hostile-media-type-content";
        },
      },
      {
        reason: "digest",
        mutate: (descriptor) => {
          descriptor.digest =
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        },
      },
      {
        reason: "size type",
        mutate: (descriptor) => {
          descriptor.size = "hostile-size-type";
        },
      },
      {
        reason: "size range below-zero cumulative at-most-1MiB",
        mutate: (descriptor) => {
          descriptor.size = -1;
        },
      },
      {
        reason: "size range at-most-256MiB cumulative at-most-1MiB",
        mutate: (descriptor) => {
          descriptor.size = 128 * 1024 * 1024 + 1;
        },
      },
    ];
    for (const testCase of cases) {
      const fixture = layoutFixture();
      const invocationRoot = mkdtempSync(join(tmpdir(), "aih-scan-oci-verifier-invocation-"));
      roots.push(invocationRoot);
      const index = JSON.parse(readFileSync(join(fixture.root, "index.json"), "utf8")) as {
        readonly manifests?: unknown;
      };
      if (!Array.isArray(index.manifests) || index.manifests[0] === undefined)
        throw new Error("test fixture index must contain one manifest descriptor");
      const descriptor = index.manifests[0] as Record<string, unknown>;
      testCase.mutate(descriptor);
      writeFileSync(join(fixture.root, "index.json"), JSON.stringify(index));
      const metadataPath = join(invocationRoot, "metadata.json");
      const imageIdPath = join(invocationRoot, "image-id.txt");
      writeFileSync(metadataPath, JSON.stringify(fixture.metadata));
      writeFileSync(imageIdPath, fixture.config);
      const result = spawnSync(
        process.execPath,
        [
          verifierPath,
          "--metadata",
          metadataPath,
          "--layout-root",
          fixture.root,
          "--image-id",
          imageIdPath,
          "--summary",
          join(invocationRoot, "summary.json"),
          "--canonical-layout",
          join(invocationRoot, "layout.json"),
        ],
        { encoding: "utf8", shell: false, windowsHide: true },
      );
      expect(result.error).toBeUndefined();
      expect(result.status).toBe(1);
      expect(result.stdout).toBe("");
      expect(result.stderr).toBe(
        `Cisco OCI verifier rejected input: index manifest ${testCase.reason}\n`,
      );
      expect(result.stderr).not.toMatch(/hostile|AAAA|content|Error|stack/i);
    }
  });

  it("accepts an exact 128MiB layer and rejects one byte beyond the file bound", () => {
    const exact = layoutFixture();
    const exactConfigDigest = replaceWithSingleLayer(exact, Buffer.alloc(128 * 1024 * 1024, 1));
    expect(
      verifyCiscoOciCandidateV1({ ...input(exact), loadedImageId: exactConfigDigest })
        .manifestDigestSha256,
    ).toMatch(/^sha256:[a-f0-9]{64}$/);

    const above = layoutFixture();
    replaceWithSingleLayer(above, Buffer.alloc(128 * 1024 * 1024 + 1, 2));
    expect(() => verifyCiscoOciCandidateV1(input(above))).toThrow(
      "layer size range at-most-256MiB",
    );
  });

  it("accepts an exact 256MiB layout and rejects one byte beyond the aggregate bound", () => {
    const exact = layoutFixture();
    const exactConfigDigest = replaceWithExactTotalLayout(exact, 0);
    expect(
      verifyCiscoOciCandidateV1({ ...input(exact), loadedImageId: exactConfigDigest })
        .manifestDigestSha256,
    ).toMatch(/^sha256:[a-f0-9]{64}$/);

    const above = layoutFixture();
    const aboveConfigDigest = replaceWithExactTotalLayout(above, 1);
    expect(() =>
      verifyCiscoOciCandidateV1({ ...input(above), loadedImageId: aboveConfigDigest }),
    ).toThrow("layout bound at-most-512MiB");
  });

  it("classifies rejected Docker descriptor media types without echoing them", () => {
    const cases = [
      ["application/vnd.docker.distribution.manifest.v2+json", "docker manifest"],
      ["application/vnd.docker.distribution.manifest.list.v2+json", "docker manifest list"],
    ] as const;
    for (const [mediaType, classification] of cases) {
      const fixture = layoutFixture();
      const invocationRoot = mkdtempSync(join(tmpdir(), "aih-scan-oci-verifier-invocation-"));
      roots.push(invocationRoot);
      const index = JSON.parse(readFileSync(join(fixture.root, "index.json"), "utf8")) as {
        readonly manifests?: unknown;
      };
      if (!Array.isArray(index.manifests) || index.manifests[0] === undefined)
        throw new Error("test fixture index must contain one manifest descriptor");
      (index.manifests[0] as Record<string, unknown>).mediaType = mediaType;
      writeFileSync(join(fixture.root, "index.json"), JSON.stringify(index));
      const metadataPath = join(invocationRoot, "metadata.json");
      const imageIdPath = join(invocationRoot, "image-id.txt");
      writeFileSync(metadataPath, JSON.stringify(fixture.metadata));
      writeFileSync(imageIdPath, fixture.config);
      const result = spawnSync(
        process.execPath,
        [
          verifierPath,
          "--metadata",
          metadataPath,
          "--layout-root",
          fixture.root,
          "--image-id",
          imageIdPath,
          "--summary",
          join(invocationRoot, "summary.json"),
          "--canonical-layout",
          join(invocationRoot, "layout.json"),
        ],
        { encoding: "utf8", shell: false, windowsHide: true },
      );
      expect(result.error).toBeUndefined();
      expect(result.status).toBe(1);
      expect(result.stdout).toBe("");
      expect(result.stderr).toBe(
        `Cisco OCI verifier rejected input: index manifest media type ${classification}\n`,
      );
      expect(result.stderr).not.toContain(mediaType);
    }
  });

  it("classifies manifest annotation key sets without exposing annotation names or values", () => {
    const cases = [
      {
        annotations: { "io.containerd.image.name": "local.invalid/aih-scan/cisco" },
        reason: "manifest annotations keys containerd",
      },
      {
        annotations: { "hostile.annotation.name": "hostile-annotation-value" },
        reason: `manifest annotations keys unknown 1 key digest ${createHash("sha256")
          .update("hostile.annotation.name")
          .digest("hex")}`,
      },
    ] as const;
    for (const testCase of cases) {
      const fixture = layoutFixture();
      const invocationRoot = mkdtempSync(join(tmpdir(), "aih-scan-oci-verifier-invocation-"));
      roots.push(invocationRoot);
      const index = JSON.parse(readFileSync(join(fixture.root, "index.json"), "utf8")) as {
        readonly manifests?: unknown;
      };
      if (!Array.isArray(index.manifests) || index.manifests[0] === undefined)
        throw new Error("test fixture index must contain one manifest descriptor");
      (index.manifests[0] as Record<string, unknown>).annotations = testCase.annotations;
      writeFileSync(join(fixture.root, "index.json"), JSON.stringify(index));
      const metadataPath = join(invocationRoot, "metadata.json");
      const imageIdPath = join(invocationRoot, "image-id.txt");
      writeFileSync(metadataPath, JSON.stringify(fixture.metadata));
      writeFileSync(imageIdPath, fixture.config);
      const result = spawnSync(
        process.execPath,
        [
          verifierPath,
          "--metadata",
          metadataPath,
          "--layout-root",
          fixture.root,
          "--image-id",
          imageIdPath,
          "--summary",
          join(invocationRoot, "summary.json"),
          "--canonical-layout",
          join(invocationRoot, "layout.json"),
        ],
        { encoding: "utf8", shell: false, windowsHide: true },
      );
      expect(result.error).toBeUndefined();
      expect(result.status).toBe(1);
      expect(result.stdout).toBe("");
      expect(result.stderr).toBe(`Cisco OCI verifier rejected input: ${testCase.reason}\n`);
      expect(result.stderr).not.toMatch(/hostile|value|Error|stack/i);
    }
  });

  it("accepts an RFC3339 created annotation but excludes it from canonical layout identity", () => {
    const first = layoutFixture();
    const second = layoutFixture();
    setRootManifestAnnotations(first, {
      "io.containerd.image.name": "local.invalid/aih-scan/cisco",
      "org.opencontainers.image.created": "2026-08-17T00:00:00Z",
      "org.opencontainers.image.ref.name": "candidate",
    });
    setRootManifestAnnotations(second, {
      "io.containerd.image.name": "local.invalid/aih-scan/cisco",
      "org.opencontainers.image.created": "2026-08-17T00:00:00.123456789+05:30",
      "org.opencontainers.image.ref.name": "candidate",
    });
    const firstResult = verifyCiscoOciCandidateV1(input(first));
    const secondResult = verifyCiscoOciCandidateV1(input(second));
    expect(firstResult).toEqual(secondResult);
    expect(canonicalCiscoOciVerifierLayoutBytesV1(firstResult)).toEqual(
      canonicalCiscoOciVerifierLayoutBytesV1(secondResult),
    );
  });

  it("rejects malformed or out-of-range created annotation timestamps", () => {
    for (const created of [
      "2026-02-30T00:00:00Z",
      "2026-08-17T24:00:00Z",
      "2026-08-17T00:00:00+14:30",
      "2026-08-17T00:00:00",
      "2026-08-17T00:00:00z",
      "not-a-timestamp",
    ]) {
      const fixture = layoutFixture();
      setRootManifestAnnotations(fixture, {
        "io.containerd.image.name": "local.invalid/aih-scan/cisco",
        "org.opencontainers.image.created": created,
        "org.opencontainers.image.ref.name": "candidate",
      });
      expect(() => verifyCiscoOciCandidateV1(input(fixture))).toThrow();
    }
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
