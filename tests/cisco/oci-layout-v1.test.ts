import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";
import {
  canonicalCiscoOciLayoutBytesV1,
  loadCiscoOciLayoutV1,
  parseCiscoOciLayoutV1,
} from "../../src/cisco/oci-layout-v1.js";

const roots: string[] = [];
const ociIndexMediaType = "application/vnd.oci.image.index.v1+json";
const ociManifestMediaType = "application/vnd.oci.image.manifest.v1+json";
const ociConfigMediaType = "application/vnd.oci.image.config.v1+json";
const ociLayerMediaType = "application/vnd.oci.image.layer.v1.tar";
const ociGzipLayerMediaType = "application/vnd.oci.image.layer.v1.tar+gzip";
const sha256 = (bytes: Buffer | string) => createHash("sha256").update(bytes).digest("hex");
const descriptor = (bytes: Buffer, mediaType: string) => ({
  mediaType,
  digest: `sha256:${sha256(bytes)}`,
  size: bytes.length,
});

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function writeBlob(root: string, bytes: Buffer): string {
  const digest = sha256(bytes);
  const directory = join(root, "blobs", "sha256");
  mkdirSync(directory, { recursive: true });
  writeFileSync(join(directory, digest), bytes);
  return digest;
}

function fixture(
  options: {
    readonly annotation?: string;
    readonly configArchitecture?: string;
    readonly configOs?: string;
    readonly diffIds?: readonly string[];
    readonly extraIndexManifest?: boolean;
    readonly layerMediaType?: string;
    readonly platform?: { readonly architecture: string; readonly os: string };
  } = {},
) {
  const root = mkdtempSync(join(tmpdir(), "aih-scan-oci-layout-"));
  roots.push(root);
  writeFileSync(join(root, "oci-layout"), JSON.stringify({ imageLayoutVersion: "1.0.0" }));
  const uncompressedLayer = Buffer.from("synthetic immutable layer\n", "utf8");
  const layer =
    options.layerMediaType === ociGzipLayerMediaType
      ? gzipSync(uncompressedLayer)
      : uncompressedLayer;
  const layerDescriptor = descriptor(layer, options.layerMediaType ?? ociLayerMediaType);
  writeBlob(root, layer);
  const config = Buffer.from(
    JSON.stringify({
      architecture: options.configArchitecture ?? "amd64",
      os: options.configOs ?? "linux",
      rootfs: {
        type: "layers",
        diff_ids: options.diffIds ?? [`sha256:${sha256(uncompressedLayer)}`],
      },
    }),
    "utf8",
  );
  const configDescriptor = descriptor(config, ociConfigMediaType);
  writeBlob(root, config);
  const manifest = Buffer.from(
    JSON.stringify({
      schemaVersion: 2,
      mediaType: ociManifestMediaType,
      config: configDescriptor,
      layers: [layerDescriptor],
    }),
    "utf8",
  );
  const manifestDescriptor = descriptor(manifest, ociManifestMediaType);
  writeBlob(root, manifest);
  const platform = options.platform ?? { architecture: "amd64", os: "linux" };
  const selectedManifestDescriptor = {
    ...manifestDescriptor,
    platform,
    annotations: { "org.opencontainers.image.ref.name": options.annotation ?? "candidate" },
  };
  const index = {
    schemaVersion: 2,
    mediaType: ociIndexMediaType,
    manifests: [selectedManifestDescriptor],
  };
  if (options.extraIndexManifest) {
    const first = index.manifests[0];
    if (first === undefined) throw new Error("OCI fixture manifest is missing");
    index.manifests.push({
      ...first,
      platform: { architecture: "arm64", os: "linux" },
    });
  }
  writeFileSync(join(root, "index.json"), JSON.stringify(index));
  return {
    root,
    manifestDescriptor,
    configDescriptor,
    layerDescriptor,
    selectedManifestDescriptor,
  };
}

function rewriteManifest(
  value: ReturnType<typeof fixture>,
  mutate: (manifest: {
    config: Record<string, unknown>;
    layers: Array<Record<string, unknown>>;
  }) => void,
): void {
  const path = join(value.root, "blobs", "sha256", value.manifestDescriptor.digest.slice(7));
  const manifest = JSON.parse(readFileSync(path, "utf8")) as {
    config: Record<string, unknown>;
    layers: Array<Record<string, unknown>>;
  };
  mutate(manifest);
  const bytes = Buffer.from(JSON.stringify(manifest));
  const next = descriptor(bytes, ociManifestMediaType);
  writeBlob(value.root, bytes);
  rmSync(path);
  const index = JSON.parse(readFileSync(join(value.root, "index.json"), "utf8")) as {
    manifests: Array<Record<string, unknown>>;
  };
  const selected = index.manifests[0];
  if (selected === undefined) throw new Error("OCI fixture index manifest is missing");
  index.manifests[0] = { ...selected, digest: next.digest, size: next.size };
  writeFileSync(join(value.root, "index.json"), JSON.stringify(index));
}

function recursivelyFrozen(value: unknown, seen = new Set<object>()): void {
  if (value === null || typeof value !== "object" || ArrayBuffer.isView(value)) return;
  if (seen.has(value)) return;
  seen.add(value);
  expect(Object.isFrozen(value)).toBe(true);
  for (const child of Object.values(value)) recursivelyFrozen(child, seen);
}

describe("Cisco OCI layout V1", () => {
  it("verifies one linux/amd64 OCI manifest and keeps manifest evidence distinct from config execution identity", () => {
    const value = fixture();
    const layout = loadCiscoOciLayoutV1({ layoutRoot: value.root });

    expect(Object.keys(layout).sort()).toEqual(
      [
        "configDigestSha256",
        "logicalReference",
        "manifestDigestSha256",
        "manifestDescriptor",
        "manifestPlatform",
        "protocol",
      ].sort(),
    );
    expect(layout.protocol).toBe("CiscoOciLayoutV1");
    expect(layout.manifestDigestSha256).toBe(value.manifestDescriptor.digest);
    expect(layout.configDigestSha256).toBe(value.configDescriptor.digest);
    expect(layout.manifestDigestSha256).not.toBe(layout.configDigestSha256);
    expect(layout.logicalReference).toBe(
      `local.invalid/aih-scan/cisco@${value.manifestDescriptor.digest}`,
    );
    expect(layout.manifestPlatform).toEqual({ architecture: "amd64", os: "linux" });
    expect(layout.manifestDescriptor).toEqual(value.selectedManifestDescriptor);
    recursivelyFrozen(layout);
    expect(() => {
      (layout as { logicalReference: string }).logicalReference = "mutable";
    }).toThrow();
    expect(canonicalCiscoOciLayoutBytesV1(layout)).toEqual(
      canonicalCiscoOciLayoutBytesV1(parseCiscoOciLayoutV1(canonicalCiscoOciLayoutBytesV1(layout))),
    );
    expect(() => canonicalCiscoOciLayoutBytesV1({ ...layout })).toThrow();
  });

  it("fails closed for corrupt blobs, descriptor confusion, duplicate or hostile JSON, and ambiguous platforms", () => {
    const cases: Array<() => void> = [];
    {
      const value = fixture();
      writeFileSync(
        join(value.root, "blobs", "sha256", value.layerDescriptor.digest.slice(7)),
        "changed",
      );
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    {
      const value = fixture();
      writeFileSync(
        join(value.root, "index.json"),
        `{"schemaVersion":2,"schemaVersion":2,"mediaType":"${ociIndexMediaType}","manifests":[]}`,
      );
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    {
      const value = fixture({ extraIndexManifest: true });
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    {
      const value = fixture({ platform: { architecture: "amd64", os: "darwin" } });
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    {
      const value = fixture({ configArchitecture: "arm64" });
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    {
      const value = fixture({ configOs: "darwin" });
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    {
      const value = fixture({ annotation: "candidate\u0301" });
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    {
      const value = fixture();
      const manifestPath = join(
        value.root,
        "blobs",
        "sha256",
        value.manifestDescriptor.digest.slice(7),
      );
      const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
        config: Record<string, unknown>;
      };
      manifest.config = { ...manifest.config, digest: value.manifestDescriptor.digest };
      writeFileSync(manifestPath, JSON.stringify(manifest));
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    for (const run of cases) expect(run).toThrow();
  });

  it("binds descriptor media type and size from index through manifest config and every layer", () => {
    const cases: Array<() => void> = [];
    {
      const value = fixture();
      const index = JSON.parse(readFileSync(join(value.root, "index.json"), "utf8")) as {
        manifests: Array<Record<string, unknown>>;
      };
      const selected = index.manifests[0];
      if (selected === undefined) throw new Error("OCI fixture index manifest is missing");
      selected.mediaType = ociConfigMediaType;
      writeFileSync(join(value.root, "index.json"), JSON.stringify(index));
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    {
      const value = fixture();
      const index = JSON.parse(readFileSync(join(value.root, "index.json"), "utf8")) as {
        manifests: Array<Record<string, unknown>>;
      };
      const selected = index.manifests[0];
      if (selected === undefined) throw new Error("OCI fixture index manifest is missing");
      selected.size = Number(selected.size) + 1;
      writeFileSync(join(value.root, "index.json"), JSON.stringify(index));
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    {
      const value = fixture();
      rewriteManifest(value, (manifest) => {
        manifest.config.mediaType = ociManifestMediaType;
      });
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    {
      const value = fixture();
      rewriteManifest(value, (manifest) => {
        manifest.config.size = Number(manifest.config.size) + 1;
      });
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    {
      const value = fixture();
      rewriteManifest(value, (manifest) => {
        const layer = manifest.layers[0];
        if (layer === undefined) throw new Error("OCI fixture layer is missing");
        layer.mediaType = ociConfigMediaType;
      });
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    {
      const value = fixture();
      rewriteManifest(value, (manifest) => {
        const layer = manifest.layers[0];
        if (layer === undefined) throw new Error("OCI fixture layer is missing");
        layer.size = Number(layer.size) + 1;
      });
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    for (const run of cases) expect(run).toThrow();
  });

  it("rejects non-regular, missing, extra, and unsafe layout entries", () => {
    const cases: Array<() => void> = [];
    {
      const value = fixture();
      writeFileSync(join(value.root, "unexpected"), "not in OCI layout");
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    {
      const value = fixture();
      writeFileSync(join(value.root, "blobs", "sha256", "G".repeat(64)), "invalid name");
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    {
      const value = fixture();
      writeFileSync(join(value.root, "blobs", "sha256", "a".repeat(64)), "unreferenced");
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    {
      const value = fixture();
      writeFileSync(join(value.root, "blobs", "sha256", "z".repeat(63)), "invalid name");
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    {
      const value = fixture();
      rmSync(join(value.root, "blobs", "sha256", value.configDescriptor.digest.slice(7)));
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    {
      const value = fixture();
      symlinkSync("index.json", join(value.root, "link"));
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    {
      const value = fixture();
      linkSync(
        join(value.root, "blobs", "sha256", value.layerDescriptor.digest.slice(7)),
        join(value.root, "blobs", "sha256", "f".repeat(64)),
      );
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    for (const run of cases) expect(run).toThrow();
  });

  it("rejects symlinks and hardlinks at every required layout boundary", () => {
    const cases: Array<() => void> = [];
    {
      const value = fixture();
      const replacement = join(value.root, "replacement-layout");
      writeFileSync(replacement, "replacement");
      rmSync(join(value.root, "oci-layout"));
      symlinkSync(replacement, join(value.root, "oci-layout"));
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    {
      const value = fixture();
      const replacement = join(value.root, "replacement-index");
      writeFileSync(replacement, "replacement");
      rmSync(join(value.root, "index.json"));
      symlinkSync(replacement, join(value.root, "index.json"));
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    {
      const value = fixture();
      const replacement = join(value.root, "replacement-blobs");
      mkdirSync(join(replacement, "sha256"), { recursive: true });
      rmSync(join(value.root, "blobs"), { recursive: true });
      symlinkSync(replacement, join(value.root, "blobs"), "junction");
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    {
      const value = fixture();
      const replacement = join(value.root, "replacement-sha256");
      mkdirSync(replacement);
      rmSync(join(value.root, "blobs", "sha256"), { recursive: true });
      symlinkSync(replacement, join(value.root, "blobs", "sha256"), "junction");
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    {
      const value = fixture();
      const blob = join(value.root, "blobs", "sha256", value.configDescriptor.digest.slice(7));
      const replacement = join(value.root, "replacement-blob");
      writeFileSync(replacement, "replacement");
      rmSync(blob);
      symlinkSync(replacement, blob);
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    {
      const value = fixture();
      const blob = join(value.root, "blobs", "sha256", value.layerDescriptor.digest.slice(7));
      const outside = mkdtempSync(join(tmpdir(), "aih-scan-oci-outside-hardlink-"));
      roots.push(outside);
      linkSync(blob, join(outside, "layer"));
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    for (const run of cases) expect(run).toThrow();
  });

  it("rejects hidden outside-root hardlinks for required files and referenced blobs", () => {
    const cases: Array<() => void> = [];
    for (const select of [
      (value: ReturnType<typeof fixture>) => join(value.root, "oci-layout"),
      (value: ReturnType<typeof fixture>) => join(value.root, "index.json"),
      (value: ReturnType<typeof fixture>) =>
        join(value.root, "blobs", "sha256", value.configDescriptor.digest.slice(7)),
      (value: ReturnType<typeof fixture>) =>
        join(value.root, "blobs", "sha256", value.manifestDescriptor.digest.slice(7)),
    ]) {
      const value = fixture();
      const outside = mkdtempSync(join(tmpdir(), "aih-scan-oci-required-hardlink-"));
      roots.push(outside);
      linkSync(select(value), join(outside, "same-bytes"));
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    for (const run of cases) expect(run).toThrow();
  });

  it.runIf(process.platform === "linux")("rejects a special file anywhere in the layout", () => {
    const value = fixture();
    execFileSync("mkfifo", [join(value.root, "blobs", "sha256", "a".repeat(64))]);
    expect(() => loadCiscoOciLayoutV1({ layoutRoot: value.root })).toThrow();
  });

  it("accepts OCI gzip and uncompressed layer descriptors while keeping rootfs diff IDs distinct", () => {
    const compressed = fixture({ layerMediaType: ociGzipLayerMediaType });
    const uncompressed = fixture();
    const compressedLayout = loadCiscoOciLayoutV1({ layoutRoot: compressed.root });
    const uncompressedLayout = loadCiscoOciLayoutV1({ layoutRoot: uncompressed.root });

    expect(compressedLayout.manifestDescriptor.mediaType).toBe(ociManifestMediaType);
    expect(compressedLayout.configDigestSha256).not.toBe(compressed.layerDescriptor.digest);
    expect(uncompressedLayout.configDigestSha256).not.toBe(uncompressed.layerDescriptor.digest);
  });

  it("rejects unknown input, forged brands, unsafe roots, and bounded overlong raw layout data", () => {
    const value = fixture();
    const rootLink = `${value.root}-link`;
    symlinkSync(value.root, rootLink, "junction");
    roots.push(rootLink);
    writeFileSync(join(value.root, "index.json"), Buffer.alloc(1024 * 1024 + 1));

    expect(() =>
      loadCiscoOciLayoutV1({ layoutRoot: value.root, extra: true } as unknown),
    ).toThrow();
    expect(() => loadCiscoOciLayoutV1({ layoutRoot: rootLink })).toThrow();
    expect(() => parseCiscoOciLayoutV1({ protocol: "CiscoOciLayoutV1" })).toThrow();
    expect(() => canonicalCiscoOciLayoutBytesV1({})).toThrow();
  });

  it("bounds each raw document/blob and the complete layout before identity construction", () => {
    const cases: Array<() => void> = [];
    for (const target of ["index.json", "oci-layout"]) {
      const value = fixture();
      writeFileSync(join(value.root, target), Buffer.alloc(1024 * 1024 + 1));
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    for (const select of ["configDescriptor", "layerDescriptor", "manifestDescriptor"] as const) {
      const value = fixture();
      const descriptor = value[select];
      writeFileSync(
        join(value.root, "blobs", "sha256", descriptor.digest.slice(7)),
        Buffer.alloc(1024 * 1024 + 1),
      );
      cases.push(() => loadCiscoOciLayoutV1({ layoutRoot: value.root }));
    }
    for (const run of cases) expect(run).toThrow();
  });
});
