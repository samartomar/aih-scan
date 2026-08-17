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
    readonly extraIndexManifest?: boolean;
    readonly platform?: { readonly architecture: string; readonly os: string };
  } = {},
) {
  const root = mkdtempSync(join(tmpdir(), "aih-scan-oci-layout-"));
  roots.push(root);
  writeFileSync(join(root, "oci-layout"), JSON.stringify({ imageLayoutVersion: "1.0.0" }));
  const layer = Buffer.from("synthetic immutable layer\n", "utf8");
  const layerDescriptor = descriptor(layer, ociLayerMediaType);
  writeBlob(root, layer);
  const config = Buffer.from(
    JSON.stringify({
      architecture: options.configArchitecture ?? "amd64",
      os: "linux",
      rootfs: { type: "layers", diff_ids: [layerDescriptor.digest] },
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
  const index = {
    schemaVersion: 2,
    mediaType: ociIndexMediaType,
    manifests: [
      {
        ...manifestDescriptor,
        platform,
        annotations: { "org.opencontainers.image.ref.name": options.annotation ?? "candidate" },
      },
    ],
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
  return { root, manifestDescriptor, configDescriptor, layerDescriptor };
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

  it("rejects non-regular, missing, extra, and unsafe layout entries", () => {
    const cases: Array<() => void> = [];
    {
      const value = fixture();
      writeFileSync(join(value.root, "unexpected"), "not in OCI layout");
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

  it.runIf(process.platform === "linux")("rejects a special file anywhere in the layout", () => {
    const value = fixture();
    execFileSync("mkfifo", [join(value.root, "blobs", "sha256", "a".repeat(64))]);
    expect(() => loadCiscoOciLayoutV1({ layoutRoot: value.root })).toThrow();
  });
});
