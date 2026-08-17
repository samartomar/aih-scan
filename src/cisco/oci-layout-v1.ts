import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, type Stats } from "node:fs";
import { join, resolve } from "node:path";
import {
  assertStrictJsonValueV1,
  canonicalStrictJsonBytesV1,
  deepFreezeStrictJsonV1,
  parseStrictJsonObjectV1,
} from "../contract/strict-json-v1.js";

const INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json";
const MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json";
const CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json";
const LAYER_MEDIA_TYPES = new Set([
  "application/vnd.oci.image.layer.v1.tar",
  "application/vnd.oci.image.layer.v1.tar+gzip",
]);
const MAX_ITEM_BYTES = 1024 * 1024;
const MAX_LAYOUT_BYTES = 4 * 1024 * 1024;
const digest = /^sha256:[a-f0-9]{64}$/;
const reference = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const brand = new WeakMap<object, Buffer>();

export type CiscoOciLayoutV1 = Readonly<{
  protocol: "CiscoOciLayoutV1";
  manifestDigestSha256: string;
  configDigestSha256: string;
  logicalReference: string;
  manifestPlatform: { readonly architecture: "amd64"; readonly os: "linux" };
  manifestDescriptor: Readonly<{
    readonly mediaType: string;
    readonly digest: string;
    readonly size: number;
    readonly platform: { readonly architecture: "amd64"; readonly os: "linux" };
    readonly annotations: { readonly "org.opencontainers.image.ref.name": string };
  }>;
}>;

type Descriptor = { mediaType: string; digest: string; size: number };
type IndexDescriptor = Descriptor & {
  platform: { architecture: "amd64"; os: "linux" };
  annotations: { "org.opencontainers.image.ref.name": string };
};

const fail = (message: string): never => {
  throw new TypeError(`invalid Cisco OCI layout V1: ${message}`);
};
const hash = (bytes: Buffer) => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
const exact = (value: Record<string, unknown>, fields: readonly string[], label: string): void => {
  if (Object.keys(value).length !== fields.length || fields.some((field) => !(field in value)))
    fail(`${label} fields`);
};
const object = (value: unknown, label: string): Record<string, unknown> => {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail(`${label} object`);
  return value as Record<string, unknown>;
};

function regular(path: string, label: string): Stats {
  const stat: Stats = (() => {
    try {
      return lstatSync(path);
    } catch {
      return fail(`${label} missing`);
    }
  })();
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink > 1)
    fail(`${label} must be a regular unlinked file`);
  if (stat.size < 0 || stat.size > MAX_ITEM_BYTES) fail(`${label} exceeds bounds`);
  return stat;
}

function directory(path: string, label: string): void {
  const stat: Stats = (() => {
    try {
      return lstatSync(path);
    } catch {
      return fail(`${label} missing`);
    }
  })();
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail(`${label} must be a real directory`);
}

function bytes(path: string, label: string, total: { value: number }): Buffer {
  const stat = regular(path, label);
  total.value += stat.size;
  if (total.value > MAX_LAYOUT_BYTES) fail("layout exceeds total bound");
  const value = readFileSync(path);
  if (value.length !== stat.size) fail(`${label} changed while reading`);
  return value;
}

function descriptor(value: unknown, label: string): Descriptor {
  const v = object(value, label);
  exact(v, ["mediaType", "digest", "size"], label);
  if (
    typeof v.mediaType !== "string" ||
    typeof v.digest !== "string" ||
    !digest.test(v.digest) ||
    typeof v.size !== "number" ||
    !Number.isSafeInteger(v.size) ||
    v.size < 0 ||
    v.size > MAX_ITEM_BYTES
  )
    fail(`${label} descriptor`);
  return { mediaType: v.mediaType as string, digest: v.digest as string, size: v.size as number };
}

function verifyBlob(
  root: string,
  value: Descriptor,
  expectedMediaType: string | Set<string>,
  total: { value: number },
  label: string,
): Buffer {
  if (
    typeof expectedMediaType === "string"
      ? value.mediaType !== expectedMediaType
      : !expectedMediaType.has(value.mediaType)
  )
    fail(`${label} media type`);
  const name = value.digest.slice("sha256:".length);
  if (!/^[a-f0-9]{64}$/.test(name)) fail(`${label} digest name`);
  const content = bytes(join(root, "blobs", "sha256", name), label, total);
  if (content.length !== value.size || hash(content) !== value.digest)
    fail(`${label} digest or size`);
  return content;
}

function strictJson(content: Buffer, label: string): Record<string, unknown> {
  const text = content.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(content)) fail(`${label} UTF-8`);
  try {
    return parseStrictJsonObjectV1(text, label);
  } catch {
    return fail(`${label} JSON`);
  }
}

function input(value: unknown): { layoutRoot: string } {
  try {
    assertStrictJsonValueV1(value, "Cisco OCI layout input");
  } catch {
    fail("input");
  }
  const v = object(value, "input");
  exact(v, ["layoutRoot"], "input");
  if (typeof v.layoutRoot !== "string" || !v.layoutRoot || v.layoutRoot.length > 4096)
    fail("layout root");
  return { layoutRoot: v.layoutRoot as string };
}

function freeze(result: CiscoOciLayoutV1): CiscoOciLayoutV1 {
  const frozen = deepFreezeStrictJsonV1(structuredClone(result)) as CiscoOciLayoutV1;
  brand.set(frozen, canonicalStrictJsonBytesV1(frozen));
  return frozen;
}

export function loadCiscoOciLayoutV1(value: unknown): CiscoOciLayoutV1 {
  const { layoutRoot } = input(value);
  const root = resolve(layoutRoot);
  directory(root, "layout root");
  const names = readdirSync(root).sort();
  if (names.length !== 3 || names.join("\0") !== ["blobs", "index.json", "oci-layout"].join("\0"))
    fail("layout entries");
  const total = { value: 0 };
  const layout = strictJson(bytes(join(root, "oci-layout"), "oci layout", total), "oci layout");
  exact(layout, ["imageLayoutVersion"], "oci layout");
  if (layout.imageLayoutVersion !== "1.0.0") fail("OCI layout version");
  directory(join(root, "blobs"), "blobs");
  const blobAlgorithms = readdirSync(join(root, "blobs")).sort();
  if (blobAlgorithms.length !== 1 || blobAlgorithms[0] !== "sha256") fail("blob algorithms");
  directory(join(root, "blobs", "sha256"), "sha256 blobs");
  const index = strictJson(bytes(join(root, "index.json"), "index", total), "index");
  exact(index, ["schemaVersion", "mediaType", "manifests"], "index");
  const manifests = index.manifests as unknown[];
  if (
    index.schemaVersion !== 2 ||
    index.mediaType !== INDEX_MEDIA_TYPE ||
    !Array.isArray(manifests) ||
    manifests.length !== 1
  )
    fail("index");
  const selected = object(manifests[0], "index manifest");
  exact(selected, ["mediaType", "digest", "size", "platform", "annotations"], "index manifest");
  const base = descriptor(
    { mediaType: selected.mediaType, digest: selected.digest, size: selected.size },
    "index manifest",
  );
  const platform = object(selected.platform, "manifest platform");
  exact(platform, ["architecture", "os"], "manifest platform");
  if (platform.architecture !== "amd64" || platform.os !== "linux") fail("manifest platform");
  const annotations = object(selected.annotations, "manifest annotations");
  exact(annotations, ["org.opencontainers.image.ref.name"], "manifest annotations");
  if (
    typeof annotations["org.opencontainers.image.ref.name"] !== "string" ||
    !reference.test(annotations["org.opencontainers.image.ref.name"] as string)
  )
    fail("manifest reference annotation");
  const selectedDescriptor: IndexDescriptor = {
    ...base,
    platform: { architecture: "amd64", os: "linux" },
    annotations: {
      "org.opencontainers.image.ref.name": annotations[
        "org.opencontainers.image.ref.name"
      ] as string,
    },
  };
  const manifestBytes = verifyBlob(
    root,
    selectedDescriptor,
    MANIFEST_MEDIA_TYPE,
    total,
    "manifest",
  );
  const manifest = strictJson(manifestBytes, "manifest");
  exact(manifest, ["schemaVersion", "mediaType", "config", "layers"], "manifest");
  const layers = manifest.layers as unknown[];
  if (
    manifest.schemaVersion !== 2 ||
    manifest.mediaType !== MANIFEST_MEDIA_TYPE ||
    !Array.isArray(layers) ||
    layers.length < 1 ||
    layers.length > 128
  )
    fail("manifest");
  const configDescriptor = descriptor(manifest.config, "config");
  const configBytes = verifyBlob(root, configDescriptor, CONFIG_MEDIA_TYPE, total, "config");
  const config = strictJson(configBytes, "config");
  exact(config, ["architecture", "os", "rootfs"], "config");
  if (config.architecture !== "amd64" || config.os !== "linux") fail("config platform");
  const rootfs = object(config.rootfs, "config rootfs");
  exact(rootfs, ["type", "diff_ids"], "config rootfs");
  if (
    rootfs.type !== "layers" ||
    !Array.isArray(rootfs.diff_ids) ||
    rootfs.diff_ids.length !== layers.length ||
    rootfs.diff_ids.length > 128 ||
    !rootfs.diff_ids.every((item) => typeof item === "string" && digest.test(item))
  )
    fail("config rootfs");
  const referenced = new Set<string>([selectedDescriptor.digest, configDescriptor.digest]);
  for (const item of layers) {
    const layer = descriptor(item, "layer");
    verifyBlob(root, layer, LAYER_MEDIA_TYPES, total, "layer");
    if (referenced.has(layer.digest)) fail("duplicate referenced blob");
    referenced.add(layer.digest);
  }
  const blobNames = readdirSync(join(root, "blobs", "sha256")).sort();
  if (
    blobNames.some((name) => !/^[a-f0-9]{64}$/.test(name)) ||
    blobNames.length !== referenced.size ||
    blobNames.some((name) => !referenced.has(`sha256:${name}`))
  )
    fail("unreferenced or unsafe blob");
  return freeze({
    protocol: "CiscoOciLayoutV1",
    manifestDigestSha256: selectedDescriptor.digest,
    configDigestSha256: configDescriptor.digest,
    logicalReference: `local.invalid/aih-scan/cisco@${selectedDescriptor.digest}`,
    manifestPlatform: { architecture: "amd64", os: "linux" },
    manifestDescriptor: selectedDescriptor,
  });
}

export function canonicalCiscoOciLayoutBytesV1(value: unknown): Buffer {
  const bytes = typeof value === "object" && value !== null ? brand.get(value) : undefined;
  return bytes === undefined
    ? fail("canonical bytes require a branded layout")
    : Buffer.from(bytes);
}

export function parseCiscoOciLayoutV1(value: unknown): CiscoOciLayoutV1 {
  if (!Buffer.isBuffer(value)) fail("canonical layout bytes");
  const parsed = strictJson(Buffer.from(value as Buffer), "canonical layout");
  exact(
    parsed,
    [
      "protocol",
      "manifestDigestSha256",
      "configDigestSha256",
      "logicalReference",
      "manifestPlatform",
      "manifestDescriptor",
    ],
    "canonical layout",
  );
  if (
    parsed.protocol !== "CiscoOciLayoutV1" ||
    typeof parsed.manifestDigestSha256 !== "string" ||
    typeof parsed.configDigestSha256 !== "string" ||
    !digest.test(parsed.manifestDigestSha256) ||
    !digest.test(parsed.configDigestSha256) ||
    parsed.logicalReference !== `local.invalid/aih-scan/cisco@${parsed.manifestDigestSha256}`
  )
    fail("canonical layout identity");
  const platform = object(parsed.manifestPlatform, "canonical platform");
  exact(platform, ["architecture", "os"], "canonical platform");
  const selected = object(parsed.manifestDescriptor, "canonical manifest descriptor");
  exact(
    selected,
    ["mediaType", "digest", "size", "platform", "annotations"],
    "canonical manifest descriptor",
  );
  const parsedDescriptor = descriptor(
    { mediaType: selected.mediaType, digest: selected.digest, size: selected.size },
    "canonical manifest descriptor",
  );
  const selectedPlatform = object(selected.platform, "canonical selected platform");
  exact(selectedPlatform, ["architecture", "os"], "canonical selected platform");
  const annotations = object(selected.annotations, "canonical annotations");
  exact(annotations, ["org.opencontainers.image.ref.name"], "canonical annotations");
  if (
    platform.architecture !== "amd64" ||
    platform.os !== "linux" ||
    selectedPlatform.architecture !== "amd64" ||
    selectedPlatform.os !== "linux" ||
    parsed.configDigestSha256 === parsed.manifestDigestSha256 ||
    parsedDescriptor.digest !== parsed.manifestDigestSha256 ||
    parsedDescriptor.mediaType !== MANIFEST_MEDIA_TYPE ||
    typeof annotations["org.opencontainers.image.ref.name"] !== "string" ||
    !reference.test(annotations["org.opencontainers.image.ref.name"] as string)
  )
    fail("canonical layout manifest");
  return freeze({
    protocol: "CiscoOciLayoutV1",
    manifestDigestSha256: parsed.manifestDigestSha256 as string,
    configDigestSha256: parsed.configDigestSha256 as string,
    logicalReference: parsed.logicalReference as string,
    manifestPlatform: { architecture: "amd64", os: "linux" },
    manifestDescriptor: {
      ...parsedDescriptor,
      platform: { architecture: "amd64", os: "linux" },
      annotations: {
        "org.opencontainers.image.ref.name": annotations[
          "org.opencontainers.image.ref.name"
        ] as string,
      },
    },
  });
}

export function isCiscoOciLayoutV1(value: unknown): value is CiscoOciLayoutV1 {
  return typeof value === "object" && value !== null && brand.has(value);
}
