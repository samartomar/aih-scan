import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SHA256 = /^sha256:[a-f0-9]{64}$/;
const INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json";
const MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json";
const CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json";
const DOCKER_MANIFEST_MEDIA_TYPE = "application/vnd.docker.distribution.manifest.v2+json";
const DOCKER_MANIFEST_LIST_MEDIA_TYPE = "application/vnd.docker.distribution.manifest.list.v2+json";
const LOGICAL_REFERENCE_PREFIX = "local.invalid/aih-scan/cisco@sha256:";
const LAYER_MEDIA_TYPES = new Set([
  "application/vnd.oci.image.layer.v1.tar",
  "application/vnd.oci.image.layer.v1.tar+gzip",
]);
const MAX_FILE_BYTES = 128 * 1024 * 1024;
const MAX_LAYOUT_BYTES = 256 * 1024 * 1024;
const MAX_ROOT_ENTRIES = 128;
const SIZE_BUCKETS_MIB = [1, 32, 64, 128, 256, 512, 1024];
const CONTAINERD_IMAGE_NAME_ANNOTATION = "io.containerd.image.name";
const OCI_CREATED_ANNOTATION = "org.opencontainers.image.created";
const OCI_REFERENCE_ANNOTATION = "org.opencontainers.image.ref.name";
const summaries = new WeakMap();
const metadataDescriptors = new WeakMap();

const fail = (message) => {
  throw new TypeError(`invalid Cisco OCI verifier V1: ${message}`);
};
const sha256 = (bytes) => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;

function assertUnicode(value, label) {
  if (value.normalize("NFC") !== value) fail(`${label} NFC`);
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) fail(`${label} surrogate`);
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      fail(`${label} surrogate`);
    }
  }
}

function parseJson(text, label) {
  let index = 0;
  const whitespace = () => {
    while (/\s/u.test(text[index] ?? "")) index += 1;
  };
  const string = () => {
    const start = index;
    if (text[index] !== '"') fail(`${label} JSON`);
    index += 1;
    while (index < text.length) {
      const char = text[index];
      if (char === '"') {
        index += 1;
        let parsed;
        try {
          parsed = JSON.parse(text.slice(start, index));
        } catch {
          fail(`${label} JSON`);
        }
        if (typeof parsed !== "string") fail(`${label} JSON`);
        assertUnicode(parsed, label);
        return parsed;
      }
      if (char === "\\") {
        index += 1;
        const escape = text[index];
        if (escape === undefined) fail(`${label} JSON`);
        if (escape === "u") index += 4;
      } else if (char === undefined || char < " ") {
        fail(`${label} JSON`);
      }
      index += 1;
    }
    fail(`${label} JSON`);
  };
  const value = () => {
    whitespace();
    const char = text[index];
    if (char === "{") {
      index += 1;
      whitespace();
      const output = {};
      const keys = new Set();
      if (text[index] === "}") {
        index += 1;
        return output;
      }
      while (true) {
        whitespace();
        const key = string();
        if (keys.has(key)) fail(`${label} duplicate key`);
        keys.add(key);
        whitespace();
        if (text[index] !== ":") fail(`${label} JSON`);
        index += 1;
        const child = value();
        Object.defineProperty(output, key, {
          configurable: true,
          enumerable: true,
          value: child,
          writable: true,
        });
        whitespace();
        if (text[index] === "}") {
          index += 1;
          return output;
        }
        if (text[index] !== ",") fail(`${label} JSON`);
        index += 1;
      }
    }
    if (char === "[") {
      index += 1;
      whitespace();
      const output = [];
      if (text[index] === "]") {
        index += 1;
        return output;
      }
      while (true) {
        output.push(value());
        whitespace();
        if (text[index] === "]") {
          index += 1;
          return output;
        }
        if (text[index] !== ",") fail(`${label} JSON`);
        index += 1;
      }
    }
    if (char === '"') return string();
    for (const [raw, parsed] of [["true", true], ["false", false], ["null", null]]) {
      if (text.startsWith(raw, index)) {
        index += raw.length;
        return parsed;
      }
    }
    const match = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(
      text.slice(index),
    );
    if (match === null || match.index !== 0) fail(`${label} JSON`);
    index += match[0].length;
    const number = Number(match[0]);
    if (!Number.isFinite(number) || Object.is(number, -0)) fail(`${label} JSON`);
    return number;
  };
  const parsed = value();
  whitespace();
  if (index !== text.length) fail(`${label} JSON`);
  return parsed;
}

function canonical(value) {
  if (value === null || typeof value === "boolean" || typeof value === "number")
    return JSON.stringify(value);
  if (typeof value === "string") {
    assertUnicode(value, "canonical JSON");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype)
    fail("canonical JSON");
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${canonical(key)}:${canonical(value[key])}`)
    .join(",")}}`;
}

function plain(value, fields, label) {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.getOwnPropertySymbols(value).length !== 0
  )
    fail(`${label} object`);
  const keys = Object.keys(value);
  if (keys.length !== fields.length || fields.some((field) => !Object.hasOwn(value, field)))
    fail(`${label} fields`);
  for (const key of keys) {
    if (!Object.hasOwn(Object.getOwnPropertyDescriptor(value, key) ?? {}, "value"))
      fail(`${label} accessor`);
  }
  return value;
}

function allowed(value, required, permitted, label) {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.getOwnPropertySymbols(value).length !== 0
  )
    fail(`${label} object`);
  const keys = Object.keys(value);
  if (
    required.some((field) => !Object.hasOwn(value, field)) ||
    keys.some((field) => !permitted.has(field))
  )
    fail(`${label} fields`);
  for (const key of keys) {
    if (!Object.hasOwn(Object.getOwnPropertyDescriptor(value, key) ?? {}, "value"))
      fail(`${label} accessor`);
  }
  return value;
}

function jsonData(value, label, depth = 0) {
  if (depth > 32 || value === null || typeof value === "boolean") return;
  if (typeof value === "string") {
    assertUnicode(value, label);
    return;
  }
  if (typeof value === "number" && Number.isFinite(value) && !Object.is(value, -0)) return;
  if (Array.isArray(value)) {
    for (const item of value) jsonData(item, label, depth + 1);
    return;
  }
  if (typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    for (const key of Object.keys(value)) {
      const item = Object.getOwnPropertyDescriptor(value, key);
      if (item === undefined || !("value" in item)) fail(`${label} accessor`);
      assertUnicode(key, label);
      jsonData(item.value, label, depth + 1);
    }
    return;
  }
  fail(`${label} JSON`);
}

function mediaTypeClass(value) {
  if (value === INDEX_MEDIA_TYPE) return "oci index";
  if (value === MANIFEST_MEDIA_TYPE) return "oci manifest";
  if (value === DOCKER_MANIFEST_MEDIA_TYPE) return "docker manifest";
  if (value === DOCKER_MANIFEST_LIST_MEDIA_TYPE) return "docker manifest list";
  return "unknown";
}

function sizeBucket(bytes) {
  if (typeof bytes !== "number" || !Number.isSafeInteger(bytes)) return "invalid";
  if (bytes < 0) return "below-zero";
  for (const mib of SIZE_BUCKETS_MIB) {
    if (bytes <= mib * 1024 * 1024) return `at-most-${mib}MiB`;
  }
  return "over-1024MiB";
}

function descriptor(value, label, expectedMediaTypes, total) {
  const data = plain(value, ["mediaType", "digest", "size"], label);
  if (typeof data.mediaType !== "string" || !expectedMediaTypes.has(data.mediaType))
    fail(`${label} media type ${mediaTypeClass(data.mediaType)}`);
  if (typeof data.digest !== "string" || !SHA256.test(data.digest)) fail(`${label} digest`);
  if (typeof data.size !== "number") fail(`${label} size type`);
  if (!Number.isSafeInteger(data.size) || data.size < 0 || data.size > MAX_FILE_BYTES)
    fail(`${label} size range ${sizeBucket(data.size)} cumulative ${sizeBucket(total.value)}`);
  return data;
}

function regular(path, label, total) {
  let stat;
  try {
    stat = lstatSync(path);
  } catch {
    fail(`${label} missing`);
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > MAX_FILE_BYTES)
    fail(`${label} file`);
  total.value += stat.size;
  if (total.value > MAX_LAYOUT_BYTES) fail(`layout bound ${sizeBucket(total.value)}`);
  const bytes = readFileSync(path);
  if (bytes.length !== stat.size) fail(`${label} changed`);
  return bytes;
}

function directory(path, label) {
  let stat;
  try {
    stat = lstatSync(path);
  } catch {
    fail(`${label} missing`);
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail(`${label} directory`);
}

function readBlob(root, item, label, total) {
  const digest = item.digest;
  const name = digest.slice("sha256:".length);
  if (!/^[a-f0-9]{64}$/u.test(name)) fail(`${label} digest`);
  const content = regular(join(root, "blobs", "sha256", name), label, total);
  if (content.length !== item.size || sha256(content) !== digest) fail(`${label} binding`);
  return content;
}

function jsonFromBytes(bytes, label) {
  const text = bytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(bytes)) fail(`${label} UTF-8`);
  return parseJson(text, label);
}

function rootInventory(root, entries) {
  if (entries.length > MAX_ROOT_ENTRIES) fail("layout entries bound");
  const required = ["blobs", "index.json", "oci-layout"];
  let files = 0;
  let directories = 0;
  let other = 0;
  for (const entry of entries) {
    let stat;
    try {
      stat = lstatSync(join(root, entry));
    } catch {
      fail("layout entries");
    }
    if (stat.isFile()) files += 1;
    else if (stat.isDirectory()) directories += 1;
    else other += 1;
  }
  const bits = required.map((entry) => (entries.includes(entry) ? "1" : "0")).join("");
  return { bits, files, directories, other, total: entries.length };
}

function manifestPlatform(value, label) {
  const platform = plain(value, ["os", "architecture"], label);
  if (platform.os !== "linux" || platform.architecture !== "amd64") fail(label);
  return { architecture: "amd64", os: "linux" };
}

function annotationKeySet(value) {
  if (value === undefined) return "missing";
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.getOwnPropertySymbols(value).length !== 0
  )
    return undefined;
  const keys = Object.keys(value).sort();
  if (keys.length === 0) return "empty";
  const known = new Set([
    CONTAINERD_IMAGE_NAME_ANNOTATION,
    OCI_CREATED_ANNOTATION,
    OCI_REFERENCE_ANNOTATION,
  ]);
  if (keys.every((key) => known.has(key))) {
    const names = [];
    if (keys.includes(OCI_REFERENCE_ANNOTATION)) names.push("reference");
    if (keys.includes(CONTAINERD_IMAGE_NAME_ANNOTATION)) names.push("containerd");
    if (keys.includes(OCI_CREATED_ANNOTATION)) names.push("created");
    return names.join(" ");
  }
  return `unknown ${keys.length} key digest ${createHash("sha256").update(keys.join("\n")).digest("hex")}`;
}

function assertRfc3339Timestamp(value, label) {
  if (typeof value !== "string" || value.length < 20 || value.length > 35)
    fail(`${label} timestamp`);
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(Z|[+-](\d{2}):(\d{2}))$/u.exec(
    value,
  );
  if (match === null) fail(`${label} timestamp`);
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, zone, offsetHourText, offsetMinuteText] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const offsetHour = offsetHourText === undefined ? 0 : Number(offsetHourText);
  const offsetMinute = offsetMinuteText === undefined ? 0 : Number(offsetMinuteText);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > (days[month - 1] ?? 0) ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    (zone !== "Z" && (offsetHour > 14 || offsetMinute > 59 || (offsetHour === 14 && offsetMinute !== 0)))
  )
    fail(`${label} timestamp`);
}

function manifestAnnotations(value, label) {
  const keySet = annotationKeySet(value);
  if (
    keySet !== undefined &&
    keySet !== "reference" &&
    keySet !== "reference containerd" &&
    keySet !== "reference created" &&
    keySet !== "reference containerd created"
  )
    fail(`${label} keys ${keySet}`);
  const annotations = allowed(
    value,
    [OCI_REFERENCE_ANNOTATION],
    new Set([CONTAINERD_IMAGE_NAME_ANNOTATION, OCI_CREATED_ANNOTATION, OCI_REFERENCE_ANNOTATION]),
    label,
  );
  const reference = annotations[OCI_REFERENCE_ANNOTATION];
  if (typeof reference !== "string" || !/^[a-z0-9][a-z0-9._/-]{0,255}$/u.test(reference))
    fail("manifest reference");
  const imageName = annotations[CONTAINERD_IMAGE_NAME_ANNOTATION];
  if (imageName !== undefined && (typeof imageName !== "string" || imageName.length === 0 || imageName.length > 255))
    fail(label);
  const created = annotations[OCI_CREATED_ANNOTATION];
  if (created !== undefined) assertRfc3339Timestamp(created, label);
  return { [OCI_REFERENCE_ANNOTATION]: reference };
}

function layoutFromRoot(layoutRoot) {
  if (
    typeof layoutRoot !== "string" ||
    !isAbsolute(layoutRoot) ||
    layoutRoot.includes("\0") ||
    layoutRoot.includes("\r") ||
    layoutRoot.includes("\n")
  )
    fail("layout root");
  const root = resolve(layoutRoot);
  directory(root, "layout root");
  const rootEntries = readdirSync(root).sort();
  const permittedRootEntries = new Set(["blobs", "index.json", "ingest", "manifest.json", "oci-layout"]);
  const inventory = rootInventory(root, rootEntries);
  if (
    rootEntries.some((entry) => !permittedRootEntries.has(entry)) ||
    !["blobs", "index.json", "oci-layout"].every((entry) => rootEntries.includes(entry))
  )
    fail(
      `layout entries required ${inventory.bits} total ${inventory.total} files ${inventory.files} directories ${inventory.directories} other ${inventory.other}`,
    );
  const total = { value: 0 };
  const ociLayout = jsonFromBytes(regular(join(root, "oci-layout"), "oci layout", total), "oci layout");
  const layout = plain(ociLayout, ["imageLayoutVersion"], "oci layout");
  if (layout.imageLayoutVersion !== "1.0.0") fail("oci layout version");
  if (rootEntries.includes("manifest.json"))
    regular(join(root, "manifest.json"), "legacy manifest", total);
  if (rootEntries.includes("ingest")) {
    const ingest = join(root, "ingest");
    directory(ingest, "ingest");
    if (readdirSync(ingest).length !== 0) fail("ingest entries");
  }
  directory(join(root, "blobs"), "blobs");
  if (readdirSync(join(root, "blobs")).sort().join("\0") !== "sha256") fail("blob algorithm");
  directory(join(root, "blobs", "sha256"), "blob root");
  const index = plain(
    jsonFromBytes(regular(join(root, "index.json"), "index", total), "index"),
    ["schemaVersion", "mediaType", "manifests"],
    "index",
  );
  if (index.schemaVersion !== 2 || index.mediaType !== INDEX_MEDIA_TYPE || !Array.isArray(index.manifests) || index.manifests.length !== 1)
    fail("index");
  const selected = allowed(
    index.manifests[0],
    ["mediaType", "digest", "size"],
    new Set(["mediaType", "digest", "size", "platform", "annotations"]),
    "index manifest",
  );
  const rootDescriptor = descriptor(
    { mediaType: selected.mediaType, digest: selected.digest, size: selected.size },
    "index manifest",
    new Set([INDEX_MEDIA_TYPE, MANIFEST_MEDIA_TYPE]),
    total,
  );
  const annotations = manifestAnnotations(selected.annotations, "manifest annotations");
  let manifestDescriptor;
  let manifestBytes;
  if (rootDescriptor.mediaType === MANIFEST_MEDIA_TYPE) {
    manifestDescriptor = {
      ...rootDescriptor,
      annotations,
      platform: manifestPlatform(selected.platform, "manifest platform"),
    };
    manifestBytes = readBlob(root, manifestDescriptor, "manifest", total);
  } else {
    if (selected.platform !== undefined) manifestPlatform(selected.platform, "manifest platform");
    const nestedIndex = plain(
      jsonFromBytes(readBlob(root, rootDescriptor, "nested index", total), "nested index"),
      ["schemaVersion", "mediaType", "manifests"],
      "nested index",
    );
    if (
      nestedIndex.schemaVersion !== 2 ||
      nestedIndex.mediaType !== INDEX_MEDIA_TYPE ||
      !Array.isArray(nestedIndex.manifests) ||
      nestedIndex.manifests.length !== 1
    )
      fail("nested index");
    const nestedSelected = plain(
      nestedIndex.manifests[0],
      ["mediaType", "digest", "size", "platform"],
      "nested manifest",
    );
    const nestedDescriptor = descriptor(
      { mediaType: nestedSelected.mediaType, digest: nestedSelected.digest, size: nestedSelected.size },
      "nested manifest",
      new Set([MANIFEST_MEDIA_TYPE]),
      total,
    );
    manifestDescriptor = {
      ...nestedDescriptor,
      annotations,
      platform: manifestPlatform(nestedSelected.platform, "nested manifest platform"),
    };
    manifestBytes = readBlob(root, manifestDescriptor, "manifest", total);
  }
  const manifest = plain(jsonFromBytes(manifestBytes, "manifest"), ["schemaVersion", "mediaType", "config", "layers"], "manifest");
  if (manifest.schemaVersion !== 2 || manifest.mediaType !== MANIFEST_MEDIA_TYPE || !Array.isArray(manifest.layers) || manifest.layers.length < 1 || manifest.layers.length > 128)
    fail("manifest");
  const configDescriptor = descriptor(manifest.config, "config", new Set([CONFIG_MEDIA_TYPE]), total);
  const configBytes = readBlob(root, configDescriptor, "config", total);
  const config = allowed(
    jsonFromBytes(configBytes, "config"),
    ["architecture", "os", "rootfs"],
    new Set(["architecture", "config", "created", "history", "os", "rootfs"]),
    "config",
  );
  if (config.os !== "linux" || config.architecture !== "amd64")
    fail("config platform");
  if (
    (config.created !== undefined &&
      (typeof config.created !== "string" || config.created.length === 0 || config.created.length > 128)) ||
    (config.config !== undefined &&
      (typeof config.config !== "object" || config.config === null || Array.isArray(config.config))) ||
    (config.history !== undefined && (!Array.isArray(config.history) || config.history.length > 4096))
  )
    fail("config standard fields");
  if (config.config !== undefined) jsonData(config.config, "config standard fields");
  if (config.history !== undefined) jsonData(config.history, "config standard fields");
  const rootfs = config.rootfs;
  const rootfsData = plain(rootfs, ["type", "diff_ids"], "config rootfs");
  if (
    rootfsData.type !== "layers" ||
    !Array.isArray(rootfsData.diff_ids) ||
    rootfsData.diff_ids.length !== manifest.layers.length ||
    !rootfsData.diff_ids.every((item) => typeof item === "string" && SHA256.test(item))
  )
    fail("config rootfs");
  const referenced = new Set([rootDescriptor.digest, manifestDescriptor.digest, configDescriptor.digest]);
  for (const layerInput of manifest.layers) {
    const layer = descriptor(layerInput, "layer", LAYER_MEDIA_TYPES, total);
    if (referenced.has(layer.digest)) fail("duplicate layer");
    readBlob(root, layer, "layer", total);
    referenced.add(layer.digest);
  }
  const blobNames = readdirSync(join(root, "blobs", "sha256")).sort();
  if (blobNames.length !== referenced.size || blobNames.some((name) => !referenced.has(`sha256:${name}`)))
    fail("blob inventory");
  const resultLayout = {
    protocol: "CiscoOciLayoutV1",
    manifestDigestSha256: manifestDescriptor.digest,
    configDigestSha256: configDescriptor.digest,
    logicalReference: `${LOGICAL_REFERENCE_PREFIX}${manifestDescriptor.digest.slice("sha256:".length)}`,
    manifestPlatform: { architecture: "amd64", os: "linux" },
    manifestDescriptor: {
      annotations,
      digest: manifestDescriptor.digest,
      mediaType: manifestDescriptor.mediaType,
      platform: { architecture: "amd64", os: "linux" },
      size: manifestDescriptor.size,
    },
  };
  metadataDescriptors.set(resultLayout, rootDescriptor);
  return resultLayout;
}

function metadata(value, layout) {
  const data = allowed(
    value,
    ["containerimage.digest", "containerimage.config.digest", "containerimage.descriptor"],
    new Set([
      "buildx.build.provenance",
      "buildx.build.ref",
      "buildx.build.warnings",
      "containerimage.digest",
      "containerimage.config.digest",
      "containerimage.descriptor",
    ]),
    "metadata",
  );
  const metadataDescriptor = metadataDescriptors.get(layout) ?? layout.manifestDescriptor;
  if (data["containerimage.digest"] !== metadataDescriptor.digest || data["containerimage.config.digest"] !== layout.configDigestSha256)
    fail("metadata digest");
  if (
    (data["buildx.build.ref"] !== undefined &&
      (typeof data["buildx.build.ref"] !== "string" ||
        data["buildx.build.ref"].length === 0 ||
        data["buildx.build.ref"].length > 1024)) ||
    (data["buildx.build.provenance"] !== undefined &&
      (typeof data["buildx.build.provenance"] !== "object" ||
        data["buildx.build.provenance"] === null ||
        Array.isArray(data["buildx.build.provenance"]))) ||
    (data["buildx.build.warnings"] !== undefined &&
      (typeof data["buildx.build.warnings"] !== "object" ||
        data["buildx.build.warnings"] === null ||
        Array.isArray(data["buildx.build.warnings"])))
  )
    fail("metadata buildx");
  if (data["buildx.build.provenance"] !== undefined)
    jsonData(data["buildx.build.provenance"], "metadata provenance");
  if (data["buildx.build.warnings"] !== undefined)
    jsonData(data["buildx.build.warnings"], "metadata warnings");
  const descriptorData = plain(
    data["containerimage.descriptor"],
    ["mediaType", "digest", "size", "annotations"],
    "metadata descriptor",
  );
  const descriptor = descriptorData;
  const annotations = allowed(
    descriptor.annotations,
    ["config.digest"],
    new Set(["config.digest", "org.opencontainers.image.created"]),
    "metadata descriptor annotations",
  );
  if (
    descriptor.mediaType !== metadataDescriptor.mediaType ||
    descriptor.digest !== metadataDescriptor.digest ||
    descriptor.size !== metadataDescriptor.size ||
    annotations["config.digest"] !== layout.configDigestSha256 ||
    (annotations["org.opencontainers.image.created"] !== undefined &&
      typeof annotations["org.opencontainers.image.created"] !== "string")
  )
    fail("metadata descriptor");
}

export function verifyCiscoOciCandidateV1(value) {
  const input = plain(value, ["protocol", "layoutRoot", "metadata", "loadedImageId"], "input");
  if (input.protocol !== "CiscoOciVerifierV1" || typeof input.loadedImageId !== "string" || !SHA256.test(input.loadedImageId))
    fail("input");
  const layout = layoutFromRoot(input.layoutRoot);
  metadata(input.metadata, layout);
  if (input.loadedImageId !== layout.configDigestSha256 || layout.configDigestSha256 === layout.manifestDigestSha256)
    fail("loaded image identity");
  const withoutHash = {
    configDigestSha256: layout.configDigestSha256,
    logicalReference: layout.logicalReference,
    manifestDigestSha256: layout.manifestDigestSha256,
    protocol: "CiscoOciVerifierV1",
  };
  const summary = Object.freeze({
    ...withoutHash,
    summarySha256: createHash("sha256").update(canonical(withoutHash)).digest("hex"),
  });
  summaries.set(summary, {
    layout: Buffer.from(canonical(layout)),
    summary: Buffer.from(canonical(summary)),
  });
  return summary;
}

export function canonicalCiscoOciVerifierBytesV1(value) {
  const stored = summaries.get(value);
  if (stored === undefined) fail("summary brand");
  return Buffer.from(stored.summary);
}

export function canonicalCiscoOciVerifierLayoutBytesV1(value) {
  const stored = summaries.get(value);
  if (stored === undefined) fail("summary brand");
  return Buffer.from(stored.layout);
}

function cliArguments(values) {
  const expected = ["metadata", "layout-root", "image-id", "summary", "canonical-layout"];
  if (values.length !== expected.length * 2) fail("CLI arguments");
  const result = {};
  for (let index = 0; index < values.length; index += 2) {
    const flag = values[index];
    const path = values[index + 1];
    if (typeof flag !== "string" || !flag.startsWith("--") || typeof path !== "string") fail("CLI arguments");
    const key = flag.slice(2);
    if (!expected.includes(key) || Object.hasOwn(result, key) || !isAbsolute(path)) fail("CLI arguments");
    result[key] = path;
  }
  if (Object.keys(result).length !== expected.length) fail("CLI arguments");
  return result;
}

function cliFailureReason(error) {
  const prefix = "invalid Cisco OCI verifier V1: ";
  if (error instanceof TypeError && error.message.startsWith(prefix)) {
    const reason = error.message.slice(prefix.length);
    if (/^[A-Za-z0-9 -]{1,128}$/.test(reason)) return reason;
  }
  return "rejected";
}

const invokedPath = process.argv[1];
if (
  typeof invokedPath === "string" &&
  resolve(invokedPath) === resolve(fileURLToPath(import.meta.url))
) {
  try {
    const args = cliArguments(process.argv.slice(2));
    const metadataBytes = readFileSync(args.metadata);
    const result = verifyCiscoOciCandidateV1({
      protocol: "CiscoOciVerifierV1",
      layoutRoot: args["layout-root"],
      metadata: jsonFromBytes(metadataBytes, "metadata"),
      loadedImageId: readFileSync(args["image-id"], "utf8").trim(),
    });
    writeFileSync(args.summary, canonicalCiscoOciVerifierBytesV1(result));
    writeFileSync(args["canonical-layout"], canonicalCiscoOciVerifierLayoutBytesV1(result));
  } catch (error) {
    process.stderr.write(`Cisco OCI verifier rejected input: ${cliFailureReason(error)}\n`);
    process.exitCode = 1;
  }
}
