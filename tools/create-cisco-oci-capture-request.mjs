#!/usr/bin/env node
import { createHash } from "node:crypto";
import { lstatSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, isAbsolute, relative, resolve } from "node:path";

const SHA256 = /^[a-f0-9]{64}$/u;
const DIGEST = /^sha256:[a-f0-9]{64}$/u;
const fail = (message) => {
  throw new TypeError(`Cisco OCI capture bridge rejected input: ${message}`);
};
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const sameIdentity = (left, right) =>
  left.dev === right.dev &&
  left.ino === right.ino &&
  left.size === right.size &&
  left.mtimeMs === right.mtimeMs &&
  left.ctimeMs === right.ctimeMs &&
  left.nlink === right.nlink;
const canonical = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object")
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
      .join(",")}}`;
  return JSON.stringify(value);
};
function regular(path, label) {
  const resolved = resolve(path);
  if (!isAbsolute(path) || path.includes("\0")) fail(`${label} path`);
  let before;
  try {
    before = lstatSync(resolved);
  } catch {
    fail(`${label} missing`);
  }
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.nlink !== 1 ||
    before.size <= 0 ||
    before.size > 16 * 1024 * 1024
  )
    fail(`${label} file shape`);
  const bytes = readFileSync(resolved);
  let after;
  try {
    after = lstatSync(resolved);
  } catch {
    fail(`${label} changed`);
  }
  if (bytes.byteLength !== before.size || !sameIdentity(before, after)) fail(`${label} changed`);
  return { bytes, path: resolved, sha256: hash(bytes) };
}
function directory(path, label) {
  const resolved = resolve(path);
  if (!isAbsolute(path) || path.includes("\0")) fail(`${label} path`);
  let stat;
  try {
    stat = lstatSync(resolved);
  } catch {
    fail(`${label} missing`);
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail(`${label} directory shape`);
  return resolved;
}
function parseLayout(file) {
  let layout;
  try {
    layout = JSON.parse(file.bytes.toString("utf8"));
  } catch {
    fail("canonical layout JSON");
  }
  if (!Buffer.from(canonical(layout), "utf8").equals(file.bytes)) fail("canonical layout JSON");
  const exact = (value, fields) =>
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length === fields.length &&
    fields.every((field) => Object.hasOwn(value, field));
  if (
    !exact(layout, [
      "protocol",
      "manifestDigestSha256",
      "configDigestSha256",
      "logicalReference",
      "manifestPlatform",
      "manifestDescriptor",
    ]) ||
    layout.protocol !== "CiscoOciLayoutV1" ||
    !DIGEST.test(layout.manifestDigestSha256) ||
    !DIGEST.test(layout.configDigestSha256) ||
    layout.manifestDigestSha256 === layout.configDigestSha256 ||
    layout.logicalReference !== `local.invalid/aih-scan/cisco@${layout.manifestDigestSha256}` ||
    !exact(layout.manifestPlatform, ["architecture", "os"]) ||
    layout.manifestPlatform.os !== "linux" ||
    layout.manifestPlatform.architecture !== "amd64" ||
    !exact(layout.manifestDescriptor, ["mediaType", "digest", "size", "platform", "annotations"]) ||
    layout.manifestDescriptor.digest !== layout.manifestDigestSha256 ||
    layout.manifestDescriptor.mediaType !== "application/vnd.oci.image.manifest.v1+json" ||
    !Number.isSafeInteger(layout.manifestDescriptor.size) ||
    layout.manifestDescriptor.size < 0 ||
    !exact(layout.manifestDescriptor.platform, ["architecture", "os"]) ||
    layout.manifestDescriptor.platform.os !== "linux" ||
    layout.manifestDescriptor.platform.architecture !== "amd64" ||
    !exact(layout.manifestDescriptor.annotations, ["org.opencontainers.image.ref.name"]) ||
    typeof layout.manifestDescriptor.annotations["org.opencontainers.image.ref.name"] !== "string"
  )
    fail("canonical layout identity");
  return layout;
}
function flags(values) {
  const names = new Set([
    "--layout",
    "--source-root",
    "--selected-path",
    "--dockerfile",
    "--pyproject",
    "--lock",
    "--image-id",
    "--repository",
    "--workflow",
    "--source-ref",
    "--commit",
    "--run-id",
    "--run-attempt",
    "--environment",
    "--output",
  ]);
  if (values.length !== 30) fail("CLI arguments");
  const result = {};
  for (let index = 0; index < values.length; index += 2) {
    const name = values[index];
    const value = values[index + 1];
    if (!names.has(name) || typeof value !== "string" || Object.hasOwn(result, name))
      fail("CLI arguments");
    result[name] = value;
  }
  if (Object.keys(result).length !== names.size) fail("CLI arguments");
  return result;
}
function identifier(prefix, value) {
  return `${prefix}.${hash(Buffer.from(canonical(value), "utf8")).slice(0, 12)}`;
}
function checkedCi(input) {
  const ci = {
    repository: input["--repository"],
    workflow: input["--workflow"],
    sourceRef: input["--source-ref"],
    commit: input["--commit"],
    runId: input["--run-id"],
    runAttempt: Number(input["--run-attempt"]),
    environment: input["--environment"],
  };
  if (
    !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(ci.repository) ||
    ci.workflow !== ".github/workflows/cisco-oci-equivalence.yml" ||
    !/^refs\/(heads|tags)\/[A-Za-z0-9._/-]{1,256}$/u.test(ci.sourceRef) ||
    !/^[a-f0-9]{40}$/u.test(ci.commit) ||
    !/^[1-9][0-9]{0,19}$/u.test(ci.runId) ||
    !Number.isSafeInteger(ci.runAttempt) ||
    ci.runAttempt < 1 ||
    ci.runAttempt > 1000 ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u.test(ci.environment)
  )
    fail("CI source context");
  return ci;
}
function main() {
  const input = flags(process.argv.slice(2));
  const sourceRoot = directory(input["--source-root"], "source root");
  const selectedPath = input["--selected-path"];
  const selectedFile = resolve(sourceRoot, selectedPath);
  const selectedRelative = relative(sourceRoot, selectedFile);
  if (
    !/^(?!\/)(?!.*(?:^|\/)\.\.?\/)[A-Za-z0-9._/-]{1,512}$/u.test(selectedPath) ||
    selectedPath.includes("\\") ||
    selectedRelative.startsWith("..") ||
    isAbsolute(selectedRelative)
  )
    fail("selected source path");
  regular(selectedFile, "selected source");
  const layoutFile = regular(input["--layout"], "canonical layout");
  const dockerfile = regular(input["--dockerfile"], "Dockerfile");
  const pyproject = regular(input["--pyproject"], "pyproject");
  const lock = regular(input["--lock"], "lock");
  const imageId = regular(input["--image-id"], "Docker image ID");
  const layout = parseLayout(layoutFile);
  const imageDigest = imageId.bytes.toString("utf8").trim();
  if (!DIGEST.test(imageDigest) || imageDigest !== layout.configDigestSha256)
    fail("Docker image config identity");
  const ci = checkedCi(input);
  const dependencies = [
    { name: basename(dockerfile.path), digest: { sha256: dockerfile.sha256 } },
    { name: basename(pyproject.path), digest: { sha256: pyproject.sha256 } },
    { name: basename(lock.path), digest: { sha256: lock.sha256 } },
    { name: "oci-layout-v1", digest: { sha256: layoutFile.sha256 } },
    { name: "oci-manifest", digest: { sha256: layout.manifestDigestSha256.slice(7) } },
    { name: "oci-config", digest: { sha256: layout.configDigestSha256.slice(7) } },
    { name: "loaded-docker-config", digest: { sha256: imageDigest.slice(7) } },
  ];
  const sbom = {
    SPDXID: "SPDXRef-DOCUMENT",
    bomFormat: "SPDX",
    evidenceState: "digest-bound-unverified",
    name: "aih-scan-cisco-runtime",
    packages: dependencies.map((entry) => ({ name: entry.name, sha256: entry.digest.sha256 })),
    specVersion: "SPDX-2.3",
  };
  const provenance = {
    _type: "https://in-toto.io/Statement/v1",
    predicate: {
      buildDefinition: {
        buildType: "https://aih.dev/cisco-oci-capture-bridge/v1",
        externalParameters: { ci },
        resolvedDependencies: dependencies,
      },
      evidenceState: "digest-bound-unverified",
      runDetails: { builder: { id: "digest-bound-unverified" }, metadata: { ci } },
    },
    predicateType: "https://slsa.dev/provenance/v1",
    subject: [
      {
        digest: { sha256: layout.manifestDigestSha256.slice(7) },
        name: layout.logicalReference,
      },
    ],
  };
  const runtimeInputs = { dependencies, layout };
  const runtime = {
    adapter: {
      identity: identifier("adapter", runtimeInputs),
      sha256: hash(Buffer.from(canonical({ domain: "aih.cisco.oci-bridge.adapter-v1", runtimeInputs }))),
    },
    analyzerIdentity: identifier("native", runtimeInputs),
    detectorId: "detector.cisco",
    executionProfileSha256: hash(
      Buffer.from(canonical({ domain: "aih.cisco.oci-bridge.execution-profile-v1", runtimeInputs })),
    ),
    observationConfigurationSha256: hash(
      Buffer.from(canonical({ domain: "aih.cisco.oci-bridge.configuration-v1", runtimeInputs })),
    ),
    ociImage: {
      reference: layout.logicalReference,
      sha256: layout.manifestDigestSha256.slice(7),
    },
    provenance: { mediaType: "application/vnd.in-toto+json", sha256: hash(Buffer.from(canonical(provenance))) },
    sbom: { mediaType: "application/spdx+json", sha256: hash(Buffer.from(canonical(sbom))) },
    supportedPlatforms: [{ architecture: "amd64", os: "linux" }],
  };
  const output = resolve(input["--output"]);
  if (!isAbsolute(input["--output"]) || input["--output"].includes("\0")) fail("output path");
  try {
    mkdirSync(output, { recursive: false, mode: 0o700 });
  } catch {
    fail("output directory");
  }
  const sbomPath = resolve(output, "annex.sbom.json");
  const provenancePath = resolve(output, "annex.provenance.json");
  const request = {
    annexFiles: [
      { descriptorId: "annex.sbom", path: sbomPath },
      { descriptorId: "annex.provenance", path: provenancePath },
    ],
    broker: { identity: identifier("broker", runtimeInputs) },
    layout,
    runtime,
    selectedClosurePaths: [selectedPath],
    sourceRoot,
  };
  writeFileSync(sbomPath, canonical(sbom));
  writeFileSync(provenancePath, canonical(provenance));
  writeFileSync(resolve(output, "ci-context.json"), canonical(ci));
  writeFileSync(resolve(output, "capture-request.json"), canonical(request));
}

try {
  main();
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : "Cisco OCI capture bridge rejected input"}\n`);
  process.exitCode = 1;
}
