import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const CORE_COMMIT = "e53fe219002515c092ebb68c5b91c91a2fc6110d";
const CORE_SCHEMA_SHA256 = "88c0a36e9177201660e773351958d89059c7d5b54e1c437d0afd06f48c5288bc";
const CORE_SCHEMA_PATH = "schemas/aih-organization-evidence-envelope-v1.schema.json";
const scannerRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));

function fail(reason) {
  throw new Error(`cold Core evidence proof failed: ${reason}`);
}
function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
function canonical(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string" || typeof value === "number")
    return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value === "object")
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
      .join(",")}}`;
  fail("unsupported mechanics JSON");
}
function npmCliPath() {
  const fromEnvironment = process.env.npm_execpath;
  if (typeof fromEnvironment === "string" && isAbsolute(fromEnvironment) && existsSync(fromEnvironment))
    return fromEnvironment;
  const nodeDirectory = dirname(process.execPath);
  for (const candidate of [
    join(nodeDirectory, "node_modules", "npm", "bin", "npm-cli.js"),
    resolve(nodeDirectory, "..", "lib", "node_modules", "npm", "bin", "npm-cli.js"),
  ])
    if (existsSync(candidate)) return candidate;
  fail("npm CLI unavailable");
}
function runNpm(args, cwd) {
  return execFileSync(process.execPath, [npmCliPath(), ...args], {
    cwd,
    encoding: "utf8",
    stdio: "pipe",
  });
}
function runNode(script, args, cwd, environment = process.env) {
  const result = spawnSync(process.execPath, [script, ...args], {
    cwd,
    encoding: "utf8",
    env: environment,
    stdio: "pipe",
  });
  return {
    status: result.status,
    stdout: typeof result.stdout === "string" ? result.stdout : "",
    stderr: typeof result.stderr === "string" ? result.stderr : "",
    error: result.error,
  };
}
function exactCleanCoreRoot() {
  const supplied = process.env.AIH_SCAN_CORE_SOURCE;
  if (typeof supplied !== "string" || !isAbsolute(supplied) || supplied === CORE_COMMIT)
    fail("AIH_SCAN_CORE_SOURCE must be an absolute Core checkout path");
  const root = resolve(supplied);
  const stat = lstatSync(root);
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail("Core checkout path shape");
  const head = execFileSync("git", ["-C", root, "rev-parse", "HEAD"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  }).trim();
  if (head !== CORE_COMMIT) fail("unexpected Core commit");
  const status = execFileSync("git", ["-C", root, "status", "--porcelain=v1", "--untracked-files=all"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  if (status.length !== 0) fail("Core checkout must be clean");
  return root;
}
function packedTarball(root, destination) {
  const result = JSON.parse(runNpm(["pack", "--json", "--pack-destination", destination], root));
  if (!Array.isArray(result) || result.length !== 1 || typeof result[0]?.filename !== "string")
    fail("packed artifact metadata");
  const tarball = join(destination, result[0].filename);
  if (!existsSync(tarball)) fail("packed artifact missing");
  return tarball;
}
function writeMechanicsSetup(path) {
  writeFileSync(
    path,
    String.raw`
import { createHash, generateKeyPairSync } from "node:crypto";
import { chmodSync, writeFileSync } from "node:fs";
import * as scan from "@aihq/scan";

const hash = (value) => createHash("sha256").update(value).digest("hex");
const canonical = (value) => {
  if (value === null || typeof value === "boolean" || typeof value === "string" || typeof value === "number") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  return "{" + Object.keys(value).sort().map((key) => JSON.stringify(key) + ":" + canonical(value[key])).join(",") + "}";
};
const digestJson = (value) => hash(Buffer.from(canonical(value), "utf8"));
const source = hash("cold-core-evidence-mechanics-source");
const entries = [{ kind: "file", path: "SKILL.md", sha256: source, byteLength: 35 }];
const sourceTreeSha256 = digestJson({ protocol: "SourceTreeV2", entries });
const selectedClosureSha256 = digestJson({ protocol: "SelectedClosureV2", files: entries });
const seal = {
  protocol: "SourceSealV2", algorithm: "code-unit-canonical-json-v1", entries,
  selectedClosurePaths: ["SKILL.md"], selectedFiles: entries, sourceTreeSha256, selectedClosureSha256,
  sealedSnapshotSha256: digestJson({ protocol: "SealedSnapshotV2", sourceTreeSha256, selectedClosureSha256 }),
};
const sourceSealV1 = {
  protocol: "SourceSealV1", sourceTreeSha256: hash("mechanics-v1-source"),
  selectedClosureSha256: hash("mechanics-v1-closure"), sealedSnapshotSha256: hash("mechanics-v1-snapshot"),
};
const annexArtifacts = [
  { descriptorId: "annex.cisco-raw", bytes: Buffer.from("mechanics raw annex", "utf8") },
  { descriptorId: "annex.provenance", bytes: Buffer.from("mechanics provenance annex", "utf8") },
  { descriptorId: "annex.sbom", bytes: Buffer.from("mechanics sbom annex", "utf8") },
];
const detector = {
  detectorId: "detector.cisco", analyzerIdentity: "native.0123456789ab",
  ociImage: { reference: "local.invalid/aih-scan/cisco@sha256:" + hash("mechanics manifest"), sha256: hash("mechanics manifest") },
  adapter: { identity: "adapter.0123456789ab", sha256: hash("mechanics adapter") },
  observationConfigurationSha256: hash("mechanics configuration"), executionProfileSha256: hash("mechanics execution"),
  supportedPlatforms: [{ os: "linux", architecture: "amd64" }],
  sbom: { mediaType: "application/spdx+json", sha256: hash(annexArtifacts[2].bytes) },
  provenance: { mediaType: "application/vnd.in-toto+json", sha256: hash(annexArtifacts[1].bytes) },
};
const manifestEntry = {
  ...detector,
  supportedPlatforms: detector.supportedPlatforms,
  scannerManifestEntrySha256: digestJson({ domain: "aih.scanner-manifest-v1.entry", entry: detector }),
};
const manifestSha256 = digestJson({ domain: "aih.scanner-manifest-v1.aggregate", protocol: "ScannerManifestV1", detectors: [manifestEntry] });
const facts = [{ rawOccurrenceFingerprint: "raw-occurrence-v1:" + hash("mechanics fact"), multiplicity: 1 }];
const coverage = [{ coverageKind: "selected-closure", coverageSha256: sourceSealV1.selectedClosureSha256 }];
const relevantFactsSha256 = digestJson({ domain: "aih.cisco.oci-candidate.relevant-facts-v1", sourceSeal: sourceSealV1 });
const observationKey = {
  protocol: "ObservationKeyV1", sourceSeal: sourceSealV1, nativeAnalyzerIdentity: detector.analyzerIdentity,
  observationConfigurationSha256: detector.observationConfigurationSha256,
  platform: { os: "linux", architecture: "amd64", relevantFactsSha256 },
  scannerManifestEntrySha256: manifestEntry.scannerManifestEntrySha256,
};
const observationKeySha256 = digestJson({ domain: "aih.observation-key-v1", key: observationKey });
const observationSetSha256 = digestJson({ domain: "aih.observation-set-v1", observationKeySha256, facts, coverage });
const broker = {
  identity: "broker.0123456789ab", sarifSha256: hash("mechanics sarif"), enforcementState: "unverified",
  policyDigestSha256: digestJson({ domain: "aih.cisco.oci-candidate.broker-binding-v1", brokerIdentity: "broker.0123456789ab", scannerManifestEntrySha256: manifestEntry.scannerManifestEntrySha256, sarifSha256: hash("mechanics sarif") }),
  appliedFactsSha256: digestJson({ domain: "aih.cisco.oci-candidate.applied-facts-v1", facts, coverage }),
};
const candidate = scan.createScanCandidateV2({
  protocol: "ScanCandidateV2",
  coreContract: { commit: "e53fe219002515c092ebb68c5b91c91a2fc6110d", decisionSchemaSha256: "27295aee8d8be333abe2c73adc72884b534b1c9980a9b7a39d12be8d34c5caff" },
  subject: { name: "source-tree", digest: { sha256: seal.sourceTreeSha256 } }, sourceSeals: { before: seal, after: seal },
  observation: { keySha256: observationKeySha256, setSha256: observationSetSha256 },
  scanner: {
    manifestSha256, runtimeSha256: digestJson({ domain: "aih.cisco.capture-v2.runtime", detector: manifestEntry }), configurationSha256: detector.observationConfigurationSha256,
    cisco: {
      detectorId: detector.detectorId, analyzerIdentity: detector.analyzerIdentity,
      oci: { logicalReference: detector.ociImage.reference, manifestDigestSha256: "sha256:" + detector.ociImage.sha256, configDigestSha256: "sha256:" + hash("mechanics config") },
      adapter: detector.adapter, observationConfigurationSha256: detector.observationConfigurationSha256, executionProfileSha256: detector.executionProfileSha256,
      supportedPlatform: detector.supportedPlatforms[0], sbom: { ...detector.sbom, state: "digest-bound-unverified" }, provenance: { ...detector.provenance, state: "digest-bound-unverified" },
      scannerManifestEntrySha256: manifestEntry.scannerManifestEntrySha256, sourceSealV1,
      platform: observationKey.platform, observation: { keySha256: observationKeySha256, setSha256: observationSetSha256, facts, coverage }, broker,
    },
  },
  platform: { os: "linux", architecture: "amd64" }, coverage: { kind: "selected-closure", sha256: seal.selectedClosureSha256, complete: true },
  annexes: annexArtifacts.map(({ descriptorId, bytes }) => ({ descriptorId, sha256: hash(bytes), byteLength: bytes.byteLength })),
  cleanup: { outcome: "completed" }, scan: { outcome: "succeeded" },
});
scan.writeScanCaptureBundleV2({ outputDirectory: "bundle", candidate, annexArtifacts });
const keyPair = generateKeyPairSync("ed25519");
const keyId = "ed25519:" + hash(keyPair.publicKey.export({ format: "der", type: "spki" }));
const signer = { identity: "test-mechanics.organization", class: "organization", keyId };
const claims = {
  repository: "test-mechanics/aih-scan", workflow: ".github/workflows/mechanics.yml", issuer: "https://test.invalid/mechanics",
  sourceRef: "refs/heads/mechanics", commit: "e53fe219002515c092ebb68c5b91c91a2fc6110d", environment: "test-mechanics", runId: "1", runAttempt: 1,
  signedAt: "2026-08-24T00:00:00.000Z", expiresAt: "2026-08-24T01:00:00.000Z",
};
const expected = { ...claims, now: "2026-08-24T00:30:00.000Z", subjectSha256: candidate.subject.digest.sha256, signer };
writeFileSync("signer.json", canonical(signer), { mode: 0o600 });
writeFileSync("claims.json", canonical(claims), { mode: 0o600 });
writeFileSync("roots.json", canonical({ roots: [{ ...signer, publicKeySpkiBase64: Buffer.from(keyPair.publicKey.export({ format: "der", type: "spki" })).toString("base64") }] }), { mode: 0o600 });
writeFileSync("expected.json", canonical(expected), { mode: 0o600 });
writeFileSync("signer.pem", keyPair.privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
chmodSync("signer.pem", 0o600);
writeFileSync("mechanics.json", canonical({ subjectDigest: "sha256:" + hash("Core mechanics subject"), signerClass: signer.class, label: "non-public-test-mechanics-only" }), { mode: 0o600 });
`,
    { mode: 0o600 },
  );
}
function validateExactSchema(value, schema, path = "$") {
  if (schema === null || typeof schema !== "object" || Array.isArray(schema)) fail(`schema node at ${path}`);
  if (Object.hasOwn(schema, "const") && canonical(value) !== canonical(schema.const)) fail(`schema const at ${path}`);
  switch (schema.type) {
    case "object": {
      if (value === null || typeof value !== "object" || Array.isArray(value)) fail(`schema object at ${path}`);
      const properties = schema.properties;
      if (properties === null || typeof properties !== "object" || Array.isArray(properties)) fail(`schema properties at ${path}`);
      if (!Array.isArray(schema.required) || schema.additionalProperties !== false) fail(`schema object boundary at ${path}`);
      for (const key of schema.required)
        if (typeof key !== "string" || !Object.hasOwn(value, key)) fail(`schema required property at ${path}`);
      for (const key of Object.keys(value)) {
        if (!Object.hasOwn(properties, key)) fail(`schema unknown property at ${path}`);
        validateExactSchema(value[key], properties[key], `${path}.${key}`);
      }
      return;
    }
    case "array": {
      if (!Array.isArray(value)) fail(`schema array at ${path}`);
      if (typeof schema.minItems !== "number" || typeof schema.maxItems !== "number" || schema.minItems > value.length || value.length > schema.maxItems)
        fail(`schema array bounds at ${path}`);
      for (const [index, item] of value.entries()) validateExactSchema(item, schema.items, `${path}[${index}]`);
      return;
    }
    case "string": {
      if (typeof value !== "string") fail(`schema string at ${path}`);
      const length = Array.from(value).length;
      if ((typeof schema.minLength === "number" && length < schema.minLength) || (typeof schema.maxLength === "number" && length > schema.maxLength))
        fail(`schema string bounds at ${path}`);
      if (typeof schema.pattern === "string" && !new RegExp(schema.pattern, "u").test(value)) fail(`schema string pattern at ${path}`);
      return;
    }
    case "number":
      if (typeof value !== "number" || !Number.isFinite(value)) fail(`schema number at ${path}`);
      return;
    default:
      fail(`unsupported exact Core schema type at ${path}`);
  }
}
function exactSchemaCompatible(bytes, schemaBytes) {
  const schema = JSON.parse(schemaBytes.toString("utf8"));
  const value = JSON.parse(bytes.toString("utf8"));
  if (schema?.$schema !== "https://json-schema.org/draft/2020-12/schema") fail("unexpected packed Core schema");
  validateExactSchema(value, schema);
  if (
    canonical(value) !== bytes.toString("utf8") ||
    value.evidence.artifactDigests.some((digest, index) => index > 0 && value.evidence.artifactDigests[index - 1] >= digest)
  )
    fail("canonical Core schema-compatible envelope");
  return `sha256:${sha256(Buffer.from(`aih-organization-evidence/v1\0${bytes.toString("utf8")}`, "utf8"))}`;
}

const coreRoot = exactCleanCoreRoot();
const temporaryRoot = mkdtempSync(join(tmpdir(), "aih-cold-core-evidence-"));
try {
  const packs = join(temporaryRoot, "packs");
  const consumer = join(temporaryRoot, "consumer");
  const target = join(temporaryRoot, "target");
  mkdirSync(packs, { recursive: true, mode: 0o700 });
  mkdirSync(consumer, { recursive: true, mode: 0o700 });
  mkdirSync(target, { recursive: true, mode: 0o700 });
  runNpm(["run", "build"], coreRoot);
  exactCleanCoreRoot();
  const coreTarball = packedTarball(coreRoot, packs);
  const scannerTarball = packedTarball(scannerRoot, packs);
  writeFileSync(join(consumer, "package.json"), '{"private":true}', { mode: 0o600 });
  runNpm(["install", "--ignore-scripts", "--no-audit", "--no-fund", coreTarball, scannerTarball], consumer);
  writeMechanicsSetup(join(consumer, "setup.mjs"));
  const setup = runNode("setup.mjs", [], consumer);
  if (setup.status !== 0) fail("packed Scanner mechanics setup");
  const scannerCli = join(consumer, "node_modules", "@aihq", "scan", "dist", "cli.js");
  for (const args of [
    ["sign", "--bundle", "bundle", "--signer", "signer.json", "--private-key", "signer.pem", "--claims", "claims.json", "--output", "evidence.json"],
    ["project-core-evidence", "--evidence", "evidence.json", "--bundle", "bundle", "--roots", "roots.json", "--expected", "expected.json", "--subject-digest", JSON.parse(readFileSync(join(consumer, "mechanics.json"), "utf8")).subjectDigest, "--output", "core-evidence.json"],
  ]) {
    const result = runNode(scannerCli, args, consumer);
    if (result.status !== 0) fail("packed Scanner CLI mechanics");
  }
  const evidenceBytes = readFileSync(join(consumer, "core-evidence.json"));
  const consumerRequire = createRequire(join(consumer, "package.json"));
  const schemaBytes = readFileSync(consumerRequire.resolve(`@aihq/harness/${CORE_SCHEMA_PATH}`));
  if (sha256(schemaBytes) !== CORE_SCHEMA_SHA256) fail("packed Core schema digest");
  const evidenceDigest = exactSchemaCompatible(evidenceBytes, schemaBytes);
  writeFileSync(join(target, "evidence.json"), evidenceBytes, { mode: 0o600 });
  const coreCli = join(consumer, "node_modules", "@aihq", "harness", "dist", "cli.js");
  const resolver = runNode(
    coreCli,
    [
      "policy", "resolve", target, "--json", "--decision", "decision-test-mechanics",
      "--decision-digest", `sha256:${"0".repeat(64)}`, "--target", "claude", "--effect", "configure", "--evidence", "evidence.json",
    ],
    consumer,
    { ...process.env, AIH_POLICY_AUTHORITY_REPOSITORY: undefined, AIH_POLICY_AUTHORITY_WORKFLOW: undefined },
  );
  if (resolver.status !== 1) fail("packed Core resolver must refuse without authority");
  let output;
  try {
    output = JSON.parse(resolver.stdout);
  } catch {
    fail("packed Core resolver JSON");
  }
  const result = output?.digests?.[0]?.data;
  if (result?.reason !== "authority-unverified" || result?.outcome !== "refused")
    fail("packed Core resolver authority refusal");
  process.stdout.write(`${JSON.stringify({
    status: "PASS",
    coreCommit: CORE_COMMIT,
    evidenceDigest,
    schemaCompatible: true,
    resolver: { outcome: "refused", reason: "authority-unverified" },
    limitation: "Core e53 has no exported organization-evidence parser; without genuine V3 authority the resolver does not reach qualification parsing. This proves schema compatibility and fail-closed refusal only.",
    mechanics: "The generated key and organization-class signer are non-public test mechanics only; they are not organization authority, qualification, or a production effect.",
  })}\n`);
} finally {
  if (basename(temporaryRoot).startsWith("aih-cold-core-evidence-"))
    rmSync(temporaryRoot, { recursive: true, force: true, maxRetries: 1 });
}
