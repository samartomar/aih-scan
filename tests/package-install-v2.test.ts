import { execFileSync, execSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { gunzipSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";
import {
  type BaselineAnalyzerExecutionV1,
  canonicalBaselineVetRequestV1Bytes,
  createBaselineVetRequestV1,
  executeBaselineVetBatchV1,
} from "../src/baseline/batch-v1.js";
import { writeBaselineVetBundleV1 } from "../src/baseline/bundle-v1.js";
import { canonicalStrictJsonBytesV1 } from "../src/contract/strict-json-v1.js";
import {
  createObservationKeyV1,
  createObservationSetV1,
} from "../src/observation/observation-evidence-v1.js";
import { createScannerManifestV1 } from "../src/observation/scanner-manifest-v1.js";
import { hashComponentTreeV1, hashSourceTreeV1 } from "../src/observation/source-hash-v1.js";

const root = resolve(import.meta.dirname, "..");
const temporaryDirectories: string[] = [];
const sha256 = (value: string | Uint8Array) => createHash("sha256").update(value).digest("hex");
const publicV2Exports = [
  // The packed tarball must expose exactly the boundary src/index.ts declares,
  // including Workstream D detector execution: the capability record, the production
  // runner and the findings reader.
  "AI_HARNESS_CORE_CONTRACTS_ACCEPTED",
  "AI_HARNESS_DECISION_V2_SCHEMA_SHA256",
  "AI_HARNESS_DECISION_V2_SCHEMA_SHA256_ACCEPTED",
  "AI_HARNESS_ORGANIZATION_EVIDENCE_ENVELOPE_V1_SCHEMA_SHA256",
  "AI_HARNESS_STRICT_V2_COMMIT",
  "AI_HARNESS_STRICT_V2_COMMIT_ACCEPTED",
  "BASELINE_ANALYZERS_V1",
  "SCAN_RESULT_RECORD_FORMAT_V1",
  "SCAN_RESULT_RECORD_VERSION_V1",
  "SCAN_RESULT_SUBJECT_NAME_V1",
  "assertCompleteScanAnnexArtifactsV2",
  "baselineVetPublicationResultV1",
  "canonicalBaselineVetAttestationEnvelopeV1Bytes",
  "canonicalBaselineVetDiscoveryV1Bytes",
  "canonicalBaselineVetPublicationV1Bytes",
  "canonicalBaselineVetReceiptV1Bytes",
  "canonicalBaselineVetRequestV1Bytes",
  "canonicalCoreOrganizationEvidenceEnvelopeV1Bytes",
  "canonicalDetectorRegistrationV1Bytes",
  "canonicalDssePaeV2",
  "canonicalScanAttestationEnvelopeBytesV2",
  "canonicalScanCandidateBytesV2",
  "canonicalSourceSealsV2Bytes",
  "captureCiscoOciCandidateV2",
  "captureRegisteredDetectorCandidateV2",
  "coreOrganizationEvidenceEnvelopeDigestV1",
  "createBaselineVetDiscoveryV1",
  "createBaselineVetPublicationV1",
  "createBaselineVetRequestV1",
  "createDetectorRegistrationV1",
  "createScanCandidateV2",
  "ed25519KeyIdV2",
  "isVerifiedScanAttestationV2",
  "listDetectorCapabilitiesV1",
  "parseBaselineVetAttestationEnvelopeV1Json",
  "parseBaselineVetDiscoveryV1Json",
  "parseBaselineVetPublicationV1Json",
  "parseBaselineVetReceiptV1Json",
  "parseBaselineVetRequestV1Json",
  "parseDetectorRegistrationV1Json",
  "parseScanResultRecordV1",
  "parseScanAttestationEnvelopeV2Json",
  "parseScanCandidateV2Json",
  "projectVerifiedScanAttestationToCoreEvidenceEnvelopeV1",
  "readBaselineVetBundleV1",
  "readScanCaptureBundleV2",
  "readScanFindingsV1",
  "readScanResultRecordV1",
  "readScanResultSubjectBindingV1",
  "resolveBaselineVetDiscoveryV1",
  "resolveDetectorCapabilityV1",
  "resolveDetectorExecutionProfileDocumentV1",
  "runDetectorV1",
  "sealSourceV2",
  "signBaselineVetBundleV1",
  "signScanCandidateV2",
  "verifyAiHarnessCoreEvidenceContractV1",
  "verifyAiHarnessStrictV2Contract",
  "verifyBaselineVetAttestationV1",
  "verifyCoreOrganizationEvidenceEnvelopeSchemaLockV1",
  "verifyScanAttestationV2",
  "writeScanCaptureBundleV2",
].sort();
const npmDiscoveryMetadata = {
  repository: { type: "git", url: "git+https://github.com/samartomar/aih-scan.git" },
  homepage: "https://github.com/samartomar/aih-scan#readme",
  bugs: { url: "https://github.com/samartomar/aih-scan/issues" },
} as const;

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

function packagePaths(directory: string): { tarball: string; paths: readonly string[] } {
  const output = runNpm(["pack", "--json", "--pack-destination", directory], root);
  const packed: unknown = JSON.parse(output);
  if (!Array.isArray(packed) || packed.length !== 1) throw new Error("unexpected npm pack output");
  const entry = packed[0];
  if (typeof entry !== "object" || entry === null || Array.isArray(entry))
    throw new Error("unexpected npm pack entry");
  const { filename, files } = entry as { filename?: unknown; files?: unknown };
  if (typeof filename !== "string" || !Array.isArray(files))
    throw new Error("missing npm pack files");
  const paths = files.map((file) => {
    if (typeof file !== "object" || file === null || Array.isArray(file))
      throw new Error("unexpected npm pack file");
    const path = (file as { path?: unknown }).path;
    if (typeof path !== "string") throw new Error("missing npm pack path");
    return path;
  });
  return { tarball: join(directory, filename), paths };
}

function packedManifest(tarball: string): Record<string, unknown> {
  const archive = gunzipSync(readFileSync(tarball));
  for (let offset = 0; offset + 512 <= archive.byteLength; ) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const name = header.subarray(0, 100).toString("utf8").replace(/\0.*$/, "");
    const sizeText = header.subarray(124, 136).toString("ascii").replace(/\0.*$/, "").trim();
    if (!/^[0-7]+$/.test(sizeText)) throw new Error("invalid packed tar size");
    const size = Number.parseInt(sizeText, 8);
    const contentStart = offset + 512;
    const contentEnd = contentStart + size;
    if (!Number.isSafeInteger(size) || contentEnd > archive.byteLength)
      throw new Error("invalid packed tar bounds");
    if (name === "package/package.json") {
      const parsed: unknown = JSON.parse(
        archive.subarray(contentStart, contentEnd).toString("utf8"),
      );
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed))
        throw new Error("unexpected packed package manifest");
      return parsed as Record<string, unknown>;
    }
    offset = contentStart + Math.ceil(size / 512) * 512;
  }
  throw new Error("packed package manifest missing");
}

function npmCliPath(environment: { readonly npm_execpath?: string } = process.env): string {
  const fromEnvironment = environment.npm_execpath;
  if (
    typeof fromEnvironment === "string" &&
    isAbsolute(fromEnvironment) &&
    basename(fromEnvironment) === "npm-cli.js" &&
    existsSync(fromEnvironment)
  )
    return fromEnvironment;
  const nodeDirectory = dirname(process.execPath);
  for (const candidate of [
    join(nodeDirectory, "node_modules", "npm", "bin", "npm-cli.js"),
    resolve(nodeDirectory, "..", "lib", "node_modules", "npm", "bin", "npm-cli.js"),
  ])
    if (existsSync(candidate)) return candidate;
  throw new Error("npm CLI entrypoint unavailable");
}

function runNpm(args: readonly string[], cwd: string, environment = process.env): string {
  const npmCli = npmCliPath();
  return execFileSync(process.execPath, [npmCli, ...args], {
    cwd,
    encoding: "utf8",
    stdio: "pipe",
    env: environment,
  });
}

function isolatedNpmInstallEnvironment(
  userconfig: string,
  inherited: NodeJS.ProcessEnv,
): NodeJS.ProcessEnv {
  const environment = { ...inherited };
  for (const key of Object.keys(environment)) {
    if (/^npm_config_(?:allow[-_]?scripts|userconfig)$/i.test(key)) delete environment[key];
  }
  environment.npm_config_userconfig = userconfig;
  return environment;
}

function writeCandidateInput(path: string): void {
  const source = sha256("installed-package-source");
  const rawAnnex = Buffer.from("installed-package-raw-annex", "utf8");
  const sbom = Buffer.from("installed-package-sbom", "utf8");
  const provenance = Buffer.from("installed-package-provenance", "utf8");
  const sourceEntries = [
    { kind: "file" as const, path: "SKILL.md", sha256: source, byteLength: 24 },
  ];
  const sourceSeal = {
    protocol: "SourceSealV2" as const,
    algorithm: "code-unit-canonical-json-v1" as const,
    entries: sourceEntries,
    selectedClosurePaths: ["SKILL.md"],
    selectedFiles: sourceEntries,
    sourceTreeSha256: sha256(
      canonicalStrictJsonBytesV1({ protocol: "SourceTreeV2", entries: sourceEntries }),
    ),
    selectedClosureSha256: sha256(
      canonicalStrictJsonBytesV1({ protocol: "SelectedClosureV2", files: sourceEntries }),
    ),
  };
  const seal = {
    ...sourceSeal,
    sealedSnapshotSha256: sha256(
      canonicalStrictJsonBytesV1({
        protocol: "SealedSnapshotV2",
        sourceTreeSha256: sourceSeal.sourceTreeSha256,
        selectedClosureSha256: sourceSeal.selectedClosureSha256,
      }),
    ),
  };
  const sourceSealV1 = {
    protocol: "SourceSealV1" as const,
    sourceTreeSha256: sha256("installed-v1-source"),
    selectedClosureSha256: sha256("installed-v1-selected"),
    sealedSnapshotSha256: sha256("installed-v1-snapshot"),
  };
  const rawFacts = [
    { rawOccurrenceFingerprint: `raw-occurrence-v1:${sha256("installed-fact")}`, multiplicity: 1 },
  ];
  const rawCoverage = [
    {
      coverageKind: "selected-closure" as const,
      coverageSha256: sourceSealV1.selectedClosureSha256,
    },
  ];
  const observationConfigurationSha256 = sha256("installed-configuration");
  const ociManifest = sha256("installed-oci-manifest");
  const detector = {
    detectorId: "detector.cisco" as const,
    analyzerIdentity: "native.0123456789ab",
    ociImage: {
      reference: `local.invalid/aih-scan/cisco@sha256:${ociManifest}`,
      sha256: ociManifest,
    },
    adapter: { identity: "adapter.0123456789ab", sha256: sha256("installed-adapter") },
    observationConfigurationSha256,
    executionProfileSha256: sha256("installed-execution"),
    supportedPlatforms: [{ os: "linux" as const, architecture: "amd64" as const }],
    sbom: { mediaType: "application/spdx+json" as const, sha256: sha256(sbom) },
    provenance: {
      mediaType: "application/vnd.in-toto+json" as const,
      sha256: sha256(provenance),
    },
  };
  const scannerManifest = createScannerManifestV1({
    protocol: "ScannerManifestV1",
    detectors: [detector],
  });
  const scannerEntry = scannerManifest.detectors[0];
  if (scannerEntry === undefined) throw new Error("missing scanner manifest entry");
  const relevantFactsSha256 = sha256(
    canonicalStrictJsonBytesV1({
      domain: "aih.cisco.oci-candidate.relevant-facts-v1",
      sourceSeal: sourceSealV1,
    }),
  );
  const observationKeyInput = {
    protocol: "ObservationKeyV1" as const,
    sourceSeal: sourceSealV1,
    nativeAnalyzerIdentity: detector.analyzerIdentity,
    observationConfigurationSha256,
    platform: { os: "linux" as const, architecture: "amd64" as const, relevantFactsSha256 },
    scannerManifestEntrySha256: scannerEntry.scannerManifestEntrySha256,
  };
  const observationKey = createObservationKeyV1(observationKeyInput);
  const observationSet = createObservationSetV1({
    protocol: "ObservationSetV1",
    observationKey: observationKeyInput,
    facts: rawFacts,
    coverage: rawCoverage,
  });
  const broker = {
    identity: "broker.0123456789ab",
    sarifSha256: sha256("installed-sarif"),
    enforcementState: "unverified" as const,
    policyDigestSha256: sha256(
      canonicalStrictJsonBytesV1({
        domain: "aih.cisco.oci-candidate.broker-binding-v1",
        brokerIdentity: "broker.0123456789ab",
        scannerManifestEntrySha256: scannerEntry.scannerManifestEntrySha256,
        sarifSha256: sha256("installed-sarif"),
      }),
    ),
    appliedFactsSha256: sha256(
      canonicalStrictJsonBytesV1({
        domain: "aih.cisco.oci-candidate.applied-facts-v1",
        facts: rawFacts,
        coverage: rawCoverage,
      }),
    ),
  };
  const annexes = [
    { descriptorId: "annex.cisco-raw", bytes: rawAnnex },
    { descriptorId: "annex.provenance", bytes: provenance },
    { descriptorId: "annex.sbom", bytes: sbom },
  ];
  writeFileSync(
    path,
    JSON.stringify({
      candidate: {
        protocol: "ScanCandidateV2",
        coreContract: {
          commit: "6130dd837b8e8bd41e999fb40733e0e460e69720",
          decisionSchemaSha256: "27295aee8d8be333abe2c73adc72884b534b1c9980a9b7a39d12be8d34c5caff",
        },
        subject: { name: "source-tree", digest: { sha256: seal.sourceTreeSha256 } },
        sourceSeals: { before: seal, after: seal },
        observation: {
          keySha256: observationKey.observationKeySha256,
          setSha256: observationSet.observationSetSha256,
        },
        scanner: {
          manifestSha256: scannerManifest.scannerManifestSha256,
          runtimeSha256: sha256(
            canonicalStrictJsonBytesV1({
              domain: "aih.cisco.capture-v2.runtime",
              detector: scannerEntry,
            }),
          ),
          configurationSha256: observationConfigurationSha256,
          detector: {
            adapterCapability: "cisco-oci-v1",
            detectorId: detector.detectorId,
            analyzerIdentity: detector.analyzerIdentity,
            oci: {
              logicalReference: detector.ociImage.reference,
              manifestDigestSha256: `sha256:${ociManifest}`,
              configDigestSha256: `sha256:${sha256("installed-oci-config")}`,
            },
            adapter: detector.adapter,
            observationConfigurationSha256,
            executionProfileSha256: detector.executionProfileSha256,
            supportedPlatform: { os: "linux", architecture: "amd64" },
            sbom: { ...detector.sbom, state: "digest-bound-unverified" },
            provenance: { ...detector.provenance, state: "digest-bound-unverified" },
            scannerManifestEntrySha256: scannerEntry.scannerManifestEntrySha256,
            sourceSealV1,
            platform: observationKeyInput.platform,
            observation: {
              keySha256: observationKey.observationKeySha256,
              setSha256: observationSet.observationSetSha256,
              facts: rawFacts,
              coverage: rawCoverage,
            },
            broker,
          },
        },
        platform: { os: "linux", architecture: "amd64" },
        coverage: {
          kind: "selected-closure",
          sha256: seal.selectedClosureSha256,
          complete: true,
        },
        annexes: annexes.map(({ descriptorId, bytes }) => ({
          descriptorId,
          sha256: sha256(bytes),
          byteLength: bytes.byteLength,
        })),
        cleanup: { outcome: "completed" },
        scan: { outcome: "succeeded" },
      },
      annexes: annexes.map(({ descriptorId, bytes }) => ({
        descriptorId,
        base64: bytes.toString("base64"),
      })),
    }),
    { mode: 0o600 },
  );
}

function runInstalledBin(project: string, args: readonly string[]): string {
  const bin = join(
    project,
    "node_modules",
    ".bin",
    process.platform === "win32" ? "aih-scan.cmd" : "aih-scan",
  );
  if (process.platform !== "win32")
    return execFileSync(bin, args, { cwd: project, encoding: "utf8", stdio: "pipe" });
  const command = `call ${[bin, ...args]
    .map((value) => `"${value.replaceAll('"', '""')}"`)
    .join(" ")}`;
  return execSync(command, {
    cwd: project,
    encoding: "utf8",
    stdio: "pipe",
  });
}

function outputText(value: unknown): string {
  if (typeof value === "string") return value;
  if (value instanceof Uint8Array) return Buffer.from(value).toString("utf8");
  return "";
}

function rejectedInstalledBin(
  project: string,
  args: readonly string[],
): {
  status: number | undefined;
  stdout: string;
  stderr: string;
} {
  try {
    return { status: 0, stdout: runInstalledBin(project, args), stderr: "" };
  } catch (error) {
    if (typeof error !== "object" || error === null) throw error;
    const result = error as { status?: unknown; stdout?: unknown; stderr?: unknown };
    return {
      status: typeof result.status === "number" ? result.status : undefined,
      stdout: outputText(result.stdout),
      stderr: outputText(result.stderr),
    };
  }
}

function expectRejectedInstalledBin(
  project: string,
  args: readonly string[],
  secret?: string,
): string {
  const result = rejectedInstalledBin(project, args);
  expect(result.status).toBe(2);
  expect(result.stdout).toBe("");
  expect(Buffer.byteLength(result.stderr, "utf8")).toBeLessThanOrEqual(512);
  expect(result.stderr).toMatch(/^[A-Za-z0-9 :.-]+\r?\n$/);
  expect(result.stderr).not.toMatch(/envelopeValid|payloadSha256|release\.admin/i);
  if (secret !== undefined) expect(result.stderr).not.toContain(secret);
  return result.stderr;
}

describe("npm CLI resolution", () => {
  it("accepts a validated absolute npm_execpath and otherwise uses an installed npm CLI", () => {
    const directory = mkdtempSync(join(tmpdir(), "aih-scan-npm-cli-"));
    temporaryDirectories.push(directory);
    const npmCli = join(directory, "npm-cli.js");
    writeFileSync(npmCli, "", { mode: 0o600 });

    expect(npmCliPath({ npm_execpath: npmCli })).toBe(npmCli);
    expect(npmCliPath({ npm_execpath: join(directory, "not-npm-cli.js") })).not.toBe(
      join(directory, "not-npm-cli.js"),
    );
    expect(existsSync(npmCliPath())).toBe(true);
  });
});

describe("packed install npm configuration", () => {
  it("drops only inherited script and userconfig overrides while retaining connection settings", () => {
    const inherited = {
      NPM_CONFIG_ALLOW_SCRIPTS: "true",
      npm_config_userconfig: "poisoned.npmrc",
      HTTPS_PROXY: "http://proxy.invalid",
      NODE_EXTRA_CA_CERTS: "ca.pem",
      npm_config_registry: "https://registry.invalid",
    };
    const isolated = isolatedNpmInstallEnvironment("empty.npmrc", inherited);
    expect(isolated).toEqual({
      HTTPS_PROXY: inherited.HTTPS_PROXY,
      NODE_EXTRA_CA_CERTS: inherited.NODE_EXTRA_CA_CERTS,
      npm_config_registry: inherited.npm_config_registry,
      npm_config_userconfig: "empty.npmrc",
    });
    expect(inherited.NPM_CONFIG_ALLOW_SCRIPTS).toBe("true");
    expect(inherited.npm_config_userconfig).toBe("poisoned.npmrc");
  });
});

describe("published V2 package installation", () => {
  it("packs a minimal public boundary and signs then verifies a fully detached bundle", async () => {
    const directory = mkdtempSync(join(tmpdir(), "aih-scan-package-install-v2-"));
    temporaryDirectories.push(directory);
    const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
      scripts?: { prepack?: unknown };
    };
    expect(manifest.scripts?.prepack).toBe("npm run build");
    const { tarball, paths } = packagePaths(directory);

    expect(paths).toContain("dist/index.d.ts");
    expect(paths).toContain("dist/index.js");
    expect(paths).toContain("dist/cli.js");
    expect(paths).toContain("tools/baseline-analyzers/cisco-skill-scanner/uv.lock");
    expect(paths).toContain("tools/baseline-analyzers/semgrep/uv.lock");
    expect(paths).toContain("README.md");
    expect(paths).not.toContain("src/index.ts");
    expect(
      paths.some((path) =>
        /(?:^|\/)(?:src|tests|secrets)(?:\/|$)|(?:^|\/)\.env(?:\.|$)|\.(?:key|pem)$/i.test(path),
      ),
    ).toBe(false);
    expect(paths.some((path) => /(?:^|\/)\S+\.local(?:\.|\/|$)/i.test(path))).toBe(false);
    expect(readFileSync(tarball)).not.toContain(Buffer.from(root, "utf8"));
    expect(basename(tarball)).toBe("aihq-scan-0.5.0.tgz");
    expect(packedManifest(tarball)).toMatchObject({
      name: "@aihq/scan",
      version: "0.5.0",
      bin: { "aih-scan": "./dist/cli.js" },
      ...npmDiscoveryMetadata,
    });

    writeFileSync(join(directory, "package.json"), JSON.stringify({ private: true }), {
      mode: 0o600,
    });
    const poisonedUserconfig = join(directory, "poisoned.npmrc");
    writeFileSync(poisonedUserconfig, "allow-scripts=true\n");
    const emptyUserconfig = join(directory, "empty.npmrc");
    writeFileSync(emptyUserconfig, "");
    const inheritedEnvironment = {
      ...process.env,
      npm_config_userconfig: poisonedUserconfig,
      npm_config_allow_scripts: "true",
    };
    runNpm(
      [
        "install",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--userconfig",
        emptyUserconfig,
        tarball,
      ],
      directory,
      isolatedNpmInstallEnvironment(emptyUserconfig, inheritedEnvironment),
    );
    const installedReadme = readFileSync(
      join(directory, "node_modules/@aihq/scan/README.md"),
      "utf8",
    );
    expect(installedReadme).toContain("promoted `@aihq/scan` stable train");
    expect(installedReadme).toContain("Candidate versions are first published under npm `next`");
    expect(installedReadme).toContain("Source state alone never proves publication");
    expect(installedReadme).not.toContain("source candidate");
    expect(installedReadme).not.toContain("is not public until");
    expect(installedReadme).not.toContain("the public release remains");
    writeCandidateInput(join(directory, "candidate-input.json"));
    writeFileSync(
      join(directory, "consumer.mjs"),
      [
        'import * as scan from "@aihq/scan";',
        'import { createHash } from "node:crypto";',
        'import { mkdirSync, readFileSync, writeFileSync } from "node:fs";',
        'import { resolve } from "node:path";',
        'const input = JSON.parse(readFileSync("candidate-input.json", "utf8"));',
        'const manifest = JSON.parse(readFileSync("node_modules/@aihq/scan/package.json", "utf8"));',
        "const candidate = scan.createScanCandidateV2(input.candidate);",
        "scan.writeScanCaptureBundleV2({",
        '  outputDirectory: "bundle",',
        "  candidate,",
        "  annexArtifacts: input.annexes.map(({ descriptorId, base64 }) => ({",
        "    descriptorId,",
        '    bytes: Buffer.from(base64, "base64"),',
        "  })),",
        "});",
        'const denied = await Promise.all(["@aihq/scan/dist/contract/strict-json-v1.js", "@aihq/scan/private-v1"].map(async (specifier) => {',
        "  try {",
        "    await import(specifier);",
        '    return { specifier, code: "resolved" };',
        "  } catch (error) {",
        "    return { specifier, code: error?.code };",
        "  }",
        "}));",
        "const capabilities = scan.listDetectorCapabilitiesV1();",
        "const refusal = await scan.runDetectorV1({",
        '  detectorId: "detector.not-owned-by-scan",',
        '  subject: { kind: "source-tree", sourceRoot: ".", selectedClosurePaths: ["consumer.mjs"] },',
        "});",
        // The installed package itself executes the in-process analyzer on this host.
        'mkdirSync("native-subject/rules", { recursive: true });',
        'writeFileSync("native-subject/README.md", "# native subject\\n");',
        'writeFileSync("native-subject/rules/base.md", "# rule\\n");',
        "const native = await scan.runDetectorV1({",
        '  detectorId: "detector.aih-native",',
        '  subject: { kind: "source-tree", sourceRoot: resolve("native-subject"), selectedClosurePaths: ["README.md", "rules/base.md"] },',
        "});",
        // An unreadable request must resolve to a refusal from the installed code too.
        "const unreadableRequest = {};",
        'Object.defineProperty(unreadableRequest, "detectorId", { enumerable: true, get() { throw new Error("hostile getter"); } });',
        "const unreadable = await scan.runDetectorV1(unreadableRequest).then(",
        '  (value) => ({ settled: "resolved", outcome: value.outcome, reason: value.reason }),',
        '  () => ({ settled: "rejected" }),',
        ");",
        'const nativeCapability = capabilities.find((entry) => entry.detectorId === "detector.aih-native");',
        "const nativeObservation = native.evidence?.observation;",
        "const findings = scan.readScanFindingsV1({ verified: { facts: {} } });",
        "process.stdout.write(JSON.stringify({",
        "  exports: Object.keys(scan).sort(),",
        "  denied,",
        "  detectorExecution: {",
        "    detectorIds: capabilities.map((entry) => entry.detectorId),",
        "    profileDocumentIds: capabilities.map((entry) =>",
        "      scan.resolveDetectorExecutionProfileDocumentV1(entry.executionProfile.id)?.id ?? null,",
        "    ),",
        "    profileDigestsMatchDocuments: capabilities.every((entry) =>",
        "      typeof scan.resolveDetectorExecutionProfileDocumentV1(entry.executionProfile.id) ===",
        '      "object",',
        "    ),",
        "    refusal: { outcome: refusal.outcome, reason: refusal.reason },",
        "    nativeRun: {",
        "      outcome: native.outcome,",
        "      executionProfileId: native.executionProfile?.id,",
        "      profileDigestIsCapabilityProfile: native.executionProfile?.sha256 === nativeCapability?.executionProfile.sha256,",
        "      analyzerVersionIsCapabilityIdentity: nativeObservation?.analyzerVersion === nativeCapability?.analyzerIdentity,",
        '      annexDigestNamesBytes: nativeObservation?.annex.sha256 === createHash("sha256").update(nativeObservation.bytes).digest("hex"),',
        "      producerIsInstalledManifest: native.producer?.name === manifest.name && native.producer?.version === manifest.version,",
        "      producer: native.producer,",
        "      seams: native.seams,",
        "      isolation: native.executionProfile?.isolation,",
        "      network: native.executionProfile?.network,",
        "      analyzer: nativeObservation?.analyzer,",
        "      mediaType: nativeObservation?.mediaType,",
        "      annexByteLengthNamesBytes: nativeObservation?.annex.byteLength === nativeObservation?.bytes.length,",
        "      coverage: {",
        "        kind: native.coverage?.kind,",
        "        complete: native.coverage?.complete,",
        "        coveredPaths: native.coverage?.coveredPaths,",
        "        excludedPaths: native.coverage?.excludedPaths,",
        "        uncoveredPaths: native.coverage?.uncoveredPaths,",
        "      },",
        "      coverageNamesSealedSourceTree: native.coverage?.sha256 === native.sourceSeal?.before.sourceTreeSha256,",
        "      sourceUnchangedByRun: native.sourceSeal?.before.sealedSnapshotSha256 === native.sourceSeal?.after.sealedSnapshotSha256,",
        "      findingsSource: native.findings?.source,",
        "    },",
        "    unreadable,",
        "    findingsStatus: findings.status,",
        "  },",
        "  metadata: { repository: manifest.repository, homepage: manifest.homepage, bugs: manifest.bugs },",
        '}) + "\\n");',
      ].join("\n"),
      { mode: 0o600 },
    );
    const consumer = JSON.parse(
      execFileSync(process.execPath, ["consumer.mjs"], {
        cwd: directory,
        encoding: "utf8",
        stdio: "pipe",
      }),
    ) as {
      exports?: unknown;
      denied?: readonly { code?: unknown }[];
      detectorExecution?: unknown;
      metadata?: unknown;
    };
    expect(consumer.exports).toEqual(publicV2Exports);
    // The packed package must be able to run a detector, not merely name one.
    expect(consumer.detectorExecution).toEqual({
      detectorIds: [
        "detector.aih-native",
        "detector.cisco",
        "detector.semgrep",
        "detector.skillspector",
      ],
      profileDocumentIds: [
        "in-process-native-v1",
        "linux-namespace-uv-v1",
        "linux-namespace-uv-v1",
        "docker-hardened-skillspector-v1",
      ],
      profileDigestsMatchDocuments: true,
      refusal: { outcome: "refused", reason: "unknown-detector" },
      nativeRun: {
        outcome: "succeeded",
        executionProfileId: "in-process-native-v1",
        profileDigestIsCapabilityProfile: true,
        analyzerVersionIsCapabilityIdentity: true,
        annexDigestNamesBytes: true,
        producerIsInstalledManifest: true,
        producer: { name: "@aihq/scan", version: "0.5.0" },
        seams: { runner: "scan-owned-default", prerequisiteProbe: "scan-owned-default" },
        isolation: "none",
        network: "none",
        analyzer: "aih-native",
        mediaType: "application/vnd.aih.baseline-native+json",
        annexByteLengthNamesBytes: true,
        coverage: {
          kind: "source-tree",
          complete: true,
          coveredPaths: ["README.md", "rules/base.md"],
          excludedPaths: [],
          uncoveredPaths: [],
        },
        coverageNamesSealedSourceTree: true,
        sourceUnchangedByRun: true,
        findingsSource: "analyzer-output-digest-bound",
      },
      unreadable: { settled: "resolved", outcome: "refused", reason: "unknown-detector" },
      findingsStatus: "unverified",
    });
    expect(consumer.metadata).toEqual(npmDiscoveryMetadata);
    expect(consumer.denied?.map(({ code }) => code)).toEqual([
      "ERR_PACKAGE_PATH_NOT_EXPORTED",
      "ERR_PACKAGE_PATH_NOT_EXPORTED",
    ]);
    expect(runInstalledBin(directory, ["--help"])).not.toMatch(/v1/i);
    expect(runInstalledBin(directory, ["project-core-evidence", "--help"])).toContain(
      "Usage: aih-scan project-core-evidence",
    );
    expect(runInstalledBin(directory, ["baseline-vet", "--help"])).toContain(
      "Usage: aih-scan baseline-vet",
    );
    expect(runInstalledBin(directory, ["baseline-sign", "--help"])).toContain(
      "Usage: aih-scan baseline-sign",
    );
    expect(runInstalledBin(directory, ["baseline-verify", "--help"])).toContain(
      "Usage: aih-scan baseline-verify",
    );
    expect(runInstalledBin(directory, ["baseline-pack", "--help"])).toContain(
      "Usage: aih-scan baseline-pack",
    );
    expect(runInstalledBin(directory, ["baseline-inspect", "--help"])).toContain(
      "Usage: aih-scan baseline-inspect",
    );

    const keyPair = generateKeyPairSync("ed25519");
    const keyId = `ed25519:${sha256(keyPair.publicKey.export({ format: "der", type: "spki" }))}`;
    const privateKey = join(directory, "signer.pem");
    const privateKeyPem = keyPair.privateKey.export({ format: "pem", type: "pkcs8" }).toString();
    writeFileSync(privateKey, privateKeyPem, { mode: 0o600 });
    chmodSync(privateKey, 0o600);
    if (process.platform !== "win32") {
      expect(readFileSync(privateKey).byteLength).toBeGreaterThan(0);
      expect(statSync(privateKey).mode & 0o077).toBe(0);
    }
    const signer = { identity: "release.admin", class: "organization", keyId };
    const claims = {
      repository: "aihq/scan",
      workflow: ".github/workflows/package-install-v2.yml",
      issuer: "https://token.actions.githubusercontent.com",
      sourceRef: "refs/heads/main",
      commit: "1".repeat(40),
      environment: "test",
      runId: "123",
      runAttempt: 1,
      signedAt: "2026-08-22T00:00:00.000Z",
      expiresAt: "2026-08-22T01:00:00.000Z",
    };
    const roots = {
      roots: [
        {
          ...signer,
          publicKeySpkiBase64: Buffer.from(
            keyPair.publicKey.export({ format: "der", type: "spki" }),
          ).toString("base64"),
        },
      ],
    };
    const expected = {
      ...claims,
      now: "2026-08-22T00:30:00.000Z",
      subjectSha256: sha256(
        canonicalStrictJsonBytesV1({
          protocol: "SourceTreeV2",
          entries: [
            {
              kind: "file",
              path: "SKILL.md",
              sha256: sha256("installed-package-source"),
              byteLength: 24,
            },
          ],
        }),
      ),
      signer,
    };
    for (const [name, value] of Object.entries({ signer, claims, roots, expected }))
      writeFileSync(join(directory, `${name}.json`), JSON.stringify(value), { mode: 0o600 });

    const baselineRoot = join(directory, "baseline-source");
    mkdirSync(join(baselineRoot, "rules"), { recursive: true });
    writeFileSync(join(baselineRoot, "rules", "base.md"), "# Baseline\n", { mode: 0o600 });
    const baselineRequest = createBaselineVetRequestV1({
      protocol: "BaselineVetRequestV1",
      profile: "aih-baseline-v1",
      source: {
        id: "ecc",
        owner: "affaan-m",
        repository: "everything-claude-code",
        pinnedCommit: "a".repeat(40),
        treeSha256: hashSourceTreeV1(baselineRoot).treeSha256,
      },
      components: [
        {
          id: "rules-core",
          content: "general",
          paths: ["rules"],
          treeSha256: hashComponentTreeV1(baselineRoot, ["rules"]).treeSha256,
          analyzers: ["aih-native", "skillspector", "semgrep"],
        },
      ],
    });
    const baselineExecute: BaselineAnalyzerExecutionV1 = async ({ analyzer }) =>
      analyzer === "aih-native"
        ? {
            mediaType: "application/vnd.aih.baseline-native+json",
            bytes: canonicalStrictJsonBytesV1({
              protocol: "BaselineNativeObservationV1",
              files: [],
            }),
            analyzerVersion: "native.0123456789ab",
          }
        : {
            mediaType: "application/sarif+json",
            bytes: canonicalStrictJsonBytesV1({
              version: "2.1.0",
              runs: [{ tool: { driver: { name: analyzer } }, results: [] }],
            }),
            analyzerVersion: `${analyzer}.0123456789ab`,
          };
    const baselineResult = await executeBaselineVetBatchV1(baselineRequest, {
      sourceRoot: baselineRoot,
      execute: baselineExecute,
    });
    writeFileSync(
      join(directory, "baseline-request.json"),
      canonicalBaselineVetRequestV1Bytes(baselineRequest),
      { mode: 0o600 },
    );
    writeBaselineVetBundleV1({
      outputDirectory: join(directory, "baseline-bundle"),
      result: baselineResult,
    });
    const baselineClaims = {
      signedAt: "2026-08-22T00:00:00.000Z",
      expiresAt: "2026-08-22T01:00:00.000Z",
    };
    const baselineSigner = {
      ...signer,
      class: process.platform === "linux" ? "organization" : "test-ephemeral",
    };
    const baselineRoots = {
      roots: roots.roots.map((root) => ({ ...root, class: baselineSigner.class })),
    };
    const baselineExpected = {
      now: "2026-08-22T00:30:00.000Z",
      signer: baselineSigner,
    };
    writeFileSync(join(directory, "baseline-claims.json"), JSON.stringify(baselineClaims), {
      mode: 0o600,
    });
    writeFileSync(join(directory, "baseline-expected.json"), JSON.stringify(baselineExpected), {
      mode: 0o600,
    });
    writeFileSync(join(directory, "baseline-signer.json"), JSON.stringify(baselineSigner), {
      mode: 0o600,
    });
    writeFileSync(join(directory, "baseline-roots.json"), JSON.stringify(baselineRoots), {
      mode: 0o600,
    });
    runInstalledBin(directory, [
      "baseline-sign",
      "--request",
      "baseline-request.json",
      "--bundle",
      "baseline-bundle",
      "--signer",
      "baseline-signer.json",
      "--private-key",
      "signer.pem",
      "--claims",
      "baseline-claims.json",
      "--output",
      "baseline-evidence.json",
    ]);
    const baselineVerified = JSON.parse(
      runInstalledBin(directory, [
        "baseline-verify",
        "--evidence",
        "baseline-evidence.json",
        "--request",
        "baseline-request.json",
        "--bundle",
        "baseline-bundle",
        "--roots",
        "baseline-roots.json",
        "--expected",
        "baseline-expected.json",
      ]),
    ) as { envelopeValid?: unknown; authority?: unknown; evidenceDigestSha256?: unknown };
    expect(baselineVerified).toMatchObject({ envelopeValid: true, authority: "none" });
    expect(baselineVerified.evidenceDigestSha256).toMatch(/^[0-9a-f]{64}$/);
    const locator =
      "https://github.com/samartomar/aih-scan/releases/download/baseline-request/publication.json";
    const packed = JSON.parse(
      runInstalledBin(directory, [
        "baseline-pack",
        "--evidence",
        "baseline-evidence.json",
        "--request",
        "baseline-request.json",
        "--bundle",
        "baseline-bundle",
        "--roots",
        "baseline-roots.json",
        "--expected",
        "baseline-expected.json",
        "--locator",
        locator,
        "--publication",
        "baseline-publication.json",
        "--discovery",
        "baseline-discovery.json",
      ]),
    ) as { authority?: unknown; requestSha256?: unknown; publicationSha256?: unknown };
    expect(packed).toMatchObject({
      authority: "none",
      requestSha256: baselineRequest.requestSha256,
    });
    expect(packed.publicationSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(existsSync(join(directory, "baseline-publication.json"))).toBe(true);
    expect(existsSync(join(directory, "baseline-discovery.json"))).toBe(true);
    const inspected = JSON.parse(
      runInstalledBin(directory, [
        "baseline-inspect",
        "--discovery",
        "baseline-discovery.json",
        "--publication",
        "baseline-publication.json",
        "--request-sha256",
        baselineRequest.requestSha256,
      ]),
    ) as { envelopeValid?: unknown; authority?: unknown; requestSha256?: unknown };
    expect(inspected).toMatchObject({
      envelopeValid: true,
      authority: "none",
      requestSha256: baselineRequest.requestSha256,
    });
    writeFileSync(
      join(directory, "baseline-seen.json"),
      JSON.stringify({
        digests: [baselineVerified.evidenceDigestSha256],
        receipts: [
          {
            requestSha256: baselineRequest.requestSha256,
            receiptSha256: baselineResult.receipt.receiptSha256,
          },
        ],
      }),
      { mode: 0o600 },
    );
    expect(
      expectRejectedInstalledBin(directory, [
        "baseline-verify",
        "--evidence",
        "baseline-evidence.json",
        "--request",
        "baseline-request.json",
        "--bundle",
        "baseline-bundle",
        "--roots",
        "baseline-roots.json",
        "--expected",
        "baseline-expected.json",
        "--seen",
        "baseline-seen.json",
      ]),
    ).toBe("invalid BaselineVetAttestationV1: replayed evidence\n");

    writeFileSync(join(directory, "invalid-capture-request.json"), "{}", { mode: 0o600 });
    expect(expectRejectedInstalledBin(directory, ["capture"])).toBe("aih-scan: capture usage\n");
    expect(
      expectRejectedInstalledBin(directory, [
        "capture",
        "--request",
        "invalid-capture-request.json",
        "--output",
        "capture-output",
      ]),
    ).toBe("aih-scan: Cisco capture request fields\n");
    const signArgs = [
      "sign",
      "--bundle",
      "bundle",
      "--signer",
      "signer.json",
      "--private-key",
      "signer.pem",
      "--claims",
      "claims.json",
      "--output",
      "evidence.json",
    ];
    if (process.platform !== "win32") {
      chmodSync(privateKey, 0o644);
      expect(expectRejectedInstalledBin(directory, signArgs, privateKeyPem)).toBe(
        "aih-scan: private key file permissions\n",
      );
      chmodSync(privateKey, 0o600);
    }
    runInstalledBin(directory, signArgs);
    const verifyArgs = [
      "verify",
      "--evidence",
      "evidence.json",
      "--bundle",
      "bundle",
      "--roots",
      "roots.json",
      "--expected",
      "expected.json",
    ];
    const verified = JSON.parse(runInstalledBin(directory, verifyArgs)) as {
      envelopeValid?: unknown;
      signer?: { identity?: unknown };
      replayIdentity?: unknown;
    };
    expect(verified).toMatchObject({ envelopeValid: true, signer: { identity: "release.admin" } });
    expect(typeof verified.replayIdentity).toBe("string");
    const coreSubjectDigest = `sha256:${sha256("installed-core-subject")}`;
    const projectionArgs = [
      "project-core-evidence",
      "--evidence",
      "evidence.json",
      "--bundle",
      "bundle",
      "--roots",
      "roots.json",
      "--expected",
      "expected.json",
      "--subject-digest",
      coreSubjectDigest,
      "--output",
      "core-evidence.json",
    ];
    const projected = JSON.parse(runInstalledBin(directory, projectionArgs)) as {
      outcome?: unknown;
      envelopeSha256?: unknown;
      organizationEvidenceDigest?: unknown;
    };
    expect(projected).toMatchObject({ outcome: "projected" });
    expect(projected.envelopeSha256).toMatch(/^sha256:[0-9a-f]{64}$/);
    const coreEvidenceBytes = readFileSync(join(directory, "core-evidence.json"));
    expect(projected.organizationEvidenceDigest).toBe(
      `sha256:${sha256(
        Buffer.concat([Buffer.from("aih-organization-evidence/v1\0", "utf8"), coreEvidenceBytes]),
      )}`,
    );
    expect(projected.organizationEvidenceDigest).not.toBe(projected.envelopeSha256);
    const coreEvidence = JSON.parse(coreEvidenceBytes.toString("utf8")) as {
      subjectDigest?: unknown;
      evidence?: { summary?: unknown; payloadDigest?: unknown; artifactDigests?: unknown };
    };
    expect(coreEvidence.subjectDigest).toBe(coreSubjectDigest);
    expect(coreEvidence.evidence?.summary).toMatch(/scanner evidence only/i);
    expect(coreEvidence.evidence?.payloadDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(coreEvidence.evidence?.artifactDigests).toEqual(
      [...(coreEvidence.evidence?.artifactDigests as string[])].sort(),
    );
    expect(coreEvidenceBytes.toString("utf8")).toBe(JSON.stringify(coreEvidence));
    expect(expectRejectedInstalledBin(directory, projectionArgs)).toBe(
      "aih-scan: projection output already exists\n",
    );
    const safeParent = join(directory, "safe-projection-parent");
    const linkedParent = join(directory, "linked-projection-parent");
    mkdirSync(safeParent, { mode: 0o700 });
    symlinkSync(safeParent, linkedParent, process.platform === "win32" ? "junction" : "dir");
    expect(
      expectRejectedInstalledBin(directory, [
        ...projectionArgs.slice(0, -1),
        join("linked-projection-parent", "unsafe-core-evidence.json"),
      ]),
    ).toBe("aih-scan: output parent link or reparse\n");
    writeFileSync(
      join(directory, "seen.json"),
      JSON.stringify({ identities: [verified.replayIdentity] }),
      { mode: 0o600 },
    );
    expect(expectRejectedInstalledBin(directory, [...verifyArgs, "--seen", "seen.json"])).toBe(
      "invalid ScanAttestationV2: replayed evidence\n",
    );
    const tampered = JSON.parse(readFileSync(join(directory, "evidence.json"), "utf8")) as {
      signatures?: { sig?: unknown }[];
    };
    const signatureEntry = tampered.signatures?.[0];
    const signature = signatureEntry?.sig;
    if (signatureEntry === undefined || typeof signature !== "string" || signature.length === 0)
      throw new Error("missing signature");
    const first = signature[0];
    if (first === undefined) throw new Error("missing signature byte");
    signatureEntry.sig = first === "A" ? `B${signature.slice(1)}` : `A${signature.slice(1)}`;
    writeFileSync(join(directory, "tampered-evidence.json"), JSON.stringify(tampered), {
      mode: 0o600,
    });
    expect(
      expectRejectedInstalledBin(directory, [
        "verify",
        "--evidence",
        "tampered-evidence.json",
        "--bundle",
        "bundle",
        "--roots",
        "roots.json",
        "--expected",
        "expected.json",
      ]),
    ).toBe("invalid ScanAttestationV2: signature verification\n");
  }, 30_000);
});
