import { execFileSync, execSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { gunzipSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";
import { canonicalStrictJsonBytesV1 } from "../src/contract/strict-json-v1.js";
import {
  createObservationKeyV1,
  createObservationSetV1,
} from "../src/observation/observation-evidence-v1.js";
import { createScannerManifestV1 } from "../src/observation/scanner-manifest-v1.js";

const root = resolve(import.meta.dirname, "..");
const temporaryDirectories: string[] = [];
const sha256 = (value: string | Uint8Array) => createHash("sha256").update(value).digest("hex");
const publicV2Exports = [
  "AI_HARNESS_DECISION_V2_SCHEMA_SHA256",
  "AI_HARNESS_STRICT_V2_COMMIT",
  "assertCompleteScanAnnexArtifactsV2",
  "canonicalDssePaeV2",
  "canonicalScanAttestationEnvelopeBytesV2",
  "canonicalScanCandidateBytesV2",
  "canonicalSourceSealsV2Bytes",
  "captureCiscoOciCandidateV2",
  "createScanCandidateV2",
  "ed25519KeyIdV2",
  "isVerifiedScanAttestationV2",
  "parseScanAttestationEnvelopeV2Json",
  "parseScanCandidateV2Json",
  "readScanCaptureBundleV2",
  "sealSourceV2",
  "signScanCandidateV2",
  "verifyAiHarnessStrictV2Contract",
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

function runNpm(args: readonly string[], cwd: string): string {
  const npmCli = resolve(process.execPath, "..", "node_modules", "npm", "bin", "npm-cli.js");
  return execFileSync(process.execPath, [npmCli, ...args], {
    cwd,
    encoding: "utf8",
    stdio: "pipe",
  });
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
          commit: "e27a55dcebb635c8298aa4fd6fd871f59089bcf7",
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
          cisco: {
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

describe("published V2 package installation", () => {
  it("packs a minimal public boundary and signs then verifies a fully detached bundle", () => {
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
    expect(paths).toContain("README.md");
    expect(paths).not.toContain("src/index.ts");
    expect(
      paths.some((path) =>
        /(?:^|\/)(?:src|tests|secrets)(?:\/|$)|(?:^|\/)\.env(?:\.|$)|\.(?:key|pem)$/i.test(path),
      ),
    ).toBe(false);
    expect(paths.some((path) => /(?:^|\/)\S+\.local(?:\.|\/|$)/i.test(path))).toBe(false);
    expect(readFileSync(tarball)).not.toContain(Buffer.from(root, "utf8"));
    expect(packedManifest(tarball)).toMatchObject(npmDiscoveryMetadata);

    writeFileSync(join(directory, "package.json"), JSON.stringify({ private: true }), {
      mode: 0o600,
    });
    runNpm(["install", "--ignore-scripts", "--no-audit", "--no-fund", tarball], directory);
    writeCandidateInput(join(directory, "candidate-input.json"));
    writeFileSync(
      join(directory, "consumer.mjs"),
      [
        'import * as scan from "@aihq/scan";',
        'import { readFileSync } from "node:fs";',
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
        "process.stdout.write(JSON.stringify({",
        "  exports: Object.keys(scan).sort(),",
        "  denied,",
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
      metadata?: unknown;
    };
    expect(consumer.exports).toEqual(publicV2Exports);
    expect(consumer.metadata).toEqual(npmDiscoveryMetadata);
    expect(consumer.denied?.map(({ code }) => code)).toEqual([
      "ERR_PACKAGE_PATH_NOT_EXPORTED",
      "ERR_PACKAGE_PATH_NOT_EXPORTED",
    ]);
    expect(runInstalledBin(directory, ["--help"])).not.toMatch(/v1/i);

    const keyPair = generateKeyPairSync("ed25519");
    const keyId = `ed25519:${sha256(keyPair.publicKey.export({ format: "der", type: "spki" }))}`;
    const privateKey = join(directory, "signer.pem");
    writeFileSync(privateKey, keyPair.privateKey.export({ format: "pem", type: "pkcs8" }), {
      mode: 0o600,
    });
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
      commit: "e27a55dcebb635c8298aa4fd6fd871f59089bcf7",
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
    runInstalledBin(directory, [
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
    ]);
    const verified = JSON.parse(
      runInstalledBin(directory, [
        "verify",
        "--evidence",
        "evidence.json",
        "--bundle",
        "bundle",
        "--roots",
        "roots.json",
        "--expected",
        "expected.json",
      ]),
    ) as { envelopeValid?: unknown; signer?: { identity?: unknown } };
    expect(verified).toMatchObject({ envelopeValid: true, signer: { identity: "release.admin" } });
  }, 30_000);
});
