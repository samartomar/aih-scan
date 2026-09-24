import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  canonicalBaselineVetAttestationEnvelopeV1Bytes,
  signBaselineVetBundleV1,
  verifyBaselineVetAttestationV1,
} from "../../src/baseline/attestation-v1.js";
import {
  type BaselineAnalyzerExecutionV1,
  createBaselineVetRequestV1,
  executeBaselineVetBatchV1,
} from "../../src/baseline/batch-v1.js";
import {
  baselineVetPublicationResultV1,
  canonicalBaselineVetDiscoveryV1Bytes,
  canonicalBaselineVetPublicationV1Bytes,
  createBaselineVetDiscoveryV1,
  createBaselineVetPublicationV1,
} from "../../src/baseline/publication-v1.js";
import { canonicalStrictJsonBytesV1 } from "../../src/contract/strict-json-v1.js";
import { ed25519KeyIdV2 } from "../../src/observation/scan-attestation-v2.js";
import { hashComponentTreeV1, hashSourceTreeV1 } from "../../src/observation/source-hash-v1.js";
import {
  type ConsumerHandoffGhRunner,
  emitConsumerHandoffV1,
  parseArguments,
} from "../../tools/emit-consumer-handoff.mjs";

// The consumer contract lives in Catalog's tools/generate-source-assessment-rows.mjs.
// These are its exact closed key sets; the producer must emit nothing more or less.
const HANDOFF_KEYS = [
  "analyzerGaps",
  "analyzers",
  "api",
  "attestation",
  "authority",
  "components",
  "coverageNotifications",
  "discoverySha256",
  "envelope",
  "findings",
  "inspectionSha256",
  "localInspection",
  "mapping",
  "outcome",
  "protocol",
  "publicationSha256",
  "publisherCommit",
  "rawReports",
  "receiptSha256",
  "release",
  "requestSha256",
  "riskDecision",
  "source",
  "sourceArchive",
  "workflow",
];
const HANDOFF_COMPONENT_KEYS = [
  "catalogAssetId",
  "content",
  "findings",
  "globalCoverage",
  "locationBoundCoverage",
  "observationArtifact",
  "paths",
  "requestedAnalyzers",
  "scannerComponentId",
  "treeSha256",
];
const MAPPING_KEYS = [
  "components",
  "contentClass",
  "exclusions",
  "requestSha256",
  "runtimeCapabilityClaim",
  "sourceId",
  "sourceTreeSha256",
];
const MAPPING_COMPONENT_KEYS = [
  "analyzers",
  "catalogAssetId",
  "paths",
  "scannerComponentId",
  "treeSha256",
];
const COMPONENT_ARTIFACT_KEYS = [
  "analyzerExecution",
  "authority",
  "catalogAssetId",
  "content",
  "coverageComplete",
  "coverageDisposition",
  "coverageGaps",
  "findingSummary",
  "findings",
  "globalCoverageNotifications",
  "globalCoverageSummary",
  "locationBoundCoverageNotifications",
  "locationBoundCoverageSummary",
  "outcome",
  "paths",
  "protocol",
  "publicationSha256",
  "publisherCommit",
  "receiptSha256",
  "requestSha256",
  "requestedAnalyzers",
  "riskDecision",
  "scannerComponentId",
  "source",
  "treeSha256",
];

const tool = resolve("tools/emit-consumer-handoff.mjs");
const repository = "samartomar/aih-scan";
const publisherCommit = "e".repeat(40);
const workflowPath = ".github/workflows/baseline-publication.yml";
const runId = 34871782344;
const signedAt = "2026-09-14T17:03:45.000Z";
const expiresAt = "2026-09-14T17:48:45.000Z";
const analyzers = ["aih-native", "skillspector", "semgrep", "cisco"] as const;

const sha256 = (bytes: string | Buffer) => createHash("sha256").update(bytes).digest("hex");
const keys = (value: unknown) => Object.keys(value as object).sort();
const sorted = (values: readonly string[]) => [...values].sort();
type Json = Record<string, unknown>;
const readJson = (path: string) => JSON.parse(readFileSync(path, "utf8")) as Json;
const writeJson = (path: string, value: unknown) =>
  writeFileSync(path, `${JSON.stringify(value)}\n`, "utf8");

const temporaryDirectories: string[] = [];
afterEach(() => {
  for (const directory of temporaryDirectories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

function sarif(analyzer: string, results: unknown[], notifications: unknown[] = []) {
  return canonicalStrictJsonBytesV1({
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: analyzer } },
        invocations: [{ executionSuccessful: true, toolExecutionNotifications: notifications }],
        results,
      },
    ],
  });
}

async function fixture({ quiet = false }: { quiet?: boolean } = {}) {
  const root = mkdtempSync(join(tmpdir(), "aih-scan-consumer-handoff-"));
  temporaryDirectories.push(root);
  const source = join(root, "source");
  mkdirSync(join(source, "skills", "demo"), { recursive: true });
  mkdirSync(join(source, "skills", "other"), { recursive: true });
  writeFileSync(join(source, "README.md"), "# Fixture\n");
  writeFileSync(join(source, "skills", "demo", "SKILL.md"), "# Demo\n\nReview this.\n");
  writeFileSync(join(source, "skills", "demo", "LICENSE.txt"), "MIT License\n");
  writeFileSync(join(source, "skills", "other", "SKILL.md"), "# Other\n");
  const sourceTreeSha256 = hashSourceTreeV1(source).treeSha256;
  const request = createBaselineVetRequestV1({
    protocol: "BaselineVetRequestV1",
    profile: "aih-baseline-v1",
    source: {
      id: "fixture-skills",
      owner: "example",
      repository: "skills",
      pinnedCommit: "a".repeat(40),
      treeSha256: sourceTreeSha256,
    },
    components: [
      {
        id: "skill:skills-demo-0123456789ab",
        content: "skill",
        paths: ["skills/demo"],
        treeSha256: hashComponentTreeV1(source, ["skills/demo"]).treeSha256,
        analyzers: [...analyzers],
      },
      {
        id: "skill:skills-other-ba9876543210",
        content: "skill",
        paths: ["skills/other"],
        treeSha256: hashComponentTreeV1(source, ["skills/other"]).treeSha256,
        analyzers: [...analyzers],
      },
    ],
  });
  const location = (uri: string, region?: Json) => ({
    physicalLocation: { artifactLocation: { uri }, ...(region ? { region } : {}) },
  });
  const execute: BaselineAnalyzerExecutionV1 = async ({ analyzer }) => {
    if (analyzer === "aih-native")
      return {
        mediaType: "application/vnd.aih.baseline-native+json",
        bytes: canonicalStrictJsonBytesV1({
          protocol: "BaselineNativeObservationV1",
          files: [],
          sourceTreeSha256,
        }),
        analyzerVersion: "native.0123456789ab",
      };
    const bytes = quiet
      ? sarif(analyzer, [])
      : analyzer === "skillspector"
        ? sarif(
            analyzer,
            [
              {
                ruleId: "AST4",
                level: "warning",
                message: { text: "subprocess module call" },
                locations: [location("skills/demo/SKILL.md", { startLine: 1, endLine: 2 })],
              },
              {
                ruleId: "E1",
                level: "error",
                message: { text: "outside every component" },
                locations: [location("README.md", { startLine: 1 })],
              },
              {
                ruleId: "AS2",
                message: { text: "absolute container path" },
                locations: [location("/scan/skills/other/SKILL.md", { startLine: 1 })],
              },
            ],
            [
              {
                level: "warning",
                message: { text: "Analyzer was disabled by the requested configuration." },
                properties: { kind: "inspection_limitation" },
              },
              {
                level: "note",
                message: { text: "Hidden file is excluded from the configured scan scope." },
                locations: [location("skills/demo/.hidden")],
                properties: { reasonCode: "hidden_file" },
              },
              {
                level: "note",
                message: { text: "Hidden file is excluded from the configured scan scope." },
                locations: [location(".github/.hidden")],
                properties: { reasonCode: "hidden_file" },
              },
            ],
          )
        : analyzer === "semgrep"
          ? sarif(analyzer, [
              {
                ruleId: "aih.work.semgrep.malicious-code",
                message: { text: "download-and-execute shell shape" },
                locations: [
                  location("/aih/source/skills/demo/SKILL.md", { startLine: 3, startColumn: 5 }),
                ],
              },
            ])
          : sarif(analyzer, []);
    return {
      mediaType: "application/sarif+json",
      bytes,
      analyzerVersion: `${analyzer}.0123456789ab`,
    };
  };
  const result = await executeBaselineVetBatchV1(request, { sourceRoot: source, execute });
  const pair = generateKeyPairSync("ed25519");
  const keyId = ed25519KeyIdV2(pair.publicKey);
  const signer = {
    identity: "github-actions:aih-scan-baseline-publication",
    class: "test-ephemeral" as const,
    keyId,
  };
  const envelope = JSON.parse(
    canonicalBaselineVetAttestationEnvelopeV1Bytes(
      signBaselineVetBundleV1({
        request,
        result,
        signer: { ...signer, privateKey: pair.privateKey },
        claims: { signedAt, expiresAt },
      }),
    ).toString("utf8"),
  );
  const publication = createBaselineVetPublicationV1({
    request,
    result,
    envelope,
    roots: [{ ...signer, publicKey: pair.publicKey }],
    expected: { now: signedAt, signer },
    seenEvidenceDigests: [],
    seenReceiptBindings: [],
  });
  const tag = `baseline-v1-${publisherCommit}-${request.requestSha256}`;
  const releaseRoot = join(root, "release");
  mkdirSync(releaseRoot);
  const files: Record<string, Buffer> = {
    "publication.json": canonicalBaselineVetPublicationV1Bytes(publication),
    "discovery.json": canonicalBaselineVetDiscoveryV1Bytes(
      createBaselineVetDiscoveryV1({
        publication,
        locator: `https://github.com/${repository}/releases/download/${tag}/publication.json`,
      }),
    ),
    "inspection.json": Buffer.from(
      `${canonicalStrictJsonBytesV1(
        verifyBaselineVetAttestationV1({
          ...baselineVetPublicationResultV1(publication),
          seenEvidenceDigests: [],
          seenReceiptBindings: [],
        }).facts,
      ).toString("utf8")}\n`,
    ),
  };
  for (const [name, bytes] of Object.entries(files)) writeFileSync(join(releaseRoot, name), bytes);
  const writeSums = () =>
    writeFileSync(
      join(releaseRoot, "SHA256SUMS"),
      ["publication.json", "discovery.json", "inspection.json"]
        .map((name) => `${sha256(readFileSync(join(releaseRoot, name)))}  ${name}\n`)
        .join(""),
    );
  writeSums();
  const releaseMetadata = () => ({
    assets: ["discovery.json", "inspection.json", "publication.json", "SHA256SUMS"].map(
      (name, index) => {
        const bytes = readFileSync(join(releaseRoot, name));
        return {
          apiUrl: `https://api.github.com/repos/${repository}/releases/assets/${index + 1}`,
          contentType: name === "SHA256SUMS" ? "application/octet-stream" : "application/json",
          createdAt: "2026-09-14T17:04:01Z",
          digest: `sha256:${sha256(bytes)}`,
          downloadCount: 1,
          id: `RA_${index}`,
          label: "",
          name,
          size: bytes.length,
          state: "uploaded",
          updatedAt: "2026-09-14T17:04:02Z",
          url: `https://github.com/${repository}/releases/download/${tag}/${name}`,
        };
      },
    ),
    isDraft: false,
    tagName: tag,
    targetCommitish: publisherCommit,
    url: `https://github.com/${repository}/releases/tag/${tag}`,
  });
  const publicationSha256 = sha256(files["publication.json"] as Buffer);
  const bundle = {
    mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
    verificationMaterial: { certificate: { rawBytes: "AA==" }, tlogEntries: [] },
    dsseEnvelope: { payload: "e30=", payloadType: "application/vnd.in-toto+json", signatures: [] },
  };
  const attestation = (subjectSha256 = publicationSha256) => [
    {
      attestation: {
        bundle: structuredClone(bundle),
        bundle_url: "https://example.invalid/bundle",
        initiator: "user",
      },
      verificationResult: {
        mediaType: "application/vnd.dev.sigstore.verificationresult+json;version=0.1",
        signature: {
          certificate: {
            certificateIssuer: "CN=sigstore-intermediate,O=sigstore.dev",
            subjectAlternativeName: `https://github.com/${repository}/${workflowPath}@refs/heads/main`,
            issuer: "https://token.actions.githubusercontent.com",
            githubWorkflowTrigger: "workflow_dispatch",
            githubWorkflowSHA: publisherCommit,
            githubWorkflowName: "immutable baseline publication",
            githubWorkflowRepository: repository,
            githubWorkflowRef: "refs/heads/main",
            buildSignerURI: `https://github.com/${repository}/${workflowPath}@refs/heads/main`,
            buildSignerDigest: publisherCommit,
            runnerEnvironment: "github-hosted",
            sourceRepositoryURI: `https://github.com/${repository}`,
            sourceRepositoryDigest: publisherCommit,
            sourceRepositoryRef: "refs/heads/main",
            sourceRepositoryIdentifier: "1336836161",
            sourceRepositoryOwnerURI: "https://github.com/samartomar",
            sourceRepositoryOwnerIdentifier: "9993940",
            buildConfigURI: `https://github.com/${repository}/${workflowPath}@refs/heads/main`,
            buildConfigDigest: publisherCommit,
            buildTrigger: "workflow_dispatch",
            runInvocationURI: `https://github.com/${repository}/actions/runs/${runId}/attempts/1`,
            sourceRepositoryVisibilityAtSigning: "public",
          },
        },
        verifiedTimestamps: [
          {
            type: "Tlog",
            uri: "https://rekor.sigstore.dev",
            timestamp: "2026-09-14T12:03:59-05:00",
          },
        ],
        verifiedIdentity: {
          subjectAlternativeName: {
            subjectAlternativeName: `https://github.com/${repository}/${workflowPath}@refs/heads/main`,
          },
          issuer: { issuer: "", regexp: ".*" },
          runnerEnvironment: "github-hosted",
        },
        statement: {
          _type: "https://in-toto.io/Statement/v1",
          subject: [{ name: "publication.json", digest: { sha256: subjectSha256 } }],
          predicateType: "https://slsa.dev/provenance/v1",
          predicate: {},
        },
      },
    },
  ];
  const run = {
    attempt: 1,
    conclusion: "success",
    databaseId: runId,
    event: "workflow_dispatch",
    headBranch: "main",
    headSha: publisherCommit,
    status: "completed",
    url: `https://github.com/${repository}/actions/runs/${runId}`,
    workflowName: "immutable baseline publication",
  };
  const mapping = {
    protocol: "ScannerConsumerMappingV1",
    requestSha256: request.requestSha256,
    contentClass: "exact direct plugin skill/source files for assessment only",
    components: [
      {
        scannerComponentId: "skill:skills-demo-0123456789ab",
        catalogAssetId: "fixture-skills/skill:demo",
      },
    ],
    exclusions: [
      {
        scannerComponentId: "skill:skills-other-ba9876543210",
        reason: "Reviewed outside this Catalog provider.",
      },
    ],
  };
  const inputs = join(root, "inputs");
  mkdirSync(inputs);
  const paths = {
    release: join(inputs, "release.json"),
    attestationBundle: join(inputs, "attestation.jsonl"),
    run: join(inputs, "run.json"),
    mapping: join(inputs, "mapping.json"),
  };
  writeJson(paths.release, releaseMetadata());
  writeFileSync(paths.attestationBundle, `${JSON.stringify(bundle)}\n`);
  // What the fake gh prints (and its exit status); each test may replace it.
  const verifier: {
    status: number;
    output: unknown;
    calls: { args: string[]; subject: Buffer; bundle: Buffer }[];
  } = { status: 0, output: attestation(), calls: [] };
  const runGh: ConsumerHandoffGhRunner = (argv) => {
    const args = [...argv];
    verifier.calls.push({
      args,
      subject: readFileSync(args[2] as string),
      bundle: readFileSync(args[4] as string),
    });
    return { status: verifier.status, stdout: JSON.stringify(verifier.output) };
  };
  writeJson(paths.run, run);
  writeJson(paths.mapping, mapping);
  const output = join(root, "handoff");
  const args = (overrides: Record<string, string> = {}) => {
    const values: Record<string, string> = {
      "release-root": releaseRoot,
      release: paths.release,
      "attestation-bundle": paths.attestationBundle,
      run: paths.run,
      mapping: paths.mapping,
      repository,
      "publisher-commit": publisherCommit,
      output,
      ...overrides,
    };
    return Object.entries(values).flatMap(([key, value]) => [`--${key}`, value]);
  };
  // In process, with gh replaced by the fake verifier above.
  const emit = (argv: string[] = args()) => {
    try {
      const result = emitConsumerHandoffV1(parseArguments(argv), { runGh });
      return { status: 0, stdout: `${JSON.stringify(result)}\n`, stderr: "" };
    } catch (error) {
      return {
        status: 1,
        stdout: "",
        stderr: error instanceof Error ? error.message : String(error),
      };
    }
  };
  // The real CLI, for argument handling and the gh-unavailable path.
  const spawnTool = (argv: string[] = args(), env: NodeJS.ProcessEnv = process.env) =>
    spawnSync(process.execPath, [tool, ...argv], { cwd: root, encoding: "utf8", env });
  return {
    root,
    source,
    request,
    releaseRoot,
    output,
    paths,
    tag,
    publicationSha256,
    run,
    mapping,
    attestation,
    bundle,
    verifier,
    releaseMetadata,
    writeSums,
    args,
    emit,
    spawnTool,
  };
}

type Fixture = Awaited<ReturnType<typeof fixture>>;

function expectRejected(current: Fixture, result: ReturnType<Fixture["emit"]>, reason: RegExp) {
  expect(result.status, result.stdout).toBe(1);
  expect(result.stderr).toMatch(reason);
  expect(existsSync(current.output)).toBe(false);
}

describe("emit-consumer-handoff", () => {
  it("projects a verified publication into the closed ScannerPublicationConsumerHandoffV1 shape", async () => {
    const current = await fixture();
    const result = current.emit();
    expect(result.status, result.stderr).toBe(0);
    expect(sorted(readdirSync(current.output))).toEqual([
      "components",
      "consumer-handoff.json",
      "publication.json",
    ]);
    expect(readFileSync(join(current.output, "publication.json"))).toEqual(
      readFileSync(join(current.releaseRoot, "publication.json")),
    );
    const handoff = readJson(join(current.output, "consumer-handoff.json"));
    expect(keys(handoff)).toEqual(sorted(HANDOFF_KEYS));
    expect(handoff).toMatchObject({
      protocol: "ScannerPublicationConsumerHandoffV1",
      authority: "none",
      outcome: "observed_with_gaps",
      riskDecision: "consumer_required",
      publisherCommit,
      publicationSha256: current.publicationSha256,
      requestSha256: current.request.requestSha256,
      source: current.request.source,
      discoverySha256: sha256(readFileSync(join(current.releaseRoot, "discovery.json"))),
      inspectionSha256: sha256(readFileSync(join(current.releaseRoot, "inspection.json"))),
      release: {
        tag: current.tag,
        url: `https://github.com/${repository}/releases/tag/${current.tag}`,
        targetCommitish: publisherCommit,
      },
      workflow: { status: "completed", conclusion: "success", headSha: publisherCommit, runId },
      attestation: {
        subject: { name: "publication.json", digest: { sha256: current.publicationSha256 } },
        sourceRepositoryDigest: publisherCommit,
        sourceRepositoryRef: "refs/heads/main",
        runnerEnvironment: "github-hosted",
        verifiedTimestampCount: 1,
      },
      envelope: {
        authority: "none",
        envelopeValid: true,
        annexesComplete: true,
        sameRunArtifactAndReleaseBytesMatch: true,
        cliInspectionMatchesReleasedInspection: true,
      },
      analyzerGaps: {
        missingAnalyzers: [],
        failedAnalyzers: [],
        errorNotificationCount: 0,
        completionEvidenceAbsent: ["cisco", "semgrep", "skillspector"],
        coverageComplete: false,
      },
      api: { package: "@aihq/scan" },
    });
    const receipt = readJson(join(current.releaseRoot, "publication.json")).receipt as Json;
    expect(handoff.receiptSha256).toBe(receipt.receiptSha256);

    const mapping = handoff.mapping as Json;
    expect(keys(mapping)).toEqual(sorted(MAPPING_KEYS));
    expect(mapping).toMatchObject({
      sourceId: "fixture-skills",
      requestSha256: current.request.requestSha256,
      sourceTreeSha256: current.request.source.treeSha256,
      contentClass: current.mapping.contentClass,
      runtimeCapabilityClaim: [],
      exclusions: current.mapping.exclusions,
    });
    const mappedComponents = mapping.components as Json[];
    expect(mappedComponents).toHaveLength(1);
    expect(keys(mappedComponents[0])).toEqual(sorted(MAPPING_COMPONENT_KEYS));
    expect(mappedComponents[0]).toEqual({
      scannerComponentId: "skill:skills-demo-0123456789ab",
      catalogAssetId: "fixture-skills/skill:demo",
      paths: ["skills/demo"],
      treeSha256: current.request.components[0]?.treeSha256,
      analyzers: [...analyzers],
    });

    const components = handoff.components as Json[];
    expect(components).toHaveLength(1);
    const summary = components[0] as Json;
    expect(keys(summary)).toEqual(sorted(HANDOFF_COMPONENT_KEYS));
    const pointer = summary.observationArtifact as {
      path: string;
      byteLength: number;
      sha256: string;
    };
    expect(pointer.path).toBe("components/skill-skills-demo-0123456789ab.json");
    const artifactBytes = readFileSync(join(current.output, pointer.path));
    expect(pointer.byteLength).toBe(artifactBytes.length);
    expect(pointer.sha256).toBe(sha256(artifactBytes));
    const artifact = JSON.parse(artifactBytes.toString("utf8")) as Json;
    expect(keys(artifact)).toEqual(sorted(COMPONENT_ARTIFACT_KEYS));
    expect(artifact).toMatchObject({
      protocol: "ScannerComponentObservationHandoffV1",
      authority: "none",
      outcome: "observed",
      riskDecision: "consumer_required",
      publisherCommit,
      publicationSha256: current.publicationSha256,
      scannerComponentId: "skill:skills-demo-0123456789ab",
      catalogAssetId: "fixture-skills/skill:demo",
      content: "skill",
      paths: ["skills/demo"],
      requestedAnalyzers: [...analyzers],
      coverageComplete: false,
      coverageGaps: [
        { analyzer: "skillspector", reason: "completion-evidence-absent" },
        { analyzer: "semgrep", reason: "completion-evidence-absent" },
        { analyzer: "cisco", reason: "completion-evidence-absent" },
      ],
      source: current.request.source,
    });
    // Findings keep the exact row shape the committed Catalog digests were taken over,
    // with analyzer-root absolute paths related to the source root by Scan's own rules.
    expect(artifact.findings).toEqual([
      {
        analyzer: "skillspector",
        runIndex: 0,
        ruleId: "AST4",
        level: "warning",
        kind: null,
        message: "subprocess module call",
        locations: [{ path: "skills/demo/SKILL.md", startLine: 1, startColumn: null }],
        componentIds: ["skill:skills-demo-0123456789ab"],
        unmapped: false,
      },
      {
        analyzer: "semgrep",
        runIndex: 0,
        ruleId: "aih.work.semgrep.malicious-code",
        level: null,
        kind: null,
        message: "download-and-execute shell shape",
        locations: [{ path: "skills/demo/SKILL.md", startLine: 3, startColumn: 5 }],
        componentIds: ["skill:skills-demo-0123456789ab"],
        unmapped: false,
      },
    ]);
    expect(artifact.globalCoverageNotifications).toEqual([
      {
        analyzer: "skillspector",
        runIndex: 0,
        kind: "toolExecutionNotifications",
        level: "warning",
        message: "Analyzer was disabled by the requested configuration.",
        descriptor: null,
        properties: { kind: "inspection_limitation" },
        locations: [],
        componentIds: [],
        unmapped: true,
      },
    ]);
    expect(artifact.locationBoundCoverageNotifications).toEqual([
      {
        analyzer: "skillspector",
        runIndex: 0,
        kind: "toolExecutionNotifications",
        level: "note",
        message: "Hidden file is excluded from the configured scan scope.",
        descriptor: null,
        properties: { reasonCode: "hidden_file" },
        locations: [{ path: "skills/demo/.hidden", startLine: null, startColumn: null }],
        componentIds: ["skill:skills-demo-0123456789ab"],
        unmapped: false,
      },
    ]);
    expect(artifact.findingSummary).toEqual({
      count: 2,
      byAnalyzer: { semgrep: 1, skillspector: 1 },
      byLevel: { null: 1, warning: 1 },
      byRule: { AST4: 1, "aih.work.semgrep.malicious-code": 1 },
    });
    expect(summary.findings).toEqual(artifact.findingSummary);
    expect(summary.locationBoundCoverage).toEqual(artifact.locationBoundCoverageSummary);
    expect(summary.globalCoverage).toEqual(artifact.globalCoverageSummary);
    expect(artifact.globalCoverageSummary).toEqual({
      count: 1,
      byAnalyzer: { skillspector: 1 },
      byLevel: { warning: 1 },
      byMessage: { "Analyzer was disabled by the requested configuration.": 1 },
      byReasonCode: { null: 1 },
    });
    const executions = artifact.analyzerExecution as Json[];
    expect(executions.map((row) => [row.analyzer, row.executionSuccessful])).toEqual(
      analyzers.map((analyzer) => [analyzer, true]),
    );
    expect((handoff.findings as Json).mappedToDeclaredClosures).toMatchObject({ count: 2 });
    expect((handoff.findings as Json).unmapped).toMatchObject({ count: 1 });
    expect((handoff.rawReports as Json[]).map((row) => row.analyzer)).toEqual([...analyzers]);
  });

  it("never infers coverage from silence: a quiet publication is a typed coverage gap", async () => {
    const current = await fixture({ quiet: true });
    const result = current.emit();
    expect(result.status, result.stderr).toBe(0);
    const handoff = readJson(join(current.output, "consumer-handoff.json"));
    // No notification, no unmapped finding, every analyzer successful, and still no proof
    // that the SARIF analyzers analyzed the subject: the gap is recorded, never cleared.
    expect(handoff.analyzerGaps).toEqual({
      missingAnalyzers: [],
      failedAnalyzers: [],
      errorNotificationCount: 0,
      coverageWarningCount: 0,
      completionEvidenceAbsent: ["cisco", "semgrep", "skillspector"],
      coverageComplete: false,
    });
    expect(handoff.outcome).toBe("observed_with_gaps");
    expect((handoff.coverageNotifications as Json).global).toMatchObject({ count: 0 });
    const artifact = readJson(
      join(current.output, "components", "skill-skills-demo-0123456789ab.json"),
    );
    expect(artifact).toMatchObject({
      outcome: "observed",
      coverageComplete: false,
      coverageGaps: [
        { analyzer: "skillspector", reason: "completion-evidence-absent" },
        { analyzer: "semgrep", reason: "completion-evidence-absent" },
        { analyzer: "cisco", reason: "completion-evidence-absent" },
      ],
      globalCoverageNotifications: [],
      locationBoundCoverageNotifications: [],
    });
    expect(artifact.coverageDisposition).toBe(
      "0 location-bound and 0 global Scanner coverage notifications remain unresolved, and 3 requested analyzers (skillspector, semgrep, cisco) carry no subject-bound completion evidence; Scanner authority none.",
    );
  });

  it("rejects a tampered publication whose checksum no longer matches", async () => {
    const current = await fixture();
    const path = join(current.releaseRoot, "publication.json");
    writeFileSync(path, Buffer.concat([readFileSync(path), Buffer.from(" ")]));
    expectRejected(current, current.emit(), /SHA256SUMS publication\.json/);
  });

  it("rejects re-summed tampered bytes the release and attestation never covered", async () => {
    const current = await fixture();
    const path = join(current.releaseRoot, "publication.json");
    writeFileSync(path, `${readFileSync(path, "utf8")} `);
    current.writeSums();
    expectRejected(current, current.emit(), /release asset publication\.json|publication digest/);
  });

  it("rejects a released inspection that the Scanner does not reproduce", async () => {
    const current = await fixture();
    const path = join(current.releaseRoot, "inspection.json");
    const inspection = readJson(path);
    writeFileSync(path, `${JSON.stringify({ ...inspection, provenance: "claimed" })}\n`);
    current.writeSums();
    writeJson(current.paths.release, current.releaseMetadata());
    expectRejected(current, current.emit(), /inspection/);
  });

  const attestationCases: [string, (certificate: Json, result: Json) => void, RegExp][] = [
    [
      "another publication digest",
      (_certificate, result) => {
        ((result.statement as Json).subject as Json[])[0] = {
          name: "publication.json",
          digest: { sha256: "0".repeat(64) },
        };
      },
      /attestation subject/,
    ],
    [
      "another signer workflow",
      (certificate) => {
        certificate.buildSignerURI = `https://github.com/${repository}/.github/workflows/other.yml@refs/heads/main`;
      },
      /attestation buildSignerURI/,
    ],
    [
      "another source ref",
      (certificate) => {
        certificate.sourceRepositoryRef = "refs/heads/feature";
      },
      /attestation sourceRepositoryRef/,
    ],
    [
      "another publisher commit",
      (certificate) => {
        certificate.sourceRepositoryDigest = "f".repeat(40);
      },
      /attestation sourceRepositoryDigest/,
    ],
    [
      "a self-hosted runner",
      (certificate) => {
        certificate.runnerEnvironment = "self-hosted";
      },
      /attestation runnerEnvironment/,
    ],
    [
      "a timestamp outside the signed observation window",
      (_certificate, result) => {
        result.verifiedTimestamps = [
          { type: "Tlog", uri: "https://rekor.sigstore.dev", timestamp: "2026-09-14T18:30:00Z" },
        ];
      },
      /attestation timestamp/,
    ],
    [
      "no verified timestamp",
      (_certificate, result) => {
        result.verifiedTimestamps = [];
      },
      /attestation timestamps/,
    ],
    [
      "a repeated subject",
      (_certificate, result) => {
        const subject = (result.statement as Json).subject as Json[];
        subject.push({ ...subject[0] });
      },
      /attestation subject/,
    ],
    [
      "a subject that is not a publication",
      (_certificate, result) => {
        ((result.statement as Json).subject as Json[]).push({
          name: "discovery.json",
          digest: { sha256: "1".repeat(64) },
        });
      },
      /attestation subject/,
    ],
  ];

  it("accepts one run attestation that covers every batch publication of the run", async () => {
    const current = await fixture();
    const value = current.attestation();
    const statement = (value[0]?.verificationResult as unknown as Json).statement as Json;
    statement.subject = [
      { name: "publication.json", digest: { sha256: "1".repeat(64) } },
      ...(statement.subject as Json[]),
      { name: "publication.json", digest: { sha256: "2".repeat(64) } },
    ];
    current.verifier.output = value;
    const result = current.emit();
    expect(result.status, result.stderr).toBe(0);
    const attestation = readJson(join(current.output, "consumer-handoff.json")).attestation as Json;
    expect(attestation.subject).toEqual({
      name: "publication.json",
      digest: { sha256: current.publicationSha256 },
    });
    expect(attestation.subjectCount).toBe(3);
  });
  for (const [label, mutate, reason] of attestationCases)
    it(`rejects an attestation for ${label}`, async () => {
      const current = await fixture();
      const value = current.attestation();
      const result = value[0]?.verificationResult as unknown as Json;
      mutate((result.signature as Json).certificate as Json, result);
      current.verifier.output = value;
      expectRejected(current, current.emit(), reason);
    });

  it("verifies the bundle itself with gh and every constraint pinned, on the exact bytes", async () => {
    const current = await fixture();
    const result = current.emit();
    expect(result.status, result.stderr).toBe(0);
    expect(current.verifier.calls).toHaveLength(1);
    const [call] = current.verifier.calls;
    const args = call?.args ?? [];
    expect(args).toEqual([
      "attestation",
      "verify",
      args[2],
      "--bundle",
      args[4],
      "--format",
      "json",
      "--repo",
      "samartomar/aih-scan",
      "--predicate-type",
      "https://slsa.dev/provenance/v1",
      "--cert-identity",
      `https://github.com/samartomar/aih-scan/${workflowPath}@refs/heads/main`,
      "--cert-oidc-issuer",
      "https://token.actions.githubusercontent.com",
      "--source-ref",
      "refs/heads/main",
      "--source-digest",
      publisherCommit,
      "--signer-digest",
      publisherCommit,
      "--deny-self-hosted-runners",
    ]);
    expect(call?.subject).toEqual(readFileSync(join(current.releaseRoot, "publication.json")));
    expect(call?.bundle.toString("utf8")).toBe(`${JSON.stringify(current.bundle)}\n`);
    // The staging directory is private and removed afterwards.
    expect(existsSync(args[2] as string)).toBe(false);
  });

  it("rejects a fabricated verification result: gh must verify the supplied bundle", async () => {
    const current = await fixture();
    current.verifier.status = 1;
    expectRejected(current, current.emit(), /attestation verification failed/);
    // A verification-result file in place of a bundle is not accepted either.
    const fabricated = join(current.root, "fabricated.json");
    writeJson(fabricated, [{ attestation: null, verificationResult: {} }]);
    current.verifier.status = 0;
    expectRejected(
      current,
      current.emit(current.args({ "attestation-bundle": fabricated })),
      /attestation bundle/,
    );
    expectRejected(
      current,
      current.emit([
        ...current.args().slice(0, 4),
        "--attestation",
        fabricated,
        ...current.args().slice(6),
      ]),
      /arguments/,
    );
  });

  it("rejects a verifier report about another bundle", async () => {
    const current = await fixture();
    const value = current.attestation();
    ((value[0]?.attestation as unknown as Json).bundle as Json).mediaType = "other";
    current.verifier.output = value;
    expectRejected(current, current.emit(), /attestation bundle is not the verified bundle/);
    current.verifier.output = [{ ...current.attestation()[0], attestation: null }];
    expectRejected(current, current.emit(), /attestation record/);
  });

  it.each([
    [
      "a missing bundle file",
      (current: Fixture) => rmSync(current.paths.attestationBundle),
      /attestation bundle file missing/,
    ],
    [
      "two bundles in one JSON-lines file",
      (current: Fixture) =>
        writeFileSync(
          current.paths.attestationBundle,
          `${JSON.stringify(current.bundle)}\n${JSON.stringify(current.bundle)}\n`,
        ),
      /exactly one bundle/,
    ],
    [
      "another bundle media type",
      (current: Fixture) =>
        writeJson(current.paths.attestationBundle, {
          ...current.bundle,
          mediaType: "application/json",
        }),
      /attestation bundle mediaType/,
    ],
    [
      "an extra bundle field",
      (current: Fixture) =>
        writeJson(current.paths.attestationBundle, { ...current.bundle, extra: 1 }),
      /attestation bundle fields/,
    ],
  ] as const)("rejects %s before running the verifier", async (_label, mutate, reason) => {
    const current = await fixture();
    mutate(current);
    expectRejected(current, current.emit(), reason);
    expect(current.verifier.calls).toHaveLength(0);
  });

  it.each([
    [
      "verificationResult",
      (result: Json) => Object.assign(result, { extra: 1 }),
      /attestation verificationResult fields/,
    ],
    [
      "certificate",
      (result: Json) => Object.assign((result.signature as Json).certificate as Json, { extra: 1 }),
      /attestation certificate fields/,
    ],
    [
      "signature",
      (result: Json) => Object.assign(result.signature as Json, { extra: 1 }),
      /attestation signature fields/,
    ],
    [
      "statement",
      (result: Json) => Object.assign(result.statement as Json, { extra: 1 }),
      /attestation statement fields/,
    ],
    [
      "verifiedIdentity",
      (result: Json) => Object.assign(result.verifiedIdentity as Json, { extra: 1 }),
      /attestation verifiedIdentity fields/,
    ],
    [
      "media type",
      (result: Json) =>
        Object.assign(result, { mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json" }),
      /verificationResult mediaType/,
    ],
    [
      "statement type",
      (result: Json) => Object.assign(result.statement as Json, { _type: "x" }),
      /statement _type/,
    ],
    [
      "verified identity",
      (result: Json) =>
        Object.assign(result.verifiedIdentity as Json, {
          subjectAlternativeName: {
            subjectAlternativeName:
              "https://github.com/x/y/.github/workflows/z.yml@refs/heads/main",
          },
        }),
      /verifiedIdentity subjectAlternativeName/,
    ],
    [
      "build config digest",
      (result: Json) =>
        Object.assign((result.signature as Json).certificate as Json, {
          buildConfigDigest: "f".repeat(40),
        }),
      /attestation buildConfigDigest/,
    ],
  ] as const)("rejects a verifier report with an unexpected %s", async (_label, mutate, reason) => {
    const current = await fixture();
    const value = current.attestation();
    mutate(value[0]?.verificationResult as unknown as Json);
    current.verifier.output = value;
    expectRejected(current, current.emit(), reason);
  });

  it("projects only the pinned Scan publication repository", async () => {
    const current = await fixture();
    expectRejected(
      current,
      current.emit(current.args({ repository: "someone/aih-scan" })),
      /repository must be samartomar\/aih-scan/,
    );
    expect(current.verifier.calls).toHaveLength(0);
  });

  it("fails closed when gh is not available to verify the bundle", async () => {
    const current = await fixture();
    const env = Object.fromEntries(
      Object.entries(process.env).filter(([key]) => key.toLowerCase() !== "path"),
    );
    const result = current.spawnTool(current.args(), { ...env, PATH: "" });
    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/attestation verifier gh is unavailable/);
    expect(existsSync(current.output)).toBe(false);
  });

  it("rejects more than one attestation result", async () => {
    const current = await fixture();
    current.verifier.output = [...current.attestation(), ...current.attestation()];
    expectRejected(current, current.emit(), /attestation result count/);
  });

  it("rejects input text that is not exactly one JSON value", async () => {
    const current = await fixture();
    writeFileSync(current.paths.run, `${JSON.stringify(current.run)},"attempt":1`);
    expectRejected(current, current.emit(), /run metadata JSON/);
    writeFileSync(
      current.paths.run,
      JSON.stringify(current.run).replace('"attempt":1', '"attempt":1,"attempt":1'),
    );
    expectRejected(current, current.emit(), /run metadata JSON/);
  });

  it("rejects a run for another attempt or commit", async () => {
    const current = await fixture();
    writeJson(current.paths.run, { ...current.run, attempt: 2 });
    expectRejected(current, current.emit(), /run attempt/);
    writeJson(current.paths.run, { ...current.run, headSha: "f".repeat(40) });
    expectRejected(current, current.emit(), /run headSha/);
    writeJson(current.paths.run, { ...current.run, extra: true });
    expectRejected(current, current.emit(), /run fields/);
  });

  it("rejects a release tag for another publisher commit", async () => {
    const current = await fixture();
    expectRejected(
      current,
      current.emit(current.args({ "publisher-commit": "f".repeat(40) })),
      /discovery locator|release/,
    );
  });

  it("rejects a missing or an extra release file", async () => {
    const current = await fixture();
    const backup = join(current.root, "inspection.backup.json");
    cpSync(join(current.releaseRoot, "inspection.json"), backup);
    rmSync(join(current.releaseRoot, "inspection.json"));
    expectRejected(current, current.emit(), /downloaded asset count/);
    cpSync(backup, join(current.releaseRoot, "inspection.json"));
    writeFileSync(join(current.releaseRoot, "notes.txt"), "extra\n");
    expectRejected(current, current.emit(), /downloaded asset count/);
  });

  it("rejects mappings that are partial, ambiguous, or bound to another request", async () => {
    const current = await fixture();
    const write = (value: unknown) => writeJson(current.paths.mapping, value);
    write({ ...current.mapping, exclusions: [] });
    expectRejected(current, current.emit(), /mapping covers/);
    write({ ...current.mapping, requestSha256: "0".repeat(64) });
    expectRejected(current, current.emit(), /mapping requestSha256/);
    write({
      ...current.mapping,
      components: [
        {
          scannerComponentId: "skill:skills-demo-0123456789ab",
          catalogAssetId: "other/skill:demo",
        },
      ],
    });
    expectRejected(current, current.emit(), /catalogAssetId/);
    write({ ...current.mapping, contentClass: "anything" });
    expectRejected(current, current.emit(), /contentClass/);
    write({ ...current.mapping, runtimeCapabilityClaim: [] });
    expectRejected(current, current.emit(), /mapping fields/);
  });

  it("never overwrites an existing output and rejects malformed arguments", async () => {
    const current = await fixture();
    mkdirSync(current.output);
    const result = current.emit();
    expect(result.status).toBe(1);
    expect(result.stderr).toMatch(/output already exists/);
    expect(readdirSync(current.output)).toEqual([]);
    rmSync(current.output, { recursive: true });
    expectRejected(current, current.emit([...current.args(), "--extra", "x"]), /arguments/);
    const cli = current.spawnTool([...current.args(), "--extra", "x"]);
    expect(cli.status).toBe(1);
    expect(cli.stderr).toMatch(/arguments/);
    expectRejected(current, current.emit(current.args().slice(2)), /arguments/);
  });
});
