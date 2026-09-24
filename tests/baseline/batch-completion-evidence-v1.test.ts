import { createHash, generateKeyPairSync } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  canonicalBaselineVetAttestationEnvelopeV1Bytes,
  parseBaselineVetAttestationEnvelopeV1Json,
  signBaselineVetBundleV1,
  verifyBaselineVetAttestationV1,
} from "../../src/baseline/attestation-v1.js";
import {
  type BaselineAnalyzerExecutionV1,
  type BaselineAnalyzerV1,
  createBaselineVetRequestV1,
  executeBaselineVetBatchV1,
  verifyBaselineVetReceiptV1,
} from "../../src/baseline/batch-v1.js";
import { readBaselineVetBundleV1, writeBaselineVetBundleV1 } from "../../src/baseline/bundle-v1.js";
import { BASELINE_BATCH_EXECUTION_PROFILES_V1 } from "../../src/baseline/runtime-v1.js";
import { resolveDetectorCapabilityV1 } from "../../src/capability/detector-capability-v1.js";
import {
  canonicalStrictJsonBytesV1,
  canonicalStrictJsonSha256V1,
} from "../../src/contract/strict-json-v1.js";
import { ed25519KeyIdV2 } from "../../src/observation/scan-attestation-v2.js";
import { hashComponentTreeV1, hashSourceTreeV1 } from "../../src/observation/source-hash-v1.js";
import { batchAnalyzerVersion } from "./batch-version-support.js";

/**
 * D24 [Scan: S2j]: every baseline-vet SARIF annex carries completion evidence v1 (C2a §1.6)
 * over the analyzer snapshot, which never holds a top-level `.git`. The digests below are
 * computed by hand with node:crypto, never with Scan's own subject code.
 */

const temporaryDirectories: string[] = [];
const sha = (value: string | Uint8Array) => createHash("sha256").update(value).digest("hex");

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

const VECTOR_FILES = {
  ".git/HEAD": "ref: refs/heads/main\n",
  "SKILL.md": "---\nname: vector\ndescription: baseline completion vector\n---\n# Vector\n",
  "src/a.js": "console.log(1);\n",
} as const;
/** subject-files-v1 over F = { SKILL.md, src/a.js }: the snapshot, top-level `.git` left out. */
const VECTOR_SUBJECT_SHA256 = "6d8a18d0f8e75ac27da59b7ab2d95d40e6c7a9d514ee448212ee3d26ae9b8c3e";
const VECTOR_COUNT = 2;

/** subject-files-v1 by hand: `path NUL sha256-hex LF` over (path, bytes) in code-unit order. */
function handSubject(files: readonly (readonly [string, string])[]) {
  const ordered = [...files].sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
  const framed = ordered.map(([path, text]) => `${path}\u0000${sha(text)}\n`).join("");
  return { subjectTreeSha256: sha(Buffer.from(framed, "utf8")), analyzedFileCount: ordered.length };
}

const readLock = (project: string) =>
  sha(readFileSync(join("tools", "baseline-analyzers", project, "uv.lock")));
/** The fake versions: a uv-backed analyzer's names its batch profile's lock (S2k). */
const testVersion = (analyzer: string) => batchAnalyzerVersion(analyzer, `${analyzer}-test`);

const DEFAULT_PROFILE: Readonly<Record<BaselineAnalyzerV1, string>> = {
  "aih-native": "in-process-native-v1",
  skillspector: "docker-hardened-skillspector-v1",
  semgrep: "linux-namespace-uv-v1",
  cisco: "linux-namespace-uv-v1",
};

function vectorTree() {
  const root = mkdtempSync(join(tmpdir(), "aih-scan-s2j-"));
  temporaryDirectories.push(root);
  for (const [path, text] of Object.entries(VECTOR_FILES)) {
    mkdirSync(join(root, ...path.split("/").slice(0, -1)), { recursive: true });
    writeFileSync(join(root, ...path.split("/")), text, "utf8");
  }
  const request = createBaselineVetRequestV1({
    protocol: "BaselineVetRequestV1",
    profile: "aih-baseline-v1",
    source: {
      id: "vector",
      owner: "aihq",
      repository: "vector",
      pinnedCommit: "b".repeat(40),
      treeSha256: hashSourceTreeV1(root).treeSha256,
    },
    components: [
      {
        id: "skill-vector",
        content: "skill",
        paths: ["SKILL.md", "src"],
        treeSha256: hashComponentTreeV1(root, ["SKILL.md", "src"]).treeSha256,
        analyzers: ["aih-native", "skillspector", "semgrep", "cisco"],
      },
    ],
  });
  return { root, request };
}

type SarifShape = { runs: { invocations: Record<string, unknown>[] }[] };

const analyzerSarif = (name: string, runs = 1, invocation?: Record<string, unknown>) =>
  canonicalStrictJsonBytesV1({
    version: "2.1.0",
    runs: Array.from({ length: runs }, () => ({
      tool: { driver: { name } },
      results: [],
      invocations: [invocation ?? { executionSuccessful: true, properties: { kept: name } }],
    })),
  });

function fakeExecution(
  override: Partial<
    Record<
      BaselineAnalyzerV1,
      (sourceRoot: string) => Partial<Awaited<ReturnType<BaselineAnalyzerExecutionV1>>>
    >
  > = {},
): BaselineAnalyzerExecutionV1 {
  return async ({ analyzer, sourceRoot }) => {
    const base: Awaited<ReturnType<BaselineAnalyzerExecutionV1>> =
      analyzer === "aih-native"
        ? {
            mediaType: "application/vnd.aih.baseline-native+json",
            bytes: canonicalStrictJsonBytesV1({
              protocol: "BaselineNativeObservationV1",
              files: [],
            }),
            analyzerVersion: "native.0123456789ab",
            executionProfileId: DEFAULT_PROFILE[analyzer],
          }
        : {
            mediaType: "application/sarif+json",
            bytes: analyzerSarif(analyzer),
            analyzerVersion: testVersion(analyzer),
            executionProfileId: DEFAULT_PROFILE[analyzer],
          };
    return { ...base, ...(override[analyzer]?.(sourceRoot) ?? {}) };
  };
}

function annexOf(result: Awaited<ReturnType<typeof executeBaselineVetBatchV1>>, name: string) {
  const artifact = result.annexArtifacts.find((item) => item.path === `annex/${name}.json`);
  if (artifact === undefined) throw new Error(`missing annex ${name}`);
  return artifact;
}

describe("baseline-vet completion evidence (D24)", () => {
  it("runs each analyzer under its detector's default profile", () => {
    expect(BASELINE_BATCH_EXECUTION_PROFILES_V1).toEqual(DEFAULT_PROFILE);
    for (const [analyzer, id] of Object.entries(DEFAULT_PROFILE))
      expect(resolveDetectorCapabilityV1(`detector.${analyzer}`)?.executionProfile.id).toBe(id);
  });

  it("writes the hand-vector subject into every SARIF annex, never into the native one", async () => {
    const { root, request } = vectorTree();
    const result = await executeBaselineVetBatchV1(request, {
      sourceRoot: root,
      execute: fakeExecution(),
    });
    const expected: Record<string, Record<string, unknown>> = {
      semgrep: {
        detectorId: "detector.semgrep",
        subjectTreeSha256: VECTOR_SUBJECT_SHA256,
        analyzedFileCount: VECTOR_COUNT,
        analyzer: { version: testVersion("semgrep"), lockSha256: readLock("semgrep") },
      },
      skillspector: {
        detectorId: "detector.skillspector",
        subjectTreeSha256: VECTOR_SUBJECT_SHA256,
        analyzedFileCount: VECTOR_COUNT,
        analyzer: { version: "skillspector-test", lockSha256: null },
      },
      cisco: {
        detectorId: "detector.cisco",
        subjectTreeSha256: VECTOR_SUBJECT_SHA256,
        analyzedFileCount: VECTOR_COUNT,
        analyzer: {
          version: testVersion("cisco"),
          lockSha256: readLock("cisco-skill-scanner"),
        },
      },
    };
    for (const [name, evidence] of Object.entries(expected)) {
      const artifact = annexOf(result, name);
      const log = JSON.parse(artifact.bytes.toString("utf8")) as SarifShape;
      expect(log.runs[0]?.invocations[0]).toEqual({
        executionSuccessful: true,
        properties: { kept: name, aihScanCompletionV1: evidence },
      });
      const descriptor = result.receipt.observations.find((item) => item.analyzer === name);
      expect(descriptor?.annex.sha256).toBe(sha(artifact.bytes));
      expect(descriptor?.annex.byteLength).toBe(artifact.bytes.byteLength);
      expect(
        result.receipt.components[0]?.observations.find((item) => item.analyzer === name)
          ?.annexSha256,
      ).toBe(sha(artifact.bytes));
    }
    expect(annexOf(result, "aih-native").bytes.toString("utf8")).not.toContain(
      "aihScanCompletionV1",
    );
    expect(verifyBaselineVetReceiptV1(request, result)).toEqual({ kind: "complete" });
  });

  it("names the batch profile's lock, which the fake versions agree with", () => {
    expect(testVersion("semgrep")).toBe(`semgrep-test+uvlock.${readLock("semgrep").slice(0, 12)}`);
    expect(testVersion("cisco")).toBe(
      `cisco-test+uvlock.${readLock("cisco-skill-scanner").slice(0, 12)}`,
    );
    expect(testVersion("skillspector")).toBe("skillspector-test");
  });

  it("gives every run of a multi-run log an equal object", async () => {
    const { root, request } = vectorTree();
    const result = await executeBaselineVetBatchV1(request, {
      sourceRoot: root,
      execute: fakeExecution({ semgrep: () => ({ bytes: analyzerSarif("semgrep", 3) }) }),
    });
    const log = JSON.parse(annexOf(result, "semgrep").bytes.toString("utf8")) as SarifShape;
    expect(log.runs).toHaveLength(3);
    const objects = log.runs.map(
      (run) => (run.invocations[0]?.properties as Record<string, unknown>).aihScanCompletionV1,
    );
    expect(objects[0]).toMatchObject({ subjectTreeSha256: VECTOR_SUBJECT_SHA256 });
    expect(objects[1]).toEqual(objects[0]);
    expect(objects[2]).toEqual(objects[0]);
  });

  it.each<[string, Parameters<typeof fakeExecution>[0], RegExp]>([
    [
      "a forged key in the first invocation",
      {
        semgrep: () => ({
          bytes: analyzerSarif("semgrep", 1, {
            executionSuccessful: true,
            properties: {
              aihScanCompletionV1: {
                detectorId: "detector.semgrep",
                subjectTreeSha256: VECTOR_SUBJECT_SHA256,
                analyzedFileCount: VECTOR_COUNT,
                analyzer: { version: testVersion("semgrep"), lockSha256: null },
              },
            },
          }),
        }),
      },
      /forged/,
    ],
    [
      "a forged key in a later run",
      {
        cisco: () => ({
          bytes: canonicalStrictJsonBytesV1({
            version: "2.1.0",
            runs: [
              {
                tool: { driver: { name: "c" } },
                results: [],
                invocations: [{ executionSuccessful: true }],
              },
              {
                tool: { driver: { name: "c" } },
                results: [],
                invocations: [
                  { executionSuccessful: true, properties: { aihScanCompletionV1: {} } },
                ],
              },
            ],
          }),
        }),
      },
      /forged/,
    ],
    [
      "an unsuccessful invocation",
      { semgrep: () => ({ bytes: analyzerSarif("semgrep", 1, { executionSuccessful: false }) }) },
      /did not complete successfully/,
    ],
    [
      "an error notification",
      {
        skillspector: () => ({
          bytes: analyzerSarif("skillspector", 1, {
            executionSuccessful: true,
            toolExecutionNotifications: [{ level: "error", message: { text: "boom" } }],
          }),
        }),
      },
      /error notification/,
    ],
    [
      "a run without invocations",
      {
        semgrep: () => ({
          bytes: canonicalStrictJsonBytesV1({
            version: "2.1.0",
            runs: [{ tool: { driver: { name: "semgrep" } }, results: [] }],
          }),
        }),
      },
      /reports no invocation/,
    ],
    [
      "a profile the detector does not run under",
      { skillspector: () => ({ executionProfileId: "linux-namespace-uv-v1" }) },
      /execution profile/,
    ],
    [
      "an undeclared profile",
      { semgrep: () => ({ executionProfileId: undefined as unknown as string }) },
      /execution profile/,
    ],
    [
      "a source that changes while an analyzer runs",
      {
        semgrep: (sourceRoot) => {
          writeFileSync(join(sourceRoot, "src", "a.js"), "console.log(2);\n", "utf8");
          return {};
        },
      },
      /snapshot changed during the run/,
    ],
  ])("publishes nothing for %s", async (_label, override, message) => {
    const { root, request } = vectorTree();
    await expect(
      executeBaselineVetBatchV1(request, { sourceRoot: root, execute: fakeExecution(override) }),
    ).rejects.toThrow(message);
  });
});

/** A request over the vector tree as it is now on disk (links included in the source digest). */
function requestOver(root: string) {
  return createBaselineVetRequestV1({
    protocol: "BaselineVetRequestV1",
    profile: "aih-baseline-v1",
    source: {
      id: "vector",
      owner: "aihq",
      repository: "vector",
      pinnedCommit: "b".repeat(40),
      treeSha256: hashSourceTreeV1(root).treeSha256,
    },
    components: [
      {
        id: "skill-vector",
        content: "skill",
        paths: ["SKILL.md", "src"],
        treeSha256: hashComponentTreeV1(root, ["SKILL.md", "src"]).treeSha256,
        analyzers: ["aih-native", "skillspector", "semgrep", "cisco"],
      },
    ],
  });
}

const evidenceOf = (result: BatchResult, name: string) =>
  (
    (JSON.parse(annexOf(result, name).bytes.toString("utf8")) as SarifShape).runs[0]?.invocations[0]
      ?.properties as { aihScanCompletionV1: Record<string, unknown> }
  ).aihScanCompletionV1;

describe("D26: no analyzer snapshot recreates a directory link", () => {
  it("omits a sibling directory link, so F is exactly the files the analyzer received", async () => {
    const { root } = vectorTree();
    symlinkSync("src", join(root, "alias"), "dir");
    const request = requestOver(root);
    const seen: string[] = [];
    const result = await executeBaselineVetBatchV1(request, {
      sourceRoot: root,
      execute: fakeExecution({
        semgrep: (sourceRoot) => {
          seen.push(...readdirSync(sourceRoot).sort());
          expect(existsSync(join(sourceRoot, "alias"))).toBe(false);
          return {};
        },
      }),
    });
    expect(seen).toEqual(["SKILL.md", "src"]);
    // F = { SKILL.md, src/a.js }: the alias contributes nothing and was never shown.
    const expected = handSubject([
      ["SKILL.md", VECTOR_FILES["SKILL.md"]],
      ["src/a.js", VECTOR_FILES["src/a.js"]],
    ]);
    expect(expected).toEqual({
      subjectTreeSha256: VECTOR_SUBJECT_SHA256,
      analyzedFileCount: VECTOR_COUNT,
    });
    for (const name of ["semgrep", "skillspector", "cisco"])
      expect(evidenceOf(result, name)).toMatchObject(expected);
    expect(verifyBaselineVetReceiptV1(request, result)).toEqual({ kind: "complete" });
  });

  it("keeps an in-root file link keyed by its link path and hashed over its target", async () => {
    const { root } = vectorTree();
    symlinkSync("SKILL.md", join(root, "AGENTS.md"), "file");
    const request = requestOver(root);
    const result = await executeBaselineVetBatchV1(request, {
      sourceRoot: root,
      execute: fakeExecution({
        semgrep: (sourceRoot) => {
          expect(lstatSync(join(sourceRoot, "AGENTS.md")).isSymbolicLink()).toBe(true);
          expect(readlinkSync(join(sourceRoot, "AGENTS.md"))).toBe("SKILL.md");
          return {};
        },
      }),
    });
    expect(evidenceOf(result, "semgrep")).toMatchObject(
      handSubject([
        ["AGENTS.md", VECTOR_FILES["SKILL.md"]],
        ["SKILL.md", VECTOR_FILES["SKILL.md"]],
        ["src/a.js", VECTOR_FILES["src/a.js"]],
      ]),
    );
  });

  it("refuses a source whose directory link changed after the request was bound", async () => {
    const { root } = vectorTree();
    mkdirSync(join(root, "lib"));
    writeFileSync(join(root, "lib", "b.js"), "console.log(2);\n", "utf8");
    symlinkSync("src", join(root, "alias"), "dir");
    const request = requestOver(root);
    rmSync(join(root, "alias"));
    symlinkSync("lib", join(root, "alias"), "dir");
    await expect(
      executeBaselineVetBatchV1(request, { sourceRoot: root, execute: fakeExecution() }),
    ).rejects.toThrow(/baseline source digest mismatch/);
  });
});

type BatchResult = Awaited<ReturnType<typeof executeBaselineVetBatchV1>>;
type Evidence = Record<string, unknown> & { analyzer: Record<string, unknown> };

/** Rewrites every run's evidence of one annex; `undefined` removes it. */
function rewriteEvidence(
  bytes: Buffer,
  change: (evidence: Evidence, run: number) => Evidence | undefined,
): Buffer {
  const log = JSON.parse(bytes.toString("utf8")) as SarifShape;
  log.runs.forEach((run, index) => {
    const properties = run.invocations[0]?.properties as Record<string, unknown>;
    const next = change(structuredClone(properties.aihScanCompletionV1) as Evidence, index);
    if (next === undefined) delete properties.aihScanCompletionV1;
    else properties.aihScanCompletionV1 = next;
  });
  return canonicalStrictJsonBytesV1(log);
}

function withAnnex(result: BatchResult, name: string, bytes: Buffer): BatchResult {
  return {
    receipt: result.receipt,
    annexArtifacts: result.annexArtifacts.map((item) =>
      item.path === `annex/${name}.json` ? { path: item.path, bytes } : item,
    ),
  };
}

/** Re-binds the receipt (annex digest, component bindings, receipt digest) to new annex bytes. */
function rebound(
  result: BatchResult,
  name: string,
  bytes: Buffer,
  analyzerVersion?: string,
): BatchResult {
  const digest = sha(bytes);
  const { receiptSha256: _old, ...authoring } = structuredClone(result.receipt) as unknown as {
    receiptSha256: string;
    observations: {
      analyzer: string;
      analyzerVersion: string;
      annex: { sha256: string; byteLength: number };
    }[];
    components: { observations: { analyzer: string; annexSha256: string }[] }[];
  };
  for (const item of authoring.observations)
    if (item.analyzer === name) {
      item.annex = { ...item.annex, sha256: digest, byteLength: bytes.byteLength };
      if (analyzerVersion !== undefined) item.analyzerVersion = analyzerVersion;
    }
  for (const component of authoring.components)
    for (const item of component.observations)
      if (item.analyzer === name) item.annexSha256 = digest;
  const receipt = {
    ...authoring,
    receiptSha256: canonicalStrictJsonSha256V1({
      domain: "aih.baseline-vet-receipt-v1",
      receipt: authoring,
    }),
  } as unknown as BatchResult["receipt"];
  return withAnnex({ receipt, annexArtifacts: result.annexArtifacts }, name, bytes);
}

type Change = (evidence: Evidence, run: number) => Evidence | undefined;
const REMOVED: [string, Change] = ["removed", () => undefined];
const TAMPERING: [string, Change][] = [
  REMOVED,
  ["another subject", (evidence) => ({ ...evidence, subjectTreeSha256: "0".repeat(64) })],
  ["another count", (evidence) => ({ ...evidence, analyzedFileCount: 3 })],
];

describe("baseline-vet annex consumers keep the evidence (D24)", () => {
  it.each(
    TAMPERING,
  )("an annex whose evidence is %s fails the annex digest binding", async (_label, change) => {
    const { root, request } = vectorTree();
    const result = await executeBaselineVetBatchV1(request, {
      sourceRoot: root,
      execute: fakeExecution(),
    });
    const tampered = withAnnex(
      result,
      "semgrep",
      rewriteEvidence(annexOf(result, "semgrep").bytes, change),
    );
    expect(verifyBaselineVetReceiptV1(request, tampered)).toEqual({
      kind: "required",
      reason: "annex-mismatch",
    });

    const parent = mkdtempSync(join(tmpdir(), "aih-scan-s2j-bundle-"));
    temporaryDirectories.push(parent);
    const bundle = join(parent, "bundle");
    writeBaselineVetBundleV1({ outputDirectory: bundle, result });
    expect(readBaselineVetBundleV1({ bundleDirectory: bundle })).toEqual(result);
    writeFileSync(join(bundle, "annex", "semgrep.json"), annexOf(tampered, "semgrep").bytes);
    expect(() => readBaselineVetBundleV1({ bundleDirectory: bundle })).toThrow(
      /annex artifact mismatch: semgrep/,
    );

    const keys = generateKeyPairSync("ed25519");
    const signer = {
      identity: "organization-scanner",
      class: "organization" as const,
      keyId: ed25519KeyIdV2(keys.publicKey),
    };
    const signed = signBaselineVetBundleV1({
      request,
      result,
      signer: { ...signer, privateKey: keys.privateKey },
      claims: { signedAt: "2026-09-24T05:00:00.000Z", expiresAt: "2026-09-24T06:00:00.000Z" },
    });
    const envelope = parseBaselineVetAttestationEnvelopeV1Json(
      canonicalBaselineVetAttestationEnvelopeV1Bytes(signed).toString("utf8"),
    );
    const verify = (candidate: BatchResult) =>
      verifyBaselineVetAttestationV1({
        envelope,
        request,
        result: candidate,
        roots: [{ ...signer, publicKey: keys.publicKey }],
        expected: { now: "2026-09-24T05:30:00.000Z", signer },
        seenEvidenceDigests: [],
        seenReceiptBindings: [],
      });
    expect(verify(result).facts.annexesComplete).toBe(true);
    expect(() => verify(tampered)).toThrow(/receipt and annex verification/);
  });

  it.each<[string, BaselineAnalyzerV1, Change]>([
    ["removed", "semgrep", REMOVED[1]],
    ["another detector", "semgrep", (evidence) => ({ ...evidence, detectorId: "detector.cisco" })],
    [
      "a version other than the receipt's",
      "semgrep",
      (evidence) => ({ ...evidence, analyzer: { ...evidence.analyzer, version: "other" } }),
    ],
    [
      "a lock no profile of the detector installs",
      "semgrep",
      (evidence) => ({
        ...evidence,
        analyzer: { ...evidence.analyzer, lockSha256: "f".repeat(64) },
      }),
    ],
    [
      "a null lock where every profile installs one",
      "cisco",
      (evidence) => ({ ...evidence, analyzer: { ...evidence.analyzer, lockSha256: null } }),
    ],
    [
      "a lock where no profile installs one",
      "skillspector",
      (evidence) => ({
        ...evidence,
        analyzer: { ...evidence.analyzer, lockSha256: "f".repeat(64) },
      }),
    ],
    ["an extra key", "semgrep", (evidence) => ({ ...evidence, extra: true })],
    ["a zero count for Cisco", "cisco", (evidence) => ({ ...evidence, analyzedFileCount: 0 })],
    [
      "unequal runs",
      "semgrep",
      (evidence, run) =>
        run === 0 ? evidence : { ...evidence, subjectTreeSha256: "0".repeat(64) },
    ],
  ])("a receipt re-bound over an annex whose evidence has %s is refused", async (_label, name, change) => {
    const { root, request } = vectorTree();
    const result = await executeBaselineVetBatchV1(request, {
      sourceRoot: root,
      execute: fakeExecution({ [name]: () => ({ bytes: analyzerSarif(name, 2) }) }),
    });
    expect(verifyBaselineVetReceiptV1(request, result)).toEqual({ kind: "complete" });
    const candidate = rebound(result, name, rewriteEvidence(annexOf(result, name).bytes, change));
    expect(verifyBaselineVetReceiptV1(request, candidate)).toEqual({
      kind: "required",
      reason: "annex-mismatch",
    });
  });

  it("refuses a re-bound annex that also carries the key in a later invocation", async () => {
    const { root, request } = vectorTree();
    const result = await executeBaselineVetBatchV1(request, {
      sourceRoot: root,
      execute: fakeExecution(),
    });
    const log = JSON.parse(annexOf(result, "semgrep").bytes.toString("utf8")) as SarifShape;
    const run = log.runs[0];
    if (run === undefined) throw new Error("expected a run");
    run.invocations.push({
      executionSuccessful: true,
      properties: {
        aihScanCompletionV1: (run.invocations[0]?.properties as Record<string, unknown>)
          .aihScanCompletionV1,
      },
    });
    const candidate = rebound(result, "semgrep", canonicalStrictJsonBytesV1(log));
    expect(verifyBaselineVetReceiptV1(request, candidate)).toEqual({
      kind: "required",
      reason: "annex-mismatch",
    });
  });
});

/** Cisco's host lock: the reviewer's case runs the host profile and claims the namespace one. */
const HOST_CISCO_VERSION = `2.0.14+uvlock.${readLock("cisco-skill-scanner-host").slice(0, 12)}`;

describe("S2k: a batch annex names the batch profile, never the executor's claim", () => {
  it.each<[string, Parameters<typeof fakeExecution>[0], RegExp]>([
    [
      "Cisco's host-lock version declared as linux-namespace-uv-v1 (the reviewer's case)",
      { cisco: () => ({ analyzerVersion: HOST_CISCO_VERSION }) },
      /cisco analyzer version .* does not name the lock of linux-namespace-uv-v1/,
    ],
    [
      "Cisco declaring the host profile",
      {
        cisco: () => ({
          executionProfileId: "host-process-uv-v1",
          analyzerVersion: HOST_CISCO_VERSION,
        }),
      },
      /cisco execution profile "host-process-uv-v1" contradicts the batch profile linux-namespace-uv-v1/,
    ],
    [
      "SkillSpector declaring the host-Docker profile",
      { skillspector: () => ({ executionProfileId: "docker-host-local-skillspector-v1" }) },
      /contradicts the batch profile docker-hardened-skillspector-v1/,
    ],
    [
      "a Semgrep version without the lock suffix",
      { semgrep: () => ({ analyzerVersion: "1.173.0" }) },
      /semgrep analyzer version .* does not name the lock/,
    ],
    [
      "a Semgrep version naming another lock",
      { semgrep: () => ({ analyzerVersion: "1.173.0+uvlock.000000000000" }) },
      /semgrep analyzer version .* does not name the lock/,
    ],
    [
      "a lock suffix on a profile that installs no lock",
      { skillspector: () => ({ analyzerVersion: "rev@sha256:abc+uvlock.0123456789ab" }) },
      /skillspector analyzer version .* names a lock/,
    ],
  ])("publishes nothing for %s", async (_label, override, message) => {
    const { root, request } = vectorTree();
    await expect(
      executeBaselineVetBatchV1(request, { sourceRoot: root, execute: fakeExecution(override) }),
    ).rejects.toThrow(message);
  });

  it.each<[string, BaselineAnalyzerV1, Change, string | undefined]>([
    [
      "Cisco's host lock, although a Cisco profile installs it",
      "cisco",
      (evidence) => ({
        ...evidence,
        analyzer: { ...evidence.analyzer, lockSha256: readLock("cisco-skill-scanner-host") },
      }),
      undefined,
    ],
    [
      "the namespace lock under a host-lock version (the reviewer's case)",
      "cisco",
      (evidence) => ({
        ...evidence,
        analyzer: { ...evidence.analyzer, version: HOST_CISCO_VERSION },
      }),
      HOST_CISCO_VERSION,
    ],
    [
      "a lock suffix on SkillSpector's version",
      "skillspector",
      (evidence) => ({
        ...evidence,
        analyzer: { ...evidence.analyzer, version: "skillspector-test+uvlock.0123456789ab" },
      }),
      "skillspector-test+uvlock.0123456789ab",
    ],
  ])("a receipt re-bound over %s is refused on read", async (_label, name, change, version) => {
    const { root, request } = vectorTree();
    const result = await executeBaselineVetBatchV1(request, {
      sourceRoot: root,
      execute: fakeExecution(),
    });
    const candidate = rebound(
      result,
      name,
      rewriteEvidence(annexOf(result, name).bytes, change),
      version,
    );
    expect(verifyBaselineVetReceiptV1(request, candidate)).toEqual({
      kind: "required",
      reason: "annex-mismatch",
    });
  });
});

/** An otherwise successful analyzer SARIF holding one result at `uri`. */
const locatedSarif = (name: string, uri: string) =>
  canonicalStrictJsonBytesV1({
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name } },
        results: [
          {
            ruleId: `${name}.rule`,
            level: "warning",
            message: { text: "finding" },
            locations: [
              { physicalLocation: { artifactLocation: { uri }, region: { startLine: 1 } } },
            ],
          },
        ],
        invocations: [{ executionSuccessful: true }],
      },
    ],
  });

describe("S2k: every annex SARIF passes the §1.4 location rules before it is certified", () => {
  it.each<[string, BaselineAnalyzerV1, string]>([
    ["an escaping location (the reviewer's case)", "semgrep", "../../outside.js"],
    ["an escaping Cisco location", "cisco", "../outside/SKILL.md"],
    ["an absolute location", "skillspector", "/etc/passwd"],
    ["a drive-letter location", "semgrep", "C:/outside.js"],
    ["a file URL", "semgrep", "file:///tmp/outside.js"],
    ["a backslash location", "semgrep", "srca.js"],
    ["a path that is not a sealed file", "semgrep", "src/missing.js"],
  ])("publishes nothing for %s", async (_label, name, uri) => {
    const { root, request } = vectorTree();
    await expect(
      executeBaselineVetBatchV1(request, {
        sourceRoot: root,
        execute: fakeExecution({ [name]: () => ({ bytes: locatedSarif(name, uri) }) }),
      }),
    ).rejects.toThrow(new RegExp(`${name} SARIF fails the §1.4 location rules`));
  });

  it("refuses a location through an omitted directory link (D26)", async () => {
    const { root } = vectorTree();
    symlinkSync("src", join(root, "alias"), "dir");
    await expect(
      executeBaselineVetBatchV1(requestOver(root), {
        sourceRoot: root,
        execute: fakeExecution({
          semgrep: () => ({ bytes: locatedSarif("semgrep", "alias/a.js") }),
        }),
      }),
    ).rejects.toThrow(/semgrep SARIF fails the §1.4 location rules/);
  });

  it("certifies a legitimate source-relative location", async () => {
    const { root, request } = vectorTree();
    const result = await executeBaselineVetBatchV1(request, {
      sourceRoot: root,
      execute: fakeExecution({
        semgrep: () => ({ bytes: locatedSarif("semgrep", "src/a.js") }),
        cisco: () => ({ bytes: locatedSarif("cisco", "SKILL.md") }),
      }),
    });
    const log = JSON.parse(annexOf(result, "semgrep").bytes.toString("utf8")) as {
      runs: { results: { locations: unknown[] }[] }[];
    };
    expect(log.runs[0]?.results[0]?.locations).toEqual([
      { physicalLocation: { artifactLocation: { uri: "src/a.js" }, region: { startLine: 1 } } },
    ]);
    expect(evidenceOf(result, "semgrep")).toMatchObject({
      subjectTreeSha256: VECTOR_SUBJECT_SHA256,
    });
    expect(verifyBaselineVetReceiptV1(request, result)).toEqual({ kind: "complete" });
  });
});
