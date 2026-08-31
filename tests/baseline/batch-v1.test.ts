import { createHash } from "node:crypto";
import {
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
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
  type BaselineAnalyzerExecutionV1,
  canonicalBaselineVetReceiptV1Bytes,
  createBaselineVetRequestV1,
  executeBaselineVetBatchV1,
  parseBaselineVetRequestV1Json,
  verifyBaselineVetReceiptV1,
} from "../../src/baseline/batch-v1.js";
import {
  canonicalStrictJsonBytesV1,
  canonicalStrictJsonSha256V1,
} from "../../src/contract/strict-json-v1.js";
import { hashComponentTreeV1, hashSourceTreeV1 } from "../../src/observation/source-hash-v1.js";

const temporaryDirectories: string[] = [];
const sha = (value: string | Uint8Array) => createHash("sha256").update(value).digest("hex");

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "aih-scan-baseline-"));
  temporaryDirectories.push(root);
  mkdirSync(join(root, "skills", "demo"), { recursive: true });
  mkdirSync(join(root, "rules"), { recursive: true });
  writeFileSync(join(root, "skills", "demo", "SKILL.md"), "# Demo\n", "utf8");
  writeFileSync(join(root, "rules", "base.md"), "# Rule\n", "utf8");
  const source = hashSourceTreeV1(root);
  const skill = hashComponentTreeV1(root, ["skills/demo"]);
  const rules = hashComponentTreeV1(root, ["rules"]);
  const request = createBaselineVetRequestV1({
    protocol: "BaselineVetRequestV1",
    profile: "aih-baseline-v1",
    source: {
      id: "ecc",
      owner: "affaan-m",
      repository: "everything-claude-code",
      pinnedCommit: "a".repeat(40),
      treeSha256: source.treeSha256,
    },
    components: [
      {
        id: "rules-core",
        content: "general",
        paths: ["rules"],
        treeSha256: rules.treeSha256,
        analyzers: ["aih-native", "skillspector", "semgrep"],
      },
      {
        id: "skill-demo",
        content: "skill",
        paths: ["skills/demo"],
        treeSha256: skill.treeSha256,
        analyzers: ["aih-native", "skillspector", "semgrep", "cisco"],
      },
    ],
  });
  return { root, request };
}

function requestForCurrentSource(root: string, request: ReturnType<typeof fixture>["request"]) {
  return createBaselineVetRequestV1({
    protocol: request.protocol,
    profile: request.profile,
    source: {
      ...request.source,
      treeSha256: hashSourceTreeV1(root).treeSha256,
    },
    components: request.components,
  });
}

const sarif = (name: string) =>
  canonicalStrictJsonBytesV1({
    version: "2.1.0",
    runs: [{ tool: { driver: { name } }, results: [] }],
  });

describe("BaselineVetRequestV1", () => {
  it("creates one canonical, content-addressed request for up to 100 components", () => {
    const { request } = fixture();
    const bytes = canonicalStrictJsonBytesV1(request);

    expect(parseBaselineVetRequestV1Json(bytes.toString("utf8"))).toEqual(request);
    expect(request.requestSha256).toBe(
      sha(
        canonicalStrictJsonBytesV1({
          domain: "aih.baseline-vet-request-v1",
          request: {
            protocol: request.protocol,
            profile: request.profile,
            source: request.source,
            components: request.components,
          },
        }),
      ),
    );
    expect(Object.isFrozen(request.components)).toBe(true);
  });

  it.each([
    ["unknown field", (value: Record<string, unknown>) => (value.authority = "approved")],
    [
      "duplicate component",
      (value: Record<string, unknown>) => {
        const components = value.components as Record<string, unknown>[];
        const first = components[0];
        if (first === undefined) throw new Error("expected component fixture");
        components.push(structuredClone(first));
      },
    ],
    [
      "unsafe path",
      (value: Record<string, unknown>) =>
        ((
          ((value.components as Record<string, unknown>[])[0] as Record<string, unknown>)
            .paths as string[]
        )[0] = "../rules"),
    ],
    [
      "unknown analyzer",
      (value: Record<string, unknown>) =>
        (((value.components as Record<string, unknown>[])[0] as Record<string, unknown>).analyzers =
          ["custom-command"]),
    ],
    [
      "weakened general analyzer floor",
      (value: Record<string, unknown>) =>
        (((value.components as Record<string, unknown>[])[0] as Record<string, unknown>).analyzers =
          ["aih-native"]),
    ],
    [
      "missing Cisco for Skill content",
      (value: Record<string, unknown>) =>
        (((value.components as Record<string, unknown>[])[1] as Record<string, unknown>).analyzers =
          ["aih-native", "skillspector", "semgrep"]),
    ],
    [
      "non-canonical analyzer order",
      (value: Record<string, unknown>) =>
        (((value.components as Record<string, unknown>[])[0] as Record<string, unknown>).analyzers =
          ["semgrep", "aih-native"]),
    ],
  ])("rejects %s", (_label, mutate) => {
    const { request } = fixture();
    const value = structuredClone(request) as unknown as Record<string, unknown>;
    mutate(value);
    expect(() => parseBaselineVetRequestV1Json(JSON.stringify(value))).toThrow(
      /BaselineVetRequestV1/,
    );
  });

  it("rejects a changed or non-canonical wire digest", () => {
    const { request } = fixture();
    const changed = structuredClone(request) as unknown as Record<string, unknown>;
    changed.requestSha256 = "f".repeat(64);
    expect(() => parseBaselineVetRequestV1Json(JSON.stringify(changed))).toThrow(
      /request digest|canonical wire/,
    );
    expect(() => parseBaselineVetRequestV1Json(JSON.stringify(request, null, 2))).toThrow(
      /canonical wire/,
    );
  });
});

describe("baseline batch execution", () => {
  it("preserves safe relative source symlinks to files and directories outside components", async () => {
    const { root, request } = fixture();
    writeFileSync(join(root, "CLAUDE.md"), "# Shared guidance\n", "utf8");
    mkdirSync(join(root, "shared"));
    writeFileSync(join(root, "shared", "README.md"), "# Shared directory\n", "utf8");
    try {
      symlinkSync("CLAUDE.md", join(root, "AGENTS.md"), "file");
      symlinkSync("shared", join(root, "shared-link"), "dir");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EPERM") return;
      throw error;
    }
    const currentRequest = requestForCurrentSource(root, request);
    let calls = 0;
    const execute: BaselineAnalyzerExecutionV1 = async ({ analyzer, sourceRoot }) => {
      calls += 1;
      expect(lstatSync(join(sourceRoot, "AGENTS.md")).isSymbolicLink()).toBe(true);
      expect(readlinkSync(join(sourceRoot, "AGENTS.md"))).toBe("CLAUDE.md");
      expect(readFileSync(join(sourceRoot, "AGENTS.md"), "utf8")).toBe("# Shared guidance\n");
      expect(lstatSync(join(sourceRoot, "shared-link")).isSymbolicLink()).toBe(true);
      expect(readlinkSync(join(sourceRoot, "shared-link"))).toBe("shared");
      expect(readFileSync(join(sourceRoot, "shared-link", "README.md"), "utf8")).toBe(
        "# Shared directory\n",
      );
      return analyzer === "aih-native"
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
            bytes: sarif(analyzer),
            analyzerVersion: `${analyzer}.0123456789ab`,
          };
    };

    await expect(
      executeBaselineVetBatchV1(currentRequest, { sourceRoot: root, execute }),
    ).resolves.toBeDefined();
    expect(calls).toBe(4);
  });

  it.each([
    ["a dangling target", "missing.md", false],
    ["a parent escape", "../outside.md", false],
    ["a symlink chain", "alias.md", true],
  ])("rejects source symlinks with %s before analyzer execution", async (_label, target, chain) => {
    const { root, request } = fixture();
    writeFileSync(join(root, "CLAUDE.md"), "# Shared guidance\n", "utf8");
    if (chain) symlinkSync("CLAUDE.md", join(root, "alias.md"), "file");
    try {
      symlinkSync(target, join(root, "AGENTS.md"), "file");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EPERM") return;
      throw error;
    }
    const currentRequest = requestForCurrentSource(root, request);
    const never: BaselineAnalyzerExecutionV1 = async () => {
      throw new Error("analyzer must not run");
    };

    await expect(
      executeBaselineVetBatchV1(currentRequest, { sourceRoot: root, execute: never }),
    ).rejects.toThrow(/symbolic link/);
  });

  it("acquires each analyzer once and binds its observation to every requesting component", async () => {
    const { root, request } = fixture();
    const calls: string[] = [];
    let snapshotRoot = "";
    const execute: BaselineAnalyzerExecutionV1 = async ({ analyzer, sourceRoot }) => {
      calls.push(`${analyzer}:${sourceRoot}`);
      snapshotRoot ||= sourceRoot;
      expect(sourceRoot).toBe(snapshotRoot);
      expect(sourceRoot).not.toBe(root);
      expect(readFileSync(join(sourceRoot, "skills", "demo", "SKILL.md"), "utf8")).toBe("# Demo\n");
      return analyzer === "aih-native"
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
            bytes: sarif(analyzer),
            analyzerVersion: `${analyzer}.0123456789ab`,
          };
    };

    const result = await executeBaselineVetBatchV1(request, { sourceRoot: root, execute });

    expect(calls).toEqual(
      ["aih-native", "skillspector", "semgrep", "cisco"].map(
        (analyzer) => `${analyzer}:${snapshotRoot}`,
      ),
    );
    expect(existsSync(snapshotRoot)).toBe(false);
    expect(result.annexArtifacts).toHaveLength(4);
    expect(result.receipt.observations.map((item) => item.analyzer)).toEqual([
      "aih-native",
      "skillspector",
      "semgrep",
      "cisco",
    ]);
    expect(result.receipt.components[0]?.observations).toHaveLength(3);
    expect(result.receipt.components[1]?.observations).toHaveLength(4);
    expect(verifyBaselineVetReceiptV1(request, result)).toEqual({ kind: "complete" });
    expect(canonicalBaselineVetReceiptV1Bytes(result.receipt)).toEqual(
      canonicalStrictJsonBytesV1(result.receipt),
    );
  });

  it("rejects links before any analyzer can observe the source", async () => {
    const hardlinked = fixture();
    linkSync(join(hardlinked.root, "rules", "base.md"), join(hardlinked.root, "rules", "alias.md"));
    const never: BaselineAnalyzerExecutionV1 = async () => {
      throw new Error("analyzer must not run");
    };
    await expect(
      executeBaselineVetBatchV1(hardlinked.request, {
        sourceRoot: hardlinked.root,
        execute: never,
      }),
    ).rejects.toThrow(/file shape/);

    const symbolic = fixture();
    try {
      symlinkSync(
        join(symbolic.root, "rules", "base.md"),
        join(symbolic.root, "rules", "alias.md"),
        "file",
      );
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EPERM") return;
      throw error;
    }
    await expect(
      executeBaselineVetBatchV1(symbolic.request, {
        sourceRoot: symbolic.root,
        execute: never,
      }),
    ).rejects.toThrow(/symbolic link/);
  });

  it("rejects original-source mutation even though analyzers receive a private snapshot", async () => {
    const { root, request } = fixture();
    const execute: BaselineAnalyzerExecutionV1 = async ({ analyzer }) => {
      if (analyzer === "semgrep")
        writeFileSync(join(root, "rules", "base.md"), "changed outside snapshot", "utf8");
      return analyzer === "aih-native"
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
            bytes: sarif(analyzer),
            analyzerVersion: `${analyzer}.0123456789ab`,
          };
    };

    await expect(executeBaselineVetBatchV1(request, { sourceRoot: root, execute })).rejects.toThrow(
      /source digest mismatch/,
    );
  });

  it("fails closed on source drift, component drift, missing output, malformed SARIF, or mutation", async () => {
    const scenarios: Array<{
      name: string;
      mutate?: (root: string) => void;
      execute?: BaselineAnalyzerExecutionV1;
    }> = [
      {
        name: "source drift",
        mutate: (root) => writeFileSync(join(root, "extra.md"), "changed", "utf8"),
      },
      {
        name: "component drift",
        mutate: (root) => writeFileSync(join(root, "rules", "base.md"), "changed", "utf8"),
      },
      {
        name: "missing output",
        execute: async () => ({
          mediaType: "application/sarif+json",
          bytes: Buffer.alloc(0),
          analyzerVersion: "missing.0123456789ab",
        }),
      },
      {
        name: "malformed SARIF",
        execute: async ({ analyzer }) => ({
          mediaType:
            analyzer === "aih-native"
              ? "application/vnd.aih.baseline-native+json"
              : "application/sarif+json",
          bytes:
            analyzer === "aih-native"
              ? canonicalStrictJsonBytesV1({ protocol: "BaselineNativeObservationV1", files: [] })
              : Buffer.from("{}", "utf8"),
          analyzerVersion: `${analyzer}.0123456789ab`,
        }),
      },
      {
        name: "mutation during execution",
        execute: async ({ analyzer, sourceRoot }) => {
          if (analyzer === "semgrep")
            writeFileSync(join(sourceRoot, "rules", "base.md"), "changed", "utf8");
          return analyzer === "aih-native"
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
                bytes: sarif(analyzer),
                analyzerVersion: `${analyzer}.0123456789ab`,
              };
        },
      },
    ];
    for (const scenario of scenarios) {
      const { root, request } = fixture();
      scenario.mutate?.(root);
      const execute: BaselineAnalyzerExecutionV1 =
        scenario.execute ??
        (async ({ analyzer }) =>
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
                bytes: sarif(analyzer),
                analyzerVersion: `${analyzer}.0123456789ab`,
              });
      await expect(
        executeBaselineVetBatchV1(request, { sourceRoot: root, execute }),
        scenario.name,
      ).rejects.toThrow(/baseline|SARIF|observation|source|component/i);
    }
  });

  it("detects missing, substituted, duplicated, and replay-conflicting annexes", async () => {
    const { root, request } = fixture();
    const execute: BaselineAnalyzerExecutionV1 = async ({ analyzer }) =>
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
            bytes: sarif(analyzer),
            analyzerVersion: `${analyzer}.0123456789ab`,
          };
    const result = await executeBaselineVetBatchV1(request, { sourceRoot: root, execute });
    const first = result.annexArtifacts[0];
    if (first === undefined) throw new Error("expected annex fixture");

    expect(
      verifyBaselineVetReceiptV1(request, {
        receipt: result.receipt,
        annexArtifacts: result.annexArtifacts.slice(1),
      }),
    ).toMatchObject({ kind: "required", reason: "missing-annex" });
    expect(
      verifyBaselineVetReceiptV1(request, {
        receipt: result.receipt,
        annexArtifacts: [
          { ...first, bytes: Buffer.from("substitution") },
          ...result.annexArtifacts.slice(1),
        ],
      }),
    ).toMatchObject({ kind: "required", reason: "annex-mismatch" });
    expect(
      verifyBaselineVetReceiptV1(request, {
        receipt: result.receipt,
        annexArtifacts: [...result.annexArtifacts, first],
      }),
    ).toMatchObject({ kind: "required", reason: "duplicate-annex" });
    expect(
      verifyBaselineVetReceiptV1(request, result, [
        { requestSha256: request.requestSha256, receiptSha256: "f".repeat(64) },
      ]),
    ).toMatchObject({ kind: "required", reason: "replay-conflict" });
    expect(
      verifyBaselineVetReceiptV1(request, result, [
        {
          requestSha256: request.requestSha256,
          receiptSha256: result.receipt.receiptSha256,
          extra: "not-canonical",
        } as never,
      ]),
    ).toMatchObject({ kind: "required", reason: "receipt-mismatch" });
    expect(
      verifyBaselineVetReceiptV1(request, result, [
        { requestSha256: request.requestSha256, receiptSha256: result.receipt.receiptSha256 },
        { requestSha256: request.requestSha256, receiptSha256: result.receipt.receiptSha256 },
      ]),
    ).toMatchObject({ kind: "required", reason: "receipt-mismatch" });

    const reboundReceipt = structuredClone(result.receipt) as unknown as Record<string, unknown>;
    const components = reboundReceipt.components as Array<Record<string, unknown>>;
    const observations = components[0]?.observations as Array<Record<string, unknown>>;
    if (observations?.[0] === undefined) throw new Error("expected receipt observation fixture");
    observations[0].annexSha256 = "e".repeat(64);
    expect(
      verifyBaselineVetReceiptV1(request, {
        receipt: reboundReceipt as never,
        annexArtifacts: result.annexArtifacts,
      }),
    ).toMatchObject({ kind: "required", reason: "receipt-mismatch" });
  });

  it("rejects top-level analyzer observations outside the request-derived union", async () => {
    const { root, request: completeRequest } = fixture();
    const general = completeRequest.components[0];
    if (general === undefined) throw new Error("expected general component fixture");
    const request = createBaselineVetRequestV1({
      protocol: completeRequest.protocol,
      profile: completeRequest.profile,
      source: completeRequest.source,
      components: [general],
    });
    const result = await executeBaselineVetBatchV1(request, {
      sourceRoot: root,
      execute: async ({ analyzer }) =>
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
              bytes: sarif(analyzer),
              analyzerVersion: `${analyzer}.0123456789ab`,
            },
    });
    const ciscoBytes = sarif("cisco");
    const { receiptSha256: _receiptSha256, ...receiptAuthoring } = result.receipt;
    const observations = [
      ...receiptAuthoring.observations,
      {
        analyzer: "cisco" as const,
        analyzerVersion: "cisco.0123456789ab",
        annex: {
          path: "annex/cisco.json",
          mediaType: "application/sarif+json" as const,
          sha256: sha(ciscoBytes),
          byteLength: ciscoBytes.byteLength,
        },
      },
    ];
    const forgedAuthoring = { ...receiptAuthoring, observations };
    const forgedReceipt = {
      ...forgedAuthoring,
      receiptSha256: canonicalStrictJsonSha256V1({
        domain: "aih.baseline-vet-receipt-v1",
        receipt: forgedAuthoring,
      }),
    };

    expect(
      verifyBaselineVetReceiptV1(request, {
        receipt: forgedReceipt,
        annexArtifacts: [...result.annexArtifacts, { path: "annex/cisco.json", bytes: ciscoBytes }],
      }),
    ).toMatchObject({ kind: "required", reason: "request-mismatch" });
  });
});
