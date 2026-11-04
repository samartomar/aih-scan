import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
  aiEligible,
  exportCandidate,
  importCandidate,
  loadRuntime,
  maintenancePythonPath,
  mergePrepared,
  type PreparedRuntime,
  recoverPrepared,
  scanPrepared,
  validateContent,
  validateManifest,
  verifyCandidate,
  verifyResult,
  workerLaunchBudget,
  writeCheckpointAtomic,
} from "../../tools/publisher/prepared.mjs";
import {
  digest,
  downloadArchive,
  extractArchive,
  readArchive,
  writeArchive,
} from "../../tools/publisher/prepared-archive.mjs";
import { fakeAnalyzer, skillSpectorReport } from "../support/analyzer-cli-v1.js";
import { compatibleAiServiceV1 } from "../support/compatible-ai-service-v1.js";
import { readPackedPackage } from "../support/npm-pack-output.js";

const repo = resolve(import.meta.dirname, "../..");
const root = mkdtempSync(join(tmpdir(), "scan-prepared-proof-"));
const hash = (value: string | Uint8Array) => createHash("sha256").update(value).digest("hex");
let consumer: string, tarball: string, runtime: PreparedRuntime;
const scanner = { name: "@aihq/scan", version: "0.1.0", tarballSha256: "" };
const assessment = {
  mode: "ai",
  tools: ["aih-trust-lint", "skillspector"],
  provider: "openai_compatible",
  baseUrl: "https://api.deepseek.com",
  credentialVariable: "DEEPSEEK_API",
  model: "deepseek-flash",
  reasoningEffort: "none",
  structuredOutputMethod: "function_calling",
};
beforeAll(async () => {
  const npm = join(dirname(process.execPath), "node_modules/npm/bin/npm-cli.js");
  const npmPath = existsSync(npm)
    ? npm
    : resolve(dirname(process.execPath), "../lib/node_modules/npm/bin/npm-cli.js");
  if (process.env.AIH_SCAN_PACKED_TARBALL) tarball = resolve(process.env.AIH_SCAN_PACKED_TARBALL);
  else {
    const staging = join(root, "package");
    mkdirSync(staging);
    execFileSync(
      process.execPath,
      [
        join(repo, "node_modules/typescript/bin/tsc"),
        "-p",
        join(repo, "tsconfig.build.json"),
        "--outDir",
        join(staging, "dist"),
      ],
      { windowsHide: true },
    );
    const manifest = JSON.parse(readFileSync(join(repo, "package.json"), "utf8"));
    for (const path of ["package.json", "README.md", "LICENSE", ...manifest.files])
      if (path !== "dist") cpSync(join(repo, path), join(staging, path), { recursive: true });
    const packed = readPackedPackage(
      execFileSync(
        process.execPath,
        [npmPath, "pack", "--ignore-scripts", "--json", "--pack-destination", root],
        { cwd: staging, encoding: "utf8", windowsHide: true },
      ),
    );
    tarball = join(root, packed.filename);
  }
  scanner.tarballSha256 = hash(readFileSync(tarball));
  consumer = join(root, "consumer");
  mkdirSync(consumer);
  writeFileSync(
    join(consumer, "package.json"),
    '{"name":"prepared-proof","version":"1.0.0","private":true,"type":"module"}',
  );
  execFileSync(
    process.execPath,
    [npmPath, "install", "--ignore-scripts", "--no-audit", "--no-fund", tarball],
    { cwd: consumer, stdio: "pipe", windowsHide: true },
  );
  runtime = await loadRuntime(consumer, tarball, scanner);
}, 120000);
afterAll(() => rmSync(root, { recursive: true, force: true }));
afterEach(() => vi.unstubAllEnvs());

let sequence = 0;
async function prepared(families: Record<string, Record<string, string>>) {
  const folder = join(root, `case-${sequence++}`),
    content = join(folder, "content");
  mkdirSync(content, { recursive: true });
  const items = [];
  for (const [path, files] of Object.entries(families)) {
    const inventory = [];
    for (const [local, text] of Object.entries(files)) {
      const target = join(content, path, local);
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, text);
      chmodSync(target, 0o644);
      inventory.push({ path: local, mode: "100644", sha256: hash(text) });
    }
    const key = await runtime.contracts.scanKeyOf(
      Object.entries(files).map(([path, text]) => ({
        path,
        mode: "100644" as const,
        bytes: new TextEncoder().encode(text),
      })),
    );
    if (key.status !== "ok") throw new Error("Fixture key");
    items.push({
      path,
      scanKey: key.scanKey,
      files: inventory,
      labels: { caller: `unsigned-${path}` },
    });
  }
  const manifest = { format: "aih-scan-prepared/1", scanner, assessment, items };
  const bytes = Buffer.from(JSON.stringify(manifest)),
    manifestPath = join(folder, "manifest.json");
  writeFileSync(manifestPath, bytes);
  return {
    folder,
    content,
    manifest,
    manifestPath,
    manifestSha256: hash(bytes),
    consumer,
    tarball,
    out: join(folder, "state"),
    concurrency: 2,
    workerMemoryMiB: 1,
    reserveMemoryMiB: 0,
  };
}
const skill = {
  "SKILL.md": "---\nname: greeter\ndescription: Greets users.\n---\n# Greeting\nSay hello.\n",
};

describe("prepared manifest and exact inventory", () => {
  it.runIf(process.env.AIH_SCAN_TEST_SKILLSPECTOR !== undefined)(
    "rejects installed module shadowing and alternate bytecode carriers",
    () => {
      execFileSync(
        maintenancePythonPath(process.env.AIH_SCAN_TEST_SKILLSPECTOR!),
        ["-I", join(repo, "tests/support/maintenance-verifier.test.py")],
        { windowsHide: true, stdio: "pipe" },
      );
    },
  );

  it("locates the maintenance verifier interpreter beside the selected executable", () => {
    expect(maintenancePythonPath("C:\\tools\\venv\\Scripts\\skillspector.exe", "win32")).toBe(
      "C:\\tools\\venv\\Scripts\\python.exe",
    );
    expect(maintenancePythonPath("/tmp/venv/bin/skillspector", "linux")).toBe(
      "/tmp/venv/bin/python",
    );
  });
  it("binds maintenance identity and rejects invalid TP4 controls without requests", async () => {
    const setup = await prepared({ item: skill });
    const artifact = JSON.parse(
      readFileSync(join(repo, "tools/analyzers/skillspector/maintenance/artifact.json"), "utf8"),
    );
    const valid = {
      version: artifact.version,
      wheelSha256: artifact.wheelSha256,
      tp4: { maxFiles: 256, maxFindings: 256, maxBatches: 256 },
    };
    const validate = (skillspector: unknown) => {
      const bytes = Buffer.from(
        JSON.stringify({ ...setup.manifest, assessment: { ...assessment, skillspector } }),
      );
      return validateManifest(bytes, hash(bytes));
    };
    expect(validate(valid).assessment.skillspector).toEqual(valid);
    for (const value of [0, -1, 1.5, "256", 4097, null])
      expect(() => validate({ ...valid, tp4: { ...valid.tp4, maxFiles: value } })).toThrow(
        "TP4 capacity",
      );
    expect(() => validate({ ...valid, version: "2.13.3" })).toThrow("identity");
    expect(() => validate({ ...valid, wheelSha256: "0".repeat(64) })).toThrow("identity");
    expect(
      validateManifest(Buffer.from(JSON.stringify(setup.manifest)), setup.manifestSha256)
        .assessment,
    ).not.toHaveProperty("skillspector");
  });

  it("durably records unsigned host refusal diagnostics when a child input disappears", async () => {
    const setup = await prepared({ item: skill });
    const attempt = join(setup.folder, "failed-state/attempts/one");
    mkdirSync(attempt, { recursive: true });
    const request = join(attempt, "request.json");
    writeFileSync(
      request,
      JSON.stringify({
        scanner,
        assessment: { mode: "static", tools: assessment.tools },
        consumer,
        tarball,
        folder: join(setup.folder, "missing-input"),
        item: setup.manifest.items[0],
        out: join(attempt, "output"),
      }),
    );
    execFileSync(
      process.execPath,
      [join(repo, "tools/publisher/prepared.mjs"), "worker", request],
      {
        windowsHide: true,
      },
    );
    const receipt = JSON.parse(readFileSync(join(attempt, "result.json"), "utf8"));
    expect(receipt.record).toMatchObject({ status: "failed", detail: "refused" });
    expect(receipt.record.notes).toEqual([
      "not-a-folder: the folder does not exist or cannot be read",
    ]);
    expect(receipt.record).not.toHaveProperty("summary");
  });
  it("accepts only explicit positive safe integer AI concurrency and keeps static controls empty", async () => {
    const setup = await prepared({ item: skill });
    const validate = (controls: Record<string, unknown>) => {
      const bytes = Buffer.from(JSON.stringify({ ...setup.manifest, assessment: controls }));
      return validateManifest(bytes, hash(bytes));
    };
    expect(validate({ ...assessment, llmConcurrency: 24 }).assessment).toMatchObject({
      llmConcurrency: 24,
    });
    expect(validate(assessment).assessment).not.toHaveProperty("llmConcurrency");
    for (const value of [0, -1, 1.5, "10", null, Number.MAX_SAFE_INTEGER + 1])
      expect(() => validate({ ...assessment, llmConcurrency: value })).toThrow("concurrency");
    expect(() => validate({ mode: "static", tools: assessment.tools, llmConcurrency: 2 })).toThrow(
      "Static assessment",
    );
  });
  it("validates explicit model token metadata without accepting a caller registry path", async () => {
    const setup = await prepared({ item: skill });
    const validate = (controls: Record<string, unknown>) => {
      const bytes = Buffer.from(JSON.stringify({ ...setup.manifest, assessment: controls }));
      return validateManifest(bytes, hash(bytes));
    };
    const modelTokenLimits = { contextLength: 1048576, maxOutputTokens: 131072 };
    expect(validate({ ...assessment, modelTokenLimits }).assessment).toMatchObject({
      modelTokenLimits,
    });
    expect(validate(assessment).assessment).not.toHaveProperty("modelTokenLimits");
    for (const value of [0, -1, 1.5, "10", null, Number.MAX_SAFE_INTEGER + 1]) {
      expect(() =>
        validate({
          ...assessment,
          modelTokenLimits: { ...modelTokenLimits, contextLength: value },
        }),
      ).toThrow("token");
      expect(() =>
        validate({
          ...assessment,
          modelTokenLimits: { ...modelTokenLimits, maxOutputTokens: value },
        }),
      ).toThrow("token");
    }
    for (const value of [
      null,
      [],
      "registry.json",
      {},
      { contextLength: 100 },
      { maxOutputTokens: 10 },
      { ...modelTokenLimits, path: "registry.json" },
    ])
      expect(() => validate({ ...assessment, modelTokenLimits: value })).toThrow();
    expect(() =>
      validate({ ...assessment, modelTokenLimits: { contextLength: 100, maxOutputTokens: 101 } }),
    ).toThrow("context");
    expect(() => validate({ ...assessment, modelRegistry: "registry.json" })).toThrow();
    expect(() => validate({ mode: "static", tools: assessment.tools, modelTokenLimits })).toThrow(
      "Static assessment",
    );
  });
  it("atomically flushes and replaces a native checkpoint using a writable descriptor", () => {
    const path = join(root, "native-checkpoint.json");
    writeCheckpointAtomic(path, { completed: ["first"] });
    writeCheckpointAtomic(path, { completed: ["first", "second"] });
    expect(JSON.parse(readFileSync(path, "utf8"))).toEqual({ completed: ["first", "second"] });
  });
  it("retains outstanding worker reservations across refill waves without double-counting resident memory", () => {
    // Initial headroom is 800 MiB. Three unallocated 200 MiB workers remain after
    // a fast peer finishes; only one replacement can be reserved, even if RSS lags.
    expect(workerLaunchBudget(1000, 200, 800, 600)).toBe(200);
    expect(workerLaunchBudget(1000, 200, 800, 800)).toBe(0);
    // If those residents are reflected in free RAM, do not subtract their whole
    // reservation from free RAM again: the remaining estimate still permits one.
    expect(workerLaunchBudget(400, 200, 800, 600)).toBe(200);
    expect(workerLaunchBudget(150, 200, 800, 600)).toBe(0);
  });
  it("binds bytes, paths, modes and keys, across unrelated content families", async () => {
    const setup = await prepared({
      "plain-skill": skill,
      "plugin-family": {
        "plugin.json": '{"name":"example"}',
        "agents/helper.md": "Summarise text.",
      },
    });
    const manifest = validateManifest(readFileSync(setup.manifestPath), setup.manifestSha256);
    expect((await validateContent(manifest, setup.content, runtime)).size).toBe(2);
    writeFileSync(join(setup.content, "plain-skill/SKILL.md"), "changed");
    await expect(validateContent(manifest, setup.content, runtime)).rejects.toThrow(
      "digest mismatch",
    );
  });
  it("refuses malformed manifests, traversal, expected key changes and extra files", async () => {
    const setup = await prepared({ item: skill });
    expect(() => validateManifest(readFileSync(setup.manifestPath), "0".repeat(64))).toThrow(
      "digest",
    );
    const changed = structuredClone(setup.manifest);
    changed.items[0]!.path = "../escape";
    const unsafe = Buffer.from(JSON.stringify(changed));
    expect(() => validateManifest(unsafe, hash(unsafe))).toThrow("relative path");
    const notLoopback = {
      ...setup.manifest,
      assessment: { ...assessment, baseUrl: "http://127.example.com" },
    };
    const notLoopbackBytes = Buffer.from(JSON.stringify(notLoopback));
    expect(() => validateManifest(notLoopbackBytes, hash(notLoopbackBytes))).toThrow(
      "HTTPS or loopback",
    );
    changed.items[0]!.path = "item";
    changed.items[0]!.scanKey = `git-sha1:${"a".repeat(40)}`;
    await expect(validateContent(changed, setup.content, runtime)).rejects.toThrow("key mismatch");
    writeFileSync(join(setup.content, "item/extra.txt"), "x");
    await expect(validateContent(setup.manifest, setup.content, runtime)).rejects.toThrow(
      "extra inventory",
    );
  });
  it.runIf(process.platform !== "win32")("refuses mode-only changes and links", async () => {
    const setup = await prepared({ item: skill });
    const file = join(setup.content, "item/SKILL.md");
    chmodSync(file, 0o755);
    await expect(validateContent(setup.manifest, setup.content, runtime)).rejects.toThrow(
      "mode mismatch",
    );
    chmodSync(file, 0o644);
    symlinkSync("SKILL.md", join(setup.content, "item/link"));
    await expect(validateContent(setup.manifest, setup.content, runtime)).rejects.toThrow("Links");
  });
  it("refuses installed scanner bytes that differ from the reviewed package", async () => {
    await expect(
      loadRuntime(consumer, tarball, { ...scanner, tarballSha256: "0".repeat(64) }),
    ).rejects.toThrow("tarball digest");
  });
  it("matches declared executable modes using actual bytes through the portable installed reader", async () => {
    const setup = await prepared({ item: { "script.sh": "#!/bin/sh\necho hello\n" } });
    const item = setup.manifest.items[0]!;
    item.files[0]!.mode = "100755";
    if (process.platform !== "win32") chmodSync(join(setup.content, "item/script.sh"), 0o755);
    const key = await runtime.contracts.scanKeyOf([
      {
        path: "script.sh",
        mode: "100755",
        bytes: readFileSync(join(setup.content, "item/script.sh")),
      },
    ]);
    if (key.status !== "ok") throw new Error("Fixture executable key");
    item.scanKey = key.scanKey;
    await validateContent(setup.manifest, setup.content, runtime);
    vi.stubEnv("AIH_SCAN_SKILLSPECTOR", "none");
    const result = await runtime.host.scan(
      {
        format: "aih-scan-request/1",
        origin: "published",
        items: [{ path: join(setup.content, "item"), executable: ["script.sh"] }],
      },
      { outDir: join(setup.folder, "mode-output") },
    );
    const resultItem = result.results[0];
    if (resultItem?.status !== "ok") throw new Error("Fixture result");
    const summaryPath = resultItem.summaryPath;
    const read = runtime.read.readSummary(readFileSync(summaryPath));
    if (read.status !== "ok") throw new Error("Fixture summary");
    const summary = read.summary;
    const record = {
      status: "incomplete",
      summary: "summary.json",
      summarySha256: hash(readFileSync(summaryPath)),
      sarif: summary.sarif,
      elapsedMs: 1,
    };
    expect(
      (
        await verifyResult(
          dirname(summaryPath),
          record,
          [item],
          setup.manifest,
          setup.content,
          runtime,
        )
      ).eligible,
    ).toBe(false);
  });
});

describe.runIf(process.platform !== "win32")(
  "prepared local scans through the installed public API (synthetic analyzer)",
  () => {
    function analyzer(folder: string, complete = true) {
      return fakeAnalyzer(folder, "skillspector", {
        versionText: "SkillSpector v2.13.3",
        outputFlag: "--output",
        report: skillSpectorReport([], {
          llm: complete,
          analyzerStatuses: [
            {
              analyzer_id: "semantic_security_discovery",
              status: complete ? "completed" : "failed",
            },
          ],
          provenance: {
            provider: { effective_adapter: "openai_compatible" },
            analyzers: [{ analyzer_id: "semantic_security_discovery", model: "deepseek-flash" }],
          },
        }),
      });
    }
    it("binds explicit child LLM concurrency to reuse while omission and static mode scrub ambient controls", async () => {
      const setup = await prepared({ item: skill });
      const ss = analyzer(setup.folder);
      vi.stubEnv("AIH_SCAN_SKILLSPECTOR", ss.path);
      vi.stubEnv("DEEPSEEK_API", "fixture-not-a-real-key");
      vi.stubEnv("SKILLSPECTOR_MAX_LLM_CONCURRENCY", "999");
      const ambientRegistry = join(setup.folder, "caller-registry.json");
      writeFileSync(ambientRegistry, "caller file must not be read or changed");
      vi.stubEnv("SKILLSPECTOR_MODEL_REGISTRY", ambientRegistry);
      const first = await scanPrepared(setup);
      expect((await scanPrepared(setup)).reused).toBe(1);
      expect(ss.calls().find((call) => call.args[0] === "scan")!.env).not.toHaveProperty(
        "SKILLSPECTOR_MAX_LLM_CONCURRENCY",
      );
      expect(ss.calls().find((call) => call.args[0] === "scan")!.env).not.toHaveProperty(
        "SKILLSPECTOR_MODEL_REGISTRY",
      );
      const bytes = Buffer.from(
        JSON.stringify({
          ...setup.manifest,
          assessment: { ...assessment, llmConcurrency: 24 },
        }),
      );
      writeFileSync(setup.manifestPath, bytes);
      const explicit = { ...setup, manifestSha256: hash(bytes) };
      const changed = await scanPrepared(explicit);
      expect(changed).toMatchObject({ reused: 0, completed: 1 });
      expect(changed.root).not.toBe(first.root);
      expect((await scanPrepared(explicit)).reused).toBe(1);
      const scans = ss.calls().filter((call) => call.args[0] === "scan");
      expect(scans).toHaveLength(2);
      expect(scans[1]!.env.SKILLSPECTOR_MAX_LLM_CONCURRENCY).toBe("24");
      const receipt = JSON.parse(readFileSync(changed.receiptPath, "utf8"));
      expect(receipt.config.assessment.llmConcurrency).toBe(24);
      expect(receipt.scheduler.concurrency).toBe(2);
      const modelTokenLimits = { contextLength: 1048576, maxOutputTokens: 131072 };
      const tokenBytes = Buffer.from(
        JSON.stringify({
          ...setup.manifest,
          assessment: { ...assessment, llmConcurrency: 24, modelTokenLimits },
        }),
      );
      writeFileSync(setup.manifestPath, tokenBytes);
      const tokenProfile = { ...setup, manifestSha256: hash(tokenBytes) };
      const tokenRun = await scanPrepared(tokenProfile);
      expect(tokenRun).toMatchObject({ reused: 0, completed: 1 });
      expect(tokenRun.root).not.toBe(changed.root);
      const tokenReceipt = JSON.parse(readFileSync(tokenRun.receiptPath, "utf8"));
      expect(tokenReceipt.config.assessment.modelTokenLimits).toEqual(modelTokenLimits);
      const record = tokenReceipt.results[setup.manifest.items[0]!.scanKey];
      const attempt = join(tokenRun.root, record.summary.split("/").slice(0, 2).join("/"));
      const registryPath = ss.calls().filter((call) => call.args[0] === "scan")[2]!
        .env.SKILLSPECTOR_MODEL_REGISTRY;
      expect(registryPath).toBe(join(attempt, "model-registry.json"));
      expect(JSON.parse(readFileSync(registryPath!, "utf8"))).toEqual({
        models: {
          "deepseek-flash": { context_length: 1048576, max_output_tokens: 131072 },
        },
      });
      expect(readFileSync(registryPath!, "utf8")).not.toContain("fixture-not-a-real-key");
      expect(await scanPrepared(tokenProfile)).toMatchObject({ reused: 1, completed: 0 });
      writeFileSync(setup.manifestPath, bytes);
      expect(await scanPrepared(explicit)).toMatchObject({ reused: 1, completed: 0 });
      expect(ss.calls().filter((call) => call.args[0] === "scan")).toHaveLength(3);
      expect(readFileSync(ambientRegistry, "utf8")).toBe("caller file must not be read or changed");
      const staticBytes = Buffer.from(
        JSON.stringify({
          ...setup.manifest,
          assessment: { mode: "static", tools: assessment.tools },
        }),
      );
      writeFileSync(setup.manifestPath, staticBytes);
      await scanPrepared({ ...setup, manifestSha256: hash(staticBytes) });
      const staticCall = ss
        .calls()
        .filter((call) => call.args[0] === "scan")
        .at(-1)!;
      expect(staticCall.args).toContain("--no-llm");
      expect(staticCall.env).not.toHaveProperty("SKILLSPECTOR_MAX_LLM_CONCURRENCY");
      expect(staticCall.env).not.toHaveProperty("SKILLSPECTOR_COMPAT_API_KEY");
      expect(staticCall.env).not.toHaveProperty("SKILLSPECTOR_MODEL_REGISTRY");
    }, 120000);
    it.each([
      ["fixture-secret-value-166", "fixture-secret-value-166"],
      [" \tfixture-edge-whitespace-166\r\n", "fixture-edge-whitespace-166"],
      ["\u0085fixture-python-nel-166\u0085", "fixture-python-nel-166"],
      ["\u001cfixture-python-separator-166\u001f", "fixture-python-separator-166"],
    ])(
      "retains credential-redacted unsigned partial diagnostics in receipts and checkpoints only (%j)",
      async (secret, effectiveSecret) => {
        const setup = await prepared({ item: skill });
        const ss = fakeAnalyzer(setup.folder, "skillspector", {
          versionText: "SkillSpector v2.13.3",
          outputFlag: "--output",
          report: skillSpectorReport([], {
            llm: false,
            ledgerExceptions: [
              { reason_code: `fixture failure ${effectiveSecret} ${effectiveSecret}`, fatal: true },
            ],
          }),
        });
        vi.stubEnv("AIH_SCAN_SKILLSPECTOR", ss.path);
        vi.stubEnv("DEEPSEEK_API", secret);
        const result = await scanPrepared(setup);
        const receipt = JSON.parse(readFileSync(result.receiptPath, "utf8"));
        const record = receipt.results[setup.manifest.items[0]!.scanKey];
        expect(record.status).toBe("incomplete");
        expect(record.notes).toContain(
          "SkillSpector reported partial inspection: fixture failure [REDACTED] [REDACTED]",
        );
        const checkpoint = JSON.parse(readFileSync(join(result.root, "checkpoint.json"), "utf8"));
        expect(checkpoint.results[setup.manifest.items[0]!.scanKey].notes).toEqual(record.notes);
        const attempt = join(result.root, record.summary.split("/").slice(0, 2).join("/"));
        expect(JSON.parse(readFileSync(join(attempt, "result.json"), "utf8")).record.notes).toEqual(
          record.notes,
        );
        for (const path of [
          result.receiptPath,
          join(result.root, "checkpoint.json"),
          join(attempt, "result.json"),
          join(attempt, "request.json"),
        ])
          expect(readFileSync(path, "utf8")).not.toContain(effectiveSecret);
        const summary = readFileSync(join(result.root, record.summary), "utf8");
        expect(summary).not.toContain("fixture failure");
        expect(summary).not.toContain("[REDACTED]");
        const items = setup.manifest.items;
        expect(
          (await verifyResult(result.root, record, items, setup.manifest, setup.content, runtime))
            .eligible,
        ).toBe(false);
        for (const notes of ["bad", [5], ["x".repeat(4097)], ["bad\u0000note"]])
          await expect(
            verifyResult(
              result.root,
              { ...record, notes },
              items,
              setup.manifest,
              setup.content,
              runtime,
            ),
          ).rejects.toThrow("notes");
        const { notes: _notes, ...legacy } = record;
        expect(
          (await verifyResult(result.root, legacy, items, setup.manifest, setup.content, runtime))
            .eligible,
        ).toBe(false);
      },
      120000,
    );
    it("deduplicates, resumes pilot results into a larger manifest and imports only reviewed output bytes", async () => {
      const setup = await prepared({
        first: skill,
        duplicate: skill,
        "plugin-family": {
          "plugin.json": '{"name":"example"}',
          "agents/helper.md": "Summarise text.",
        },
      });
      const ss = analyzer(setup.folder);
      vi.stubEnv("AIH_SCAN_SKILLSPECTOR", ss.path);
      vi.stubEnv("DEEPSEEK_API", "fixture-not-a-real-key");
      const pilot = { ...setup.manifest, items: setup.manifest.items.slice(0, 1) };
      const bytes = Buffer.from(JSON.stringify(pilot));
      writeFileSync(setup.manifestPath, bytes);
      const first = await scanPrepared({ ...setup, manifestSha256: hash(bytes) });
      expect(first.completed).toBe(1);
      expect(first.uniqueKeys).toBe(1);
      const checkpointPath = join(first.root, "checkpoint.json");
      rmSync(checkpointPath);
      const orphan = await recoverPrepared({ ...setup, manifestSha256: hash(bytes) });
      expect(orphan.recovered).toBe(1);
      expect(orphan.completedKeys).toHaveLength(1);
      // Older workers may have no durable result receipt at all. The original
      // request and actual completed output still permit verified recovery.
      const firstCheckpoint = JSON.parse(readFileSync(checkpointPath, "utf8"));
      const firstRecord = Object.values(firstCheckpoint.results)[0] as { summary: string };
      const attemptPath = resolve(first.root, firstRecord.summary.split("/").slice(0, 2).join("/"));
      rmSync(join(attemptPath, "result.json"));
      rmSync(checkpointPath);
      expect((await recoverPrepared({ ...setup, manifestSha256: hash(bytes) })).recovered).toBe(1);
      writeFileSync(setup.manifestPath, JSON.stringify(setup.manifest));
      const interrupted = await scanPrepared({ ...setup, signal: AbortSignal.abort() });
      expect(interrupted).toMatchObject({ reused: 1, completed: 0, pending: 1, cancelled: true });
      const full = await scanPrepared(setup);
      expect(full).toMatchObject({ completed: 1, reused: 1, uniqueKeys: 2, references: 3 });
      expect(ss.calls().filter((call) => call.args[0] === "scan")).toHaveLength(2);
      const combined = { ...setup, out: join(setup.folder, "merged-state") };
      const merged = await mergePrepared({ ...combined, receipts: [full.receiptPath] });
      expect(merged.imported).toBe(2);
      expect(await scanPrepared(combined)).toMatchObject({ reused: 2, completed: 0 });
      const mergedCheckpointPath = join(merged.root, "checkpoint.json");
      const mergedCheckpoint = JSON.parse(readFileSync(mergedCheckpointPath, "utf8"));
      mergedCheckpoint.results[setup.manifest.items[0]!.scanKey].summarySha256 = "0".repeat(64);
      writeFileSync(mergedCheckpointPath, JSON.stringify(mergedCheckpoint));
      await expect(recoverPrepared(combined)).rejects.toThrow("Summary digest");
      const archive = join(setup.folder, "candidate.tar");
      const withNotes = JSON.parse(readFileSync(full.receiptPath, "utf8"));
      for (const record of Object.values(withNotes.results) as { notes?: string[] }[])
        record.notes = ["unsigned local diagnostic"];
      const notedReceipt = join(full.root, "with-notes.json");
      writeFileSync(notedReceipt, JSON.stringify(withNotes));
      const exported = await exportCandidate({
        ...setup,
        receiptPath: notedReceipt,
        out: archive,
      });
      const importedCli = join(setup.folder, "imported-cli");
      const cliResult = JSON.parse(
        execFileSync(
          process.execPath,
          [
            join(repo, "tools/publisher/prepared.mjs"),
            "import",
            archive,
            exported.archiveSha256,
            exported.manifestSha256,
            exported.receiptSha256,
            consumer,
            importedCli,
          ],
          { encoding: "utf8", windowsHide: true },
        ),
      );
      expect(cliResult.execution).toBe("local");
      expect(cliResult.summaries).toHaveLength(2);
      const imported = join(setup.folder, "imported");
      const verified = await importCandidate(
        archive,
        exported.archiveSha256,
        exported.manifestSha256,
        exported.receiptSha256,
        consumer,
        imported,
      );
      expect(verified.summaries).toHaveLength(2);
      expect(readFileSync(join(imported, "receipt.json"), "utf8")).not.toContain(
        "unsigned local diagnostic",
      );
      const paths = [...readArchive(readFileSync(archive)).keys()];
      expect(paths.some((path) => path.startsWith("content/"))).toBe(false);
      for (const path of verified.summaries)
        expect(readFileSync(join(imported, path), "utf8")).not.toContain("unsigned-");
      const resultRecord = verified.receipt.results[setup.manifest.items[0]!.scanKey];
      if (!resultRecord?.sarif[0]) throw new Error("Fixture SARIF");
      const sarif = resultRecord.sarif[0].path;
      writeFileSync(join(imported, sarif), "{}");
      await expect(
        verifyCandidate(
          imported,
          exported.manifestSha256,
          exported.receiptSha256,
          consumer,
          join(imported, "scanner.tgz"),
        ),
      ).rejects.toThrow("SARIF");
    }, 120000);
    it("retains failed/static fallback results for retry and refuses them as completed AI evidence", async () => {
      const setup = await prepared({ item: skill });
      const ss = analyzer(setup.folder, false);
      vi.stubEnv("AIH_SCAN_SKILLSPECTOR", ss.path);
      vi.stubEnv("DEEPSEEK_API", "fixture-not-a-real-key");
      const result = await scanPrepared(setup);
      const receipt = JSON.parse(readFileSync(result.receiptPath, "utf8"));
      expect(receipt.results[setup.manifest.items[0]!.scanKey].status).toBe("incomplete");
      await expect(
        exportCandidate({
          ...setup,
          receiptPath: result.receiptPath,
          out: join(setup.folder, "refused.tar"),
        }),
      ).rejects.toThrow("complete AI");
      expect((await scanPrepared(setup)).completed).toBe(1);
    }, 120000);
  },
);

it.runIf(process.env.AIH_SCAN_TEST_SKILLSPECTOR !== undefined)(
  "binds real prepared child HTTP output budgets to explicit token metadata and reuses both profiles",
  async () => {
    const service = await compatibleAiServiceV1();
    try {
      const setup = await prepared({ item: skill });
      vi.stubEnv("AIH_SCAN_SKILLSPECTOR", process.env.AIH_SCAN_TEST_SKILLSPECTOR!);
      vi.stubEnv("DEEPSEEK_API", "fixture-only-not-a-real-key");
      vi.stubEnv("SKILLSPECTOR_MODEL_REGISTRY", join(setup.folder, "unreadable-ambient-registry"));
      const profile = (contextLength: number, maxOutputTokens: number) => {
        const bytes = Buffer.from(
          JSON.stringify({
            ...setup.manifest,
            assessment: {
              ...assessment,
              baseUrl: service.endpoint,
              modelTokenLimits: { contextLength, maxOutputTokens },
            },
          }),
        );
        writeFileSync(setup.manifestPath, bytes);
        return { ...setup, manifestSha256: hash(bytes) };
      };
      const large = await scanPrepared(profile(1048576, 131072));
      const largeReceipt = JSON.parse(readFileSync(large.receiptPath, "utf8"));
      expect(largeReceipt.results[setup.manifest.items[0]!.scanKey].status).toBe("complete-ai");
      expect(service.requests.length).toBeGreaterThan(0);
      expect(new Set(service.requests.map((request) => request.max_completion_tokens))).toEqual(
        new Set([131072]),
      );
      const before = service.requests.length;
      const capped = await scanPrepared(profile(32768, 16384));
      expect(capped).toMatchObject({ reused: 0, completed: 1 });
      expect(capped.root).not.toBe(large.root);
      const cappedReceipt = JSON.parse(readFileSync(capped.receiptPath, "utf8"));
      expect(cappedReceipt.results[setup.manifest.items[0]!.scanKey].status).toBe("complete-ai");
      const cappedRequests = service.requests.slice(before);
      expect(cappedRequests.length).toBeGreaterThan(0);
      expect(new Set(cappedRequests.map((request) => request.max_completion_tokens))).toEqual(
        new Set([8192]),
      );
      const requests = service.requests.length;
      expect(await scanPrepared(profile(1048576, 131072))).toMatchObject({
        reused: 1,
        completed: 0,
      });
      expect(await scanPrepared(profile(32768, 16384))).toMatchObject({ reused: 1, completed: 0 });
      expect(service.requests).toHaveLength(requests);
      expect(readFileSync(large.receiptPath, "utf8")).not.toContain("fixture-only-not-a-real-key");
    } finally {
      await service.close();
    }
  },
  180000,
);

it.runIf(process.env.AIH_SCAN_TEST_SKILLSPECTOR !== undefined)(
  "uses the locked real SkillSpector concurrency control through prepared children and reuses each profile",
  async () => {
    const service = await compatibleAiServiceV1({ delayMs: 150 });
    try {
      const files = { ...skill } as Record<string, string>;
      for (let index = 0; index < 6; index++)
        files[`notes/topic-${index}.md`] =
          `# Topic ${index}\n\nSummarise the supplied text carefully.\n`;
      const setup = await prepared({ item: files });
      vi.stubEnv("AIH_SCAN_SKILLSPECTOR", process.env.AIH_SCAN_TEST_SKILLSPECTOR!);
      vi.stubEnv("DEEPSEEK_API", "fixture-only-not-a-real-key");
      const profile = (llmConcurrency: number) => {
        const bytes = Buffer.from(
          JSON.stringify({
            ...setup.manifest,
            assessment: { ...assessment, baseUrl: service.endpoint, llmConcurrency },
          }),
        );
        writeFileSync(setup.manifestPath, bytes);
        return { ...setup, manifestSha256: hash(bytes), concurrency: 1 };
      };
      const serial = await scanPrepared(profile(1));
      const serialReceipt = JSON.parse(readFileSync(serial.receiptPath, "utf8"));
      expect(serialReceipt.results[setup.manifest.items[0]!.scanKey].status).toBe("complete-ai");
      expect(service.security).toEqual({ started: 7, completed: 7, active: 0, maxActive: 1 });
      const parallel = await scanPrepared(profile(3));
      expect(parallel).toMatchObject({ reused: 0, completed: 1 });
      expect(parallel.root).not.toBe(serial.root);
      const receipt = JSON.parse(readFileSync(parallel.receiptPath, "utf8"));
      expect(receipt.results[setup.manifest.items[0]!.scanKey].status).toBe("complete-ai");
      expect(service.security).toEqual({ started: 14, completed: 14, active: 0, maxActive: 3 });
      for (const path of Object.keys(files))
        expect(
          service.requests.filter(
            (request) =>
              JSON.stringify(request.messages).includes("intent and attack-phrasing risks") &&
              JSON.stringify(request.messages).includes(path),
          ),
        ).toHaveLength(2);
      const requests = service.requests.length;
      expect(await scanPrepared(profile(3))).toMatchObject({ reused: 1, completed: 0 });
      expect(await scanPrepared(profile(1))).toMatchObject({ reused: 1, completed: 0 });
      expect(service.requests).toHaveLength(requests);
      expect(readFileSync(parallel.receiptPath, "utf8")).not.toContain(
        "fixture-only-not-a-real-key",
      );
    } finally {
      await service.close();
    }
  },
  180000,
);

describe("prepared transport and eligibility", () => {
  it("refuses private literal addresses before any HTTPS request (literal IPs bypass DNS lookup)", async () => {
    await expect(
      downloadArchive(
        {
          url: "https://127.0.0.1/candidate.tar",
          allowedHosts: ["127.0.0.1"],
          sha256: "a".repeat(64),
        },
        join(root, "never-downloaded.tar"),
      ),
    ).rejects.toThrow("Non-public");
    expect(existsSync(join(root, "never-downloaded.tar"))).toBe(false);
  });
  it("refuses static fallback or partial metadata regardless of a clean risk label", () => {
    const base = {
      origin: "published",
      coverage: "complete",
      tools: [
        { tool: "aih-trust-lint", result: "pass" },
        {
          tool: "skillspector",
          version: "2.13.3",
          result: "pass",
          mode: "ai",
          ai: { via: "provider", provider: "openai_compatible", model: "deepseek-flash" },
        },
      ],
    };
    expect(aiEligible(base, { assessment })).toBe(true);
    expect(aiEligible({ ...base, coverage: "partial" }, { assessment })).toBe(false);
    expect(
      aiEligible(
        { ...base, tools: [{ tool: "skillspector", mode: "static", result: "pass" }] },
        { assessment },
      ),
    ).toBe(false);
  });
  it("round-trips regular-file ustar, rejecting digest corruption, traversal and links before writing", () => {
    const archive = join(root, `tar-${sequence++}.tar`);
    writeArchive([{ path: "safe/data.json", bytes: Buffer.from("{}") }], archive);
    const bytes = readFileSync(archive);
    expect(readArchive(bytes).get("safe/data.json")!.bytes.toString()).toBe("{}");
    const corrupted = Buffer.from(bytes);
    corrupted[0] = (corrupted[0] ?? 0) ^ 1;
    expect(() => readArchive(corrupted)).toThrow("checksum");
    expect(() =>
      writeArchive([{ path: "../escape", bytes: Buffer.from("x") }], join(root, "bad.tar")),
    ).toThrow("relative path");
    const out = join(root, `extract-${sequence++}`);
    extractArchive(bytes, out);
    expect(readFileSync(join(out, "safe/data.json"), "utf8")).toBe("{}");
    expect(() => extractArchive(bytes, out)).toThrow();
    expect(digest(bytes)).toBe(hash(bytes));
  });
});

it.runIf(process.env.AIH_SCAN_TEST_SKILLSPECTOR_WHEEL !== undefined)(
  "retains complete TP4 sources and findings through an explicit maintenance prepared profile",
  async () => {
    const service = await compatibleAiServiceV1({ tp4Mismatch: true });
    vi.stubEnv("AIH_SCAN_SKILLSPECTOR_WHEEL", process.env.AIH_SCAN_TEST_SKILLSPECTOR_WHEEL!);
    try {
      const files: Record<string, string> = { ...skill };
      for (let i = 0; i < 129; i++) files[`code-${i}.py`] = `print(${i})\n`;
      const setup = await prepared({ item: files });
      vi.stubEnv("AIH_SCAN_SKILLSPECTOR", process.env.AIH_SCAN_TEST_SKILLSPECTOR!);
      vi.stubEnv("DEEPSEEK_API", "fixture-only-not-a-real-key");
      const bytes = Buffer.from(
        JSON.stringify({
          ...setup.manifest,
          assessment: {
            ...assessment,
            baseUrl: service.endpoint,
            llmConcurrency: 24,
            skillspector: {
              version:
                "2.13.3+aih.1.beab0672042e0e41eab09e381ccecd8a9db96d34a78dacddf16c737dd73cc855",
              wheelSha256: "18a124e7bd0d368ddf87926d00b43692f73a4b05cee450531d6a93ad1163b751",
              tp4: { maxFiles: 256, maxFindings: 256, maxBatches: 256 },
            },
          },
        }),
      );
      writeFileSync(setup.manifestPath, bytes);
      const result = await scanPrepared({ ...setup, manifestSha256: hash(bytes) });
      const receipt = JSON.parse(readFileSync(result.receiptPath, "utf8"));
      const record = receipt.results[setup.manifest.items[0]!.scanKey];
      expect(record.status, JSON.stringify(record)).toBe("complete-ai");
      const summary = JSON.parse(readFileSync(join(result.root, record.summary), "utf8"));
      expect(summary.files).toHaveLength(130);
      expect(
        summary.tools.find((tool: { tool: string }) => tool.tool === "skillspector").version,
      ).toBe("2.13.3+aih.1.beab0672042e0e41eab09e381ccecd8a9db96d34a78dacddf16c737dd73cc855");
      const sarif = record.sarif
        .map((entry: { path: string }) => readFileSync(join(result.root, entry.path), "utf8"))
        .join("\n");
      expect(sarif.match(/"ruleId"\s*:\s*"TP4"/g)?.length).toBeGreaterThan(64);
      const requests = service.requests.length;
      expect(await scanPrepared({ ...setup, manifestSha256: hash(bytes) })).toMatchObject({
        reused: 1,
        completed: 0,
      });
      expect(service.requests).toHaveLength(requests);
    } finally {
      await service.close();
    }
  },
  180000,
);
