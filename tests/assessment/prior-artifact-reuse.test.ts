import { createHash, generateKeyPairSync, sign } from "node:crypto";
import * as fsBoundary from "node:fs";
import { linkSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test, vi } from "vitest";
import {
  type AuthenticationTrust,
  attachAttestation,
  authenticateArtifact,
  prepareArtifact,
  runScan,
  type ScanRequest,
  signArtifact,
} from "../../src/public/host.js";
import { readArtifact } from "../../src/public/read.js";

const roots: string[] = [];
vi.mock("node:fs", async (importOriginal) => ({
  ...(await importOriginal<typeof import("node:fs")>()),
}));
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object")
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`)
      .join(",")}}`;
  return JSON.stringify(value);
}
const hash = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});
function fixture() {
  const root = mkdtempSync(join(tmpdir(), "aih-prior-artifact-test-"));
  roots.push(root);
  const source = join(root, "source");
  mkdirSync(source);
  writeFileSync(join(source, "SKILL.md"), "# Independent prior artifact fixture\n");
  const request: ScanRequest = {
    schema: "urn:aihq:scan:request:1.0.0",
    source: { kind: "local", path: source },
    selection: { paths: "all", excludedPaths: [] },
    detectors: [{ detectorId: "detector.aih-native", configuration: {} }],
  };
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ type: "spki", format: "der" });
  const keyId = `ed25519:${createHash("sha256").update(spki).digest("hex")}`;
  const trust: AuthenticationTrust = {
    keys: [
      {
        identity: "independent-test-organization",
        keyId,
        publicKeySpkiBase64: spki.toString("base64"),
      },
    ],
    publishers: [],
  };
  return { root, request, trust, signer: { keyId, privateKey } };
}

test("an independently authenticated supported artifact preserves the observation and annex in a current assessment", async () => {
  const { root, request, trust, signer } = fixture();
  const original = await runScan(request);
  expect(original.status).toBe("assessment");
  if (original.status !== "assessment") throw new Error("Fixture assessment required");
  const signed = await signArtifact({
    report: original.report,
    annexes: original.annexes.map(({ id, bytesBase64 }) => ({
      id,
      bytes: Buffer.from(bytesBase64, "base64"),
    })),
    signer,
  });
  expect((await readArtifact(signed.bytes)).status).toBe("read");
  const path = join(root, "prior.json");
  writeFileSync(path, signed.bytes);
  const current = await runScan(
    {
      ...request,
      priorArtifacts: [{ scanId: original.scanId, location: { kind: "file", path } }],
    },
    { reuseTrust: trust },
  );
  expect(current).toMatchObject({
    status: "assessment",
    report: {
      results: [
        { outcome: "succeeded", observations: [{ origin: "reused", fromScanId: original.scanId }] },
      ],
    },
  });
  if (current.status !== "assessment") throw new Error("Current assessment required");
  const observation = current.report.results[0]?.observations[0];
  const originalObservation = original.report.results[0]?.observations[0];
  if (!observation || !originalObservation) throw new Error("Fixture observations required");
  expect(observation.body).toEqual(originalObservation.body);
  expect(observation.observationId).toBe(originalObservation.observationId);
  expect(current.annexes).toEqual(original.annexes);
  expect(current.report.annexes).toEqual(original.report.annexes);
  expect(current.scanId).not.toBe(original.scanId);
  expect(current.report.source).toEqual(original.report.source);
});

test("untrusted prior evidence falls back to fresh work without exposing its locator", async () => {
  const context = await signedFixture();
  const trust = { keys: [], publishers: [] };
  const current = await runScan(
    {
      ...context.request,
      priorArtifacts: [
        { scanId: context.original.scanId, location: { kind: "file", path: context.path } },
      ],
    },
    { reuseTrust: trust },
  );
  expect(current).toMatchObject({
    status: "assessment",
    diagnostics: [expect.objectContaining({ code: "reuse-miss" })],
    report: { results: [{ outcome: "succeeded", observations: [{ origin: "fresh" }] }] },
  });
  expect(JSON.stringify(current)).not.toContain(context.root);
});

test("malformed prior evidence falls back to fresh work without exposing its locator", async () => {
  const context = await signedFixture();
  writeFileSync(context.path, "not an artifact");
  const current = await runScan(
    {
      ...context.request,
      priorArtifacts: [
        { scanId: context.original.scanId, location: { kind: "file", path: context.path } },
      ],
    },
    { reuseTrust: context.trust },
  );
  expect(current).toMatchObject({
    status: "assessment",
    diagnostics: [expect.objectContaining({ code: "reuse-miss" })],
    report: { results: [{ outcome: "succeeded", observations: [{ origin: "fresh" }] }] },
  });
  expect(JSON.stringify(current)).not.toContain(context.root);
});

test("missing prior evidence falls back to fresh work without exposing its locator", async () => {
  const context = await signedFixture();
  rmSync(context.path);
  const current = await runScan(
    {
      ...context.request,
      priorArtifacts: [
        { scanId: context.original.scanId, location: { kind: "file", path: context.path } },
      ],
    },
    { reuseTrust: context.trust },
  );
  expect(current).toMatchObject({
    status: "assessment",
    diagnostics: [expect.objectContaining({ code: "reuse-miss" })],
    report: { results: [{ outcome: "succeeded", observations: [{ origin: "fresh" }] }] },
  });
  expect(JSON.stringify(current)).not.toContain(context.root);
});

test("wrong-ID prior evidence falls back to fresh work without exposing its locator", async () => {
  const context = await signedFixture();

  const current = await runScan(
    {
      ...context.request,
      priorArtifacts: [
        { scanId: `scan:sha256:${"0".repeat(64)}`, location: { kind: "file", path: context.path } },
      ],
    },
    { reuseTrust: context.trust },
  );
  expect(current).toMatchObject({
    status: "assessment",
    diagnostics: [expect.objectContaining({ code: "reuse-miss" })],
    report: { results: [{ outcome: "succeeded", observations: [{ origin: "fresh" }] }] },
  });
  expect(JSON.stringify(current)).not.toContain(context.root);
});

test("independent authentication of opaque report bytes cannot admit unsupported detailed observations", async () => {
  const context = await signedFixture();
  const reportBytes = Buffer.from('{"schema":"urn:example:opaque-report:9.0.0"}');
  const scanId =
    `scan:sha256:${hash(Buffer.concat([Buffer.from(`aih.scan.report.v1${String.fromCharCode(0)}`), reportBytes]))}` as const;
  const { attestation: _attestation, ...originalArtifact } = context.signed.artifact;
  const artifact = {
    ...originalArtifact,
    scanId,
    report: {
      schema: "urn:example:opaque-report:9.0.0",
      mediaType: "application/json",
      sha256: hash(reportBytes),
      byteLength: reportBytes.length,
      bytesBase64: reportBytes.toString("base64"),
    },
  };
  const descriptors = artifact.annexes.map(({ bytesBase64: _bytes, ...descriptor }) => descriptor);
  const statement = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "scan-report", digest: { sha256: hash(reportBytes) } }],
    predicateType: "urn:aihq:scan:artifact-attestation:1.0.0",
    predicate: {
      scanId,
      reportSchema: artifact.report.schema,
      reportByteLength: reportBytes.length,
      annexManifestSha256: hash(Buffer.from(canonical(descriptors))),
    },
  };
  const payload = Buffer.from(canonical(statement));
  const payloadType = "application/vnd.in-toto+json";
  const signature = sign(
    null,
    Buffer.concat([
      Buffer.from(`DSSEv1 ${Buffer.byteLength(payloadType)} ${payloadType} ${payload.length} `),
      payload,
    ]),
    context.signer.privateKey,
  );
  const opaque = await attachAttestation({
    bytes: Buffer.from(canonical(artifact)),
    bundle: {
      mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
      verificationMaterial: { publicKey: { hint: context.signer.keyId }, tlogEntries: [] },
      dsseEnvelope: {
        payloadType,
        payload: payload.toString("base64"),
        signatures: [{ keyid: context.signer.keyId, sig: signature.toString("base64") }],
      },
    },
  });
  expect(
    await authenticateArtifact({
      bytes: opaque.bytes,
      expectedScanId: scanId,
      trust: context.trust,
    }),
  ).toMatchObject({ status: "authenticated", reportRead: "not-requested" });
  expect(await readArtifact(opaque.bytes)).toMatchObject({ status: "unsupported-report" });
  writeFileSync(context.path, opaque.bytes);
  const current = await runScan(
    {
      ...context.request,
      priorArtifacts: [{ scanId, location: { kind: "file", path: context.path } }],
    },
    { reuseTrust: context.trust },
  );
  expect(current).toMatchObject({
    status: "assessment",
    diagnostics: [expect.objectContaining({ code: "reuse-miss" })],
    report: { results: [{ outcome: "succeeded", observations: [{ origin: "fresh" }] }] },
  });
});

test("tampered signature prior input cannot borrow completed findings", async () => {
  const context = await signedFixture();
  const artifact = structuredClone(context.signed.artifact);
  if (!artifact.attestation) throw new Error("Signed fixture required");
  artifact.attestation.dsseEnvelope.signatures[0] = {
    keyid: context.signer.keyId,
    sig: Buffer.alloc(64).toString("base64"),
  };
  const bytes = Buffer.from(canonical(artifact));
  expect((await readArtifact(bytes)).status).toBe("read");
  writeFileSync(context.path, bytes);
  const current = await runScan(
    {
      ...context.request,
      priorArtifacts: [
        { scanId: context.original.scanId, location: { kind: "file", path: context.path } },
      ],
    },
    { reuseTrust: context.trust },
  );
  expect(current).toMatchObject({
    status: "assessment",
    diagnostics: [expect.objectContaining({ code: "reuse-miss" })],
    report: { results: [{ outcome: "succeeded", observations: [{ origin: "fresh" }] }] },
  });
});

test("tampered annex prior input cannot borrow completed findings", async () => {
  const context = await signedFixture();
  const artifact = structuredClone(context.signed.artifact);
  if (!artifact.annexes[0]) throw new Error("Annex fixture required");
  artifact.annexes[0].bytesBase64 = Buffer.from("substituted evidence").toString("base64");
  const bytes = Buffer.from(canonical(artifact));
  expect((await readArtifact(bytes)).status).toBe("invalid");
  writeFileSync(context.path, bytes);
  const current = await runScan(
    {
      ...context.request,
      priorArtifacts: [
        { scanId: context.original.scanId, location: { kind: "file", path: context.path } },
      ],
    },
    { reuseTrust: context.trust },
  );
  expect(current).toMatchObject({
    status: "assessment",
    diagnostics: [expect.objectContaining({ code: "reuse-miss" })],
    report: { results: [{ outcome: "succeeded", observations: [{ origin: "fresh" }] }] },
  });
});

test("an explicitly selected HTTPS prior streams only its chosen URL with redirects and credentials disabled", async () => {
  const context = await signedFixture();
  const url = "https://evidence.example.test/selected-artifact.json";
  const transport = vi.fn(
    async (_url: string, _options: RequestInit) =>
      new Response(
        new ReadableStream({
          start(controller) {
            const midpoint = Math.floor(context.signed.bytes.length / 2);
            controller.enqueue(context.signed.bytes.slice(0, midpoint));
            controller.enqueue(context.signed.bytes.slice(midpoint));
            controller.close();
          },
        }),
      ),
  );
  vi.stubGlobal("fetch", transport);
  const current = await runScan(
    {
      ...context.request,
      priorArtifacts: [{ scanId: context.original.scanId, location: { kind: "https", url } }],
    },
    {
      reuseTrust: context.trust,
      gitCredentials: { username: "fixture-user", password: "fixture-password" },
    },
  );
  expect(current).toMatchObject({
    status: "assessment",
    report: { results: [{ observations: [{ origin: "reused" }] }] },
  });
  expect(transport.mock.calls).toHaveLength(1);
  expect(transport.mock.calls[0]).toEqual([
    url,
    expect.objectContaining({
      redirect: "error",
      credentials: "omit",
      signal: expect.any(AbortSignal),
    }),
  ]);
  expect(transport.mock.calls[0]?.[1]).not.toHaveProperty("headers");
  expect(JSON.stringify(current)).not.toContain("fixture-password");
  if (current.status === "assessment") expect(current.annexes).toEqual(context.original.annexes);
});

test("HTTPS stream overflow cancels acquisition and performs honest fresh work", async () => {
  const context = await signedFixture();
  const cancelled = vi.fn();
  const maxArtifactBytes = context.signed.bytes.length + 512;
  vi.stubGlobal(
    "fetch",
    async () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(context.signed.bytes);
            controller.enqueue(new Uint8Array(maxArtifactBytes));
          },
          cancel: cancelled,
        }),
      ),
  );
  const current = await runScan(
    {
      ...context.request,
      limits: { maxArtifactBytes },
      priorArtifacts: [
        {
          scanId: context.original.scanId,
          location: { kind: "https", url: "https://evidence.example.test/oversized" },
        },
      ],
    },
    { reuseTrust: context.trust },
  );
  expect(current).toMatchObject({
    status: "assessment",
    diagnostics: [expect.objectContaining({ code: "reuse-miss" })],
    report: { results: [{ observations: [{ origin: "fresh" }] }] },
  });
  expect(cancelled).toHaveBeenCalledOnce();
});

test("a refused HTTPS redirect cannot acquire another origin or disclose upstream errors", async () => {
  const context = await signedFixture();
  const transport = vi.fn(async (_url: string, _options: RequestInit) => {
    throw new Error("private upstream redirect detail");
  });
  vi.stubGlobal("fetch", transport);
  const current = await runScan(
    {
      ...context.request,
      priorArtifacts: [
        {
          scanId: context.original.scanId,
          location: { kind: "https", url: "https://evidence.example.test/redirect" },
        },
      ],
    },
    { reuseTrust: context.trust },
  );
  expect(current).toMatchObject({
    status: "assessment",
    diagnostics: [expect.objectContaining({ code: "reuse-miss" })],
    report: { results: [{ observations: [{ origin: "fresh" }] }] },
  });
  expect(transport.mock.calls).toHaveLength(1);
  expect(transport.mock.calls[0]?.[1]).toMatchObject({ redirect: "error", credentials: "omit" });
  expect(JSON.stringify(current)).not.toContain("private upstream");
});

test("HTTPS cancellation after capture retains an assessment and leaves requested work cancelled", async () => {
  const context = await signedFixture();
  const controller = new AbortController();
  vi.stubGlobal(
    "fetch",
    async (_url: string, options: RequestInit) =>
      new Promise((_resolve, reject) => {
        options.signal?.addEventListener(
          "abort",
          () => reject(new Error("private transport cancellation")),
          { once: true },
        );
        controller.abort();
      }),
  );
  const current = await runScan(
    {
      ...context.request,
      priorArtifacts: [
        {
          scanId: context.original.scanId,
          location: { kind: "https", url: "https://evidence.example.test/cancel" },
        },
      ],
    },
    { reuseTrust: context.trust, signal: controller.signal },
  );
  expect(current).toMatchObject({
    status: "assessment",
    diagnostics: [expect.objectContaining({ code: "reuse-miss" })],
    report: {
      completion: "partial",
      results: [
        { outcome: "cancelled", observations: [], coverage: { uncoveredPaths: ["SKILL.md"] } },
      ],
    },
  });
  expect(JSON.stringify(current)).not.toContain("private transport");
});

test("a stalled HTTPS prior reaches its finite deadline and leaves current detector work available", async () => {
  const context = await signedFixture();
  vi.stubGlobal(
    "fetch",
    async (_url: string, options: RequestInit) =>
      new Promise((_resolve, reject) => {
        options.signal?.addEventListener("abort", () => reject(options.signal?.reason), {
          once: true,
        });
      }),
  );
  const current = await runScan(
    {
      ...context.request,
      limits: { detectorTimeoutMs: 100 },
      priorArtifacts: [
        {
          scanId: context.original.scanId,
          location: { kind: "https", url: "https://evidence.example.test/stalled" },
        },
      ],
    },
    { reuseTrust: context.trust },
  );
  expect(current).toMatchObject({
    status: "assessment",
    diagnostics: [expect.objectContaining({ code: "reuse-miss" })],
    report: { results: [{ outcome: "succeeded", observations: [{ origin: "fresh" }] }] },
  });
});

test.each([
  "file",
  "https",
] as const)("aggregate %s prior acquisition preserves the first admitted observation when later bytes exceed the budget", async (kind) => {
  const context = await signedFixture();
  if (kind === "https") vi.stubGlobal("fetch", async () => new Response(context.signed.bytes));
  const location =
    kind === "file"
      ? { kind, path: context.path }
      : { kind, url: "https://evidence.example.test/aggregate" };
  const current = await runScan(
    {
      ...context.request,
      limits: { maxArtifactBytes: context.signed.bytes.length * 2 - 1 },
      priorArtifacts: [
        { scanId: context.original.scanId, location },
        { scanId: context.original.scanId, location },
      ],
    },
    { reuseTrust: context.trust },
  );
  expect(current).toMatchObject({
    status: "assessment",
    diagnostics: [expect.objectContaining({ code: "reuse-miss" })],
    report: {
      results: [
        {
          outcome: "succeeded",
          observations: [{ origin: "reused", fromScanId: context.original.scanId }],
        },
      ],
    },
  });
  if (current.status === "assessment") expect(current.annexes).toEqual(context.original.annexes);
});

test("the retained decoded prior budget cannot discard an earlier validated candidate", async () => {
  const context = await signedFixture();
  const decoded =
    context.signed.artifact.report.byteLength +
    context.signed.artifact.annexes.reduce((sum, annex) => sum + annex.byteLength, 0);
  const prior = {
    scanId: context.original.scanId,
    location: { kind: "file" as const, path: context.path },
  };
  const current = await runScan(
    {
      ...context.request,
      limits: { maxDecodedArtifactBytes: decoded * 2 - 1 },
      priorArtifacts: [prior, prior],
    },
    { reuseTrust: context.trust },
  );
  expect(current).toMatchObject({
    status: "assessment",
    diagnostics: [expect.objectContaining({ code: "reuse-miss" })],
    report: { results: [{ outcome: "succeeded", observations: [{ origin: "reused" }] }] },
  });
});

test("a prior locator without independent trust never triggers HTTPS lookup", async () => {
  const context = await signedFixture();
  const transport = vi.fn();
  vi.stubGlobal("fetch", transport);
  const current = await runScan({
    ...context.request,
    priorArtifacts: [
      {
        scanId: context.original.scanId,
        location: { kind: "https", url: "https://evidence.example.test/no-trust" },
      },
    ],
  });
  expect(current).toMatchObject({
    status: "assessment",
    diagnostics: [expect.objectContaining({ code: "reuse-miss" })],
    report: { results: [{ outcome: "succeeded", observations: [{ origin: "fresh" }] }] },
  });
  expect(transport).not.toHaveBeenCalled();
});

test.for([
  "hardlink",
  "symlink",
] as const)("an artifact %s cannot substitute for an explicitly selected stable regular file", async (kind, {
  skip,
}) => {
  const context = await signedFixture();
  const linked = join(context.root, "linked-prior.json");
  try {
    if (kind === "hardlink") linkSync(context.path, linked);
    else symlinkSync(context.path, linked, "file");
  } catch (error) {
    if (
      error instanceof Error &&
      "code" in error &&
      ["EPERM", "EACCES", "ENOTSUP"].includes(String(error.code))
    ) {
      skip();
      return;
    }
    throw error;
  }
  const path = kind === "hardlink" ? context.path : linked;
  const current = await runScan(
    {
      ...context.request,
      priorArtifacts: [{ scanId: context.original.scanId, location: { kind: "file", path } }],
    },
    { reuseTrust: context.trust },
  );
  expect(current).toMatchObject({
    status: "assessment",
    diagnostics: [expect.objectContaining({ code: "reuse-miss" })],
    report: { results: [{ outcome: "succeeded", observations: [{ origin: "fresh" }] }] },
  });
  expect(JSON.stringify(current)).not.toContain(path);
});

test("authentic old observations retain their original times and producer across a current assessment", async () => {
  const context = await signedFixture();
  const observation = context.input.report.results[0]?.observations[0];
  if (!observation) throw new Error("Fixture observation required");
  observation.body.startedAt = "2000-01-01T00:00:00.000Z";
  observation.body.completedAt = "2000-01-01T00:00:01.000Z";
  observation.body.producer.version = "0.0.1";
  observation.observationId = `observation:sha256:${hash(Buffer.concat([Buffer.from(`aih.scan.observation.v1${String.fromCharCode(0)}`), Buffer.from(canonical(observation.body))]))}`;
  const historical = await signArtifact({ ...context.input, signer: context.signer });
  expect((await readArtifact(historical.bytes)).status).toBe("read");
  writeFileSync(context.path, historical.bytes);
  const current = await runScan(
    {
      ...context.request,
      priorArtifacts: [
        { scanId: historical.scanId, location: { kind: "file", path: context.path } },
      ],
    },
    { reuseTrust: context.trust },
  );
  expect(current).toMatchObject({
    status: "assessment",
    report: {
      results: [
        {
          observations: [
            {
              origin: "reused",
              fromScanId: historical.scanId,
              observationId: observation.observationId,
              body: {
                startedAt: "2000-01-01T00:00:00.000Z",
                completedAt: "2000-01-01T00:00:01.000Z",
                producer: { version: "0.0.1" },
              },
            },
          ],
        },
      ],
    },
  });
  if (current.status === "assessment")
    expect(current.report.results[0]?.observations[0]?.body).toEqual(observation.body);
});

test("authenticated rules input mismatch cannot supply the current observation", async () => {
  const context = await signedFixture();
  const observation = context.input.report.results[0]?.observations[0];
  if (!observation) throw new Error("Fixture observation required");
  observation.body.input.rulesSha256 = "0".repeat(64);
  observation.observationId = `observation:sha256:${hash(Buffer.concat([Buffer.from(`aih.scan.observation.v1${String.fromCharCode(0)}`), Buffer.from(canonical(observation.body))]))}`;
  const changed = await signArtifact({ ...context.input, signer: context.signer });
  expect((await readArtifact(changed.bytes)).status).toBe("read");
  expect(
    (
      await authenticateArtifact({
        bytes: changed.bytes,
        expectedScanId: changed.scanId,
        trust: context.trust,
      })
    ).status,
  ).toBe("authenticated");
  writeFileSync(context.path, changed.bytes);
  const current = await runScan(
    {
      ...context.request,
      priorArtifacts: [{ scanId: changed.scanId, location: { kind: "file", path: context.path } }],
    },
    { reuseTrust: context.trust },
  );
  expect(current).toMatchObject({
    status: "assessment",
    report: { results: [{ outcome: "succeeded", observations: [{ origin: "fresh" }] }] },
  });
  if (current.status === "assessment") {
    expect(current.report.results[0]?.observations[0]?.observationId).not.toBe(
      observation.observationId,
    );
    expect(
      current.diagnostics.some((diagnostic) => diagnostic.code === "reuse-miss") ||
        current.report.results[0]?.diagnostics.some(
          (diagnostic) => diagnostic.code === "reuse-miss",
        ),
    ).toBe(true);
  }
});

test("authenticated profile input mismatch cannot supply the current observation", async () => {
  const context = await signedFixture();
  const observation = context.input.report.results[0]?.observations[0];
  if (!observation) throw new Error("Fixture observation required");
  observation.body.input.profileSha256 = "0".repeat(64);
  observation.observationId = `observation:sha256:${hash(Buffer.concat([Buffer.from(`aih.scan.observation.v1${String.fromCharCode(0)}`), Buffer.from(canonical(observation.body))]))}`;
  const changed = await signArtifact({ ...context.input, signer: context.signer });
  expect((await readArtifact(changed.bytes)).status).toBe("read");
  expect(
    (
      await authenticateArtifact({
        bytes: changed.bytes,
        expectedScanId: changed.scanId,
        trust: context.trust,
      })
    ).status,
  ).toBe("authenticated");
  writeFileSync(context.path, changed.bytes);
  const current = await runScan(
    {
      ...context.request,
      priorArtifacts: [{ scanId: changed.scanId, location: { kind: "file", path: context.path } }],
    },
    { reuseTrust: context.trust },
  );
  expect(current).toMatchObject({
    status: "assessment",
    report: { results: [{ outcome: "succeeded", observations: [{ origin: "fresh" }] }] },
  });
  if (current.status === "assessment") {
    expect(current.report.results[0]?.observations[0]?.observationId).not.toBe(
      observation.observationId,
    );
    expect(
      current.diagnostics.some((diagnostic) => diagnostic.code === "reuse-miss") ||
        current.report.results[0]?.diagnostics.some(
          (diagnostic) => diagnostic.code === "reuse-miss",
        ),
    ).toBe(true);
  }
});

test("authenticated platform input mismatch cannot supply the current observation", async () => {
  const context = await signedFixture();
  const observation = context.input.report.results[0]?.observations[0];
  if (!observation) throw new Error("Fixture observation required");
  observation.body.input.platform.relevantFactsSha256 = "0".repeat(64);
  observation.observationId = `observation:sha256:${hash(Buffer.concat([Buffer.from(`aih.scan.observation.v1${String.fromCharCode(0)}`), Buffer.from(canonical(observation.body))]))}`;
  const changed = await signArtifact({ ...context.input, signer: context.signer });
  expect((await readArtifact(changed.bytes)).status).toBe("read");
  expect(
    (
      await authenticateArtifact({
        bytes: changed.bytes,
        expectedScanId: changed.scanId,
        trust: context.trust,
      })
    ).status,
  ).toBe("authenticated");
  writeFileSync(context.path, changed.bytes);
  const current = await runScan(
    {
      ...context.request,
      priorArtifacts: [{ scanId: changed.scanId, location: { kind: "file", path: context.path } }],
    },
    { reuseTrust: context.trust },
  );
  expect(current).toMatchObject({
    status: "assessment",
    report: { results: [{ outcome: "succeeded", observations: [{ origin: "fresh" }] }] },
  });
  if (current.status === "assessment") {
    expect(current.report.results[0]?.observations[0]?.observationId).not.toBe(
      observation.observationId,
    );
    expect(
      current.diagnostics.some((diagnostic) => diagnostic.code === "reuse-miss") ||
        current.report.results[0]?.diagnostics.some(
          (diagnostic) => diagnostic.code === "reuse-miss",
        ),
    ).toBe(true);
  }
});

test("authenticated configuration input mismatch cannot supply the current observation", async () => {
  const context = await signedFixture();
  const observation = context.input.report.results[0]?.observations[0];
  if (!observation) throw new Error("Fixture observation required");
  const requested = context.input.report.requestedDetectors[0];
  if (!requested) throw new Error("Requested detector fixture required");
  requested.configuration = { fixture: "different" };
  requested.configurationSha256 = hash(Buffer.from(canonical(requested.configuration)));
  observation.body.input.configurationSha256 = requested.configurationSha256;
  observation.observationId = `observation:sha256:${hash(Buffer.concat([Buffer.from(`aih.scan.observation.v1${String.fromCharCode(0)}`), Buffer.from(canonical(observation.body))]))}`;
  const changed = await signArtifact({ ...context.input, signer: context.signer });
  expect((await readArtifact(changed.bytes)).status).toBe("read");
  expect(
    (
      await authenticateArtifact({
        bytes: changed.bytes,
        expectedScanId: changed.scanId,
        trust: context.trust,
      })
    ).status,
  ).toBe("authenticated");
  writeFileSync(context.path, changed.bytes);
  const current = await runScan(
    {
      ...context.request,
      priorArtifacts: [{ scanId: changed.scanId, location: { kind: "file", path: context.path } }],
    },
    { reuseTrust: context.trust },
  );
  expect(current).toMatchObject({
    status: "assessment",
    report: { results: [{ outcome: "succeeded", observations: [{ origin: "fresh" }] }] },
  });
  if (current.status === "assessment") {
    expect(current.report.results[0]?.observations[0]?.observationId).not.toBe(
      observation.observationId,
    );
    expect(
      current.diagnostics.some((diagnostic) => diagnostic.code === "reuse-miss") ||
        current.report.results[0]?.diagnostics.some(
          (diagnostic) => diagnostic.code === "reuse-miss",
        ),
    ).toBe(true);
  }
});

test("replacement of the artifact path during its descriptor read is an explained miss", async () => {
  const context = await signedFixture();
  const actualRead = fsBoundary.readSync;
  let replaced = false;
  vi.spyOn(fsBoundary, "readSync").mockImplementation(((
    ...args: Parameters<typeof fsBoundary.readSync>
  ) => {
    const count = Reflect.apply(actualRead, fsBoundary, args);
    if (!replaced && fsBoundary.fstatSync(args[0]).size === context.signed.bytes.length) {
      fsBoundary.renameSync(context.path, `${context.path}.old`);
      writeFileSync(context.path, context.signed.bytes);
      replaced = true;
    }
    return count;
  }) as typeof fsBoundary.readSync);
  const current = await runScan(
    {
      ...context.request,
      priorArtifacts: [
        { scanId: context.original.scanId, location: { kind: "file", path: context.path } },
      ],
    },
    { reuseTrust: context.trust },
  );
  expect(replaced).toBe(true);
  expect(current).toMatchObject({
    status: "assessment",
    diagnostics: [expect.objectContaining({ code: "reuse-miss" })],
    report: { results: [{ outcome: "succeeded", observations: [{ origin: "fresh" }] }] },
  });
});

async function signedFixture() {
  const context = fixture();
  const original = await runScan(context.request);
  if (original.status !== "assessment") throw new Error("Fixture assessment required");
  const input = {
    report: original.report,
    annexes: original.annexes.map(({ id, bytesBase64 }) => ({
      id,
      bytes: Buffer.from(bytesBase64, "base64"),
    })),
  };
  const signed = await signArtifact({ ...input, signer: context.signer });
  const path = join(context.root, "prior.json");
  writeFileSync(path, signed.bytes);
  return { ...context, original, input, signed, path };
}

test("unsigned readable prior evidence produces an explained miss and reliable fresh work", async () => {
  const context = await signedFixture();
  const unsigned = await prepareArtifact(context.input);
  expect((await readArtifact(unsigned.bytes)).status).toBe("read");
  writeFileSync(context.path, unsigned.bytes);
  const current = await runScan(
    {
      ...context.request,
      priorArtifacts: [
        { scanId: context.original.scanId, location: { kind: "file", path: context.path } },
      ],
    },
    { reuseTrust: context.trust },
  );
  expect(current).toMatchObject({
    status: "assessment",
    diagnostics: [expect.objectContaining({ code: "reuse-miss" })],
    report: { results: [{ outcome: "succeeded", observations: [{ origin: "fresh" }] }] },
  });
  expect(JSON.stringify(current)).not.toContain(context.root);
});
