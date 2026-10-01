import { spawn, spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test } from "vitest";
import { parse } from "yaml";
import { prepareArtifact, signArtifact } from "../../src/public/host.js";
import { readArtifact } from "../../src/public/read.js";
import { emptyReport } from "../assessment/fixtures.js";

const hash = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const run = (tool: string, args: string[]) =>
  spawnSync(process.execPath, [join(process.cwd(), "tools", "artifact", tool), ...args], {
    encoding: "utf8",
  });

describe("restricted publisher", () => {
  test("unsigned candidate preparation cannot replace an existing or concurrently claimed output directory", async () => {
    const temporary = mkdtempSync(join(tmpdir(), "scan-candidate-race-"));
    try {
      const prepared = await prepareArtifact({ report: emptyReport(), annexes: [] });
      const input = join(temporary, "run.json");
      writeFileSync(
        input,
        JSON.stringify({
          schema: "urn:aihq:scan:run-result:1.0.0",
          status: "assessment",
          scanId: prepared.scanId,
          report: emptyReport(),
          annexes: [],
          diagnostics: [],
        }),
      );
      const output = join(temporary, "candidate");
      const invoke = () =>
        new Promise<number | null>((resolve, reject) => {
          const child = spawn(
            process.execPath,
            [join(process.cwd(), "tools/artifact/prepare-candidate.mjs"), input, output],
            { stdio: "ignore" },
          );
          child.once("error", reject);
          child.once("exit", resolve);
        });
      expect((await Promise.all([invoke(), invoke()])).sort()).toEqual([0, 2]);
      const original = readFileSync(join(output, "artifact.json"));
      expect(run("prepare-candidate.mjs", [input, output]).status).toBe(2);
      expect(readFileSync(join(output, "artifact.json"))).toEqual(original);
      expect(await readArtifact(original)).toMatchObject({
        status: "read",
        authenticity: "unchecked",
      });
    } finally {
      rmSync(temporary, { recursive: true, force: true });
    }
  });
  test("a merge cannot invoke the activated publisher and signing is confined to its dedicated exact identity", () => {
    const path = ".github/workflows/scan-report-publisher.yml";
    const workflow = parse(readFileSync(path, "utf8"));
    expect(existsSync(".github/workflow-templates/scan-report-publisher.yml")).toBe(true);
    expect(Object.keys(workflow.on)).toEqual(["workflow_dispatch"]);
    expect(workflow.permissions).toEqual({});
    expect(workflow.jobs["bounded-candidate"].permissions["id-token"]).toBeUndefined();
    const signer = workflow.jobs.signer;
    expect(signer.environment).toBe("scan-report-signing-prod");
    expect(signer.permissions["id-token"]).toBe("write");
    for (const required of [
      "github.event_name == 'workflow_dispatch'",
      "1336836161",
      "9993940",
      "refs/heads/main",
      ".github/workflows/scan-report-publisher.yml@refs/heads/main",
      "github.sha == vars.SCAN_REPORT_REVIEWED_HEAD",
    ])
      expect(signer.if).toContain(required);
    const downloads = signer.steps.filter((s: { uses?: string }) =>
      s.uses?.startsWith("actions/download-artifact@"),
    );
    expect(downloads.map((s: { with: { name: string } }) => s.with.name)).toEqual([
      "checked-detached-statement",
    ]);
    expect(workflow.jobs["authenticate-before-promotion"].permissions["id-token"]).toBeUndefined();
    expect(JSON.stringify(workflow.jobs["authenticate-before-promotion"].steps)).toContain(
      "verify-promotion.mjs",
    );
    for (const job of Object.values(workflow.jobs) as { steps: { uses?: string }[] }[]) {
      for (const step of job.steps)
        if (step.uses) expect(step.uses).toMatch(/^[a-z-]+\/[a-z-]+@[0-9a-f]{40}$/);
    }
  });
  test("the inert independently selected trust pins public roots and exact repo, caller, ref and runner DER values", () => {
    const trust = JSON.parse(
      readFileSync(".github/workflow-templates/scan-report-trust.candidate.json", "utf8"),
    );
    expect(trust.keys).toEqual([]);
    const publisher = trust.publishers[0];
    expect(publisher.policy.subjectAlternativeName).toBe(
      "https://github.com/samartomar/aih-scan/.github/workflows/scan-report-publisher.yml@refs/heads/main",
    );
    expect(publisher.policy.issuer).toBe("https://token.actions.githubusercontent.com");
    const values = new Map(
      publisher.policy.requiredCertificateExtensions.map(
        (extension: { oid: number[]; valueDerBase64: string }) => [
          extension.oid.at(-1),
          Buffer.from(extension.valueDerBase64, "base64"),
        ],
      ),
    );
    for (const [oid, expected] of [
      [11, "github-hosted"],
      [14, "refs/heads/main"],
      [15, "1336836161"],
      [17, "9993940"],
      [18, publisher.policy.subjectAlternativeName],
      [20, "workflow_dispatch"],
      [22, "public"],
    ] as const) {
      const bytes = values.get(oid) as Buffer;
      expect(bytes[0]).toBe(12);
      expect(bytes.subarray(bytes[1] === 0x81 ? 3 : 2).toString()).toBe(expected);
    }
    expect(
      publisher.trustedRoot.tlogs.some(
        (l: { baseUrl: string }) => l.baseUrl === "https://rekor.sigstore.dev",
      ),
    ).toBe(true);
    expect(
      publisher.trustedRoot.tlogs.some((l: { baseUrl: string }) => l.baseUrl.includes("github")),
    ).toBe(false);
  });
  test("trusted detached checker accepts only the reviewed digest and promotion requires independent authentication", async () => {
    const temporary = mkdtempSync(join(tmpdir(), "scan-publisher-"));
    try {
      const annex = Buffer.from("nonempty publication conformance bytes\n");
      const report = emptyReport();
      report.annexes = [
        { id: "annex.raw", mediaType: "text/plain", sha256: hash(annex), byteLength: annex.length },
      ];
      const input = { report, annexes: [{ id: "annex.raw", bytes: annex }] };
      const prepared = await prepareArtifact(input);
      const statement = Buffer.from(JSON.stringify(prepared.statement));
      const statementPath = join(temporary, "statement.json"),
        predicatePath = join(temporary, "predicate.json");
      writeFileSync(statementPath, statement);
      expect(
        run("check-statement.mjs", [statementPath, hash(statement), predicatePath]).status,
      ).toBe(0);
      expect(JSON.parse(readFileSync(predicatePath, "utf8"))).toEqual(prepared.statement.predicate);
      const refused = join(temporary, "refused.json");
      expect(run("check-statement.mjs", [statementPath, "0".repeat(64), refused]).status).toBe(2);
      expect(existsSync(refused)).toBe(false);
      const key = generateKeyPairSync("ed25519"),
        spki = key.publicKey.export({ type: "spki", format: "der" }),
        keyId = `ed25519:${hash(spki)}`;
      const signed = await signArtifact({
        ...input,
        signer: { keyId, privateKey: key.privateKey },
      });
      const unsignedPath = join(temporary, "artifact.json"),
        bundlePath = join(temporary, "bundle.json"),
        trustPath = join(temporary, "trust.json"),
        promotedPath = join(temporary, "promoted.json");
      writeFileSync(unsignedPath, prepared.bytes);
      writeFileSync(bundlePath, JSON.stringify(signed.artifact.attestation));
      writeFileSync(
        trustPath,
        JSON.stringify({
          keys: [
            { identity: "test-only-operator", keyId, publicKeySpkiBase64: spki.toString("base64") },
          ],
          publishers: [],
        }),
      );
      expect(
        run("verify-promotion.mjs", [
          unsignedPath,
          bundlePath,
          trustPath,
          prepared.scanId,
          promotedPath,
        ]).status,
      ).toBe(0);
      expect(await readArtifact(readFileSync(promotedPath))).toMatchObject({
        status: "read",
        annexBytes: "checked",
        authenticity: "unchecked",
      });
      writeFileSync(trustPath, JSON.stringify({ keys: [], publishers: [] }));
      const untrusted = join(temporary, "untrusted.json");
      expect(
        run("verify-promotion.mjs", [
          unsignedPath,
          bundlePath,
          trustPath,
          prepared.scanId,
          untrusted,
        ]).status,
      ).toBe(2);
      expect(existsSync(untrusted)).toBe(false);
      expect(
        run("verify-promotion.mjs", [
          unsignedPath,
          bundlePath,
          trustPath,
          prepared.scanId,
          promotedPath,
        ]).status,
      ).toBe(2);
    } finally {
      rmSync(temporary, { recursive: true, force: true });
    }
  });
});
