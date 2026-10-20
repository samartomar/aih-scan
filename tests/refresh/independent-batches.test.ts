import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { expect, test } from "vitest";
import { parse } from "yaml";

test("five independent packed captures keep reports, matching, mixed outcomes, signing and subset custody", () => {
  const root = resolve(import.meta.dirname, "../.."),
    temporary = mkdtempSync(join(tmpdir(), "scan-independent-batches-"));
  try {
    const npm = [
      process.env.npm_execpath,
      join(dirname(process.execPath), "node_modules/npm/bin/npm-cli.js"),
      resolve(dirname(process.execPath), "../lib/node_modules/npm/bin/npm-cli.js"),
    ].find((path): path is string => typeof path === "string" && existsSync(path));
    expect(npm).toBeDefined();
    const run = (args: string[], cwd: string) =>
      spawnSync(process.execPath, args, {
        cwd,
        encoding: "utf8",
        windowsHide: true,
        maxBuffer: 16 * 1024 * 1024,
        timeout: 180000,
        env: Object.fromEntries(
          Object.entries(process.env).filter(([key]) => !/^npm_config_allow_scripts$/i.test(key)),
        ),
      });
    const packed = run(
      [npm as string, "pack", "--ignore-scripts", "--json", "--pack-destination", temporary],
      root,
    );
    expect(packed.status, packed.stderr).toBe(0);
    const tarball = join(temporary, JSON.parse(packed.stdout)[0].filename),
      consumer = join(temporary, "consumer");
    mkdirSync(consumer);
    writeFileSync(
      join(consumer, "package.json"),
      JSON.stringify({
        name: "capture-batch-fixture",
        version: "0.0.0",
        private: true,
        type: "module",
      }),
    );
    const installed = run(
      [npm as string, "install", "--ignore-scripts", "--no-audit", "--no-fund", tarball],
      consumer,
    );
    expect(installed.status, installed.stderr).toBe(0);
    const boundary = join(temporary, "fixture-runtime.cjs");
    // Portable runtime/precondition boundary only; real Linux profile proof is separate.
    writeFileSync(
      boundary,
      `const fs=require('node:fs'),m=require('node:module'),stat=fs.statSync;Object.defineProperty(process,'platform',{value:'linux'});fs.statSync=function(p,...args){if(['/usr/bin/bwrap','/usr/local/bin/uv'].includes(String(p))){const e=new Error('Controlled fixture prerequisite absence');e.code='ENOENT';throw e;}return stat.call(this,p,...args);};m.syncBuiltinESMExports();`,
    );
    const output = join(temporary, "proof"),
      result = run(
        [
          "--require",
          boundary,
          join(root, "tests/support/independent-capture-consumer.mjs"),
          tarball,
          consumer,
          output,
        ],
        temporary,
      );
    expect(result.status, result.stderr).toBe(0);
    const receipt = JSON.parse(readFileSync(join(output, "receipt.json"), "utf8"));
    expect(receipt.signatures).toBe(5);
    expect(receipt.reports).toHaveLength(6);
    expect(
      new Set(
        receipt.reports
          .filter((row: { scanId?: string }) => row.scanId)
          .map((row: { scanId: string }) => row.scanId),
      ).size,
    ).toBe(5);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}, 240000);

test("selected batch uses freeze/run/publisher dispatches and one protected seven-slot signing approval", () => {
  const candidate = parse(
      readFileSync(".github/workflows/scan-report-candidate-upload.yml", "utf8"),
    ),
    publisher = parse(readFileSync(".github/workflows/scan-report-publisher.yml", "utf8"));
  expect(candidate.on.workflow_dispatch.inputs.phase.options).toEqual(["freeze", "run"]);
  const protectedJobs = Object.values(publisher.jobs).filter(
    (job: unknown) => (job as { environment?: string }).environment === "scan-report-signing-prod",
  );
  expect(protectedJobs).toHaveLength(1);
  const signer = publisher.jobs.signer;
  expect(signer.permissions).toEqual({
    "id-token": "write",
    attestations: "write",
    contents: "read",
  });
  expect(
    signer.steps
      .filter((step: { id?: string }) => step.id?.startsWith("attest_"))
      .map((step: { id: string }) => step.id),
  ).toEqual(["attest_0", "attest_1", "attest_2", "attest_3", "attest_4", "attest_5", "attest_6"]);
});
