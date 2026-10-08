import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { afterAll, beforeAll, expect, test } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../..");
let temporary: string;
let consumer: string;
let tarball: string;
let fixture: string;
let commit: string;
const run = (executable: string, args: string[], cwd: string) => {
  const env = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => !/^npm_config_allow_scripts$/i.test(key)),
  );
  const result = spawnSync(executable, args, {
    env,
    cwd,
    encoding: "utf8",
    windowsHide: true,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status !== 0) throw new Error(result.stderr || result.stdout || String(result.error));
  return result.stdout.trim();
};
const npmCli = [
  process.env.npm_execpath,
  join(dirname(process.execPath), "node_modules/npm/bin/npm-cli.js"),
  resolve(dirname(process.execPath), "../lib/node_modules/npm/bin/npm-cli.js"),
].find((candidate): candidate is string => typeof candidate === "string" && existsSync(candidate));
if (!npmCli) throw new Error("npm CLI entrypoint missing for installed refresh fixtures");
function setupOperationDrivers() {
  writeFileSync(
    join(temporary, "freeze-driver.mjs"),
    `import {freezeBatch} from ${JSON.stringify(new URL("../../tools/refresh/refresh.mjs", import.meta.url).href)};
import {canonicalBytes} from ${JSON.stringify(new URL("../../tools/refresh/contracts.mjs", import.meta.url).href)};
import {readFileSync,writeFileSync} from 'node:fs';
const input=JSON.parse(readFileSync(process.argv[2],'utf8'));
const result=await freezeBatch({input,scannerTarball:process.argv[3],scannerInstall:process.argv[4],resolveRepository:async repository=>({repository,repositoryUrl:'https://github.com/'+repository+'.git'}),resolveRef:async()=>process.argv[5]});
writeFileSync(process.argv[6],canonicalBytes(result));`,
  );
  const boundary = join(temporary, "git-boundary.cjs");
  const helper = join(temporary, "fixture-git-command.cjs");
  writeFileSync(
    helper,
    `const cp=require('node:child_process');const argv=JSON.parse(process.argv[2]);const operation=argv.findIndex(arg=>['init','fetch','rev-parse','ls-tree','cat-file'].includes(arg));const tail=argv.slice(operation);let bytes=Buffer.alloc(0);if(!['init','fetch'].includes(tail[0])){const result=cp.spawnSync('git',['--git-dir',${JSON.stringify(join(fixture, ".git"))},...tail],{windowsHide:true,maxBuffer:268435456});if(result.status!==0)process.exit(1);bytes=result.stdout;}process.stdout.write(JSON.stringify({bytesBase64:bytes.toString('base64')}));`,
  );
  writeFileSync(
    boundary,
    `const cp=require('node:child_process');const fs=require('node:fs');const moduleApi=require('node:module');const original=cp.spawn;const originalStat=fs.statSync;
// Platform control permits exercising the portable producer fixture on Windows. It supplies no Linux execution evidence.
Object.defineProperty(process,'platform',{value:'linux'});
fs.statSync=function(path,...args){if(['/usr/bin/bwrap','/usr/local/bin/uv'].includes(String(path))){const error=new Error('Controlled unavailable prerequisite');error.code='ENOENT';throw error;}return originalStat.call(this,path,...args);};
cp.spawn=function(executable,args,options){if(executable===process.execPath&&typeof args?.[0]==='string'&&args[0].endsWith('git-command.js'))return original(executable,[${JSON.stringify(helper)},...args.slice(1)],options);return original(executable,args,options);};moduleApi.syncBuiltinESMExports();`,
  );
  const runDriver = join(temporary, "run-driver.mjs");
  writeFileSync(
    runDriver,
    `import { runBatch } from ${JSON.stringify(new URL("../../tools/refresh/refresh.mjs", import.meta.url).href)};
import {readFileSync} from 'node:fs';
const inventory=await runBatch({manifest:JSON.parse(readFileSync(process.argv[2],'utf8')),scannerTarball:process.argv[3],scannerInstall:process.argv[4],output:process.argv[5]});
process.exitCode=inventory.targets.some(target=>target.status!=='assessment'||target.completion!=='complete')?1:0;`,
  );
}
beforeAll(() => {
  temporary = mkdtempSync(join(tmpdir(), "scan-refresh-test-"));
  // CI/verify builds first. Reuse those bytes: prepack would rewrite shared dist
  // while parallel historical subprocess consumers are importing it.
  tarball = join(
    temporary,
    JSON.parse(
      run(
        process.execPath,
        [npmCli, "pack", "--ignore-scripts", "--json", "--pack-destination", temporary],
        repositoryRoot,
      ),
    )[0].filename,
  );
  consumer = join(temporary, "consumer");
  mkdirSync(consumer);
  writeFileSync(
    join(consumer, "package.json"),
    JSON.stringify({
      name: "scan-refresh-fixture",
      version: "0.0.0",
      private: true,
      type: "module",
    }),
  );
  run(
    process.execPath,
    [npmCli, "install", "--ignore-scripts", "--no-audit", "--no-fund", "--save-exact", tarball],
    consumer,
  );
  fixture = join(temporary, "git-source");
  mkdirSync(fixture);
  run("git", ["init", "--quiet"], fixture);
  writeFileSync(join(fixture, "SKILL.md"), "# Refresh fixture\n");
  run("git", ["add", "."], fixture);
  run(
    "git",
    [
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.invalid",
      "commit",
      "--quiet",
      "-m",
      "fixture",
    ],
    fixture,
  );
  commit = run("git", ["rev-parse", "HEAD"], fixture);
  setupOperationDrivers();
}, 120000);
afterAll(() => {
  if (temporary) rmSync(temporary, { recursive: true, force: true });
});

test("freeze retains exact roster commits and refuses unknown maintainer input fields", () => {
  const driver = join(temporary, "freeze-driver.mjs");
  writeFileSync(
    driver,
    `import { freezeBatch } from ${JSON.stringify(new URL("../../tools/refresh/refresh.mjs", import.meta.url).href)};
import {readFileSync,writeFileSync} from 'node:fs';
import {canonicalBytes} from ${JSON.stringify(new URL("../../tools/refresh/contracts.mjs", import.meta.url).href)};
const input=JSON.parse(readFileSync(process.argv[2],'utf8'));
const result=await freezeBatch({input,scannerTarball:process.argv[3],scannerInstall:process.argv[4],resolveRepository:async repository=>({repository,repositoryUrl:'https://github.com/'+repository+'.git'}),resolveRef:async()=>process.argv[5]});
writeFileSync(process.argv[6],canonicalBytes(result));`,
  );
  const input = join(temporary, "input.json");
  const roster = [
    "mattpocock/skills",
    "affaan-m/ECC",
    "anthropics/skills",
    "obra/superpowers",
    "nextlevelbuilder/ui-ux-pro-max-skill",
    "DietrichGebert/ponytail",
    "samartomar/aih-extensions",
  ];
  writeFileSync(
    input,
    JSON.stringify({
      schema: "urn:aihq:scan:refresh-input:1.0.0",
      scannerSourceCommit: "735914577bc7b4230727d739749b851d42f4a53e",
      profile: "independent-linux-v1",
      runtime: { node: process.version, platform: "linux", architecture: "x64" },
      limits: {
        maxSourceEntries: 100000,
        maxSourceBytes: 268435456,
        maxRequestBytes: 2097152,
        maxReportBytes: 16777216,
        maxAnnexBytes: 16777216,
        maxDecodedArtifactBytes: 67108864,
        maxArtifactBytes: 100663296,
        maxStatementBytes: 131072,
        detectorTimeoutMs: 600000,
      },
      targets: roster.map((repository) => ({
        repository,
        ref: "refs/heads/main",
        selection: { paths: "all", excludedPaths: [] },
        trustLint: { internalScopes: [], mcpConfigPaths: [] },
      })),
    }),
  );
  const output = join(temporary, "frozen.json");
  run(process.execPath, [driver, input, tarball, consumer, commit, output], temporary);
  const frozen = JSON.parse(readFileSync(output, "utf8"));
  expect(
    frozen.targets.map((target: { repository: string; commit: string }) => [
      target.repository,
      target.commit,
    ]),
  ).toEqual(roster.map((repository) => [repository, commit]));
  expect(frozen.scanner).toMatchObject({
    name: "@aihq/scan",
    version: "0.5.0",
    sourceCommit: "735914577bc7b4230727d739749b851d42f4a53e",
  });
  expect(
    frozen.targets[0].detectors.map((detector: { detectorId: string }) => detector.detectorId),
  ).toEqual([
    "detector.aih-native",
    "detector.aih-trust-lint",
    "detector.aih-binding-gate",
    "detector.semgrep",
  ]);
  const invalid = JSON.parse(readFileSync(input, "utf8"));
  invalid.sign = true;
  writeFileSync(input, JSON.stringify(invalid));
  const refused = spawnSync(process.execPath, [driver, input, tarball, consumer, commit, output], {
    encoding: "utf8",
    windowsHide: true,
  });
  expect(refused.status).not.toBe(0);
}, 120000);

function frozenFixture(name: string) {
  const driver = join(temporary, "freeze-driver.mjs");
  const input = join(temporary, `${name}-input.json`);
  writeFileSync(
    input,
    JSON.stringify({
      schema: "urn:aihq:scan:refresh-input:1.0.0",
      scannerSourceCommit: "735914577bc7b4230727d739749b851d42f4a53e",
      profile: "independent-linux-v1",
      runtime: { node: process.version, platform: "linux", architecture: "x64" },
      limits: {
        maxSourceEntries: 100000,
        maxSourceBytes: 268435456,
        maxRequestBytes: 2097152,
        maxReportBytes: 16777216,
        maxAnnexBytes: 16777216,
        maxDecodedArtifactBytes: 67108864,
        maxArtifactBytes: 100663296,
        maxStatementBytes: 131072,
        detectorTimeoutMs: 600000,
      },
      targets: [
        "mattpocock/skills",
        "affaan-m/ECC",
        "anthropics/skills",
        "obra/superpowers",
        "nextlevelbuilder/ui-ux-pro-max-skill",
        "DietrichGebert/ponytail",
        "samartomar/aih-extensions",
      ].map((repository) => ({
        repository,
        ref: "refs/heads/main",
        selection: { paths: "all", excludedPaths: [] },
        trustLint: { internalScopes: [], mcpConfigPaths: [] },
      })),
    }),
  );
  const output = join(temporary, `${name}-frozen.json`);
  run(process.execPath, [driver, input, tarball, consumer, commit, output], temporary);
  return output;
}

test("profile refuses a statement budget too small for a detached candidate", () => {
  frozenFixture("statement-budget");
  const input = join(temporary, "statement-budget-input.json");
  const value = JSON.parse(readFileSync(input, "utf8"));
  value.limits.maxStatementBytes = 1;
  writeFileSync(input, JSON.stringify(value));
  const output = join(temporary, "statement-budget-refused.json");
  const result = spawnSync(
    process.execPath,
    [join(temporary, "freeze-driver.mjs"), input, tarball, consumer, commit, output],
    { encoding: "utf8", windowsHide: true },
  );
  expect(result.status).not.toBe(0);
}, 120000);

test("runtime, scanner identity and existing output substitutions refuse before target execution", () => {
  const original = frozenFixture("custody");
  const mutate = join(temporary, "custody-mutation.mjs");
  writeFileSync(
    mutate,
    `import {canonicalBytes,batchId} from ${JSON.stringify(new URL("../../tools/refresh/contracts.mjs", import.meta.url).href)};
import {readFileSync,writeFileSync} from 'node:fs';
const manifest=JSON.parse(readFileSync(process.argv[2],'utf8'));
if(process.argv[4]==='runtime')manifest.runtime.node=manifest.runtime.node==='v24.15.0'?'v24.16.0':'v24.15.0';
if(process.argv[4]==='scanner')manifest.scanner.tarballSha256='0'.repeat(64);
manifest.batchId=batchId(manifest);writeFileSync(process.argv[3],canonicalBytes(manifest));`,
  );
  const platformBoundary = join(temporary, "custody-platform.cjs");
  writeFileSync(platformBoundary, "Object.defineProperty(process,'platform',{value:'linux'});");
  for (const scenario of ["runtime", "scanner", "existing"]) {
    const manifest = join(temporary, `custody-${scenario}.json`);
    run(process.execPath, [mutate, original, manifest, scenario], temporary);
    const output = join(temporary, `custody-${scenario}-output`);
    if (scenario === "existing") {
      mkdirSync(output);
      writeFileSync(join(output, "sentinel"), "retained exact bytes\n");
    }
    const result = spawnSync(
      process.execPath,
      [
        "--require",
        platformBoundary,
        join(repositoryRoot, "tools/refresh/refresh.mjs"),
        "run",
        "--manifest",
        manifest,
        "--scanner-tgz",
        tarball,
        "--scanner-install",
        consumer,
        "--out",
        output,
      ],
      {
        encoding: "utf8",
        windowsHide: true,
        maxBuffer: 16 * 1024 * 1024,
      },
    );
    expect(result.status).toBe(2);
    if (scenario === "existing")
      expect(readFileSync(join(output, "sentinel"), "utf8")).toBe("retained exact bytes\n");
    else expect(existsSync(output)).toBe(false);
  }
}, 120000);

test("run retains pinned Git bytes and every detector outcome when Semgrep is unavailable", () => {
  const manifest = frozenFixture("pinned");
  writeFileSync(join(fixture, "SKILL.md"), "# Later live tree\n");
  run("git", ["add", "."], fixture);
  run(
    "git",
    [
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.invalid",
      "commit",
      "--quiet",
      "-m",
      "moved main",
    ],
    fixture,
  );
  const boundary = join(temporary, "git-boundary.cjs"),
    runDriver = join(temporary, "run-driver.mjs"),
    output = join(temporary, "pinned-candidates");
  const result = spawnSync(
    process.execPath,
    ["--require", boundary, runDriver, manifest, tarball, consumer, output],
    { encoding: "utf8", windowsHide: true, maxBuffer: 16 * 1024 * 1024 },
  );
  expect(result.status, result.stderr).toBe(1);
  expect(result.stderr).toBe("");
  const inventory = JSON.parse(readFileSync(join(output, "inventory.json"), "utf8"));
  expect(inventory.targets).toHaveLength(7);
  for (const target of inventory.targets) {
    expect(target).toMatchObject({
      status: "assessment",
      commit,
      completion: "partial",
      authenticity: "unsigned",
      detectors: [
        { detectorId: "detector.aih-native", outcome: "succeeded" },
        { detectorId: "detector.aih-trust-lint", outcome: "succeeded" },
        { detectorId: "detector.aih-binding-gate", outcome: "succeeded" },
        { detectorId: "detector.semgrep", outcome: "refused" },
      ],
    });
    const retained = JSON.parse(readFileSync(join(output, target.resultPath), "utf8"));
    expect(retained.report.source.capture.entries).toEqual([
      {
        kind: "file",
        path: "SKILL.md",
        byteLength: 18,
        sha256: "0f2dfdbb5da4f9656e8dcbac28f44f958e52be79f3fe96f5a24e4f421bb0fb50",
      },
    ]);
    expect(retained.annexes.length).toBeGreaterThan(0);
    const artifact = JSON.parse(readFileSync(join(output, target.artifactPath), "utf8"));
    expect(artifact).not.toHaveProperty("attestation");
    expect(
      artifact.annexes.map(({ id, bytesBase64 }: { id: string; bytesBase64: string }) => ({
        id,
        bytesBase64,
      })),
    ).toEqual(retained.annexes);
  }
}, 120000);

test("capture resource refusal accounts for every source without any Scan ID", () => {
  const manifest = frozenFixture("bounded");
  const change = join(temporary, "lower-bound.mjs");
  writeFileSync(
    change,
    `import {canonicalBytes,batchId} from ${JSON.stringify(new URL("../../tools/refresh/contracts.mjs", import.meta.url).href)};
import {readFileSync,writeFileSync} from 'node:fs';
const manifest=JSON.parse(readFileSync(process.argv[2],'utf8'));
manifest.limits.maxSourceBytes=5;
for(const target of manifest.targets)target.selection.excludedPaths=['SKILL.md'];
manifest.batchId=batchId(manifest);writeFileSync(process.argv[2],canonicalBytes(manifest));`,
  );
  run(process.execPath, [change, manifest], temporary);
  const output = join(temporary, "bounded-candidates");
  const result = spawnSync(
    process.execPath,
    [
      "--require",
      join(temporary, "git-boundary.cjs"),
      join(temporary, "run-driver.mjs"),
      manifest,
      tarball,
      consumer,
      output,
    ],
    { encoding: "utf8", windowsHide: true, maxBuffer: 16 * 1024 * 1024 },
  );
  expect(result.stderr).toBe("");
  expect(result.status).toBe(1);
  const inventory = JSON.parse(readFileSync(join(output, "inventory.json"), "utf8"));
  expect(inventory.targets).toHaveLength(7);
  for (const target of inventory.targets) {
    expect(target.status).toBe("diagnostic");
    expect(target).not.toHaveProperty("scanId");
    expect(target).not.toHaveProperty("artifactPath");
    expect(target.detectors.map((detector: { outcome: string }) => detector.outcome)).toEqual([
      "not-run",
      "not-run",
      "not-run",
      "not-run",
    ]);
    const result = JSON.parse(readFileSync(join(output, target.resultPath), "utf8"));
    expect(result).toMatchObject({ status: "diagnostic", phase: "capture" });
    expect(result).not.toHaveProperty("scanId");
  }
}, 120000);

async function interruptedFixture(signal: NodeJS.Signals, shell: boolean) {
  const identity = shell ? `shell-${signal}` : "interrupted";
  const manifest = frozenFixture(identity),
    boundary = join(temporary, `${identity}-boundary.cjs`),
    output = join(temporary, `${identity}-candidates`),
    trace = join(temporary, `${identity}-fetches.log`),
    activePid = join(temporary, `${identity}-pid.txt`);
  const base = readFileSync(join(temporary, "git-boundary.cjs"), "utf8");
  writeFileSync(
    boundary,
    "const fixtureHostPlatform=process.platform;\n" +
      base +
      `
// A genuine delayed Git child lets cancellation interrupt acquisition, before detectors.
// On Windows only, translate fake-POSIX group addressing to the sole fixture child;
// this boundary does not establish real Linux process-tree containment.
if(fixtureHostPlatform==='win32'){const nativeKill=process.kill.bind(process);process.kill=(pid,...args)=>nativeKill(pid<0?-pid:pid,...args);}
let fixtureFetches=0;const fixtureSpawn=cp.spawn;
cp.spawn=function(executable,args,options){if(executable===process.execPath&&args?.[0]?.endsWith('git-command.js')&&JSON.parse(args[1]).includes('fetch')){fs.appendFileSync(${JSON.stringify(trace)},'fetch\\n');fixtureFetches++;if(fixtureFetches===2){const child=original(process.execPath,['-e','setTimeout(()=>{},60000)'],options);fs.writeFileSync(${JSON.stringify(activePid)},String(process.pid));setImmediate(()=>process.send?.({phase:'second-source'}));return child;}}return fixtureSpawn(executable,args,options);};
// Windows cannot deliver POSIX signals to Node. Only this labelled process ingress
// translates real parent IPC into the same signal event; Linux sends actual SIGTERM.
process.on('message',message=>{if(message==='fixture-SIGTERM'){process.emit('SIGTERM');process.disconnect();}});process.channel?.unref();moduleApi.syncBuiltinESMExports();`,
  );
  const cliArgs = [
    "--require",
    boundary,
    join(repositoryRoot, "tools/refresh/refresh.mjs"),
    "run",
    "--manifest",
    manifest,
    "--scanner-tgz",
    tarball,
    "--scanner-install",
    consumer,
    "--out",
    output,
  ];
  const child = spawn(
    shell ? "bash" : process.execPath,
    shell
      ? [
          join(repositoryRoot, "tools/refresh/run-workflow.sh"),
          manifest,
          tarball,
          consumer,
          output,
          "a".repeat(64),
          join(temporary, `${identity}-selection.json`),
        ]
      : cliArgs,
    {
      cwd: repositoryRoot,
      env: shell ? { ...process.env, NODE_OPTIONS: `--require=${boundary}` } : process.env,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe", shell ? "ignore" : "ipc"],
    },
  );
  let stdout = "",
    stderr = "",
    interruptedAt: number | undefined,
    originals: Map<string, Buffer> | undefined;
  child.stdout?.on("data", (chunk) => {
    stdout += chunk;
  });
  child.stderr?.on("data", (chunk) => {
    stderr += chunk;
  });
  const interrupt = () => {
    interruptedAt = Date.now();
    originals = new Map(
      ["result.json", "artifact.json", "statement.json", "candidate.json"].map((name) => [
        name,
        readFileSync(join(output, "targets", "mattpocock--skills", name)),
      ]),
    );
    if (process.platform === "win32") child.send("fixture-SIGTERM");
    else child.kill(signal); // The shell test signals the actual Bash entry PID.
  };
  child.on("message", interrupt);
  const poll = shell
    ? setInterval(() => {
        if (originals || !existsSync(activePid)) return;
        interrupt();
      }, 25)
    : undefined;
  const status = await new Promise<number | null>((resolve, reject) => {
    const deadline = setTimeout(() => {
      child.kill("SIGKILL");
      if (shell && existsSync(activePid))
        process.kill(Number(readFileSync(activePid, "utf8")), "SIGKILL");
      clearInterval(poll);
      reject(new Error(`Interrupted CLI did not finish bounded cleanup: ${stderr}`));
    }, 20000);
    child.once("error", (error) => {
      clearTimeout(deadline);
      clearInterval(poll);
      reject(error);
    });
    child.once("close", (code) => {
      clearTimeout(deadline);
      clearInterval(poll);
      resolve(code);
    });
  });
  expect(status, stderr).toBe(2);
  expect(originals).toBeDefined();
  expect(interruptedAt).toBeDefined();
  expect(Date.now() - (interruptedAt ?? 0)).toBeLessThan(7000);
  expect(JSON.parse(stdout).event).toBe("scan-refresh.cancelled");
  const inventory = JSON.parse(readFileSync(join(output, "inventory.json"), "utf8"));
  expect(inventory.targets).toHaveLength(7);
  expect(inventory.targets[0].status).toBe("assessment");
  expect(
    inventory.targets
      .slice(1)
      .every(
        (row: { status: string; scanId?: string; detectors: { outcome: string }[] }) =>
          row.status === "diagnostic" &&
          !row.scanId &&
          row.detectors.every((detector) => detector.outcome === "not-run"),
      ),
  ).toBe(true);
  expect(readFileSync(trace, "utf8").trim().split("\n")).toHaveLength(2);
  expect(existsSync(join(temporary, `${identity}-selection.json`))).toBe(false);
  const recovery = join(temporary, `${identity}-evidence`);
  const retained = spawnSync(
    process.execPath,
    [
      join(repositoryRoot, "tools/artifact/retain-failure-evidence.mjs"),
      output,
      join(temporary, "no-frozen"),
      recovery,
    ],
    { encoding: "utf8", windowsHide: true },
  );
  expect(retained.status, retained.stderr).toBe(0);
  for (const [name, bytes] of originals ?? [])
    expect(readFileSync(join(recovery, "targets", "mattpocock--skills", name))).toEqual(bytes);
  const index = JSON.parse(readFileSync(join(recovery, "root", "failure.json"), "utf8"));
  expect(index.publishable).toBe(false);
  expect(index.targets).toHaveLength(7);
  expect(
    index.targets.every(
      (row: { files: { status: string }[] }) => row.files[0]?.status === "retained",
    ),
  ).toBe(true);
}

test("interrupted maintainer CLI preserves completed sibling bytes, accounts for all seven sources and stops new capture/detector work", async () => {
  await interruptedFixture("SIGTERM", false);
}, 120000);

test.skipIf(process.platform !== "linux").each(["SIGINT", "SIGTERM"] as const)(
  "Linux workflow Bash entry-PID %s forwards cancellation and retains exact siblings and all seven rows",
  async (signal) => {
    await interruptedFixture(signal, true);
  },
  120000,
);

test.skipIf(
  process.platform !== "linux" ||
    process.arch !== "x64" ||
    process.env.AIH_SCAN_REFRESH_LINUX_PROOF !== "1",
)(
  "Linux profile executes real Semgrep and retains complete installed-reader candidates",
  () => {
    const manifest = frozenFixture("linux-real");
    const boundary = join(temporary, "real-linux-boundary.cjs");
    writeFileSync(
      boundary,
      `const cp=require('node:child_process');const moduleApi=require('node:module');const original=cp.spawn;
// Only remote Git transport is controlled. No detector, prerequisite, filesystem, runtime or platform substitution.
cp.spawn=function(executable,args,options){if(executable===process.execPath&&typeof args?.[0]==='string'&&args[0].endsWith('git-command.js'))return original(executable,[${JSON.stringify(join(temporary, "fixture-git-command.cjs"))},...args.slice(1)],options);return original(executable,args,options);};moduleApi.syncBuiltinESMExports();`,
    );
    const output = join(temporary, "linux-real-candidates");
    const result = spawnSync(
      process.execPath,
      [
        "--require",
        boundary,
        join(repositoryRoot, "tools/refresh/refresh.mjs"),
        "run",
        "--manifest",
        manifest,
        "--scanner-tgz",
        tarball,
        "--scanner-install",
        consumer,
        "--out",
        output,
      ],
      {
        encoding: "utf8",
        windowsHide: true,
        maxBuffer: 16 * 1024 * 1024,
        // First hosted seven-source proof took 12.1 minutes. Bound the child
        // below the 20-minute assertion budget without changing detector limits.
        timeout: 18 * 60 * 1000,
        killSignal: "SIGTERM",
      },
    );
    expect(result.stderr).toBe("");
    expect(
      result.status,
      JSON.stringify({
        signal: result.signal,
        error: result.error?.message,
        stdout: result.stdout,
        stderr: result.stderr,
      }),
    ).toBe(0);
    const inventory = JSON.parse(readFileSync(join(output, "inventory.json"), "utf8"));
    expect(inventory.targets).toHaveLength(7);
    for (const target of inventory.targets) {
      expect(target).toMatchObject({
        status: "assessment",
        completion: "complete",
        authenticity: "unsigned",
      });
      expect(target.detectors.map((detector: { outcome: string }) => detector.outcome)).toEqual([
        "succeeded",
        "succeeded",
        "succeeded",
        "succeeded",
      ]);
      expect(target.measurements.annexBytes).toBeGreaterThan(0);
    }
  },
  20 * 60 * 1000,
);
