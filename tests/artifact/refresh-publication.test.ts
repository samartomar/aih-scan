import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { afterAll, beforeAll, expect, test } from "vitest";

let temporary: string,
  candidate: string,
  consumer: string,
  selection: string,
  manifestSha: string,
  selectionSha: string;
const execute = (args: string[], cwd = process.cwd()) =>
  spawnSync(process.execPath, args, {
    cwd,
    encoding: "utf8",
    windowsHide: true,
    maxBuffer: 16 * 1024 * 1024,
    env: Object.fromEntries(
      Object.entries(process.env).filter(([key]) => !/^npm_config_allow_scripts$/i.test(key)),
    ),
  });
const canonical = (value: unknown): Buffer => {
  const order = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(order);
    if (value && typeof value === "object")
      return Object.fromEntries(
        Object.entries(value)
          .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
          .map(([key, item]) => [key, order(item)]),
      );
    return value;
  };
  return Buffer.from(JSON.stringify(order(value)));
};
beforeAll(() => {
  temporary = mkdtempSync(join(tmpdir(), "scan-packed-publication-"));
  consumer = join(temporary, "consumer");
  mkdirSync(consumer);
  const npm = [
    process.env.npm_execpath,
    join(dirname(process.execPath), "node_modules/npm/bin/npm-cli.js"),
    resolve(dirname(process.execPath), "../lib/node_modules/npm/bin/npm-cli.js"),
  ].find((path) => typeof path === "string" && existsSync(path));
  if (!npm) throw new Error("npm CLI unavailable");
  const packed = execute([npm, "pack", "--json", "--pack-destination", temporary]);
  expect(packed.status, packed.stderr).toBe(0);
  const tarball = join(temporary, "scanner.tgz");
  copyFileSync(join(temporary, JSON.parse(packed.stdout)[0].filename), tarball);
  writeFileSync(
    join(consumer, "package.json"),
    JSON.stringify({
      name: "publication-fixture",
      private: true,
      version: "0.0.0",
      type: "module",
    }),
  );
  const install = execute(
    [
      npm,
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "--save-exact",
      "../scanner.tgz",
    ],
    consumer,
  );
  expect(install.status, install.stderr).toBe(0);
  const fixture = join(temporary, "source");
  mkdirSync(fixture);
  for (const args of [
    ["init", "--quiet"],
    ["config", "user.name", "Fixture"],
    ["config", "user.email", "fixture@example.invalid"],
  ])
    expect(spawnSync("git", args, { cwd: fixture, windowsHide: true }).status).toBe(0);
  writeFileSync(join(fixture, "SKILL.md"), "# Publisher fixture\n");
  expect(spawnSync("git", ["add", "."], { cwd: fixture, windowsHide: true }).status).toBe(0);
  expect(
    spawnSync("git", ["commit", "--quiet", "-m", "fixture"], { cwd: fixture, windowsHide: true })
      .status,
  ).toBe(0);
  const oid = spawnSync("git", ["rev-parse", "HEAD"], {
    cwd: fixture,
    encoding: "utf8",
    windowsHide: true,
  }).stdout.trim();
  const helper = join(temporary, "git-helper.cjs"),
    boundary = join(temporary, "git-boundary.cjs");
  writeFileSync(
    helper,
    `const cp=require('node:child_process');const args=JSON.parse(process.argv[2]);const i=args.findIndex(a=>['init','fetch','rev-parse','ls-tree','cat-file'].includes(a));const tail=args.slice(i);let bytes=Buffer.alloc(0);if(!['init','fetch'].includes(tail[0])){const r=cp.spawnSync('git',['--git-dir',${JSON.stringify(join(fixture, ".git"))},...tail],{windowsHide:true});if(r.status!==0)process.exit(1);bytes=r.stdout;}process.stdout.write(JSON.stringify({bytesBase64:bytes.toString('base64')}));`,
  );
  // Portable boundary fixture; this does not establish actual Linux execution.
  writeFileSync(
    boundary,
    `const cp=require('node:child_process'),fs=require('node:fs'),m=require('node:module'),original=cp.spawn,stat=fs.statSync;Object.defineProperty(process,'platform',{value:'linux'});fs.statSync=function(p,...a){if(['/usr/bin/bwrap','/usr/local/bin/uv'].includes(String(p))){const e=new Error('Fixture unavailable prerequisite');e.code='ENOENT';throw e;}return stat.call(this,p,...a);};cp.spawn=function(e,a,o){if(e===process.execPath&&a?.[0]?.endsWith('git-command.js'))return original(e,[${JSON.stringify(helper)},...a.slice(1)],o);return original(e,a,o);};m.syncBuiltinESMExports();`,
  );
  const driver = join(temporary, "fixture.mjs"),
    module = new URL("../../tools/artifact/refresh-publication.mjs", import.meta.url).href,
    refresh = new URL("../../tools/refresh/refresh.mjs", import.meta.url).href,
    contracts = new URL("../../tools/refresh/contracts.mjs", import.meta.url).href;
  candidate = join(temporary, "candidate");
  selection = join(temporary, "selection.json");
  writeFileSync(
    driver,
    `import {mkdirSync,writeFileSync} from 'node:fs';import {generateKeyPairSync,createHash} from 'node:crypto';import {join} from 'node:path';import {freezeBatch} from ${JSON.stringify(refresh)};import {canonicalBytes,roster,ceilings,targetDirectory} from ${JSON.stringify(contracts)};import {loadScanner} from ${JSON.stringify(new URL("../../tools/refresh/scanner.mjs", import.meta.url).href)};import {retainCustody} from ${JSON.stringify(module)};
const [tgz,install,oid,out,bundles,trustPath]=process.argv.slice(2);const hash=b=>createHash('sha256').update(b).digest('hex');
const input={schema:'urn:aihq:scan:refresh-input:1.0.0',scannerSourceCommit:'735914577bc7b4230727d739749b851d42f4a53e',runtime:{node:process.version,platform:'linux',architecture:'x64'},profile:'independent-linux-v1',limits:{...ceilings,detectorTimeoutMs:1000},targets:roster.map(repository=>({repository,ref:oid,selection:{paths:'all',excludedPaths:[]},trustLint:{internalScopes:[],mcpConfigPaths:[]}}))};
const manifest=await freezeBatch({input,scannerTarball:tgz,scannerInstall:install,resolveRepository:async repository=>({repository,repositoryUrl:'https://github.com/'+repository+'.git'})});const scanner=await loadScanner(tgz,install,input.scannerSourceCommit);const result=await scanner.host.runScan({schema:'urn:aihq:scan:request:1.0.0',source:{kind:'git',repository:manifest.targets[0].repositoryUrl,commit:oid},selection:{paths:'all',excludedPaths:[]},detectors:manifest.targets[0].detectors,limits:manifest.limits});if(result.status!=='assessment')throw Error(JSON.stringify(result));
mkdirSync(out);mkdirSync(join(out,'targets'));mkdirSync(bundles);const key=generateKeyPairSync('ed25519'),spki=key.publicKey.export({type:'spki',format:'der'}),keyId='ed25519:'+hash(spki);writeFileSync(trustPath,JSON.stringify({keys:[{identity:'disposable-fixture',keyId,publicKeySpkiBase64:spki.toString('base64')}],publishers:[]}));const inventory={schema:'urn:aihq:scan:refresh-inventory:1.0.0',batchId:manifest.batchId,manifestSha256:hash(canonicalBytes(manifest)),createdAt:new Date().toISOString(),scanner:manifest.scanner,runtime:manifest.runtime,profile:manifest.profile,unavailableCoverage:manifest.unavailableCoverage,targets:[]};
for(let i=0;i<7;i++){const target=manifest.targets[i],dir='targets/'+targetDirectory(target.repository);mkdirSync(join(out,dir));const r=structuredClone(result);r.report.source.repository=target.repositoryUrl;const prepared=await scanner.host.prepareArtifact({report:r.report,annexes:r.annexes.map(a=>({id:a.id,bytes:Buffer.from(a.bytesBase64,'base64')}))});r.scanId=prepared.scanId;const resultBytes=canonicalBytes(r),statementBytes=canonicalBytes(prepared.statement);const row={repository:target.repository,commit:oid,status:'assessment',resultPath:dir+'/result.json',resultSha256:hash(resultBytes),diagnostics:r.diagnostics,detectors:target.detectors.map(d=>{const a=r.report.results.find(r=>r.detectorId===d.detectorId);return {detectorId:a.detectorId,profileId:d.profileId,outcome:a.outcome,coverage:a.coverage,diagnostics:a.diagnostics};}),measurements:{durationMs:0,sourceEntries:r.report.source.capture.entries.length,sourceBytes:r.report.source.capture.entries.filter(e=>e.kind==='file').reduce((n,e)=>n+e.byteLength,0),reportBytes:prepared.artifact.report.byteLength,annexBytes:prepared.artifact.annexes.reduce((n,a)=>n+a.byteLength,0),artifactBytes:prepared.bytes.length},scanId:r.scanId,completion:r.report.completion,authenticity:'unsigned',artifactPath:dir+'/artifact.json',artifactSha256:hash(prepared.bytes),statementPath:dir+'/statement.json',statementSha256:hash(statementBytes),candidatePath:dir+'/candidate.json'};writeFileSync(join(out,row.resultPath),resultBytes);writeFileSync(join(out,row.artifactPath),prepared.bytes);writeFileSync(join(out,row.statementPath),statementBytes);writeFileSync(join(out,row.candidatePath),canonicalBytes({schema:'urn:aihq:scan:refresh-candidate:1.0.0',batchId:manifest.batchId,repository:row.repository,commit:oid,scanId:r.scanId,artifactSha256:row.artifactSha256,statementSha256:row.statementSha256,resultSha256:row.resultSha256}));inventory.targets.push(row);if(i===0){const signed=await scanner.host.signArtifact({report:r.report,annexes:r.annexes.map(a=>({id:a.id,bytes:Buffer.from(a.bytesBase64,'base64')})),signer:{keyId,privateKey:key.privateKey}});writeFileSync(join(bundles,'bundle-0.json'),JSON.stringify(signed.artifact.attestation));}}
writeFileSync(join(out,'manifest.json'),canonicalBytes(manifest));writeFileSync(join(out,'inventory.json'),canonicalBytes(inventory));await retainCustody({candidate:out,scannerTarball:tgz,scannerInstall:install});`,
  );
  const built = execute([
    "--require",
    boundary,
    driver,
    tarball,
    consumer,
    oid,
    candidate,
    join(temporary, "bundles"),
    join(temporary, "trust.json"),
  ]);
  expect(built.status, built.stderr).toBe(0);
  manifestSha = JSON.parse(readFileSync(join(candidate, "inventory.json"), "utf8")).manifestSha256;
  const checked = execute([
    "tools/artifact/refresh-publication.mjs",
    "check",
    candidate,
    consumer,
    manifestSha,
    selection,
  ]);
  expect(checked.status, checked.stderr).toBe(0);
  selectionSha = JSON.parse(checked.stdout).selectionSha256;
}, 120000);
afterAll(() => {
  if (temporary) rmSync(temporary, { recursive: true, force: true });
});

test("packed consumer validates every candidate binding and isolates bounded signing data", () => {
  const output = join(temporary, "signing");
  expect(
    execute([
      "tools/artifact/refresh-publication.mjs",
      "prepare-signing",
      candidate,
      selection,
      selectionSha,
      output,
    ]).status,
  ).toBe(0);
  expect(
    execute(["tools/artifact/refresh-publication.mjs", "recheck-signing", output, selectionSha])
      .status,
  ).toBe(0);
  expect(existsSync(join(output, "scanner.tgz"))).toBe(false);
  expect(
    execute([
      "tools/artifact/refresh-publication.mjs",
      "check",
      candidate,
      consumer,
      "0".repeat(64),
      join(temporary, "wrong-selection"),
    ]).status,
  ).toBe(2);
  const inventoryPath = join(candidate, "inventory.json"),
    bytes = readFileSync(inventoryPath),
    inventory = JSON.parse(bytes.toString());
  inventory.targets[0].detectors.pop();
  writeFileSync(inventoryPath, canonical(inventory));
  expect(
    execute([
      "tools/artifact/refresh-publication.mjs",
      "check",
      candidate,
      consumer,
      manifestSha,
      join(temporary, "wrong-inventory"),
    ]).status,
  ).toBe(2);
  writeFileSync(inventoryPath, bytes);
}, 60000);

test("retained package and dependency lock restore the exact actual host installation", () => {
  const restored = join(temporary, "restore", "consumer");
  const result = execute([
    "tools/artifact/install-retained-scanner.mjs",
    candidate,
    manifestSha,
    restored,
  ]);
  expect(result.status, result.stderr).toBe(0);
  expect(
    execute([
      "tools/artifact/refresh-publication.mjs",
      "check",
      candidate,
      restored,
      manifestSha,
      join(temporary, "restored-selection.json"),
    ]).status,
  ).toBe(0);
}, 60000);

test("diagnostic batches retain all sources without invented Scan IDs and reject a missing terminal inventory", () => {
  const diagnostic = join(temporary, "diagnostic");
  cpSync(candidate, diagnostic, { recursive: true });
  const inventory = JSON.parse(readFileSync(join(diagnostic, "inventory.json"), "utf8"));
  for (const row of inventory.targets) {
    const result = {
      schema: "urn:aihq:scan:run-result:1.0.0",
      status: "diagnostic",
      phase: "capture",
      diagnostics: [
        { code: "resource-limit", detail: "Fixture source capture exceeds declared bound." },
      ],
    };
    const bytes = canonical(result);
    writeFileSync(join(diagnostic, row.resultPath), bytes);
    for (const path of [row.artifactPath, row.statementPath, row.candidatePath])
      unlinkSync(join(diagnostic, path));
    for (const key of [
      "scanId",
      "completion",
      "authenticity",
      "artifactPath",
      "artifactSha256",
      "statementPath",
      "statementSha256",
      "candidatePath",
    ])
      delete row[key];
    row.status = "diagnostic";
    row.diagnostics = result.diagnostics;
    row.detectors = row.detectors.map((detector: { detectorId: string; profileId: string }) => ({
      detectorId: detector.detectorId,
      profileId: detector.profileId,
      outcome: "not-run",
      coverage: null,
      diagnostics: result.diagnostics,
    }));
    row.measurements = {
      durationMs: 0,
      sourceEntries: null,
      sourceBytes: null,
      reportBytes: null,
      annexBytes: null,
      artifactBytes: null,
    };
    const hashDriver = join(temporary, "hash.mjs");
    writeFileSync(
      hashDriver,
      "import {readFileSync} from 'node:fs';import {createHash} from 'node:crypto';process.stdout.write(createHash('sha256').update(readFileSync(process.argv[2])).digest('hex'));",
    );
    row.resultSha256 = execute([hashDriver, join(diagnostic, row.resultPath)]).stdout;
  }
  writeFileSync(join(diagnostic, "inventory.json"), canonical(inventory));
  const selected = join(temporary, "diagnostic-selection.json");
  const result = execute([
    "tools/artifact/refresh-publication.mjs",
    "check",
    diagnostic,
    consumer,
    manifestSha,
    selected,
  ]);
  expect(result.status, result.stderr).toBe(0);
  expect(JSON.parse(readFileSync(selected, "utf8")).targets).toEqual([]);
  unlinkSync(join(diagnostic, "inventory.json"));
  expect(
    execute([
      "tools/artifact/refresh-publication.mjs",
      "check",
      diagnostic,
      consumer,
      manifestSha,
      join(temporary, "missing-selection.json"),
    ]).status,
  ).toBe(2);
}, 60000);

test("annex or statement substitution is refused before any signing directory is created", () => {
  const tampered = join(temporary, "tampered");
  cpSync(candidate, tampered, { recursive: true });
  const inventory = JSON.parse(readFileSync(join(tampered, "inventory.json"), "utf8")),
    first = inventory.targets[0];
  const artifactPath = join(tampered, first.artifactPath),
    artifact = JSON.parse(readFileSync(artifactPath, "utf8"));
  expect(artifact.annexes.length).toBeGreaterThan(0);
  artifact.annexes[0].bytesBase64 = Buffer.from("changed original annex").toString("base64");
  writeFileSync(artifactPath, canonical(artifact));
  expect(
    execute([
      "tools/artifact/refresh-publication.mjs",
      "check",
      tampered,
      consumer,
      manifestSha,
      join(temporary, "tampered-selection.json"),
    ]).status,
  ).toBe(2);
  const statement = join(tampered, first.statementPath);
  writeFileSync(statement, "{}");
  const output = join(temporary, "tampered-signing");
  expect(
    execute([
      "tools/artifact/refresh-publication.mjs",
      "prepare-signing",
      tampered,
      selection,
      selectionSha,
      output,
    ]).status,
  ).toBe(2);
  expect(existsSync(output)).toBe(false);
}, 60000);

test("assembly authenticates supplied bundles before exclusive output and retains unsigned siblings", () => {
  const output = join(temporary, "durable");
  const custodyPath = join(temporary, "actions-custody.json");
  const manifest = JSON.parse(readFileSync(join(candidate, "manifest.json"), "utf8"));
  writeFileSync(
    custodyPath,
    JSON.stringify({
      event: "scan-refresh-custody.verified",
      phase: "actions-custody",
      runId: 123,
      head: manifest.scanner.sourceCommit,
      artifactId: 456,
      serviceDigest: `sha256:${"b".repeat(64)}`,
      archiveBytes: 1000,
    }),
  );
  const args = [
    "tools/artifact/refresh-publication.mjs",
    "assemble",
    candidate,
    consumer,
    manifestSha,
    selectionSha,
    join(temporary, "bundles"),
    join(temporary, "trust.json"),
    output,
    custodyPath,
  ];
  const result = execute(args);
  expect(result.status, result.stderr).toBe(0);
  const inventory = JSON.parse(readFileSync(join(output, "inventory.json"), "utf8"));
  expect(inventory.targets).toHaveLength(7);
  expect(inventory.targets[0].authenticity).toBe("authenticated");
  expect(inventory.actionsCustody).toEqual({
    runId: 123,
    head: manifest.scanner.sourceCommit,
    artifactId: 456,
    serviceDigest: `sha256:${"b".repeat(64)}`,
    archiveBytes: 1000,
  });
  expect(
    inventory.targets
      .slice(1)
      .every((row: { authenticity: string }) => row.authenticity === "unsigned"),
  ).toBe(true);
  expect(readFileSync(join(output, "scanner.tgz"))).toEqual(
    readFileSync(join(candidate, "scanner.tgz")),
  );
  expect(execute(args).status).toBe(2);
  expect(
    execute([
      "tools/artifact/refresh-publication.mjs",
      "verify-publication",
      output,
      consumer,
      manifestSha,
      selectionSha,
      join(temporary, "trust.json"),
    ]).status,
  ).toBe(0);
  writeFileSync(join(temporary, "untrusted.json"), JSON.stringify({ keys: [], publishers: [] }));
  args[7] = join(temporary, "untrusted.json");
  args[8] = join(temporary, "untrusted-output");
  expect(execute(args).status).toBe(2);
  expect(existsSync(args[8])).toBe(false);
}, 90000);

test("durable HTTP publication preserves drafts, retries equal bytes, rejects collisions and preflights immutability", () => {
  const driver = join(temporary, "release-driver.mjs");
  writeFileSync(
    driver,
    `import {publishRelease,githubTransport} from ${JSON.stringify(new URL("../../tools/artifact/publish-refresh-release.mjs", import.meta.url).href)};
const files=new Map(),calls=[];let release=null,enabled=true,failOnce=true;
const json=(body,status=200)=>new Response(JSON.stringify(body),{status});
const request=async(url,options)=>{url=String(url);const method=options.method??'GET';
 if(url.endsWith('/immutable-releases'))return json({enabled});
 if(url.includes('/releases/tags/'))return release?json(release):json({},404);
 if(url.endsWith('/releases')&&method==='POST'){calls.push('create');const b=JSON.parse(options.body);return json(release={id:1,tag_name:b.tag_name,draft:true,assets:[]});}
 if(url.includes('uploads.github.com')){if(failOnce&&files.size===1){failOnce=false;return json({},503);}const name=new URL(url).searchParams.get('name');if(release.assets.some(a=>a.name===name))throw Error('Overwrite');const bytes=Buffer.from(options.body),id=files.size+1;files.set(id,bytes);release.assets.push({id,name,size:bytes.length});calls.push(name);return json({id});}
 if(url.includes('/releases/assets/'))return new Response(files.get(Number(url.split('/').at(-1))));
 if(method==='PATCH'){calls.push('publish');release.draft=false;release.immutable=true;return json(release);}
 throw Error('Unexpected external request');
};const transport=githubTransport({token:'disposable-test-token',reviewedHead:'a'.repeat(40),fetch:request}),directory=process.argv[2];
let failed=false;try{await publishRelease({directory,transport});}catch{failed=true;}if(!failed||!release.draft||files.size!==1)throw Error('Partial draft lost');
await publishRelease({directory,transport});const count=calls.length;await publishRelease({directory,transport});if(count!==calls.length)throw Error('Retry replaced assets');
files.set(1,Buffer.from('collision'));let refused=false;try{await publishRelease({directory,transport});}catch{refused=true;}if(!refused)throw Error('Collision accepted');
enabled=false;const before=calls.length;refused=false;try{await publishRelease({directory,transport});}catch(e){refused=e.code==='immutable-releases-disabled';}if(!refused||before!==calls.length)throw Error('Disabled immutability wrote release');`,
  );
  const result = execute([driver, join(temporary, "durable")]);
  expect(result.status, result.stderr).toBe(0);
});

test("batch custody accepts one selected immutable archive and refuses substitutions and oversized transport", () => {
  const directory = mkdtempSync(join(tmpdir(), "scan-batch-custody-"));
  try {
    const repository = { id: 1336836161, full_name: "samartomar/aih-scan", owner: { id: 9993940 } };
    const actor = { login: "stomar-tech", id: 333589491 };
    const run = {
      id: 123,
      run_attempt: 1,
      event: "workflow_dispatch",
      status: "completed",
      conclusion: "success",
      head_sha: "a".repeat(40),
      head_branch: "main",
      path: ".github/workflows/scan-report-candidate-upload.yml",
      repository,
      head_repository: repository,
      actor,
      triggering_actor: actor,
    };
    const archive = {
      id: 456,
      name: "scan-refresh-candidate",
      digest: `sha256:${"b".repeat(64)}`,
      expired: false,
      size_in_bytes: 768 * 1024 * 1024,
      workflow_run: { id: 123, head_sha: "a".repeat(40) },
    };
    const runPath = join(directory, "run.json"),
      artifactsPath = join(directory, "artifacts.json");
    writeFileSync(runPath, JSON.stringify(run));
    const invoke = () =>
      spawnSync(
        process.execPath,
        [
          "tools/artifact/check-refresh-run.mjs",
          runPath,
          artifactsPath,
          "123",
          "a".repeat(40),
          "456",
          archive.digest,
        ],
        { encoding: "utf8", windowsHide: true },
      );
    writeFileSync(artifactsPath, JSON.stringify({ total_count: 1, artifacts: [archive] }));
    expect(invoke().status).toBe(0);
    for (const mutation of [
      { size_in_bytes: archive.size_in_bytes + 1 },
      { id: 457 },
      { expired: true },
      { name: "other" },
      { digest: `sha256:${"c".repeat(64)}` },
    ]) {
      writeFileSync(
        artifactsPath,
        JSON.stringify({ total_count: 1, artifacts: [{ ...archive, ...mutation }] }),
      );
      expect(invoke().status).toBe(2);
    }
    expect(readFileSync(runPath, "utf8")).toBe(JSON.stringify(run));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
