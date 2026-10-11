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
  selectionSha: string,
  runtimeBoundary: string;
const execute = (args: string[], cwd = process.cwd()) =>
  spawnSync(
    process.execPath,
    args[0]?.match(/^tools\/artifact\/(?:refresh-publication|install-retained-scanner)\.mjs$/)
      ? ["--require", runtimeBoundary, ...args]
      : args,
    {
      cwd,
      encoding: "utf8",
      windowsHide: true,
      maxBuffer: 16 * 1024 * 1024,
      env: Object.fromEntries(
        Object.entries(process.env).filter(([key]) => !/^npm_config_allow_scripts$/i.test(key)),
      ),
    },
  );
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
  runtimeBoundary = join(temporary, "portable-runtime-boundary.cjs");
  // Labelled process boundary for portable tests; actual Linux proof is separate.
  writeFileSync(runtimeBoundary, "Object.defineProperty(process,'platform',{value:'linux'});");
  consumer = join(temporary, "consumer");
  mkdirSync(consumer);
  const npm = [
    process.env.npm_execpath,
    join(dirname(process.execPath), "node_modules/npm/bin/npm-cli.js"),
    resolve(dirname(process.execPath), "../lib/node_modules/npm/bin/npm-cli.js"),
  ].find((path) => typeof path === "string" && existsSync(path));
  if (!npm) throw new Error("npm CLI unavailable");
  // CI/verify builds first. Pack immutable prebuilt bytes without rewriting the
  // shared dist tree that parallel historical subprocess consumers import.
  const packed = execute([
    npm,
    "pack",
    "--ignore-scripts",
    "--json",
    "--pack-destination",
    temporary,
  ]);
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
  const mutable = join(temporary, "binding-candidate");
  cpSync(candidate, mutable, { recursive: true });
  const inventoryPath = join(mutable, "inventory.json"),
    bytes = readFileSync(inventoryPath),
    inventory = JSON.parse(bytes.toString());
  inventory.targets[0].detectors.pop();
  writeFileSync(inventoryPath, canonical(inventory));
  expect(
    execute([
      "tools/artifact/refresh-publication.mjs",
      "check",
      mutable,
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

function assembledFixture(name: string) {
  const output = join(temporary, name),
    custodyPath = join(temporary, name + "-custody.json");
  const manifest = JSON.parse(readFileSync(join(candidate, "manifest.json"), "utf8"));
  writeFileSync(
    custodyPath,
    JSON.stringify({
      event: "scan-refresh-custody.verified",
      phase: "actions-custody",
      runId: 123,
      head: manifest.scanner.sourceCommit,
      artifactId: 456,
      serviceDigest: "sha256:" + "b".repeat(64),
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
  return { output, args, manifest };
}
test("assembly authenticates supplied bundles before exclusive output and retains unsigned siblings", () => {
  const { output, args, manifest } = assembledFixture("assembly-durable");
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
import {createHash} from 'node:crypto';
const files=new Map(),calls=[];let release=null,enabled=true,failOnce=true,discovery='normal';
const json=(body,status=200)=>new Response(JSON.stringify(body),{status});
const request=async(url,options)=>{url=String(url);const method=options.method??'GET';
 if(url.endsWith('/immutable-releases'))return json({enabled});
 if(url.includes('/releases/tags/'))return release&&!release.draft?json(release):json({},404);
 if(url.includes('/releases?per_page=100&page='))return json(discovery==='ambiguous'?[release,{...release,id:2,draft:true}]:discovery==='exhausted'?Array.from({length:100},(_,i)=>({id:i+100,tag_name:'unrelated',draft:true})):release?[release]:[]);
 if(url.includes('/releases/1/assets?per_page=30&page=')){const page=Number(new URL(url).searchParams.get('page'));return json(release.assets.slice((page-1)*30,page*30));}
 if(url.endsWith('/releases')&&method==='POST'){if(release)return json({},422);calls.push('create');const b=JSON.parse(options.body);return json(release={id:1,tag_name:b.tag_name,draft:true,assets:[]});}
 if(url.includes('uploads.github.com')){if(failOnce&&files.size===1){failOnce=false;return json({},503);}const name=new URL(url).searchParams.get('name');if(release.assets.some(a=>a.name===name))throw Error('Overwrite');const bytes=Buffer.from(options.body),id=files.size+1;files.set(id,bytes);release.assets.push({id,name,size:bytes.length,digest:'sha256:'+createHash('sha256').update(bytes).digest('hex'),state:'uploaded'});calls.push(name);return json({id});}
 if(url.includes('/releases/assets/'))return new Response(files.get(Number(url.split('/').at(-1))));
 if(method==='PATCH'){calls.push('publish');release.draft=false;release.immutable=true;return json(release);}
 throw Error('Unexpected external request');
};const transport=githubTransport({token:'disposable-test-token',reviewedHead:'a'.repeat(40),fetch:request}),directory=process.argv[2];
let failed=false;try{await publishRelease({directory,transport});}catch{failed=true;}if(!failed||!release.draft||files.size!==1)throw Error('Partial draft lost');
await publishRelease({directory,transport});const count=calls.length;await publishRelease({directory,transport});if(count!==calls.length)throw Error('Retry replaced assets');
for(const mode of ['ambiguous','exhausted']){discovery=mode;let refused=false;try{await publishRelease({directory,transport});}catch{refused=true;}if(!refused||calls.length!==count)throw Error('Ambiguous or exhausted listing wrote release');}discovery='normal';
files.set(1,Buffer.from('collision'));let refused=false;try{await publishRelease({directory,transport});}catch{refused=true;}if(!refused)throw Error('Collision accepted');
enabled=false;const before=calls.length;refused=false;try{await publishRelease({directory,transport});}catch(e){refused=e.code==='immutable-releases-disabled';}if(!refused||before!==calls.length)throw Error('Disabled immutability wrote release');`,
  );
  const { output } = assembledFixture("http-durable");
  const result = execute([driver, output]);
  expect(result.status, result.stderr).toBe(0);
});

test("strict retained installation refuses a mismatched runtime while explicit independent reader records the actual host separately", () => {
  const mismatch = join(temporary, "mismatched-runtime.cjs");
  writeFileSync(mismatch, "Object.defineProperty(process,'platform',{value:'darwin'});");
  const refused = spawnSync(
    process.execPath,
    [
      "--require",
      mismatch,
      "tools/artifact/install-retained-scanner.mjs",
      candidate,
      manifestSha,
      join(temporary, "runtime-refused", "consumer"),
    ],
    { encoding: "utf8", windowsHide: true },
  );
  expect(refused.status).toBe(2);
  const output = join(temporary, "actual-reader", "consumer"),
    installed = spawnSync(
      process.execPath,
      [
        "tools/artifact/install-retained-scanner.mjs",
        candidate,
        manifestSha,
        output,
        "independent-reader",
      ],
      {
        encoding: "utf8",
        windowsHide: true,
        env: Object.fromEntries(
          Object.entries(process.env).filter(([key]) => !/^npm_config_allow_scripts$/i.test(key)),
        ),
      },
    );
  expect(installed.status, installed.stderr).toBe(0);
  const custody = JSON.parse(readFileSync(join(output, "reader-custody.json"), "utf8"));
  expect(custody.runtime).toEqual({
    node: process.version,
    platform: process.platform,
    architecture: process.arch,
  });
  expect(custody.producerRuntime.platform).toBe("linux");
  expect(custody.producerScanner).toEqual(
    JSON.parse(readFileSync(join(candidate, "manifest.json"), "utf8")).scanner,
  );
}, 60000);

test("normal maintainer command boundary authenticates selected final ZIP with an independently selected installed reader and preserves frozen claims", () => {
  const driver = join(temporary, "final-driver.mjs");
  writeFileSync(
    driver,
    `import {readFileSync,writeFileSync,cpSync} from 'node:fs';import {join} from 'node:path';import {crc32} from 'node:zlib';import {publishFinal} from ${JSON.stringify(new URL("../../tools/artifact/publish-final.mjs", import.meta.url).href)};import {validatePublication} from ${JSON.stringify(new URL("../../tools/artifact/refresh-publication.mjs", import.meta.url).href)};import {loadScanner} from ${JSON.stringify(new URL("../../tools/refresh/scanner.mjs", import.meta.url).href)};import {sha256} from ${JSON.stringify(new URL("../../tools/refresh/contracts.mjs", import.meta.url).href)};
const [directory,consumer,root,manifestSha256,selectionSha256]=process.argv.slice(2),manifest=JSON.parse(readFileSync(join(directory,'manifest.json'))),receipt=JSON.parse(readFileSync(join(directory,'publication.json'))),trustBytes=readFileSync(join(root,'trust.json')),reader=join(root,'independent-reader');cpSync(consumer,reader,{recursive:true,verbatimSymlinks:true});writeFileSync(join(reader,'node_modules','reader-fixture-marker'),'Explicitly different independently selected fixture tree');const scanner=await loadScanner(join(directory,'scanner.tgz'),reader,manifest.scanner.sourceCommit);
let strictRefused=false;try{await validatePublication({directory,scannerInstall:reader,expectedManifestSha256:manifestSha256,expectedSelectionSha256:selectionSha256,trust:JSON.parse(trustBytes)});}catch{strictRefused=true;}if(!strictRefused)throw Error('Strict producer identity relaxed');
const parts=[],central=[];let offset=0;for(const path of [...receipt.assets.map(a=>a.path),'publication.json']){const name=Buffer.from(path),data=readFileSync(join(directory,path)),crc=crc32(data),local=Buffer.alloc(30),head=Buffer.alloc(46);local.writeUInt32LE(0x04034b50);local.writeUInt32LE(crc,14);local.writeUInt32LE(data.length,18);local.writeUInt32LE(data.length,22);local.writeUInt16LE(name.length,26);head.writeUInt32LE(0x02014b50);head.writeUInt32LE(crc,16);head.writeUInt32LE(data.length,20);head.writeUInt32LE(data.length,24);head.writeUInt16LE(name.length,28);head.writeUInt32LE(offset,42);parts.push(local,name,data);central.push(head,name);offset+=30+name.length+data.length;}const centralBytes=Buffer.concat(central),end=Buffer.alloc(22),count=receipt.assets.length+1;end.writeUInt32LE(0x06054b50);end.writeUInt16LE(count,8);end.writeUInt16LE(count,10);end.writeUInt32LE(centralBytes.length,12);end.writeUInt32LE(offset,16);const zip=Buffer.concat([...parts,centralBytes,end]);
const selected={schema:'urn:aihq:scan:final-publication-selection:1.0.0',repository:'samartomar/aih-scan',sourceHead:manifest.scanner.sourceCommit,publisherRunId:'123',finalArtifactId:'456',finalArtifactDigest:'sha256:'+sha256(zip),manifestSha256,selectionSha256,readerInstallationSha256:scanner.identity.installationSha256},repository={id:1336836161,full_name:'samartomar/aih-scan',owner:{id:9993940}},actor={id:9993940,login:'samartomar'},run={id:123,run_attempt:1,event:'workflow_dispatch',status:'completed',conclusion:'success',head_sha:selected.sourceHead,head_branch:'main',path:'.github/workflows/scan-report-publisher.yml',repository,head_repository:repository,actor,triggering_actor:actor},artifacts={total_count:3,artifacts:['checked-detached-statements','scan-refresh-attestations','scan-refresh-final-publication'].map((name,i)=>({id:454+i,name,digest:i===2?selected.finalArtifactDigest:'sha256:'+'b'.repeat(64),expired:false,size_in_bytes:i===2?zip.length:100,workflow_run:{id:123,head_sha:selected.sourceHead}}))};let mode='normal',release=null,writes=0;const files=new Map();
const command=(exe,args,options)=>{if(exe!=='gh'||args[0]!=='api'||args.includes('token'))throw Error('Only labelled normal gh subprocess allowed');const path=args[1],method=args[args.indexOf('--method')+1],headers=args.filter((_,i)=>args[i-1]==='-H');if(path.endsWith('/zip')&&!headers.includes('Accept: application/vnd.github+json'))throw Error('Actions415');if(path.includes('uploads.github.com')&&(!headers.includes('Accept: application/vnd.github+json')||!headers.includes('Content-Type: application/octet-stream')))throw Error('Upload415');if(path.includes('/releases/assets/')&&!headers.includes('Accept: application/octet-stream'))throw Error('AssetJSON');let body,status=200;if(path==='user')body={login:mode==='operator'?'other':'samartomar',id:9993940};else if(path.endsWith('/git/ref/heads/main'))body={ref:'refs/heads/main',object:{type:'commit',sha:mode==='main'?'a'.repeat(40):selected.sourceHead}};else if(path==='repos/samartomar/aih-scan')body=repository;else if(path.endsWith('/actions/runs/123'))body={...run,run_attempt:mode==='attempt'?2:1,actor:mode==='dispatcher-old'?{id:333589491,login:'stomar-tech'}:mode==='dispatcher-login'?{...actor,login:'other'}:mode==='dispatcher-id'?{...actor,id:1}:actor,triggering_actor:mode==='trigger-old'?{id:333589491,login:'stomar-tech'}:mode==='trigger-login'?{...actor,login:'other'}:mode==='trigger-id'?{...actor,id:1}:actor};else if(path.includes('/artifacts?'))body=mode==='ambiguity'?{...artifacts,total_count:4}:artifacts;else if(path.endsWith('/456/zip'))body=mode==='zip-digest'?Buffer.from('substituted archive'):zip;else if(path.endsWith('/immutable-releases')){body={enabled:true};if(mode==='403')status=403;}else if(path.includes('/releases/tags/')){body=release&&!release.draft?release:{};if(!release||release.draft)status=404;}else if(path.includes('/releases/1/assets?per_page=30&page=')){const page=Number(new URL('https://api.github.com/'+path).searchParams.get('page'));body=release.assets.slice((page-1)*30,page*30);}else if(path.includes('/releases?'))body=release?[release]:[];else if(path.endsWith('/releases')&&method==='POST'){writes++;const b=JSON.parse(options.input);body=release={id:1,tag_name:b.tag_name,draft:true,assets:[]};status=201;}else if(path.includes('uploads.github.com')){writes++;const name=new URL(path).searchParams.get('name'),id=files.size+1;if(release.assets.some(a=>a.name===name))throw Error('Asset overwrite');files.set(id,Buffer.from(options.input));release.assets.push({id,name,size:options.input.length,digest:'sha256:'+sha256(options.input),state:'uploaded'});body={id};status=201;}else if(path.includes('/releases/assets/'))body=files.get(Number(path.split('/').at(-1)));else if(method==='PATCH'){writes++;release.draft=false;release.immutable=true;body=release;}else throw Error('Unexpected external command');return {status:status<400?0:1,stdout:Buffer.concat([Buffer.from('HTTP/2.0 '+status+' OK\\r\\n\\r\\n'),Buffer.isBuffer(body)?body:Buffer.from(JSON.stringify(body))]),stderr:Buffer.alloc(0)};};
let i=0;for(const failure of ['operator','main','attempt','dispatcher-old','dispatcher-login','dispatcher-id','trigger-old','trigger-login','trigger-id','ambiguity','zip-digest','reader','403']){mode=failure;let refused=false;try{await publishFinal({selection:failure==='reader'?{...selected,readerInstallationSha256:manifest.scanner.installationSha256}:selected,scannerInstall:reader,output:join(root,'final-refused-'+i++),trustBytes,command});}catch{refused=true;}if(!refused||writes)throw Error('Final refusal wrote or accepted '+failure);}
mode='normal';const output=join(root,'final-complete'),result=await publishFinal({selection:selected,scannerInstall:reader,output,trustBytes,command});if(result.assetCount!==receipt.assets.length+2||!release.immutable)throw Error('Final durable custody absent');const custody=JSON.parse(readFileSync(join(output,'publication-custody.json')));if(custody.reader.scanner.installationSha256!==selected.readerInstallationSha256||custody.producer.scanner.installationSha256!==manifest.scanner.installationSha256||custody.authenticatedTargets!==1)throw Error('Reader relabelled producer or skipped reauthentication');if(!readFileSync(join(output,'publication','manifest.json')).equals(readFileSync(join(directory,'manifest.json'))))throw Error('Frozen claims changed');`,
  );
  const result = execute([
    driver,
    assembledFixture("final-durable").output,
    consumer,
    temporary,
    manifestSha,
    selectionSha,
  ]);
  expect(result.status, result.stderr).toBe(0);
}, 90000);

test("batch custody accepts one selected immutable archive and refuses substitutions and oversized transport", () => {
  const directory = mkdtempSync(join(tmpdir(), "scan-batch-custody-"));
  try {
    const repository = { id: 1336836161, full_name: "samartomar/aih-scan", owner: { id: 9993940 } };
    const actor = { login: "samartomar", id: 9993940 };
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
