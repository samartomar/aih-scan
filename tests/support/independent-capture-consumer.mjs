// Installed public APIs + maintained producer boundaries. All input/release
// transport is a labelled fixture; no GitHub write or production signing occurs.
import assert from "node:assert/strict";
import {generateKeyPairSync} from "node:crypto";
import {cpSync,existsSync,mkdirSync,readFileSync,readdirSync,writeFileSync} from "node:fs";
import {join} from "node:path";
import {pathToFileURL} from "node:url";
import {freezeBatch,runBatch} from "../../tools/refresh/refresh.mjs";
import {prepareCatalogCapture} from "../../tools/refresh/catalog-capture.mjs";
import {batchCeilings,batchId,canonicalBytes,ceilings,sha256,targetDirectory,validateManifest} from "../../tools/refresh/contracts.mjs";
import {retainCustody,validateCandidate,prepareSigning,recheckSigning,assemblePublication,validatePublication} from "../../tools/artifact/refresh-publication.mjs";
import {publishRelease} from "../../tools/artifact/publish-refresh-release.mjs";
import {retainFailureEvidence} from "../../tools/artifact/retain-failure-evidence.mjs";

const [tgz,install,out,qualification] = process.argv.slice(2);
mkdirSync(out,{mode:0o700});
const identities=["default","extensions","ecc","superpowers","anthropic","diagnostic"];
const commit="b".repeat(40),captures=[],contents=[];
const member=(path,bytes)=>({path,sha256:sha256(bytes),byteLength:bytes.length});
const releaseBytes=value=>Buffer.from(`${canonicalBytes(value)}\n`);
// One capture is a real Catalog release 1.7 producer output (inventory 1.2.0); the rest stay release 1.5.
const current=new URL("../fixtures/catalog-capture-1.7/",import.meta.url);
for(const [index,captureId] of identities.entries()) {
  const root=join(out,captureId);
  if(captureId==="extensions") {
    cpSync(new URL("project-basics",current),root,{recursive:true});
    const path="release/baselines/project-basics/content-inventory.json",inventory=readFileSync(join(root,path));
    const bytes=prepareCatalogCapture({root,inventoryPath:path,inventorySha256:sha256(inventory)});
    captures.push({captureId,bytes,selector:{releaseId:String(11+index*2),assetId:String(12+index*2),sha256:sha256(bytes),byteLength:bytes.length,inventory:member(path,inventory)}});
    contents.push({contentBytes:readFileSync(new URL("project-basics.content.json",current)),inventory});
    continue;
  }
  mkdirSync(join(root,"release","recipes"),{recursive:true});mkdirSync(join(root,"release","materials"));
  const text=Buffer.from(`Independent ${captureId}\n`),material={id:"text",...member("release/materials/entry.txt",text)};
  const recipe={schema:"urn:aihq:core:recipe:1.0.0",id:"entry",description:"Place fixture material",inputs:{},materials:[{id:"text",sha256:material.sha256,byteLength:material.byteLength}],targets:["project"],prerequisites:[],operations:[{id:"write",kind:"file.write",purpose:"Place fixture text",scope:"project",target:{root:"project",segments:[{literal:"entry.txt"}]},material:"text",requires:[],checks:[]}],checks:[]};
  const recipeBytes=releaseBytes(recipe),recipeDescriptor={id:"entry",schema:recipe.schema,...member("release/recipes/entry.json",recipeBytes)};
  const content={schema:"urn:aihq:catalog:release:1.4.0",package:{name:"@aihq/catalog",version:"0.3.0"},sources:[{id:"fixture",origin:{kind:"authored"}}],items:[{id:"entry",label:captureId,kind:"skill",sourceIds:["fixture"],scopes:["project"],targets:[],inputs:{},recipe:recipeDescriptor,materials:[material],dependencies:{requires:[],optional:[],conflicts:[]},metadata:{fixture:true}}]};
  const inventory=releaseBytes({schema:"urn:aihq:catalog:content-inventory:1.0.0",projection:"urn:aihq:catalog:release-content:1.0.0",release:{...content,schema:"urn:aihq:catalog:release:1.5.0"}});
  writeFileSync(join(root,recipeDescriptor.path),recipeBytes);writeFileSync(join(root,material.path),text);writeFileSync(join(root,"release/inventory.json"),inventory);
  const bytes=prepareCatalogCapture({root,inventoryPath:"release/inventory.json",inventorySha256:sha256(inventory)});
  captures.push({captureId,bytes,selector:{releaseId:String(11+index*2),assetId:String(12+index*2),sha256:sha256(bytes),byteLength:bytes.length,inventory:member("release/inventory.json",inventory)}});
  contents.push({contentBytes:releaseBytes(content),inventory});
}
let substitute=false;
const api={json:async path=>{
  if(path==="repos/samartomar/aih-catalog")return {full_name:"samartomar/aih-catalog",private:false,archived:false,owner:{id:9993940}};
  const capture=captures.find(row=>path.endsWith(`/releases/${row.selector.releaseId}`)||path.endsWith(`/releases/${row.selector.releaseId}/assets?per_page=2`)||path.endsWith(`/git/ref/tags/catalog-capture-${row.selector.sha256}`));assert(capture,"Selected immutable fixture path");
  const {selector}=capture,tag=`catalog-capture-${selector.sha256}`;
  if(path.includes("/git/ref/"))return {ref:`refs/tags/${tag}`,object:{type:"commit",sha:commit}};
  if(path.endsWith(`/releases/${selector.releaseId}`))return {id:Number(selector.releaseId),immutable:true,draft:false,tag_name:tag,target_commitish:commit};
  return [{id:Number(selector.assetId),name:"catalog-capture.json",state:"uploaded",size:selector.byteLength,digest:`sha256:${selector.sha256}`,url:`https://api.github.com/repos/samartomar/aih-catalog/releases/assets/${selector.assetId}`}];
},bytes:async path=>{const row=captures.find(row=>path.endsWith(`/${row.selector.assetId}`));assert(row);return {status:200,bytes:substitute&&row===captures[4]?captures[0].bytes:row.bytes};}};
const input={schema:"urn:aihq:scan:catalog-capture-batch-input:1.0.0",scannerSourceCommit:"a".repeat(40),runtime:{node:process.version,platform:"linux",architecture:"x64"},profile:"independent-linux-v1",limits:{...ceilings,detectorTimeoutMs:1000},batchLimits:{...batchCeilings,maxDurationMs:600000},targets:captures.map(row=>({captureId:row.captureId,repository:"samartomar/aih-catalog",ref:commit,selection:{paths:"all",excludedPaths:[]},trustLint:{internalScopes:[],mcpConfigPaths:row.captureId==="diagnostic"?["missing.json"]:[]},capture:row.selector}))};
const freeze=selected=>freezeBatch({input:selected,scannerTarball:tgz,scannerInstall:install,captureTransport:api,resolveRepository:async repository=>({repository,repositoryUrl:`https://github.com/${repository}.git`})});
const manifest=await freeze(input),candidate=join(out,"candidate");
const inventory=await runBatch({manifest,scannerTarball:tgz,scannerInstall:install,captureTransport:api,output:candidate});
assert.equal(inventory.targets.length,6);assert.equal(inventory.termination,"completed");
assert.equal(new Set(inventory.targets.map(row=>row.repository)).size,1);
assert.equal(new Set(inventory.targets.map(row=>row.resultPath)).size,6);
await retainCustody({candidate,scannerTarball:tgz,scannerInstall:install});
const expectedManifestSha256=sha256(canonicalBytes(manifest));
const checked=await validateCandidate({candidate,scannerInstall:install,expectedManifestSha256});
const expectedSelectionSha256=sha256(canonicalBytes(checked.selection)),signing=join(out,"signing");
prepareSigning({candidate,selection:checked.selection,expectedSelectionSha256,output:signing});recheckSigning({directory:signing,expectedSelectionSha256});
const swappedSelection=structuredClone(checked.selection);[swappedSelection.targets[0].captureId,swappedSelection.targets[1].captureId]=[swappedSelection.targets[1].captureId,swappedSelection.targets[0].captureId];
assert.throws(()=>prepareSigning({candidate,selection:swappedSelection,expectedSelectionSha256:sha256(canonicalBytes(swappedSelection)),output:join(out,"wrong-signing")}));
assert(!existsSync(join(out,"wrong-signing")));
assert.equal(readdirSync(signing).length,11);assert.equal(checked.selection.targets.length,5);
assert(!readdirSync(signing).some(path=>path.includes("capture")||path.endsWith(".tgz")));
const key=generateKeyPairSync("ed25519"),spki=key.publicKey.export({type:"spki",format:"der"}),keyId=`ed25519:${sha256(spki)}`;
const trust={keys:[{identity:"independent-capture-fixture-only",keyId,publicKeySpkiBase64:spki.toString("base64")}],publishers:[]};
const bundles=join(out,"bundles");mkdirSync(bundles);
for(const [index,row] of inventory.targets.entries()) {
  const result=JSON.parse(readFileSync(join(candidate,row.resultPath),"utf8"));
  if(row.captureId==="diagnostic"){assert.equal(result.status,"diagnostic");assert(!row.scanId);continue;}
  assert.equal(result.status,"assessment");
  assert(result.report.results.some(row=>row.outcome==="succeeded"));
  assert(result.report.results.some(row=>row.outcome==="refused"||row.outcome==="failed"));
  const signed=await checked.scanner.host.signArtifact({report:result.report,annexes:result.annexes.map(row=>({id:row.id,bytes:Buffer.from(row.bytesBase64,"base64")})),signer:{keyId,privateKey:key.privateKey}});
  writeFileSync(join(bundles,`bundle-${index}.json`),canonicalBytes(signed.artifact.attestation));
}
const publication=join(out,"publication");
await assemblePublication({candidate,scannerInstall:install,expectedManifestSha256,expectedSelectionSha256,bundles,trust,output:publication});
const published=await validatePublication({directory:publication,scannerInstall:install,expectedManifestSha256,expectedSelectionSha256,trust});
const artifacts=[];
for(const [index,row] of published.targets.entries()) {
  if(row.captureId==="diagnostic"){assert.equal(row.status,"diagnostic");continue;}
  assert.equal(row.captureId,identities[index]);assert.equal(row.authenticity,"authenticated");
  const original=JSON.parse(readFileSync(join(candidate,row.resultPath),"utf8"));
  const bytes=readFileSync(join(publication,row.authenticatedPath)),read=await checked.scanner.read.readArtifact(bytes);artifacts.push({bytes,read});
  assert.deepEqual(read.report,original.report,"Original scopes, timestamps and outcomes remain exact");
  assert.equal((await checked.scanner.read.readContentCoverage({read,descriptors:[captures[index].selector.inventory]})).status,"matched");
  assert.equal((await checked.scanner.read.readContentCoverage({read,descriptors:[captures[(index+1)%5].selector.inventory]})).status,"mismatched");
}
// Later explicit subset has only the selected root/report. Original siblings stay exact.
const originalHashes=published.targets.filter(row=>row.authenticity==="authenticated").map(row=>sha256(readFileSync(join(publication,row.authenticatedPath))));
const subset=await freeze({...input,targets:[input.targets[1]]});
const later=await runBatch({manifest:subset,scannerTarball:tgz,scannerInstall:install,captureTransport:api,output:join(out,"subset")});
assert.deepEqual(later.targets.map(row=>row.captureId),["extensions"]);
assert.deepEqual(published.targets.filter(row=>row.authenticity==="authenticated").map(row=>sha256(readFileSync(join(publication,row.authenticatedPath)))),originalHashes);
// Candidate reorder and sibling substitution cannot enter a signing selection.
const reordered=join(out,"reordered");cpSync(candidate,reordered,{recursive:true});
const wrong=JSON.parse(readFileSync(join(reordered,"inventory.json"),"utf8"));wrong.targets.reverse();writeFileSync(join(reordered,"inventory.json"),canonicalBytes(wrong));
await assert.rejects(validateCandidate({candidate:reordered,scannerInstall:install,expectedManifestSha256}));
substitute=true;
await assert.rejects(runBatch({manifest,scannerTarball:tgz,scannerInstall:install,captureTransport:api,output:join(out,"substituted")}));assert(!existsSync(join(out,"substituted")));substitute=false;
for(const changed of [{...manifest.batchLimits,maxSourceEntries:1},{...manifest.batchLimits,maxSourceBytes:1},{...manifest.batchLimits,maxInputBytes:1}]) {
  const invalid={...manifest,batchLimits:changed};invalid.batchId=batchId(invalid);assert.throws(()=>validateManifest(invalid));
}
const deadline={...manifest,batchLimits:{...manifest.batchLimits,maxDurationMs:100}};deadline.batchId=batchId(deadline);
const slowApi={...api,json:async(...args)=>{await new Promise(done=>setTimeout(done,150));return api.json(...args);}};
const timed=join(out,"timed"),termination=await runBatch({manifest:deadline,scannerTarball:tgz,scannerInstall:install,captureTransport:slowApi,output:timed});
assert.equal(termination.termination,"deadline-exceeded");assert(termination.targets.every(row=>row.status==="diagnostic"));
await retainCustody({candidate:timed,scannerTarball:tgz,scannerInstall:install});
await assert.rejects(validateCandidate({candidate:timed,scannerInstall:install,expectedManifestSha256:sha256(canonicalBytes(deadline))}));
await assert.rejects(freezeBatch({input:{...input,batchLimits:{...input.batchLimits,maxDurationMs:100}},scannerTarball:tgz,scannerInstall:install,captureTransport:slowApi,resolveRepository:async repository=>({repository,repositoryUrl:`https://github.com/${repository}.git`})}));
const cancelled=await runBatch({manifest,scannerTarball:tgz,scannerInstall:install,captureTransport:api,output:join(out,"cancelled"),signal:AbortSignal.abort()});
assert.equal(cancelled.termination,"cancelled");assert(cancelled.targets.every(row=>!row.scanId&&row.detectors.every(detector=>detector.outcome==="not-run")));
const interruptedPath=join(out,"interrupted"),controller=new AbortController();
const completedPath=join(interruptedPath,"targets","catalog--default","result.json");
let retainedFirst;
const interrupt=setInterval(()=>{if(existsSync(completedPath)){retainedFirst=readFileSync(completedPath);controller.abort();}},1);
try {
  const interrupted=await runBatch({manifest,scannerTarball:tgz,scannerInstall:install,captureTransport:api,output:interruptedPath,signal:controller.signal});
  assert.equal(interrupted.termination,"cancelled");
  assert.equal(interrupted.targets[0].status,"assessment");
  assert(interrupted.targets.some(row=>row.status==="diagnostic"&&!row.scanId));
  assert(readFileSync(completedPath).equals(retainedFirst),"Cancellation retains completed original report bytes");
} finally {clearInterval(interrupt);}
const failure=retainFailureEvidence({candidate,frozen:candidate,output:join(out,"failure")});assert.equal(failure.targets.length,6);assert.deepEqual(failure.targets.map(row=>row.captureId),identities);
const damaged=join(out,"damaged-manifest");cpSync(candidate,damaged,{recursive:true});writeFileSync(join(damaged,"manifest.json"),"{}");
const recovered=retainFailureEvidence({candidate:damaged,frozen:damaged,output:join(out,"damaged-failure")});
assert.deepEqual(recovered.targets.filter(row=>row.captureId).map(row=>row.captureId),[...identities].sort());
for(const row of recovered.targets.filter(row=>row.captureId)) {
  const original=inventory.targets.find(target=>target.captureId===row.captureId);
  assert.equal(row.files.find(file=>file.path.endsWith("/result.json")).sha256,original.resultSha256);
}
// Actual Catalog and Core are optional explicit installed proof inputs, never sibling source imports.
const qualifications=[];
if(qualification==="qualify") {
  const entry=join(install,"qualification-services.mjs");
  writeFileSync(entry,'export * as catalog from "@aihq/catalog/node"; export * as reader from "@aihq/catalog/reader"; export * as core from "@aihq/core";', {flag:"wx"});
  const {catalog,reader,core}=await import(pathToFileURL(entry).href);
  for(const [index,artifact] of artifacts.entries()) {
    const contentBytes=contents[index].contentBytes;
    const frozen=reader.createContentInventory(contentBytes,{expectedSha256:sha256(contentBytes)});assert(frozen.valid,JSON.stringify(frozen));assert.deepEqual(Buffer.from(frozen.bytes),contents[index].inventory);
    const baseline={schema:"urn:aihq:catalog:scan-baseline:1.0.0",inventory:captures[index].selector.inventory,scanId:artifact.read.scanId,artifact:{sha256:sha256(artifact.bytes),byteLength:artifact.bytes.length,location:{kind:"package",path:"release/baseline.json"}},scope:{namespace:"package-relative",paths:artifact.read.report.selection.paths,excludedPaths:artifact.read.report.selection.excludedPaths}};
    const services={readArtifact:checked.scanner.read.readArtifact,readContentCoverage:checked.scanner.read.readContentCoverage,authenticateEvidence:core.authenticateEvidence,acquireArtifact:async()=>artifact.bytes};
    const result=await catalog.prepareReleaseBaseline({contentBytes,expectedSha256:sha256(contentBytes),baseline,trust},services);assert(result.valid,JSON.stringify(result));assert(result.itemCoverage.every(item=>item.members.every(member=>member.capture==="matched")));
    const swapped=await catalog.prepareReleaseBaseline({contentBytes,expectedSha256:sha256(contentBytes),baseline:{...baseline,scanId:artifacts[(index+1)%5].read.scanId,artifact:{...baseline.artifact,sha256:sha256(artifacts[(index+1)%5].bytes),byteLength:artifacts[(index+1)%5].bytes.length}},trust},{...services,acquireArtifact:async()=>artifacts[(index+1)%5].bytes});assert.equal(swapped.valid,false);
    qualifications.push({captureId:identities[index],scanId:artifact.read.scanId,releaseSha256:sha256(result.releaseBytes),crossTargetRefused:true});
  }
}
// Lower-level release writer transport is controlled in-memory; no upload occurs.
const assets=[],remote=new Map();let draft=true;
const publicationResult=await publishRelease({directory:publication,transport:{immutableEnabled:async()=>true,lookup:async tag=>({id:1,tag_name:tag,draft,immutable:!draft}),listAssets:async()=>assets,
  upload:async(_id,name,bytes)=>{const id=assets.length+1;remote.set(id,bytes);assets.push({id,name,state:"uploaded",size:bytes.length,digest:`sha256:${sha256(bytes)}`});},download:async id=>remote.get(id),publish:async()=>{draft=false;return {id:1,tag_name:`scan-report-batch-${manifest.batchId.slice("batch:sha256:".length)}`,draft:false,immutable:true};}}});
const receipt={fixtureOnly:true,targets:identities,signatures:5,signingPayloadFiles:readdirSync(signing),aggregateInputBytes:captures.reduce((sum,row)=>sum+row.bytes.length,0),reports:published.targets.map(row=>({captureId:row.captureId,scanId:row.scanId,completion:row.completion,detectors:row.detectors})),qualifications,publicationAssetCount:publicationResult.assetCount};
writeFileSync(join(out,"receipt.json"),JSON.stringify(receipt,null,2));console.log(JSON.stringify(receipt));
