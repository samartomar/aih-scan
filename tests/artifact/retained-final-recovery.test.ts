import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { expect, test } from "vitest";

const helper = new URL("../../tools/artifact/recover-retained-final.mjs", import.meta.url).href;
test("the hosted transfer refuses a different dispatcher before network or filesystem work", () => {
  const result = spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      `import assert from 'node:assert/strict';
import {recoverRetainedFinal} from ${JSON.stringify(helper)};
let calls=0;
await assert.rejects(recoverRetainedFinal({context:{actor:'stomar-tech'},request:()=>{calls++;throw Error('No network admitted');}}),/context/);
assert.equal(calls,0);`,
    ],
    { encoding: "utf8", timeout: 10000, windowsHide: true },
  );
  expect(result.status, result.stderr).toBe(0);
});

function invoke(mode: string) {
  const root = mkdtempSync(join(tmpdir(), "scan-retained-transfer-"));
  try {
    const driver = join(root, "driver.mjs");
    writeFileSync(
      driver,
      `
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {mkdirSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {transferRetainedPublication,retainedPins} from ${JSON.stringify(helper)};
import {canonicalBytes,sha256} from ${JSON.stringify(new URL("../../tools/refresh/contracts.mjs", import.meta.url).href)};
const [root,mode]=process.argv.slice(2),directory=join(root,'publication');mkdirSync(directory);
const token='labelled-disposable-HTTP-fixture',head='a'.repeat(40);
const context={event:'workflow_dispatch',repository:'samartomar/aih-scan',repositoryId:'1336836161',ownerId:'9993940',actor:'samartomar',actorId:'9993940',triggeringActor:'samartomar',attempt:'1',ref:'refs/heads/codex/scan-94-upload-framing',workflowRef:'samartomar/aih-scan/.github/workflows/scan-report-publisher.yml@refs/heads/codex/scan-94-upload-framing',head,recoveryHead:head,runId:'40000000000',candidateRunId:'37823479906',manifestSha256:retainedPins.manifestSha256,selectionSha256:retainedPins.selectionSha256};
const originals=new Map([
 ['inventory.json',canonicalBytes({schema:'urn:aihq:scan:publication-inventory:1.0.0',batchId:retainedPins.batchId,targets:Array.from({length:7},(_,i)=>({repository:'fixture/'+i}))})],
 ['consumer-package-lock.json',Buffer.from('fixture original lock')],['custody.json',Buffer.from('fixture original producer custody')],
 ...Array.from({length:39},(_,i)=>['data-'+i+'.bin',Buffer.from('fixture retained signed byte '+i)])]);
const entries=[];for(const [name,bytes] of originals){writeFileSync(join(directory,name),bytes);entries.push({path:name,name,byteLength:bytes.length,sha256:sha256(bytes)});}
const receipt=canonicalBytes({schema:'urn:aihq:scan:publication-assets:1.0.0',batchId:retainedPins.batchId,expandedBytes:entries.reduce((n,a)=>n+a.byteLength,0),assets:entries});writeFileSync(join(directory,'publication.json'),receipt);originals.set('publication.json',receipt);
const custodyPath=join(root,'original-external-custody.json'),custody=canonicalBytes({fixture:'original external custody, never reconstructed by transfer'});writeFileSync(custodyPath,custody);originals.set('publication-custody.json',custody);
const metadata=(name,id)=>({name,id,state:'uploaded',size:originals.get(name).length,digest:'sha256:'+sha256(originals.get(name))});
const rows=[metadata('consumer-package-lock.json',623062791),metadata('custody.json',623392024),{id:624741751,name:'inventory.json',state:'starter',digest:null,size:1069648,created_at:'2026-10-09T11:14:00Z',updated_at:'2026-10-09T11:14:00Z'}];
const files=new Map(rows.slice(0,2).map(row=>[row.id,originals.get(row.name)]));
if(mode==='wrong-old-id')rows[0].id=1;
if(mode==='starter-uploaded')rows[2].state='uploaded';
if(mode==='starter-digest')rows[2].digest='sha256:'+'0'.repeat(64);
if(mode==='starter-time')rows[2].updated_at='later';
if(mode==='extra')rows.push({...rows[0],id:2,name:'extra.bin'});
if(mode==='duplicate')rows[1].name=rows[0].name;
if(mode==='wrong-old-bytes')files.set(623062791,Buffer.alloc(rows[0].size));
if(mode==='bad-local')writeFileSync(join(directory,'data-0.bin'),'bad');
let deleted=false,postCount=0,tick=0,server;const calls=[],events=[],writes=[],downloads=[];
const repo={id:1336836161,full_name:'samartomar/aih-scan',owner:{id:9993940}},actor={login:'samartomar',id:9993940};
const draft=()=>({id:407274269,draft:mode==='published'?false:true,immutable:mode==='published',target_commitish:retainedPins.sourceHead,tag_name:'scan-report-batch-'+retainedPins.batchId.slice(13),assets:rows.filter(row=>row.state==='uploaded').slice(0,2)});
function route(url,method,bytes){
 const u=new URL(url),path=u.pathname;
 if(method==='GET'&&path==='/repos/samartomar/aih-scan')return {status:200,body:repo};
 if(method==='GET'&&path.endsWith('/git/ref/heads/main'))return {status:200,body:{ref:'refs/heads/main',object:{type:'commit',sha:mode==='wrong-main'?'0'.repeat(40):retainedPins.sourceHead}}};
 if(method==='GET'&&path.endsWith('/actions/runs/40000000000'))return {status:200,body:{id:40000000000,run_attempt:mode==='attempt2'?2:1,event:'workflow_dispatch',status:'in_progress',conclusion:null,head_sha:head,head_branch:retainedPins.branch,path:'.github/workflows/scan-report-publisher.yml',repository:repo,head_repository:repo,actor,triggering_actor:mode==='wrong-trigger'?{login:'stomar-tech',id:9993940}:actor}};
 if(method==='GET'&&path.endsWith('/releases/407274269'))return {status:200,body:draft()};
 if(method==='GET'&&path.endsWith('/releases/407274269/assets')){
   const page=Number(u.searchParams.get('page'));assert.equal(u.searchParams.get('per_page'),'30');assert(page>=1&&page<=3);
   const value=rows.map(row=>({...row}));if(mode==='changed-final-id'&&postCount===42)value[0].id=9;
   return {status:200,body:value.slice((page-1)*30,page*30)};
 }
 if(method==='GET'&&path.endsWith('/releases/assets/624741751'))return {status:200,body:{...rows.find(row=>row.id===624741751),url:'https://api.github.com/repos/samartomar/aih-scan/releases/assets/624741751'}};
 if(method==='GET'&&path.includes('/releases/assets/')){
   const id=Number(path.split('/').at(-1));assert(files.has(id));downloads.push(id);
   if(mode==='signed-download'&&u.hostname==='api.github.com')return {status:302,location:'https://release-assets.githubusercontent.com/fixture/'+id+'?fixture-signature=never-log'};
   return {status:200,body:mode==='wrong-new-bytes'&&id>=700000000?Buffer.alloc(files.get(id).length):files.get(id)};
 }
 if(method==='GET'&&u.hostname==='release-assets.githubusercontent.com'){const id=Number(path.split('/').at(-1));return {status:200,body:files.get(id)};}
 if(method==='DELETE'){
   assert.equal(path,'/repos/samartomar/aih-scan/releases/assets/624741751');assert(!deleted);assert.equal(bytes.length,0);deleted=true;writes.push('DELETE');rows.splice(rows.findIndex(row=>row.id===624741751),1);
   if(mode==='late-delete')tick=1500000;
   return {status:204,body:Buffer.alloc(0)};
 }
 if(method==='POST'){
   assert.equal(u.hostname,'uploads.github.com');assert.equal(path,'/repos/samartomar/aih-scan/releases/407274269/assets');assert(deleted);
   const name=u.searchParams.get('name');assert(originals.has(name));assert(!rows.some(row=>row.name===name));assert(bytes.equals(originals.get(name)));postCount++;writes.push('POST');
   assert(postCount<=42);const row=metadata(name,700000000+postCount);rows.push(row);files.set(row.id,bytes);
   if(mode==='upload-disconnect')return {disconnect:true};
   if(mode==='upload-503')return {status:503,body:{error:'fixture response never persisted'}};
   if(mode==='late-upload')tick=1500000;
   return {status:201,body:mode==='bad-upload-meta'?{...row,id:623062791}:row};
 }
 throw Error('Forbidden fixture route '+method+' '+path);
}
try{
 server=createServer(async(req,res)=>{try{
   const original=req.headers['x-fixture-url'];const u=new URL(original);
   assert.equal(req.headers.authorization,u.hostname==='release-assets.githubusercontent.com'?undefined:'Bearer '+token);
   const chunks=[];for await(const chunk of req)chunks.push(chunk);const received=Buffer.concat(chunks);if(req.method==='POST'){assert.equal(req.headers['content-length'],String(received.length));assert.equal(req.headers['transfer-encoding'],undefined);}calls.push({method:req.method,path:u.pathname});
   const value=route(original,req.method,received);if(value.disconnect){req.socket.destroy();return;}
   res.writeHead(value.status,value.location?{location:value.location}:{});res.end(Buffer.isBuffer(value.body)?value.body:value.body===undefined?'':JSON.stringify(value.body));
 }catch{res.writeHead(500);res.end('fixture-refused');}});
 await new Promise(done=>server.listen(0,'127.0.0.1',done));const port=server.address().port;
 const request=(url,options)=>{assert(['api.github.com','uploads.github.com','release-assets.githubusercontent.com'].includes(new URL(url).hostname));if((options.method??'GET')==='GET')assert.equal(options.body,undefined);return fetch('http://127.0.0.1:'+port+'/',{...options,headers:{...options.headers,'x-fixture-url':String(url)}});};
 let result,error;try{result=await transferRetainedPublication({directory,custodyPath,context,token,request,now:()=>tick,startedAt:0,audit:event=>{events.push(event);if(mode==='audit-expired'&&event.phase==='reserved'&&event.purpose==='original-upload')tick=1500000;}});}catch(caught){error=caught;}
 assert(!calls.some(call=>call.method==='PATCH'||call.path.endsWith('/immutable-releases')||call.path.endsWith('/releases')));
 assert(!JSON.stringify(events).includes(token));assert(!JSON.stringify(events).includes('never-log'));assert(!JSON.stringify(events).includes('fixture response'));
 if(['normal','signed-download'].includes(mode)){
   assert.equal(error,undefined);assert.equal(result.status,'uploaded-draft-originals-not-published');assert.equal(result.assetCount,44);assert.equal(result.deletesReserved,1);assert.equal(result.uploadsReserved,42);assert.equal(result.promotionsReserved,0);assert.equal(result.creationsReserved,0);assert.equal(result.retries,0);
   assert.equal(result.assetIds.length,44);assert(result.assetIds.includes(623062791)&&result.assetIds.includes(623392024));assert.equal(writes.filter(x=>x==='DELETE').length,1);assert.equal(postCount,42);assert.equal(downloads.length,48);
 }else{
   assert(error,'Hazard must refuse');assert.equal(result,undefined);
   if(['upload-disconnect','upload-503','late-upload','bad-upload-meta'].includes(mode)){assert.equal(postCount,1);assert.equal(calls.at(-1).method,'POST');}
   else if(['late-delete','audit-expired'].includes(mode)){assert.equal(postCount,0);assert.deepEqual(writes,['DELETE']);}
   else if(['changed-final-id','wrong-new-bytes'].includes(mode)){assert.equal(postCount,42);}
   else assert.deepEqual(writes,[],'Admission hazard must precede destructive/transport work');
 }
 console.log(JSON.stringify({mode,refused:!!error,deletes:writes.filter(x=>x==='DELETE').length,uploads:postCount,downloads:downloads.length}));
}finally{if(server){server.closeAllConnections();await new Promise(done=>server.close(done));}}
`,
    );
    return spawnSync(process.execPath, [driver, root, mode], {
      encoding: "utf8",
      timeout: 15000,
      windowsHide: true,
    });
  } finally {
    assert(resolve(root).startsWith(resolve(tmpdir()) + sep));
    rmSync(root, { recursive: true });
  }
}

test.each([
  "normal",
  "signed-download",
])("%s exact prepared transfer keeps all 44 originals draft with one cleanup and no promotion", (mode) => {
  const result = invoke(mode);
  expect(result.status, result.stderr + result.stdout).toBe(0);
});
test.each([
  "bad-local",
  "wrong-old-id",
  "starter-uploaded",
  "starter-digest",
  "starter-time",
  "extra",
  "duplicate",
  "wrong-old-bytes",
  "published",
  "wrong-main",
  "attempt2",
  "wrong-trigger",
  "upload-disconnect",
  "upload-503",
  "bad-upload-meta",
  "late-upload",
  "late-delete",
  "audit-expired",
  "changed-final-id",
  "wrong-new-bytes",
])("%s refuses bounded transfer without retry or promotion", (mode) => {
  const result = invoke(mode);
  expect(result.status, result.stderr + result.stdout).toBe(0);
});

test.each([
  "custody-corrupt",
  "custody-whitespace",
  "old-run-actor",
  "archive-size",
  "archive-digest",
  "redirect-host",
  "signed-archive",
])("%s loader refuses before any release write and preserves safe audit", (mode) => {
  const root = mkdtempSync(join(tmpdir(), "scan-retained-loader-"));
  try {
    const driver = join(root, "driver.mjs");
    writeFileSync(
      driver,
      `
import assert from 'node:assert/strict';
import {existsSync,readFileSync} from 'node:fs';
import {join} from 'node:path';
import {recoverRetainedFinal,retainedPins} from ${JSON.stringify(helper)};
const [root,mode]=process.argv.slice(2),output=join(root,'output'),calls=[];
const head='a'.repeat(40),repo={id:1336836161,full_name:'samartomar/aih-scan',owner:{id:9993940}},actor={login:'samartomar',id:9993940};
const context={event:'workflow_dispatch',repository:'samartomar/aih-scan',repositoryId:'1336836161',ownerId:'9993940',actor:'samartomar',actorId:'9993940',triggeringActor:'samartomar',attempt:'1',ref:'refs/heads/codex/scan-94-upload-framing',workflowRef:'samartomar/aih-scan/.github/workflows/scan-report-publisher.yml@refs/heads/codex/scan-94-upload-framing',head,recoveryHead:head,runId:'40000000000',candidateRunId:'37823479906',manifestSha256:retainedPins.manifestSha256,selectionSha256:retainedPins.selectionSha256};
const current={id:40000000000,run_attempt:1,event:'workflow_dispatch',status:'in_progress',conclusion:null,head_sha:head,head_branch:retainedPins.branch,path:'.github/workflows/scan-report-publisher.yml',repository:repo,head_repository:repo,actor,triggering_actor:actor};
const original={...current,id:37828958516,status:'completed',conclusion:'success',head_sha:retainedPins.sourceHead,head_branch:'main',actor:mode==='old-run-actor'?{...actor,id:1}:actor};
const artifacts={total_count:3,artifacts:['checked-detached-statements','scan-refresh-attestations','scan-refresh-final-publication'].map((name,i)=>({id:i===2?11573028222:100+i,name,digest:i===2?'sha256:'+retainedPins.archiveSha256:'sha256:'+'b'.repeat(64),expired:false,size_in_bytes:i===2?83224990:1,workflow_run:{id:37828958516,head_sha:retainedPins.sourceHead}}))};
const request=async(url,options)=>{
 assert.equal(options.method??'GET','GET');assert.equal(options.body,undefined);calls.push(String(url));
 const u=new URL(url),path=u.pathname;let value;
 if(u.hostname.endsWith('.blob.core.windows.net')){assert.equal(new Headers(options.headers).get('authorization'),null);return new Response(Buffer.from('wrong archive'));}
 assert.equal(u.hostname,'api.github.com');assert.equal(new Headers(options.headers).get('authorization'),'Bearer labelled-ephemeral-fixture');
 if(path==='/repos/samartomar/aih-scan')value=repo;
 else if(path.endsWith('/git/ref/heads/main'))value={ref:'refs/heads/main',object:{type:'commit',sha:retainedPins.sourceHead}};
 else if(path.endsWith('/actions/runs/40000000000'))value=current;
 else if(path.endsWith('/actions/runs/37828958516'))value=original;
 else if(path.endsWith('/actions/runs/37828958516/artifacts'))value=artifacts;
 else if(path.endsWith('/actions/artifacts/11573028222/zip')){
  if(mode==='redirect-host'||mode==='signed-archive')return new Response(null,{status:302,headers:{location:mode==='redirect-host'?'https://example.invalid/unknown':'https://productionresultssa0.blob.core.windows.net/fixture?signature=never-log'}});
  return new Response(mode==='archive-digest'?Buffer.alloc(83224990):Buffer.from('wrong archive'));
 } else throw Error('No release request admitted');
 return new Response(JSON.stringify(value));
};
let custodyBase64=${JSON.stringify(originalCustodyBase64)};
if(mode==='custody-corrupt')custodyBase64=Buffer.from('different bytes').toString('base64');
if(mode==='custody-whitespace')custodyBase64+=String.fromCharCode(10);
await assert.rejects(recoverRetainedFinal({context,custodyBase64,output,token:'labelled-ephemeral-fixture',request}));
assert(!existsSync(join(output,'publication')));assert(!existsSync(join(output,'audit/outcome.json')));
if(mode.startsWith('custody-')){assert.equal(calls.length,0);assert(!existsSync(output));}
else{assert(existsSync(join(output,'audit/refusal.json')));const audit=readFileSync(join(output,'audit/commands.jsonl'),'utf8');assert(!audit.includes('never-log'));assert(!audit.includes('labelled-ephemeral-fixture'));assert(!calls.some(url=>url.includes('/releases')));}
console.log(JSON.stringify({mode,readCalls:calls.length,mutations:0}));
`,
    );
    const result = spawnSync(process.execPath, [driver, root, mode], {
      encoding: "utf8",
      timeout: 15000,
      windowsHide: true,
    });
    expect(result.status, result.stderr + result.stdout).toBe(0);
  } finally {
    assert(resolve(root).startsWith(resolve(tmpdir()) + sep));
    rmSync(root, { recursive: true });
  }
});

// Exact public intended custody asset, including its original Windows reader attribution.
const originalCustodyBase64 =
  "eyJhY3Rpb25zQ3VzdG9keSI6eyJhcmNoaXZlQnl0ZXMiOjgzMjI0OTkwLCJhcnRpZmFjdElkIjoxMTU3MzAyODIyMiwiZXZlbnQiOiJzY2FuLXJlZnJlc2gtY3VzdG9keS52ZXJpZmllZCIsImhlYWQiOiI1M2RjMGNmZmQyNzA0ZjBjZWZkNzZiNTNhYmU4NTA2NTFkMWU5NTA1IiwicGhhc2UiOiJhY3Rpb25zLWN1c3RvZHkiLCJydW5JZCI6Mzc4Mjg5NTg1MTYsInNlcnZpY2VEaWdlc3QiOiJzaGEyNTY6NGE2NGNlZTlhOWUzYWFlYTFjMTU2NjhjMzFjZmU2YjBkOWYxZjhmMmE2MzE3MWZmNmY4MDhiZWVkMjlhYjBkOSJ9LCJhcmNoaXZlQnl0ZXMiOjgzMjI0OTkwLCJhcmNoaXZlU2hhMjU2IjoiNGE2NGNlZTlhOWUzYWFlYTFjMTU2NjhjMzFjZmU2YjBkOWYxZjhmMmE2MzE3MWZmNmY4MDhiZWVkMjlhYjBkOSIsImF1dGhlbnRpY2F0ZWRUYXJnZXRzIjo3LCJiYXRjaElkIjoiYmF0Y2g6c2hhMjU2OjYzNmMxNzEwZjg4ZjBmMGU2ZjQxYmVlY2JhNDIyNTI2NjhjZjMwZDJjZDY5MTdkYWRhYWU3M2E0YzUyOWM1ZjQiLCJjb25zdW1lckxvY2tTaGEyNTYiOiJlZjA0YTQ0NDY4M2QyZTUyYzMwYWZjZDg1NTJlY2Y2NTYyOTA1OTFmMGI2YTdkZGYwZWJiNGFiNmRiNWRhYTZhIiwiZXhwYW5kZWRCeXRlcyI6ODMyMTc2MTQsImluZGVwZW5kZW50VHJ1c3RTaGEyNTYiOiIwNDU2ZjU1Nzk1ZTQ2MTE2YWI0MzVjZmE5MzE2NWM2M2I2N2EwZDI2YjBmM2JiMTFjZDlhZDg5OTU0MDBjYTBjIiwicHJvZHVjZXIiOnsicnVudGltZSI6eyJhcmNoaXRlY3R1cmUiOiJ4NjQiLCJub2RlIjoidjI0LjE1LjAiLCJwbGF0Zm9ybSI6ImxpbnV4In0sInNjYW5uZXIiOnsiaW5zdGFsbGF0aW9uU2hhMjU2IjoiNDc5YzFlNWNjMjQ1ZWMxYTQwOTYwYzEyYzI3MmIzNWQ4MjJlODhiMTNjNzdiYTA0ZGMwMzIzYTUwMTcwZGUxYyIsIm5hbWUiOiJAYWlocS9zY2FuIiwic291cmNlQ29tbWl0IjoiNTNkYzBjZmZkMjcwNGYwY2VmZDc2YjUzYWJlODUwNjUxZDFlOTUwNSIsInRhcmJhbGxTaGEyNTYiOiI0MzMwY2Q5Y2Y2MzhlYmNiZTk5MWIwZWQwZTQ0NWRlN2Q2Yjg3ZmFhMDgyMzk3NWY2MjgyZDNiNTAwNDMzNGY3IiwidmVyc2lvbiI6IjAuNS4wIn19LCJyZWFkZXIiOnsicnVudGltZSI6eyJhcmNoaXRlY3R1cmUiOiJ4NjQiLCJub2RlIjoidjI0LjE4LjAiLCJwbGF0Zm9ybSI6IndpbjMyIn0sInNjYW5uZXIiOnsiaW5zdGFsbGF0aW9uU2hhMjU2IjoiZGNlNGRjODQ0OTQ1YTJmNjQwOWRhOGJkZjlkNDY2YTU3NGQ5ZjNlMjQyNDdlNDcyOWRiM2NjNzZhZjVmZTkxMCIsIm5hbWUiOiJAYWlocS9zY2FuIiwic291cmNlQ29tbWl0IjoiNTNkYzBjZmZkMjcwNGYwY2VmZDc2YjUzYWJlODUwNjUxZDFlOTUwNSIsInRhcmJhbGxTaGEyNTYiOiI0MzMwY2Q5Y2Y2MzhlYmNiZTk5MWIwZWQwZTQ0NWRlN2Q2Yjg3ZmFhMDgyMzk3NWY2MjgyZDNiNTAwNDMzNGY3IiwidmVyc2lvbiI6IjAuNS4wIn19LCJyZWNlaXB0U2hhMjU2IjoiNmVkMGE5MjY2MDRjNTRmZDIzYTdhZWIyOTk5MTI3YWZmZDJlNDRjYjc2OTA5ZWZjMzljZjdlNzU5Nzg5M2UzMyIsInNjaGVtYSI6InVybjphaWhxOnNjYW46ZmluYWwtcHVibGljYXRpb24tY3VzdG9keToxLjAuMCIsInNlbGVjdGlvbiI6eyJmaW5hbEFydGlmYWN0RGlnZXN0Ijoic2hhMjU2OjRhNjRjZWU5YTllM2FhZWExYzE1NjY4YzMxY2ZlNmIwZDlmMWY4ZjJhNjMxNzFmZjZmODA4YmVlZDI5YWIwZDkiLCJmaW5hbEFydGlmYWN0SWQiOiIxMTU3MzAyODIyMiIsIm1hbmlmZXN0U2hhMjU2IjoiZDY5NTA1ZTI2YmZiMDUxNmVkNDNiMGY4YTk2MDU0NTQ2Nzc5Y2M2ZDRiNjMwMjQ0MjgxN2Y2OWI5ZjQyNDdhYiIsInB1Ymxpc2hlclJ1bklkIjoiMzc4Mjg5NTg1MTYiLCJyZWFkZXJJbnN0YWxsYXRpb25TaGEyNTYiOiJkY2U0ZGM4NDQ5NDVhMmY2NDA5ZGE4YmRmOWQ0NjZhNTc0ZDlmM2UyNDI0N2U0NzI5ZGIzY2M3NmFmNWZlOTEwIiwicmVwb3NpdG9yeSI6InNhbWFydG9tYXIvYWloLXNjYW4iLCJzY2hlbWEiOiJ1cm46YWlocTpzY2FuOmZpbmFsLXB1YmxpY2F0aW9uLXNlbGVjdGlvbjoxLjAuMCIsInNlbGVjdGlvblNoYTI1NiI6ImM1MTkzZmM1N2M2ZGRjMGRlYmE5MWYwNTQwMDljM2NiMzI4N2UwMTUwNzMwM2FlMTg5ZTY0M2Y0NWNiYmU3N2UiLCJzb3VyY2VIZWFkIjoiNTNkYzBjZmZkMjcwNGYwY2VmZDc2YjUzYWJlODUwNjUxZDFlOTUwNSJ9fQ==";
