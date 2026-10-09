import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "vitest";

// Exercise the real writer and transports. HTTP uses an actual disposable server;
// normal gh uses a labelled command boundary that cannot reach a live service.
function invoke(mode: string, kind = "http") {
  const root = mkdtempSync(join(tmpdir(), "scan-asset-admission-"));
  try {
    const driver = join(root, "driver.mjs");
    writeFileSync(
      driver,
      `import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {mkdirSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {publishRelease,githubTransport,ghTransport} from ${JSON.stringify(new URL("../../tools/artifact/publish-refresh-release.mjs", import.meta.url).href)};
import {canonicalBytes,sha256} from ${JSON.stringify(new URL("../../tools/refresh/contracts.mjs", import.meta.url).href)};
const [root,mode,kind]=process.argv.slice(2),directory=join(root,'publication'),batchId='batch:sha256:'+'b'.repeat(64);
mkdirSync(directory);const originals=new Map(),entries=[];
const inventory=canonicalBytes({schema:'urn:aihq:scan:publication-inventory:1.0.0',batchId,targets:Array.from({length:7},(_,i)=>({repository:'fixture/'+i}))});originals.set('inventory.json',inventory);
for(let i=0;i<(mode==='paged-complete'?62:1);i++)originals.set('data-'+i+'.bin',Buffer.from('fixture original '+i));
for(const [name,bytes] of originals){writeFileSync(join(directory,name),bytes);entries.push({path:name,name,byteLength:bytes.length,sha256:sha256(bytes)});}
const receipt=canonicalBytes({schema:'urn:aihq:scan:publication-assets:1.0.0',batchId,expandedBytes:entries.reduce((n,a)=>n+a.byteLength,0),assets:entries});writeFileSync(join(directory,'publication.json'),receipt);originals.set('publication.json',receipt);
const names=[...originals.keys()],metadata=(name,id)=>({id,name,size:originals.get(name).length,digest:'sha256:'+sha256(originals.get(name)),state:'uploaded'});
const collection=(mode==='paged-complete'?names:names.filter(name=>name!=='inventory.json')).map((name,i)=>metadata(name,10+i));
const files=new Map(collection.map(row=>[row.id,originals.get(row.name)])),writes=[],pages=[];
const starter={id:901,name:'inventory.json',size:1069648,digest:null,state:'starter'};
if(mode==='hidden-starter')collection.push(starter);
if(mode==='unknown-state')collection[0].state='pending';
if(mode==='missing-state')delete collection[0].state;
if(mode==='invalid-id')collection[0].id=0;
if(mode==='extra')collection.push({id:902,name:'foreign.bin',size:1,digest:'sha256:'+'0'.repeat(64),state:'uploaded'});
if(mode==='duplicate-name')collection.push({...collection[0],id:903});
if(mode==='duplicate-id')collection.push({...collection[0],name:'foreign.bin'});
if(mode==='wrong-digest')collection[0].digest='sha256:'+'0'.repeat(64);
if(mode==='missing-digest')collection[0].digest=null;
if(mode==='late-byte-collision')files.set(collection[0].id,Buffer.alloc(collection[0].size));
let draft=mode!=='paged-complete',published=false,uploaded=false;
const release=()=>({id:1,tag_name:'scan-report-batch-'+batchId.slice('batch:sha256:'.length),draft,immutable:!draft,assets:collection.filter(row=>row.state==='uploaded'&&originals.has(row.name)).slice(0,mode==='paged-complete'?2:64)});
function route(url,method,bytes){
  const path=new URL(url).pathname,query=new URL(url).searchParams;
  if(method==='GET'&&path.endsWith('/immutable-releases'))return {status:200,body:{enabled:true}};
  if(method==='GET'&&path.includes('/releases/tags/'))return {status:draft?404:200,body:draft?{}:release()};
  if(method==='GET'&&path.endsWith('/releases'))return {status:200,body:[release()]};
  if(method==='GET'&&path.endsWith('/releases/1/assets')){
    const page=Number(query.get('page')),size=Number(query.get('per_page'));assert(page>=1&&page<=3);assert.equal(size,30);pages.push(page);
    if(mode==='malformed-page')return {status:200,body:{assets:collection}};
    const filler=Array.from({length:30},(_,i)=>({id:100+i+(page-1)*30,name:'foreign-'+(i+(page-1)*30),size:1,digest:'sha256:'+'0'.repeat(64),state:'uploaded'}));
    if(mode==='pagination-exhausted')return {status:200,body:filler};
    if(mode==='oversized-page')return {status:200,body:[...filler,{...filler[0],id:999,name:'overflow'}]};
    if(mode==='cross-page-duplicate')return {status:200,body:page===1?filler:[{...filler[0],id:100,name:'foreign-0'}]};
    return {status:200,body:collection.slice((page-1)*size,page*size)};
  }
  if(method==='GET'&&path.includes('/releases/assets/')){const id=Number(path.split('/').at(-1));assert(files.has(id));return {status:200,body:files.get(id)};}
  if(method==='POST'&&new URL(url).hostname==='uploads.github.com'){
    writes.push('upload');const name=query.get('name');assert.equal(name,'inventory.json');
    if(collection.some(row=>row.name===name))return {status:422,body:{message:'collision'}};
    assert(Buffer.from(bytes).equals(originals.get(name)));const row=metadata(name,900);collection.push(row);files.set(row.id,Buffer.from(bytes));uploaded=true;
    if(mode==='starter-before-promotion')collection.push({id:904,name:'foreign.bin',size:1,digest:null,state:'starter'});
    return {status:201,body:row};
  }
  if(method==='PATCH'&&path.endsWith('/releases/1')){writes.push('publish');published=true;draft=false;return {status:200,body:release()};}
  throw Error('Unexpected fixture route');
}
let server;
try{
  let transport;
  if(kind==='http'){
    server=createServer(async(request,response)=>{assert.equal(request.headers.authorization,'Bearer labelled-disposable-fixture-token');const parts=[];for await(const part of request)parts.push(part);const url=request.headers['x-fixture-original-url'];const result=route(url,request.method,Buffer.concat(parts));response.writeHead(result.status);response.end(Buffer.isBuffer(result.body)?result.body:JSON.stringify(result.body));});
    await new Promise(done=>server.listen(0,'127.0.0.1',done));const port=server.address().port;
    transport=githubTransport({token:'labelled-disposable-fixture-token',reviewedHead:'a'.repeat(40),fetch:(url,options)=>{const original=String(url);assert(['api.github.com','uploads.github.com'].includes(new URL(original).hostname));if((options.method??'GET')==='GET')assert.equal(options.body,undefined);return fetch('http://127.0.0.1:'+port+'/',{...options,headers:{...options.headers,'x-fixture-original-url':original}});}});
  }else{
    transport=ghTransport({reviewedHead:'a'.repeat(40),command:(program,args,options)=>{assert.equal(program,'gh');assert.equal(args[0],'api');const method=args[args.indexOf('--method')+1];if(method==='GET'){assert.equal(options.input,undefined);assert(!args.includes('--input'));}const url=args[1].startsWith('https:')?args[1]:'https://api.github.com/'+args[1];const result=route(url,method,options.input);return {status:result.status<400?0:1,stdout:Buffer.concat([Buffer.from('HTTP/2.0 '+result.status+' Fixture\\r\\n\\r\\n'),Buffer.isBuffer(result.body)?result.body:Buffer.from(JSON.stringify(result.body))]),stderr:Buffer.alloc(0)};}});
  }
  let result,error;try{result=await publishRelease({directory,transport});}catch(caught){error=caught;}
  if(mode==='paged-complete'){assert.equal(error,undefined);assert.equal(result.assetCount,64);assert.deepEqual(writes,[]);assert(pages.includes(2)&&pages.includes(3));}
  else if(mode==='normal'){assert.equal(error,undefined);assert.equal(result.assetCount,3);assert.deepEqual(writes,['upload','publish']);}
  else if(mode==='starter-before-promotion'){assert(error);assert(uploaded);assert(!published);assert.deepEqual(writes,['upload']);}
  else {assert(error,'Hazard must refuse');assert.deepEqual(writes,[],'Collection/byte hazard must refuse BEFORE any write');}
  console.log(JSON.stringify({mode,kind,refused:!!error,writes,pages}));
}finally{if(server){server.closeAllConnections();await new Promise(done=>server.close(done));}}
`,
    );
    return spawnSync(process.execPath, [driver, root, mode, kind], {
      encoding: "utf8",
      timeout: 15000,
      windowsHide: true,
    });
  } finally {
    rmSync(root, { recursive: true });
  }
}

test.each([
  "http",
  "gh",
])("%s transport refuses a starter hidden from the embedded release before any upload", (kind) => {
  const result = invoke("hidden-starter", kind);
  expect(result.status, result.stderr).toBe(0);
});

test.each([
  "unknown-state",
  "missing-state",
  "invalid-id",
  "extra",
  "duplicate-name",
  "duplicate-id",
  "wrong-digest",
  "missing-digest",
  "late-byte-collision",
  "malformed-page",
  "oversized-page",
  "pagination-exhausted",
  "cross-page-duplicate",
])("full collection hazard %s refuses before any write", (mode) => {
  const result = invoke(mode);
  expect(result.status, result.stderr).toBe(0);
});

test.each([
  "http",
  "gh",
])("%s transport closes a 64-asset paginated published retry without writes", (kind) => {
  const result = invoke("paged-complete", kind);
  expect(result.status, result.stderr).toBe(0);
});

test("a starter appearing after an upload blocks promotion", () => {
  const result = invoke("starter-before-promotion");
  expect(result.status, result.stderr).toBe(0);
});

test.each([
  "http",
  "gh",
])("%s transport verifies a complete draft collection before promotion", (kind) => {
  const result = invoke("normal", kind);
  expect(result.status, result.stderr).toBe(0);
});
