import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "vitest";

// The labelled command fixture replaces the external gh process only. The real
// helper constructs all command arguments and stdin bytes; no network is used.
function atCommandBoundary(scenario: string) {
  const directory = mkdtempSync(join(tmpdir(), "scan-gh-framing-"));
  try {
    const driver = join(directory, "boundary.mjs");
    writeFileSync(
      driver,
      `import assert from 'node:assert/strict';
import {ghApi} from ${JSON.stringify(new URL("../../tools/artifact/gh-api.mjs", import.meta.url).href)};
const success={status:0,stdout:Buffer.from('HTTP/2.0 200 OK\\r\\n\\r\\n{}'),stderr:Buffer.alloc(0)};
const headers=args=>args.filter((_,i)=>args[i-1]==='-H');
${scenario}`,
    );
    const result = spawnSync(process.execPath, [driver], {
      encoding: "utf8",
      windowsHide: true,
      timeout: 30000,
      maxBuffer: 1048576,
    });
    expect(result.status, result.stderr).toBe(0);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("binary upload declares the exact stdin byte length without changing its bytes", () => {
  atCommandBoundary(`const body=Buffer.from([0,255,13,10,128]);let calls=0;
const api=ghApi({command:(exe,args,options)=>{calls++;assert.equal(exe,'gh');assert.equal(args[0],'api');assert.equal(args[args.indexOf('--method')+1],'POST');assert.equal(args[args.indexOf('--input')+1],'-');assert(headers(args).includes('Content-Length: 5'));assert(headers(args).includes('Content-Type: application/octet-stream'));assert(headers(args).includes('Accept: application/vnd.github+json'));assert.equal(options.input,body);assert.deepEqual(options.input,Buffer.from([0,255,13,10,128]));assert.equal(options.encoding,'buffer');assert.equal(options.timeout,120000);assert.equal(options.maxBuffer,100+65536);assert.equal(options.windowsHide,true);assert.equal(options.shell,undefined);return success;}});
assert.equal(api.bytes('https://uploads.github.com/repos/example/project/releases/1/assets?name=fixture',{method:'POST',body,contentType:'application/octet-stream',maximum:100,timeout:120000}).status,200);assert.equal(calls,1);`);
});

test.each([
  "GET",
  "HEAD",
  "get",
  "head",
])("%s with a supplied body is refused before the external command can run", (method) => {
  atCommandBoundary(`let calls=0;const api=ghApi({command:()=>{calls++;return success;}});
for(const body of [Buffer.from('must not upload'),Buffer.alloc(0),{probe:true},null])assert.throws(()=>api.bytes('repos/example/project/releases/1/assets',{method:${JSON.stringify(method)},body}),{message:'GET/HEAD request body refused'});
assert.equal(calls,0);`);
});

test("JSON framing counts encoded UTF-8 bytes rather than JavaScript characters", () => {
  atCommandBoundary(`let calls=0;const api=ghApi({command:(exe,args,options)=>{calls++;assert.equal(exe,'gh');assert.equal(args[args.indexOf('--method')+1],'PATCH');assert(headers(args).includes('Content-Length: 17'));assert(headers(args).includes('Content-Type: application/json'));assert(Buffer.isBuffer(options.input));assert.deepEqual(options.input,Buffer.from('{"name":"é🧪"}'));assert.equal(options.input.length,17);return success;}});
assert.deepEqual(api.json('repos/example/project/releases/1',{method:'PATCH',body:{name:'é🧪'}}),{});assert.equal(calls,1);`);
});

test("an explicitly supplied empty binary body has length zero and still uses stdin", () => {
  atCommandBoundary(`const body=Buffer.alloc(0);let calls=0;const api=ghApi({command:(_exe,args,options)=>{calls++;assert.equal(args[args.indexOf('--method')+1],'POST');assert.equal(args[args.indexOf('--input')+1],'-');assert(headers(args).includes('Content-Length: 0'));assert.equal(options.input,body);return success;}});
api.bytes('https://uploads.github.com/repos/example/project/releases/1/assets?name=empty',{method:'POST',body,contentType:'application/octet-stream'});assert.equal(calls,1);`);
});

test("JSON null is a supplied four-byte body rather than an omitted body", () => {
  atCommandBoundary(`let calls=0;const api=ghApi({command:(_exe,args,options)=>{calls++;assert(headers(args).includes('Content-Length: 4'));assert.deepEqual(options.input,Buffer.from('null'));return success;}});
api.bytes('repos/example/project/releases',{method:'POST',body:null});assert.equal(calls,1);`);
});

test.each(["GET", "HEAD"])("bodyless %s stays bodyless and sends the selected method", (method) => {
  atCommandBoundary(`let calls=0;const api=ghApi({command:(_exe,args,options)=>{calls++;assert.equal(args[args.indexOf('--method')+1],${JSON.stringify(method)});assert.equal(args.includes('--input'),false);assert.equal(headers(args).some(header=>header.startsWith('Content-Length:')||header.startsWith('Content-Type:')),false);assert.equal(options.input,undefined);return success;}});
api.bytes('repos/example/project/releases/1',{method:${JSON.stringify(method)}});assert.equal(calls,1);`);
});
