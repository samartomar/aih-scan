import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "vitest";

test("real ZIP bytes extract exact receipt files and refuse traversal, duplicates, links, extra entries, corrupt CRC and expansion ceilings", () => {
  const root = mkdtempSync(join(tmpdir(), "scan-final-zip-"));
  try {
    const driver = join(root, "zip.mjs");
    writeFileSync(
      driver,
      `import {crc32} from 'node:zlib';import {existsSync,readFileSync} from 'node:fs';import {join} from 'node:path';import {extractFinalZip} from ${JSON.stringify(new URL("../../tools/artifact/extract-final-zip.mjs", import.meta.url).href)};
const zip=entries=>{const parts=[],central=[];let offset=0;for(const entry of entries){const name=Buffer.from(entry.name),data=Buffer.from(entry.data??''),crc=crc32(data),local=Buffer.alloc(30);local.writeUInt32LE(0x04034b50);local.writeUInt32LE(crc,14);local.writeUInt32LE(data.length,18);local.writeUInt32LE(data.length,22);local.writeUInt16LE(name.length,26);const head=Buffer.alloc(46);head.writeUInt32LE(0x02014b50);head.writeUInt16LE(3<<8,4);head.writeUInt32LE(entry.badCrc?0:crc,16);head.writeUInt32LE(data.length,20);head.writeUInt32LE(entry.expanded??data.length,24);head.writeUInt16LE(name.length,28);head.writeUInt32LE(((entry.mode??0o100600)<<16)>>>0,38);head.writeUInt32LE(offset,42);parts.push(local,name,data);central.push(head,name);offset+=30+name.length+data.length;}const directory=Buffer.concat(central),end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50);end.writeUInt16LE(entries.length,8);end.writeUInt16LE(entries.length,10);end.writeUInt32LE(directory.length,12);end.writeUInt32LE(offset,16);return Buffer.concat([...parts,directory,end]);};
const receipt={name:'publication.json',data:'{"assets":[{"path":"targets/a.json"}]}'},source={name:'targets/a.json',data:'original annex'};let n=0;
const good=join(process.argv[2],'good');extractFinalZip(zip([receipt,source]),good);if(readFileSync(join(good,source.name),'utf8')!==source.data)throw Error('Original changed');
for(const entries of [[receipt,{...source,name:'../outside'}],[receipt,source,source],[receipt,{...source,mode:0o120777}],[receipt,source,{name:'extra',data:'x'}],[receipt,{...source,badCrc:true}],[receipt,{...source,expanded:128*1024*1024+1}],[receipt,source,{...source,name:'targets/A.json'}]]){const out=join(process.argv[2],'refusal-'+n++);let refused=false;try{extractFinalZip(zip(entries),out);}catch{refused=true;}if(!refused||existsSync(out))throw Error('Unsafe ZIP admitted or wrote before validation');}`,
    );
    const result = spawnSync(process.execPath, [driver, root], {
      encoding: "utf8",
      windowsHide: true,
    });
    expect(result.status, result.stderr).toBe(0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
