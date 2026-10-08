import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "vitest";

test("default gh commands negotiate JSON for Actions ZIP and uploads while retaining binary request content and release-asset Accept", () => {
  const root = mkdtempSync(join(tmpdir(), "scan-gh-media-"));
  try {
    const driver = join(root, "media.mjs");
    writeFileSync(
      driver,
      `import {ghTransport} from ${JSON.stringify(new URL("../../tools/artifact/publish-refresh-release.mjs", import.meta.url).href)};import {readFileSync} from 'node:fs';
const command=(exe,args,options)=>{const path=args[1],headers=args.filter((_,i)=>args[i-1]==='-H');if(exe!=='gh'||args[0]!=='api')throw Error('Wrong subprocess');if(path.endsWith('/zip')&&!headers.includes('Accept: application/vnd.github+json'))throw Error('Actions415');if(path.includes('uploads.github.com')&&(!headers.includes('Accept: application/vnd.github+json')||!headers.includes('Content-Type: application/octet-stream')||!Buffer.isBuffer(options.input)))throw Error('Upload415');if(path.includes('/releases/assets/')&&!headers.includes('Accept: application/octet-stream'))throw Error('AssetJSON');return {status:0,stdout:Buffer.from('HTTP/2.0 '+(path.includes('uploads.github.com')?201:200)+' OK\\r\\n\\r\\nbinary'),stderr:Buffer.alloc(0)};};const transport=ghTransport({reviewedHead:'a'.repeat(40),command});transport.api.bytes('repos/samartomar/aih-scan/actions/artifacts/1/zip');await transport.upload(1,'fixture',Buffer.from('exact binary'));await transport.download(1,100);`,
    );
    const result = spawnSync(process.execPath, [driver], { encoding: "utf8", windowsHide: true });
    expect(result.status, result.stderr).toBe(0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("normal gh subprocess checks operator/current main and refuses administration403 before writes without extracting a credential", () => {
  const directory = mkdtempSync(join(tmpdir(), "scan-normal-gh-"));
  try {
    const driver = join(directory, "gh-boundary.mjs");
    writeFileSync(
      driver,
      `import {ghTransport} from ${JSON.stringify(new URL("../../tools/artifact/publish-refresh-release.mjs", import.meta.url).href)};
const calls=[];let denied=false;const command=(exe,args,options)=>{if(exe!=='gh'||args[0]!=='api'||args.includes('token'))throw Error('Not normal gh api');calls.push(args);const path=args[1];let body,status=200;if(path==='user')body={login:'samartomar',id:9993940};else if(path.endsWith('/git/ref/heads/main'))body={ref:'refs/heads/main',object:{type:'commit',sha:'a'.repeat(40)}};else if(path==='repos/samartomar/aih-scan')body={id:1336836161,full_name:'samartomar/aih-scan',owner:{id:9993940}};else if(path.endsWith('/immutable-releases')){status=denied?403:200;body={enabled:true};}else throw Error('Unexpected command or live mutation');return {status:status===200?0:1,stdout:Buffer.from('HTTP/2.0 '+status+' OK\\r\\nContent-Type: application/json\\r\\n\\r\\n'+JSON.stringify(body)),stderr:Buffer.alloc(0)};};
const transport=ghTransport({reviewedHead:'a'.repeat(40),command});await transport.verifyScope();if(!await transport.immutableEnabled())throw Error('Normal scope inaccessible');denied=true;let refused=false;try{await transport.immutableEnabled();}catch{refused=true;}if(!refused)throw Error('403 accepted');if(calls.some(args=>args.includes('POST')||args.includes('PATCH')||args.includes('auth')||args.includes('token')))throw Error('Credentials or writes touched');`,
    );
    const result = spawnSync(process.execPath, [driver], { encoding: "utf8", windowsHide: true });
    expect(result.status, result.stderr).toBe(0);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("final metadata CLI refuses malformed/duplicate metadata, failed or repeated runs, and ambiguous archives; old release CLI cannot bypass final selection", () => {
  const directory = mkdtempSync(join(tmpdir(), "scan-final-metadata-"));
  try {
    const head = "a".repeat(40),
      digest = `sha256:${"b".repeat(64)}`,
      repository = { id: 1336836161, full_name: "samartomar/aih-scan", owner: { id: 9993940 } },
      actor = { id: 333589491, login: "stomar-tech" };
    const run = {
      id: 123,
      run_attempt: 1,
      event: "workflow_dispatch",
      status: "completed",
      conclusion: "success",
      head_sha: head,
      head_branch: "main",
      path: ".github/workflows/scan-report-publisher.yml",
      repository,
      head_repository: repository,
      actor,
      triggering_actor: actor,
    };
    const artifacts = {
      total_count: 3,
      artifacts: [
        "checked-detached-statements",
        "scan-refresh-attestations",
        "scan-refresh-final-publication",
      ].map((name, i) => ({
        id: 454 + i,
        name,
        digest,
        expired: false,
        size_in_bytes: 100,
        workflow_run: { id: 123, head_sha: head },
      })),
    };
    const invoke = (
      runBytes: string = JSON.stringify(run),
      archiveBytes: string = JSON.stringify(artifacts),
    ) => {
      writeFileSync(join(directory, "run.json"), runBytes);
      writeFileSync(join(directory, "artifacts.json"), archiveBytes);
      return spawnSync(
        process.execPath,
        [
          "tools/artifact/check-refresh-run.mjs",
          join(directory, "run.json"),
          join(directory, "artifacts.json"),
          "123",
          head,
          "456",
          digest,
          "scan-refresh-final-publication",
        ],
        { encoding: "utf8", windowsHide: true },
      );
    };
    expect(invoke().status).toBe(0);
    for (const bytes of [
      '{"id":123,"id":123}',
      "null",
      "{",
      JSON.stringify({ ...run, run_attempt: 2 }),
      JSON.stringify({ ...run, conclusion: "failure" }),
      JSON.stringify({ ...run, actor: { id: 9993940, login: "samartomar" } }),
      JSON.stringify(run).padEnd(1048577, " "),
    ])
      expect(invoke(bytes).status).toBe(2);
    for (const bytes of [
      '{"total_count":3,"total_count":3}',
      JSON.stringify({ ...artifacts, total_count: 4 }),
      JSON.stringify({
        ...artifacts,
        artifacts: [artifacts.artifacts[0], artifacts.artifacts[0], artifacts.artifacts[2]],
      }),
      JSON.stringify({
        ...artifacts,
        artifacts: artifacts.artifacts.map((item) => ({
          ...item,
          name: "scan-refresh-NONPUBLISHABLE-root",
        })),
      }),
    ])
      expect(invoke(JSON.stringify(run), bytes).status).toBe(2);
    const bypass = spawnSync(
      process.execPath,
      ["tools/artifact/publish-refresh-release.mjs", directory, head],
      { encoding: "utf8", windowsHide: true },
    );
    expect(bypass.status).toBe(2);
    expect(JSON.parse(bypass.stderr).event).toBe("scan-refresh-release.refused");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
