// Installed public APIs only; external Git is a disposable offline executable.
import assert from 'node:assert/strict';
import filesystem from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { runScan } from '@aihq/scan/host';
import Ajv2020 from 'ajv/dist/2020.js';
import { readFileSync } from 'node:fs';

export async function exerciseGitDiagnostics() {
  const request = {
    schema: 'urn:aihq:scan:request:2.0.0',
    source: { kind: 'git', repository: 'https://example.invalid/fixture.git', commit: '0'.repeat(40) },
    selection: { paths: 'all', excludedPaths: [] },
    detectors: [{ detectorId: 'detector.aih-native', configuration: {} }],
  };
  const validate = new Ajv2020({ strict: false }).compile(JSON.parse(readFileSync(new URL(import.meta.resolve('@aihq/scan/schemas/run-result/2.0.0.json')), 'utf8')));
  const diagnostic = async (req, code, detail) => {
    const result = await runScan(req);
    assert.equal(result.status, 'diagnostic', JSON.stringify(result));
    assert.equal(result.diagnostics[0].code, code, JSON.stringify(result));
    assert.match(result.diagnostics[0].detail, detail);
    assert.equal(validate(result), true, JSON.stringify(validate.errors));
    assert.equal('scanId' in result, false);
    return result;
  };
  await diagnostic({ ...request, source: { ...request.source, repository: 'owner/name' } }, 'invalid-input', /repository.*credential-free HTTPS/);
  for (const commit of ['d81f3a1', 'main', 'refs/tags/v1'])
    await diagnostic({ ...request, source: { ...request.source, commit } }, 'invalid-input', /commit.*40.*lowercase.*hexadecimal/);
  if (process.platform === 'win32') return; // Real subprocess fixtures below need executable POSIX scripts; request forms run everywhere.
  const root = mkdtempSync(join(tmpdir(), 'scan-packed-git-diagnostics-'));
  const oldPath = process.env.PATH;
  const realKill = process.kill;
  const realNode = process.execPath;
  try {
    const realGit = execFileSync('which', ['git'], { encoding: 'utf8' }).trim();
    const source = join(root, 'source'); mkdirSync(source);
    const env = { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' };
    const git = args => execFileSync(realGit, args, { cwd: source, env, encoding: 'utf8', stdio: 'pipe' });
    git(['init', '-q']);
    mkdirSync(join(source, 'skills/productivity/grill-me'), { recursive: true });
    writeFileSync(join(source, 'skills/productivity/grill-me/SKILL.md'), '# grill-me\n');
    writeFileSync(join(source, 'padding'), Buffer.alloc(2 * 1024 * 1024));
    git(['add', '.']); git(['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'offline reproduction']);
    const commit = git(['rev-parse', 'HEAD']).trim();
    const bin = join(root, 'bin'); mkdirSync(bin);
    const mode = join(root, 'mode'); writeFileSync(mode, 'objects');
    writeFileSync(join(bin, 'git'), `#!${process.execPath}\nconst fs=require('node:fs');const {execFileSync}=require('node:child_process');const args=process.argv.slice(2);if(args.includes('ls-remote'))process.exit(1);const mode=fs.readFileSync(${JSON.stringify(mode)},'utf8');if(mode==='failure')process.exit(7);if(args.includes('init')||args.includes('fetch'))process.exit(0);if(mode==='stdout'&&args.includes('cat-file')){process.stdout.write(Buffer.alloc(2*1024*1024));}else if(mode==='stderr'){process.stderr.write(Buffer.alloc(70000));}else process.stdout.write(execFileSync(${JSON.stringify(realGit)},['--git-dir='+${JSON.stringify(join(source, '.git'))},...args],{stdio:['ignore','pipe','pipe'],maxBuffer:4*1024*1024}));\n`, { mode: 0o755 });
    process.env.PATH = `${bin}${delimiter}${oldPath}`;
    const exact = { ...request, source: { ...request.source, commit } };
    for (const paths of ['all', ['skills/productivity/grill-me/SKILL.md']]) {
      const run = await runScan({ ...exact, selection: { paths, excludedPaths: [] } });
      assert.equal(run.status, 'assessment', JSON.stringify(run));
      assert.equal(run.report.source.commit, commit);
      assert.equal(run.report.source.capture.entries.find(e => e.path === 'padding').byteLength, 2097152);
      await diagnostic({ ...exact, selection: { paths, excludedPaths: [] }, limits: { maxSourceEntries: 4 } }, 'resource-limit', /validate tree.*maxSourceEntries.*4.*observed 5/);
      await diagnostic({ ...exact, selection: { paths, excludedPaths: [] }, limits: { maxSourceBytes: 1024 } }, 'resource-limit', /read blob size.*maxSourceBytes.*1024.*observed 2097152/);
    }
    // Failed cleanup is a containment refusal, never a successful assessment or rejected promise.
    const realRemove = filesystem.rmSync;
    let refusedCleanup;
    filesystem.rmSync = (path, options) => {
      if (String(path).includes('aih-scan-assessment-')) {
        refusedCleanup = path;
        throw Object.assign(new Error('fixture cleanup denied'), { code: 'EPERM' });
      }
      return realRemove(path, options);
    };
    syncBuiltinESMExports();
    try { await diagnostic(exact, 'git-containment-failed', /step cleanup.*could not be removed/); }
    finally {
      filesystem.rmSync = realRemove; syncBuiltinESMExports();
      if (refusedCleanup) realRemove(refusedCleanup, { recursive: true, force: true });
    }
    writeFileSync(mode, 'failure');
    await diagnostic(exact, 'git-acquisition-failed', /git init.*exit code 1/);
    writeFileSync(mode, 'stdout');
    await diagnostic(exact, 'resource-limit', /read commit object.*gitStdoutBytes.*1048576.*observed/);
    writeFileSync(mode, 'stderr');
    await diagnostic(exact, 'resource-limit', /verify commit.*gitStderrBytes.*65536.*observed/);
    writeFileSync(mode, 'objects');
    // A malfunctioning external wrapper crosses its own stream budget. Real containment
    // and byte accounting run unchanged, independently of the raw Git helper's caps.
    const wrapper = join(bin, 'fixture-node');
    writeFileSync(wrapper, `#!${realNode}\nconst fs=require('node:fs');const {spawnSync}=require('node:child_process');const args=process.argv.slice(2);if(args.includes('ls-remote'))process.exit(1);const mode=fs.readFileSync(${JSON.stringify(mode)},'utf8');if(args[2]==='64'&&mode==='wrapper-stdout')process.stdout.write(Buffer.alloc(4096));else if(args[2]==='64'&&mode==='wrapper-stderr')process.stderr.write(Buffer.alloc(70000));else{const child=spawnSync(${JSON.stringify(realNode)},args,{stdio:'inherit'});process.exit(child.status??1);}\n`, { mode: 0o755 });
    process.execPath = wrapper;
    try {
      for (const [modeName, name, value] of [['wrapper-stdout', 'maxStdoutBytes', 152], ['wrapper-stderr', 'maxStderrBytes', 65536]]) {
        writeFileSync(mode, modeName);
        const result = await diagnostic(exact, 'resource-limit', new RegExp(`read blob size.*${name} limit ${value}; observed \\d+ bytes`));
        const observed = Number(/observed (\d+) bytes/.exec(result.diagnostics[0].detail)[1]);
        assert(observed > value);
      }
    } finally { process.execPath = realNode; }
    writeFileSync(mode, 'objects');
    // Simulated OS refusal of the group-existence probe, after a normal finite child exits.
    // No process is left running and production containment remains enabled.
    process.kill = (pid, signal) => {
      if (pid < 0 && signal === 0) throw Object.assign(new Error('fixture EPERM'), { code: 'EPERM' });
      return realKill(pid, signal);
    };
    await diagnostic(exact, 'git-containment-failed', /git init.*process-tree cleanup/);
  } finally {
    process.kill = realKill;
    process.execPath = realNode;
    process.env.PATH = oldPath;
    rmSync(root, { recursive: true, force: true });
  }
}
