// Public installed package only. The Git executable maps HTTPS to disposable offline repos.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { runScan } from '@aihq/scan/host';
import { readReport } from '@aihq/scan/read';
import Ajv2020 from 'ajv/dist/2020.js';

export async function exerciseGitReachability() {
  if (process.platform === 'win32') return; // POSIX executable transport fixture.
  const root = mkdtempSync(join(tmpdir(), 'scan-packed-reachability-'));
  const oldPath = process.env.PATH;
  try {
    const realGit = execFileSync('which', ['git'], { encoding: 'utf8' }).trim();
    const named = join(root, 'named'); mkdirSync(named);
    const git = args => execFileSync(realGit, ['-c','user.name=Fixture','-c','user.email=fixture@example.invalid',...args], { cwd: named, encoding: 'utf8', stdio: 'pipe', env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' } });
    git(['init', '-q']);
    writeFileSync(join(named, 'SKILL.md'), '# disposable content\n');
    git(['add', '.']); git(['commit', '-qm', 'branch ancestor']);
    const ancestor = git(['rev-parse', 'HEAD']).trim();
    writeFileSync(join(named, 'other'), 'descendant'); git(['add', '.']);
    git(['commit', '-qm', 'branch tip']);
    const tip = git(['rev-parse', 'HEAD']).trim();
    // This commit is present and served by the named repository's fork network,
    // and even has a pull ref, but belongs to no named branch or tag.
    const forkOnly = git(['commit-tree', `${tip}^{tree}`, '-m', 'fork-only root']).trim();
    git(['update-ref', 'refs/pull/1/head', forkOnly]);
    const tagOnly = git(['commit-tree', `${tip}^{tree}`, '-m', 'tag-only root']).trim();
    git(['tag', '-a', 'release', tagOnly, '-m', 'annotated tag']);
    const bin = join(root, 'bin'); mkdirSync(bin);
    const mode = join(root, 'mode'); writeFileSync(mode, 'normal');
    const url = 'https://example.invalid/named.git';
    writeFileSync(join(bin, 'git'), `#!${process.execPath}\nconst fs=require('node:fs');const {spawnSync}=require('node:child_process');let args=process.argv.slice(2);const mode=fs.readFileSync(${JSON.stringify(mode)},'utf8');const refs=args.some(a=>a.startsWith('+refs/heads/'));if(refs&&mode==='offline')process.exit(7);if(args.includes('rev-list')&&mode==='malformed'){process.stdout.write('not a complete ancestry\\n');process.exit(0);}if(args.includes('--is-shallow-repository')&&mode==='bounded'){process.stdout.write('x'.repeat(32));process.exit(0);}if(args.includes('--is-shallow-repository')&&mode==='shallow'){process.stdout.write('true\\n');process.exit(0);}args=args.map(a=>a===${JSON.stringify(url)}?${JSON.stringify(named)}:a);const child=spawnSync(${JSON.stringify(realGit)},['-c','protocol.file.allow=always',...args],{stdio:'inherit'});process.exit(child.status??1);\n`, { mode: 0o755 });
    process.env.PATH = `${bin}${delimiter}${oldPath}`;
    const schema = name => JSON.parse(readFileSync(new URL(import.meta.resolve(`@aihq/scan/schemas/${name}/2.0.0.json`)), 'utf8'));
    const ajv = new Ajv2020({ strict: false });
    const validRun = ajv.compile(schema('run-result')), validReport = ajv.compile(schema('report'));
    const request = commit => ({ schema: 'urn:aihq:scan:request:2.0.0', source: { kind: 'git', repository: url, commit }, selection: { paths: 'all', excludedPaths: [] }, detectors: [{ detectorId: 'detector.aih-native', configuration: {} }] });
    const assessment = async (commit, expected) => {
      const run = await runScan(request(commit));
      assert.equal(run.status, 'assessment', JSON.stringify(run));
      assert.equal(run.reachability, expected, JSON.stringify(run.diagnostics)); assert.equal(run.report.reachability, expected);
      assert.equal(run.report.source.repository, url); assert.equal(run.report.source.commit, commit);
      assert.equal(validRun(run), true, JSON.stringify(validRun.errors));
      assert.equal(validReport(run.report), true, JSON.stringify(validReport.errors));
      const bytes = new TextEncoder().encode(JSON.stringify(run.report, function (key, value) { return value && !Array.isArray(value) && typeof value === 'object' ? Object.fromEntries(Object.entries(value).sort(([a],[b]) => a < b ? -1 : a > b ? 1 : 0)) : value; }));
      const read = await readReport(bytes);
      assert.equal(read.status, 'read'); assert.equal(read.report.reachability, expected);
      return run;
    };
    await assessment(ancestor, 'reachable');
    await assessment(tip, 'reachable');
    await assessment(tagOnly, 'reachable');
    const refused = await runScan(request(forkOnly));
    assert.equal(refused.status, 'diagnostic', JSON.stringify(refused));
    assert.equal(refused.phase, 'capture'); assert.equal(refused.reachability, 'unreachable');
    assert.equal(refused.diagnostics[0].code, 'git-commit-unreachable');
    assert.match(refused.diagnostics[0].detail, /branch or tag of the named repository/);
    assert.equal('scanId' in refused, false); assert.equal('report' in refused, false);
    assert.equal(validRun(refused), true, JSON.stringify(validRun.errors));
    const legacy = await runScan({ ...request(forkOnly), schema: 'urn:aihq:scan:request:1.0.0' });
    assert.equal(legacy.status, 'diagnostic'); assert.equal(legacy.diagnostics[0].code, 'git-commit-unreachable');
    assert.equal('reachability' in legacy, false);
    // Acquisition of exact cached objects remains possible when the independent
    // membership check is unavailable. Neither branch nor fork-only is called passed.
    for (const unavailable of ['offline', 'malformed', 'shallow', 'bounded']) {
      writeFileSync(mode, unavailable);
      const unchecked = await assessment(ancestor, 'unchecked');
      assert.equal(unchecked.diagnostics[0].code, 'git-reachability-unchecked');
      if (unavailable === 'bounded') assert.match(unchecked.diagnostics[0].detail, /gitStdoutBytes.*16.*observed 32/);
      await assessment(forkOnly, 'unchecked');
    }
  } finally { process.env.PATH = oldPath; rmSync(root, { recursive: true, force: true }); }
}
