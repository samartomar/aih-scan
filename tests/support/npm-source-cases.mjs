// Runs only from an installed archive; doubles the external HTTPS boundary, never Scan internals.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { gzipSync, gunzipSync } from 'node:zlib';
import { runScan } from '@aihq/scan/host';
import { readReport } from '@aihq/scan/read';
import Ajv2020 from 'ajv/dist/2020.js';

const sorted = value => Array.isArray(value) ? value.map(sorted) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, sorted(value[key])])) : value;
export function npmTar(entries) {
  const blocks = [];
  for (const { path, text = '', mode = 0o644, type = '0', link = '' } of entries) {
    const data = Buffer.from(text), header = Buffer.alloc(512);
    header.write(path, 0, 100, 'utf8');
    for (const [offset, length, value] of [[100, 8, mode], [108, 8, 0], [116, 8, 0], [124, 12, data.length], [136, 12, 0]])
      header.write(value.toString(8).padStart(length - 1, '0') + '\0', offset, length, 'ascii');
    header.fill(32, 148, 156); header.write(type, 156); header.write(link, 157, 100);
    header.write('ustar\0', 257); header.write('00', 263);
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148, 8);
    blocks.push(header, data, Buffer.alloc((512 - data.length % 512) % 512));
  }
  return gzipSync(Buffer.concat([...blocks, Buffer.alloc(1024)]));
}
export async function exerciseNpmSources() {
  const originalFetch = globalThis.fetch;
  const archive = npmTar([
    { path: 'package/package.json', text: JSON.stringify({ name: '@fixture/mcp', version: '1.2.3', scripts: { preinstall: 'exit 99' } }) },
    { path: 'package/server.js', text: 'console.log("fixture");\n', mode: 0o755 },
    { path: 'package/data.txt', text: 'plain\n', mode: 0o644 },
  ]);
  const integrity = 'sha512-' + createHash('sha512').update(archive).digest('base64');
  const url = 'https://fixture.invalid/mcp.tgz';
  const request = source => ({ schema: 'urn:aihq:scan:request:2.0.0', source, selection: { paths: 'all', excludedPaths: [] }, detectors: [{ detectorId: 'detector.unavailable', configuration: {} }] });
  const ajv = new Ajv2020({ strict: false });
  const schema = name => ajv.compile(JSON.parse(readFileSync(new URL(import.meta.resolve(`@aihq/scan/schemas/${name}/2.0.0.json`)), 'utf8')));
  const validRequest = schema('request'), validResult = schema('run-result'), validReport = schema('report');
  let calls = 0;
  globalThis.fetch = async (location, options) => {
    calls++;
    assert.equal(options.redirect, 'error'); assert.equal(options.credentials, 'omit');
    if (String(location) === 'https://registry.npmjs.org/%40fixture%2Fmcp/1.2.3')
      return new Response(JSON.stringify({ name: '@fixture/mcp', version: '1.2.3', dist: { tarball: url, integrity } }));
    assert.equal(String(location), url);
    return new Response(archive);
  };
  try {
    for (const version of ['latest', '^1.2.3', '~1.2.3', '*', '1', 'v1.2.3', 'git+https://fixture.invalid/repo', '1.2.3 || 2.0.0']) {
      const result = await runScan(request({ kind: 'npm', package: '@fixture/mcp', version }));
      assert.equal(result.status, 'diagnostic'); assert.equal(result.phase, 'request');
      assert.equal(result.diagnostics[0].code, 'npm-version-not-exact');
      assert.equal(validResult(result), true, JSON.stringify(validResult.errors));
    }
    assert.equal(calls, 0, 'mutable requests must never acquire bytes');
    if (process.env.NPM_CASE_SLICE === 'mutable') return { mutable: 'passed' };
    for (const source of [{ kind: 'npm', package: '@fixture/mcp', version: '1.2.3' }, { kind: 'npm', archive: { url, integrity } }]) {
      assert.equal(validRequest(request(source)), true);
      const result = await runScan(request(source));
      assert.equal(result.status, 'assessment', JSON.stringify(result));
      assert.equal(validResult(result), true, JSON.stringify(validResult.errors));
      assert.equal(validReport(result.report), true, JSON.stringify(validReport.errors));
      assert.equal(result.report.source.kind, 'npm');
      assert.deepEqual(result.report.source.archive, { url, integrity });
      const entries = result.report.source.capture.entries;
      assert.equal(entries.find(e => e.path === 'server.js').executable, true);
      assert.equal(entries.find(e => e.path === 'data.txt').executable, false);
      assert.equal(entries.find(e => e.path === 'data.txt').sha256, createHash('sha256').update('plain\n').digest('hex'));
      assert.equal(result.report.completion, 'partial');
      assert.equal(result.report.results[0].outcome, 'refused');
      assert.equal((await readReport(new TextEncoder().encode(JSON.stringify(sorted(result.report))))).status, 'read');
    }
    const pinned = { kind: 'npm', archive: { url, integrity } };
    const trust = await runScan({ ...request(pinned), detectors: [{ detectorId: 'detector.aih-trust-lint', configuration: { internalScopes: [], mcpConfigPaths: [] } }] });
    assert.equal(trust.status, 'assessment', JSON.stringify(trust));
    assert.equal(trust.report.completion, 'complete');
    assert.equal(trust.report.results[0].outcome, 'succeeded');
    assert.equal(trust.report.results[0].coverage.complete, true);
    assert(trust.report.results[0].observations.some(o => o.body.findings.some(f => f.rule.state === 'present' && f.rule.value.nativeRuleId === 'trust.auto-exec-hook')), JSON.stringify(trust.report.results));
    const diagnostic = async (source, code, limits) => {
      const result = await runScan({ ...request(source), ...(limits ? { limits } : {}) });
      assert.equal(result.status, 'diagnostic', JSON.stringify(result));
      assert.equal(result.diagnostics[0].code, code, JSON.stringify(result));
      assert.equal('scanId' in result, false);
      assert.equal(validResult(result), true, JSON.stringify(validResult.errors));
      return result;
    };
    const serve = bytes => {
      const pin = 'sha512-' + createHash('sha512').update(bytes).digest('base64');
      globalThis.fetch = async () => new Response(bytes);
      return { kind: 'npm', archive: { url, integrity: pin } };
    };
    // Coordinate provenance must describe the actual package.json captured, even with an explicit archive.
    await diagnostic({ kind: 'npm', package: '@fixture/other', version: '1.2.3', archive: { url, integrity } }, 'npm-acquisition-failed');
    const linkedSource = serve(npmTar([
      { path: 'package/tool', text: 'inert', mode: 0o610 },
      { path: 'package/plain', text: 'inert', mode: 0o600 },
      { path: 'package/bin/tool', type: '2', link: '../tool' },
    ]));
    const linked = await runScan(request(linkedSource));
    assert.equal(linked.status, 'assessment', JSON.stringify(linked));
    assert.deepEqual(linked.report.source.capture.entries.map(e => [e.path, e.kind, e.executable]), [
      ['bin', 'directory', undefined], ['bin/tool', 'file-link', true], ['plain', 'file', false], ['tool', 'file', true],
    ]);
    const modifiedModes = serve(npmTar([{ path: 'package/plain', text: 'inert', mode: 0o701 }]));
    const changed = await runScan(request(modifiedModes));
    assert.equal(changed.report.source.capture.entries[0].executable, true);
    for (const [entries, code] of [
      [[{ path: 'package/../escape', text: 'x' }], 'npm-containment-failed'],
      [[{ path: '/package/escape', text: 'x' }], 'npm-containment-failed'],
      [[{ path: 'package/.git/config', text: 'x' }], 'npm-containment-failed'],
      [[{ path: 'package/x', text: 'a' }, { path: 'package/x', text: 'b' }], 'npm-containment-failed'],
      [[{ path: 'package/x', type: '1', link: 'package/y' }], 'npm-containment-failed'],
      [[{ path: 'package/x', type: '2', link: '../../escape' }], 'npm-containment-failed'],
      [[{ path: 'package/x', type: '2', link: 'absent' }], 'npm-containment-failed'],
      [[{ path: 'package/x', type: '2', link: 'target' }, { path: 'package/x/child', text: 'x' }, { path: 'package/target', type: '5' }], 'npm-containment-failed'],
      [[{ path: 'package/x', type: '6' }], 'npm-containment-failed'],
    ]) await diagnostic(serve(npmTar(entries)), code);
    await diagnostic(serve(Buffer.from('not gzip')), 'npm-acquisition-failed');
    await diagnostic(serve(npmTar([{ path: 'package/big', text: 'x'.repeat(8192) }])), 'resource-limit', { maxSourceBytes: 16 });
    await diagnostic(serve(npmTar([{ path: 'package/a', text: 'x' }, { path: 'package/b', text: 'x' }])), 'resource-limit', { maxSourceEntries: 1 });
    serve(archive);
    await diagnostic({ kind: 'npm', archive: { url, integrity: 'sha512-' + Buffer.alloc(64).toString('base64') } }, 'npm-integrity-mismatch');
    globalThis.fetch = async () => new Response('private upstream text', { status: 404 });
    const failed = await diagnostic(pinned, 'npm-acquisition-failed');
    assert.equal(JSON.stringify(failed).includes('private upstream text'), false);
    globalThis.fetch = async () => { throw new Error('private upstream secret'); };
    const network = await diagnostic(pinned, 'npm-acquisition-failed');
    assert.equal(JSON.stringify(network).includes('private upstream secret'), false);
    globalThis.fetch = async () => new Response(archive, { headers: { 'content-length': '999999999999' } });
    await diagnostic(pinned, 'resource-limit');
    globalThis.fetch = async () => new Response(Buffer.alloc(5000));
    await diagnostic(pinned, 'resource-limit', { maxSourceBytes: 1, maxSourceEntries: 1 });
    globalThis.fetch = async () => new Response(archive, { status: 302, headers: { location: 'https://other.invalid/' } });
    await diagnostic(pinned, 'npm-acquisition-failed');
    const raw = gunzipSync(archive); raw[0] ^= 1;
    await diagnostic(serve(gzipSync(raw)), 'npm-acquisition-failed');
    await diagnostic(serve(archive.subarray(0, archive.length - 8)), 'npm-acquisition-failed');
    globalThis.fetch = async () => new Response(JSON.stringify({ name: '@fixture/other', version: '1.2.3', dist: { tarball: url, integrity } }));
    await diagnostic({ kind: 'npm', package: '@fixture/mcp', version: '1.2.3' }, 'npm-acquisition-failed');
    globalThis.fetch = async () => new Response(JSON.stringify({ name: '@fixture/mcp', version: '1.2.3', dist: { tarball: url, integrity: 'sha1-not-enough' } }));
    await diagnostic({ kind: 'npm', package: '@fixture/mcp', version: '1.2.3' }, 'npm-acquisition-failed');
    const controller = new AbortController(); controller.abort();
    const cancelled = await runScan(request(pinned), { signal: controller.signal });
    assert.equal(cancelled.status, 'diagnostic');
    assert.match(cancelled.diagnostics[0].detail, /cancelled/);
    return { cases: 'npm exact coordinates/archive, mutable refusal, modes/links, findings/coverage, identity/integrity, path/link/type/size/count/network/cancellation failures' };
  } finally { globalThis.fetch = originalFetch; }
}
