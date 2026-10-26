// Coverage-only custody for the exact installed public consumer; never imports product internals.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { gunzipSync } from 'node:zlib';

const root = resolve(import.meta.dirname, '..');
const target = 'assessment/npm-source';
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
function archiveCode(archive) {
  const tar = gunzipSync(readFileSync(archive));
  for (let at = 0; at + 512 <= tar.length;) {
    const header = tar.subarray(at, at + 512);
    if (header.every(byte => byte === 0)) break;
    const name = header.subarray(0, 100).toString().split('\0')[0];
    const size = Number.parseInt(header.subarray(124, 136).toString().replace(/\0.*$/, '').trim(), 8);
    assert(Number.isSafeInteger(size) && size >= 0 && at + 512 + size <= tar.length, 'Invalid packed coverage archive');
    if (name === `package/dist/${target}.js`) return tar.subarray(at + 512, at + 512 + size);
    at += 512 + Math.ceil(size / 512) * 512;
  }
  throw new Error('Packed npm implementation is missing');
}
export function verifyPackedCoverage(receipt) {
  const source = join(root, 'src', `${target}.ts`);
  assert.equal(receipt.codeSha256, sha256(receipt.code), 'Packed coverage JavaScript digest mismatch');
  assert.deepEqual(Buffer.from(receipt.code, 'utf8'), archiveCode(receipt.archive), 'Packed coverage archive bytes changed');
  assert.equal(receipt.archiveSha256, sha256(readFileSync(receipt.archive)), 'Packed coverage archive digest mismatch');
  assert.deepEqual(receipt.map.sources, [pathToFileURL(source).href], 'Unexpected packed coverage source mapping');
  assert.equal(receipt.map.sourcesContent.length, 1, 'Packed coverage source content missing');
  assert.deepEqual(Buffer.from(receipt.map.sourcesContent[0], 'utf8'), readFileSync(source), 'Packed coverage source bytes changed');
  assert(receipt.coverages.length > 0, 'Packed npm counters are missing');
  return receipt;
}
export function collectPackedCoverage(consumer, archive, output) {
  mkdirSync(output, { recursive: true });
  const installed = join(consumer, 'node_modules/@aihq/scan/dist', `${target}.js`);
  const installedBytes = readFileSync(installed);
  const code = installedBytes.toString('utf8');
  assert.deepEqual(Buffer.from(code, 'utf8'), installedBytes, 'Packed JavaScript is not exact UTF-8');
  assert.deepEqual(installedBytes, archiveCode(archive), 'Installed coverage JavaScript differs from exact archive');
  const mapped = join(output, 'mapped');
  execFileSync(process.execPath, [join(root, 'node_modules/typescript/bin/tsc'), '-p', 'tsconfig.build.json', '--sourceMap', '--inlineSources', '--outDir', mapped], { cwd: root, stdio: 'pipe', windowsHide: true });
  const generated = readFileSync(join(mapped, `${target}.js`), 'utf8');
  const trailer = '//# sourceMappingURL=npm-source.js.map';
  assert(generated.endsWith(trailer), 'Coverage-only map trailer missing');
  assert.deepEqual(Buffer.from(generated.slice(0, -trailer.length), 'utf8'), installedBytes, 'Mapped compilation differs from packed JavaScript');
  const mapPath = join(mapped, `${target}.js.map`);
  const map = JSON.parse(readFileSync(mapPath, 'utf8'));
  assert.equal(map.file, 'npm-source.js');
  assert.deepEqual(map.sources.map(source => resolve(dirname(mapPath), map.sourceRoot || '', source)), [join(root, 'src', `${target}.ts`)]);
  map.sources = [pathToFileURL(join(root, 'src', `${target}.ts`)).href];
  map.sourceRoot = '';
  const url = pathToFileURL(installed).href;
  const coverages = readdirSync(join(output, 'raw')).filter(name => name.endsWith('.json')).flatMap(name => JSON.parse(readFileSync(join(output, 'raw', name), 'utf8')).result.filter(script => script.url === url));
  const retainedArchive = join(output, 'archive.tgz');
  copyFileSync(archive, retainedArchive);
  const receipt = verifyPackedCoverage({ archive: retainedArchive, archiveSha256: sha256(readFileSync(archive)), code, codeSha256: sha256(code), map, coverages });
  writeFileSync(join(output, 'npm-coverage.json'), JSON.stringify(receipt));
  console.log(`Packed npm coverage: exact JS sha256:${receipt.codeSha256}, ${coverages.length} counter set(s), verified TypeScript source map`);
  return receipt;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  assert.equal(process.argv.length, 5, 'Expected consumer, exact archive and coverage output');
  collectPackedCoverage(...process.argv.slice(2));
}
