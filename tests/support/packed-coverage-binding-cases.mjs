// Test the coverage evidence binding without importing any product implementation.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
const { verifyPackedCoverage } = await import(pathToFileURL(process.argv[2]).href);
const receipt = JSON.parse(readFileSync(process.argv[3], 'utf8'));
verifyPackedCoverage(receipt);
for (const tamper of [
  value => { value.code += '\n// changed'; },
  value => { value.code += '\n// changed'; value.codeSha256 = createHash('sha256').update(value.code).digest('hex'); },
  value => { value.archiveSha256 = '0'.repeat(64); },
  value => { value.map.sources = ['file:///unrelated.ts']; },
  value => { value.map.sourcesContent = ['unrelated source']; },
  value => { value.coverages = []; },
]) {
  const changed = structuredClone(receipt); tamper(changed);
  assert.throws(() => verifyPackedCoverage(changed));
}
console.log('Packed coverage rejects changed JS, archive identity, mapping, source bytes and missing counters');
