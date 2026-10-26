import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import v8 from '@vitest/coverage-v8';
import { V8CoverageProvider } from '@vitest/coverage-v8/dist/provider.js';
import { verifyPackedCoverage } from './collect-packed-coverage.mjs';

// Keep the locked provider's collection, remapping, reports and thresholds unchanged.
// Add real installed-child counters only after proving the JS/map/source byte binding.
class PackedCoverageProvider extends V8CoverageProvider {
  initialize(context) {
    super.initialize(context);
    this.packedDirectory = mkdtempSync(join(tmpdir(), 'aih-packed-coverage-'));
    process.env.AIH_SCAN_PACKED_COVERAGE = this.packedDirectory;
  }
  async generateCoverage(options) {
    const coverage = await super.generateCoverage(options);
    const path = join(this.packedDirectory, 'npm-coverage.json');
    if (!existsSync(path)) {
      if (options.allTestsRun) throw new Error('Required packed npm coverage receipt is missing');
      return coverage;
    }
    const receipt = verifyPackedCoverage(JSON.parse(readFileSync(path, 'utf8')));
    const source = fileURLToPath(receipt.map.sources[0]).replaceAll('\\', '/');
    const packed = this.createCoverageMap();
    for (const entry of receipt.coverages)
      packed.merge(await this.remapCoverage(entry.url, 0, { code: receipt.code, map: receipt.map }, entry.functions));
    assert.deepEqual(packed.files().map(path => path.replaceAll('\\', '/')), [source], 'Packed coverage mapped an unexpected file');
    const original = coverage.files().find(path => path.replaceAll('\\', '/') === source);
    if (original) {
      // The untouched source placeholder uses Vite's different compiler/map. Combining its
      // zero-hit definitions with tsc's would count the same branches twice. Replace only
      // that placeholder, refusing to discard any real in-process function execution.
      assert(Object.values(coverage.fileCoverageFor(original).f).every(count => count === 0), 'Unexpected in-process npm function coverage');
      coverage.filter(path => path !== original);
    }
    coverage.merge(packed);
    console.log(`Merged verified packed npm coverage (${receipt.codeSha256}) into normal global thresholds`);
    return coverage;
  }
}
export default { ...v8, getProvider: () => new PackedCoverageProvider() };
