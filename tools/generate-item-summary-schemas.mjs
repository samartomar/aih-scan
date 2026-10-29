// Build first. This generator owns only the policy, severity profile and item summary schemas.
import { mkdirSync, writeFileSync } from 'node:fs';
import { z } from 'zod';
import { evidencePolicyShape, itemSummaryResultShape } from '../dist/assessment/item-summary.js';
import { severityProfileShape } from '../dist/assessment/severity-profile.js';
for (const [name, shape] of [['evidence-policy', evidencePolicyShape], ['severity-profile', severityProfileShape], ['item-summary', itemSummaryResultShape]]) {
  const schema = z.toJSONSchema(shape, { target: 'draft-2020-12', unrepresentable: 'any' });
  schema.$id = `urn:aihq:scan:${name}:1.0.0`;
  const dir = new URL(`../schemas/${name}/`, import.meta.url);
  mkdirSync(dir, { recursive: true });
  writeFileSync(new URL('1.0.0.json', dir), `${JSON.stringify(schema, null, 2)}\n`);
}
