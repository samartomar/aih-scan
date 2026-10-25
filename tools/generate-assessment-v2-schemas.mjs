// Build first. This script owns only the new 2.0.0 schema files; legacy schemas stay immutable.
import { writeFileSync } from 'node:fs';
import { z } from 'zod';
import { requestV2Shape, reportV2Shape, runResultV2Shape } from '../dist/assessment/shapes.js';
for (const [name, shape] of [['request', requestV2Shape], ['report', reportV2Shape], ['run-result', runResultV2Shape]]) {
  const schema = z.toJSONSchema(shape, { target: 'draft-2020-12', unrepresentable: 'any' });
  schema.$id = `urn:aihq:scan:${name}:2.0.0`;
  writeFileSync(new URL(`../schemas/${name}/2.0.0.json`, import.meta.url), `${JSON.stringify(schema, null, 2)}\n`);
}
