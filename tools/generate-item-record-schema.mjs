// Build first. This generator owns only the item-record schema.
import { mkdirSync, writeFileSync } from 'node:fs';
import { z } from 'zod';
import { itemRecordSchema, itemRecordResultShape } from '../dist/assessment/item-record.js';
const schema = z.toJSONSchema(itemRecordResultShape, { target: 'draft-2020-12', unrepresentable: 'any' });
schema.$id = itemRecordSchema;
mkdirSync(new URL('../schemas/item-record/', import.meta.url), { recursive: true });
writeFileSync(new URL('../schemas/item-record/1.0.0.json', import.meta.url), `${JSON.stringify(schema, null, 2)}\n`);
