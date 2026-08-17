import { z } from "zod";
import {
  assertSafeRelativePosixPathV1,
  canonicalStrictJsonBytesV1,
  deepFreezeStrictJsonV1,
  parseStrictJsonObjectV1,
} from "../contract/strict-json-v1.js";

const MAX_SARIF_BYTES = 16 * 1024 * 1024;
const MAX_RESULTS = 4096;
const MAX_LOCATIONS_PER_RESULT = 16;
const MAX_PATH_LENGTH = 1024;
const MAX_RULE_ID_LENGTH = 256;
const MAX_MESSAGE_LENGTH = 4096;
const MAX_LEVEL_LENGTH = 64;
const brand = new WeakMap<object, Buffer>();

const bounded = (maximum: number) => z.string().min(1).max(maximum);
const regionSchema = z.strictObject({
  startLine: z.number().int().min(1).max(10_000_000),
  startColumn: z.number().int().min(1).max(1_000_000).optional(),
  endLine: z.number().int().min(1).max(10_000_000).optional(),
  endColumn: z.number().int().min(1).max(1_000_000).optional(),
});
const artifactLocationSchema = z.strictObject({ uri: bounded(MAX_PATH_LENGTH) });
const physicalLocationSchema = z.strictObject({
  artifactLocation: artifactLocationSchema,
  region: regionSchema.optional(),
});
const locationSchema = z.strictObject({ physicalLocation: physicalLocationSchema });
const resultSchema = z.strictObject({
  ruleId: bounded(MAX_RULE_ID_LENGTH),
  level: bounded(MAX_LEVEL_LENGTH).optional(),
  message: z.strictObject({ text: bounded(MAX_MESSAGE_LENGTH) }),
  locations: z.array(locationSchema).min(1).max(MAX_LOCATIONS_PER_RESULT),
});
const sarifSchema = z.strictObject({
  version: z.literal("2.1.0"),
  runs: z
    .array(
      z.strictObject({
        tool: z.strictObject({
          driver: z.strictObject({ name: z.literal("cisco-ai-skill-scanner") }),
        }),
        results: z.array(resultSchema).max(MAX_RESULTS),
      }),
    )
    .length(1),
});

export type CiscoSarifV1 = Readonly<z.infer<typeof sarifSchema>>;

function fail(message: string): never {
  throw new TypeError(`invalid Cisco SARIF V1: ${message}`);
}

function validatePaths(value: z.infer<typeof sarifSchema>): void {
  for (const result of value.runs[0]?.results ?? [])
    for (const location of result.locations)
      assertSafeRelativePosixPathV1(
        location.physicalLocation.artifactLocation.uri,
        "Cisco SARIF artifact path",
      );
}

export function parseCiscoSarifV1(text: string): CiscoSarifV1 {
  if (Buffer.byteLength(text, "utf8") > MAX_SARIF_BYTES) fail("SARIF exceeds bounded size");
  const raw = parseStrictJsonObjectV1(text, "Cisco SARIF");
  const parsed = sarifSchema.safeParse(raw);
  if (!parsed.success) fail(parsed.error.issues[0]?.message ?? "schema");
  validatePaths(parsed.data);
  const value = deepFreezeStrictJsonV1(structuredClone(parsed.data)) as CiscoSarifV1;
  brand.set(value as object, canonicalStrictJsonBytesV1(value));
  return value;
}

export function canonicalCiscoSarifV1Bytes(value: unknown): Buffer {
  if (typeof value !== "object" || value === null)
    fail("canonical bytes require a validated value");
  const bytes = brand.get(value);
  if (bytes === undefined) fail("canonical bytes require a validated branded value");
  return Buffer.from(bytes);
}
